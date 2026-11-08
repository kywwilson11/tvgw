"""(resolver) Who answers the TV's lookups (design decision 81): the presets, `tvgw resolver list`, `show`,
`set` and `test`, the change ledger's line, the brief's Coverage line and setup's one question. Every
network, AdGuard and lock step is a fake: no lookup leaves the test box."""

import contextlib
import dataclasses
import http.client
import io
import ipaddress
import json
import random
import ssl
from pathlib import Path

import pytest

from tvgw import adguardcfg, cli, config, db, ledger, resolver, setup
from tvgw.config import Settings

NOW = 1793020000.0
CONF = """# the owner's own notes stay as they are
TV_IP=10.10.10.17
GW_IP=10.10.10.1
DNS_FALLBACK=
"""


@pytest.fixture
def site(tmp_path):
    (tmp_path / "state").mkdir()
    conf = tmp_path / "tvgw.conf"
    conf.write_text(CONF, encoding="utf-8")
    s = Settings(state_dir=str(tmp_path / "state"), adguard_yaml=str(tmp_path / "AdGuardHome.yaml"))
    return s, str(conf)


class Gateway:
    """The fakes `resolver.change` runs on: the direct DoH answers, AdGuard's apply, the guard's probe
    after it, and the must-allow names, each scripted, each call recorded."""

    def __init__(self, answers=True, apply_fail=None, state="up", names_ok=True, restore_fail=None):
        self.answers = answers  # True, or {url: why} for the addresses that do not answer
        self.apply_fail = apply_fail  # raised by the first apply
        self.restore_fail = restore_fail  # raised by the apply that puts the old settings back
        self.state_now = state
        self.names_ok = names_ok
        self.applies: list[tuple[str, str, bool]] = []
        self.asked: list[tuple[str, str]] = []
        self.states: list[str] = []

    def ask(self, url, name):
        self.asked.append((url, name))
        if self.answers is True or url not in self.answers:
            return True, ""
        return False, self.answers[url]

    def apply(self, st, guarded):
        self.applies.append((st.dns_upstreams, st.dns_bootstrap, guarded))
        if len(self.applies) == 1 and self.apply_fail is not None:
            raise self.apply_fail
        if len(self.applies) > 1 and self.restore_fail is not None:
            raise self.restore_fail
        return ["dns.upstream_dns: ..."]

    def state(self, st):
        self.states.append(st.dns_upstreams)
        return self.state_now

    def resolve(self, name):
        return ["203.0.113.7"] if self.names_ok else None


@contextlib.contextmanager
def free(s):
    yield None


def run(site, lg, gw, name="google", urls=""):
    s, conf = site
    target = resolver.target_for(name, urls, s.gw_ip)
    return resolver.change(
        s,
        lg,
        conf,
        target,
        apply_fn=gw.apply,
        ask=gw.ask,
        state=gw.state,
        resolve=gw.resolve,
        sleep=lambda sec: None,
        lock=free,
        now=NOW,
    )


def spool(s) -> list[list[str]]:
    path = Path(ledger.spool_path(s))
    return [line.split("\t") for line in path.read_text().splitlines()] if path.exists() else []


GOOGLE = resolver.by_name("google")
CLOUDFLARE = resolver.by_name("cloudflare")


# ---- the presets ----------------------------------------------------------------------------------------
def test_every_offered_preset_is_doh_by_address_with_its_own_bootstrap_and_no_filter():
    assert resolver.PRESETS, "at least the default is offered"
    seen: set[str] = set()
    for p in resolver.PRESETS:
        assert not p.filters, p.name  # tvgw is the only filter
        assert p.checked and p.read and p.policy.startswith("https://") and p.keeps, p.name
        assert len(p.upstreams) >= 2, f"{p.name}: one address is one failure"
        for url in p.upstreams:
            host = url.removeprefix("https://").split("/", 1)[0]
            assert url.startswith("https://") and ipaddress.IPv4Address(host).is_global, url
            assert config.fallback_host(url) == host  # the same form DNS_FALLBACK takes
        for addr in p.bootstrap:
            assert ipaddress.IPv4Address(addr).is_global
        # the bootstrap is the same operator's: nothing is asked of a second party
        assert {resolver.address(u) for u in p.upstreams} == set(p.bootstrap), p.name
        assert not seen & set(p.bootstrap), "two presets share an address"
        seen |= set(p.bootstrap)
    assert len({p.name for p in resolver.CANDIDATES}) == len(resolver.CANDIDATES)


def test_the_default_preset_is_what_a_settings_file_without_the_keys_means():
    d = Settings()
    assert resolver.PRESETS[0].name == resolver.DEFAULT
    assert ",".join(CLOUDFLARE.upstreams) == d.dns_upstreams
    assert ",".join(CLOUDFLARE.bootstrap) == d.dns_bootstrap
    assert resolver.current(d) is CLOUDFLARE and resolver.label_for(d) == "Cloudflare"


def test_a_candidate_not_checked_is_offered_nowhere_and_cannot_be_set():
    held = [p for p in resolver.CANDIDATES if not p.checked]
    assert held and all(p.held for p in held)
    for p in held:
        assert p not in resolver.PRESETS and p.name not in resolver.names()
        with pytest.raises(ValueError, match="not offered yet"):
            resolver.target_for(p.name)
        assert resolver.by_name(p.name, offered_only=False) is p


def test_a_filtering_candidate_would_never_be_offered(monkeypatch):
    """Break the rule on purpose: a candidate marked as filtering drops out of the offered list."""
    bad = dataclasses.replace(GOOGLE, name="filtered", filters=True)
    offered = tuple(p for p in (*resolver.CANDIDATES, bad) if p.checked and not p.filters)
    assert bad not in offered


@pytest.mark.parametrize(
    ("ups", "expected"),
    [
        ("https://8.8.8.8/dns-query,https://8.8.4.4/dns-query", "google"),
        ("https://8.8.4.4/dns-query,https://8.8.8.8/dns-query", "google"),  # order does not matter
        ("https://1.1.1.1/dns-query", "cloudflare"),  # one of its addresses is still Cloudflare
        ("https://1.1.1.1/dns-query,https://8.8.8.8/dns-query", None),  # two operators: the owner's own
        ("https://198.51.100.9/dns-query", None),
        ("https://cloudflare-dns.com/dns-query", None),  # a host name is never a preset
    ],
)
def test_the_settings_name_a_preset_or_the_owners_own(ups, expected):
    s = Settings(dns_upstreams=ups)
    p = resolver.current(s)
    assert (p.name if p else None) == expected
    label = resolver.label_for(s)
    assert label == (p.label if p else resolver.OWN)
    assert not any(ch.isdigit() for ch in label.replace("AdGuard", ""))  # never an address


# ---- custom URLs ------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "urls",
    [
        "https://198.51.100.9/dns-query",
        "https://198.51.100.9:8443/dns-query",
        "https://198.51.100.9/dns-query, https://203.0.113.4/resolve",
        "https://10.20.30.40/dns-query",  # a resolver of the owner's own on another private network
    ],
)
def test_custom_takes_doh_by_ipv4_address(urls):
    t = resolver.target_for("custom", urls, "10.10.10.1")
    assert t.name == "custom" and t.label == resolver.OWN and t.bootstrap is None
    assert t.upstreams == tuple(u.strip() for u in urls.split(","))


@pytest.mark.parametrize(
    ("urls", "why"),
    [
        ("", "give at least one address"),
        ("https://dns.example/dns-query", "not encrypted DNS by address"),
        ("http://198.51.100.9/dns-query", "not encrypted DNS by address"),
        ("tls://198.51.100.9", "not encrypted DNS by address"),
        ("https://198.51.100.9", "not encrypted DNS by address"),  # no path
        ("https://198.51.100.9/dns-query?dns=x", "not encrypted DNS by address"),
        ("https://[2001:db8::1]/dns-query", "not encrypted DNS by address"),
        ("https://198.51.100.999/dns-query", "is not an IPv4 address"),
        ("https://127.0.0.1/dns-query", "cannot be a resolver"),
        ("https://169.254.1.1/dns-query", "cannot be a resolver"),
        ("https://224.0.0.1/dns-query", "cannot be a resolver"),
        ("https://0.0.0.0/dns-query", "cannot be a resolver"),
        ("https://240.0.0.1/dns-query", "cannot be a resolver"),
        ("https://10.10.10.1/dns-query", "the gateway itself"),
        ("https://198.51.100.9:70000/dns-query", "is not a port"),
    ],
)
def test_custom_refuses_anything_but_doh_by_address(urls, why):
    with pytest.raises(ValueError, match=why):
        resolver.target_for("custom", urls, "10.10.10.1")


def test_custom_refuses_a_random_host_name_and_takes_a_random_public_address():
    """A property over a seeded sample: every name form is refused, every public IPv4 address taken."""
    rnd = random.Random(81)
    for _ in range(200):
        label = "".join(
            rnd.choice("abcdefghijklmnopqrstuvwxyz0123456789-") for _ in range(rnd.randint(1, 12))
        )
        if label.replace(".", "").isdigit():
            continue
        with pytest.raises(ValueError):
            resolver.target_for("custom", f"https://{label}.example/dns-query")
        ip = ipaddress.IPv4Address(rnd.getrandbits(32))
        url = f"https://{ip}/dns-query"
        if ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local or ip.is_unspecified:
            with pytest.raises(ValueError, match="cannot be a resolver"):
                resolver.target_for("custom", url)
        else:  # a public address, or a private one on another network the owner runs a resolver on
            assert resolver.target_for("custom", url).upstreams == (url,)


def test_names_and_urls_only_go_together_with_custom():
    with pytest.raises(ValueError, match="takes no addresses"):
        resolver.target_for("google", "https://198.51.100.9/dns-query")
    with pytest.raises(ValueError, match="the choices are cloudflare, adguard, google, custom"):
        resolver.target_for("nextdns")
    assert resolver.target_for("GOOGLE").upstreams == GOOGLE.upstreams


# ---- list and show ------------------------------------------------------------------------------------------
def test_list_marks_the_one_answering_and_says_what_each_keeps():
    lines = resolver.list_lines(Settings())
    text = "\n".join(lines)
    assert all(len(line) <= resolver.WIDTH for line in lines[:4])
    assert "None of the services below filters anything itself" in " ".join(text.split())
    assert any(line.startswith("* cloudflare") for line in lines)
    assert any(line.startswith("  google") for line in lines)
    for p in resolver.PRESETS:
        assert f"It {p.keeps}." in text and f"read {p.read}: {p.policy}" in text
    assert all(p.name not in text for p in resolver.CANDIDATES if not p.checked)
    assert "To change it: sudo tvgw resolver set NAME" in text
    own = "\n".join(resolver.list_lines(Settings(dns_upstreams="https://198.51.100.9/dns-query")))
    assert "Now: your own choice, https://198.51.100.9/dns-query, which is none of these." in own
    assert "* " not in own.replace("* answers", "")


def test_show_names_the_operator_what_it_sees_and_keeps():
    lines = resolver.show_lines(Settings(dns_upstreams=",".join(GOOGLE.upstreams)))
    assert lines[0] == (
        "The TV's lookups are answered by Google Public DNS (United States), over an encrypted connection"
        " to 8.8.8.8 and 8.8.4.4."
    )
    assert lines[1].startswith("Google Public DNS sees every name the filter lets through")
    assert f"it {GOOGLE.keeps}: {GOOGLE.policy}" in lines[2]
    assert lines[-1] == "To see the choices: tvgw resolver list"


def test_show_for_your_own_the_fallback_and_an_adguard_that_drifted():
    s = Settings(dns_upstreams="https://198.51.100.9/dns-query", dns_fallback="https://203.0.113.4/dns-query")
    lines = resolver.show_lines(s, adguard_upstreams=["https://1.1.1.1/dns-query"])
    assert lines[0] == "The TV's lookups are answered by your own choice: https://198.51.100.9/dns-query."
    assert lines[1].startswith("That service sees every name")
    assert "When those fail, the filter asks https://203.0.113.4/dns-query instead." in lines
    assert any("sudo tvgw adguard apply puts the settings' choice in place" in line for line in lines)
    same = resolver.show_lines(s, adguard_upstreams=["https://198.51.100.9/dns-query"])
    assert not any("adguard apply" in line for line in same)
    doc = resolver.show_json(s, ["https://198.51.100.9/dns-query"])
    assert doc["preset"] is None and doc["label"] == resolver.OWN and doc["adguard_matches"] is True


def test_show_reads_adguards_own_upstreams_only_when_it_can(tmp_path):
    path = tmp_path / "AdGuardHome.yaml"
    assert resolver.adguard_upstreams(str(path)) is None  # absent
    path.write_text("dns:\n  upstream_dns:\n  - https://1.1.1.1/dns-query\n", encoding="utf-8")
    assert resolver.adguard_upstreams(str(path)) == ["https://1.1.1.1/dns-query"]
    path.write_text(": not yaml [", encoding="utf-8")
    assert resolver.adguard_upstreams(str(path)) is None


# ---- asking an operator directly ---------------------------------------------------------------------------
def reply(rcode: int) -> bytes:
    return b"\x00\x00\x81" + bytes([0x80 | rcode]) + b"\x00" * 8


class FakeHttps:
    """http.client.HTTPSConnection, scripted: what the request raises, or the status and body."""

    plan: tuple = (200, reply(3))
    made: list = []

    def __init__(self, host, port, timeout, context):
        self.args = (host, port, timeout, context)
        FakeHttps.made.append(self)

    def request(self, method, path, body, headers):
        self.sent = (method, path, body, headers)
        if isinstance(FakeHttps.plan, BaseException):
            raise FakeHttps.plan

    def getresponse(self):
        status, body = FakeHttps.plan
        return type("R", (), {"status": status, "read": lambda self, n: body})()

    def close(self):
        pass


@pytest.mark.parametrize(
    ("plan", "ok", "why"),
    [
        ((200, reply(0)), True, ""),
        ((200, reply(3)), True, ""),  # NXDOMAIN for a made-up name is an answer
        ((200, reply(2)), False, "it answered with DNS error 2"),
        ((403, b""), False, "it answered HTTP 403, not a lookup"),
        (ssl.SSLCertVerificationError("bad"), False, "its certificate is not valid for 198.51.100.9"),
        (TimeoutError(), False, "no answer (TimeoutError)"),
        (ssl.SSLEOFError(), False, "no answer (SSLEOFError)"),
        (http.client.RemoteDisconnected(), False, "no answer (RemoteDisconnected)"),
    ],
)
def test_ask_doh_posts_one_question_with_the_certificate_held_to_the_address(monkeypatch, plan, ok, why):
    monkeypatch.setattr(FakeHttps, "plan", plan)
    monkeypatch.setattr(FakeHttps, "made", [])
    monkeypatch.setattr(http.client, "HTTPSConnection", FakeHttps)
    assert resolver.ask_doh("https://198.51.100.9:8443/dns-query", "tvgw-probe-x.example.com") == (ok, why)
    conn = FakeHttps.made[0]
    host, port, _, ctx = conn.args
    assert (host, port) == ("198.51.100.9", 8443)
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname  # the address must be in it
    method, path, body, headers = conn.sent
    assert (method, path, headers["content-type"]) == ("POST", "/dns-query", "application/dns-message")
    assert body[:2] == b"\x00\x00"  # RFC 8484: id 0, so a cache can share it


def test_ask_doh_refuses_a_url_that_is_not_by_address():
    assert resolver.ask_doh("https://dns.example/dns-query", "x.example") == (
        False,
        "not encrypted DNS by address",
    )


def test_precheck_and_test_name_each_address_that_did_not_answer():
    gw = Gateway(answers={"https://8.8.4.4/dns-query": "no answer (TimeoutError)"})
    t = resolver.target_for("google")
    assert resolver.precheck(t.upstreams, "us.lgtvsdp.com", gw.ask) == [
        ("https://8.8.4.4/dns-query", "no answer (TimeoutError)")
    ]
    asked = {name for _, name in gw.asked}
    assert len(asked) == 1 and asked.pop().endswith(".us.lgtvsdp.com")  # one made-up name, never a real one
    done = resolver.trial(t, "us.lgtvsdp.com", gw.ask)
    assert done.code == 1
    assert done.lines[:2] == [
        "8.8.8.8: answered, with a certificate valid for the address",
        "8.8.4.4: no answer (TimeoutError)",
    ]
    assert resolver.trial(t, "us.lgtvsdp.com", Gateway().ask).code == 0


# ---- set: all or nothing ---------------------------------------------------------------------------------
def test_set_writes_both_settings_through_save_conf_applies_tests_and_records(site, lg, monkeypatch):
    s, conf = site
    saved = []
    real = config.save_conf
    monkeypatch.setattr(
        config,
        "save_conf",
        lambda path, changes, *a, **k: saved.append(changes) or real(path, changes, *a, **k),
    )
    gw = Gateway()
    done = run(site, lg, gw)
    assert done.code == 0, done.lines
    assert saved == [
        {"DNS_UPSTREAMS": ",".join(GOOGLE.upstreams), "DNS_BOOTSTRAP": ",".join(GOOGLE.bootstrap)}
    ]
    text = Path(conf).read_text(encoding="utf-8")
    assert text.startswith(CONF)  # the owner's lines are as they were; the two keys are appended
    c = config.parse_conf(text)
    assert (c["DNS_UPSTREAMS"], c["DNS_BOOTSTRAP"]) == (
        ",".join(GOOGLE.upstreams),
        ",".join(GOOGLE.bootstrap),
    )
    assert gw.applies == [(",".join(GOOGLE.upstreams), ",".join(GOOGLE.bootstrap), True)]  # through the guard
    assert gw.states == [",".join(GOOGLE.upstreams)]
    assert [u for u, _ in gw.asked] == list(GOOGLE.upstreams)  # each address asked before anything changed
    assert spool(s) == [[f"{NOW:.0f}", "resolver", "set", "google"]]
    assert done.lines[0] == "tvgw resolver: the TV's lookups are now answered by Google Public DNS"
    assert f"the {len(lg.must_allow)} names the TV needs" in done.lines[1]
    assert done.lines[2] == "tvgw resolver: to go back: sudo tvgw resolver set cloudflare"


def test_set_the_one_answering_now_changes_nothing(site, lg):
    gw = Gateway()
    done = run(site, lg, gw, "cloudflare")
    assert done.code == 0 and "Cloudflare already answers the TV's lookups; nothing changed" in done.lines[0]
    assert gw.applies == [] and gw.asked == [] and spool(site[0]) == []


def test_an_address_that_does_not_answer_refuses_before_anything_is_written(site, lg):
    s, conf = site
    gw = Gateway(answers={"https://8.8.8.8/dns-query": "its certificate is not valid for 8.8.8.8"})
    done = run(site, lg, gw)
    assert done.code == 1
    assert done.lines == [
        "tvgw resolver: 8.8.8.8 did not answer: its certificate is not valid for 8.8.8.8",
        "tvgw resolver: nothing changed; the TV's lookups still go to Cloudflare",
    ]
    assert Path(conf).read_text(encoding="utf-8") == CONF and gw.applies == [] and spool(s) == []


def test_a_settings_file_the_next_command_could_not_load_is_refused_whole(site, lg):
    """DNS_FALLBACK must be a second operator: a fallback on Google's address refuses Google as upstream."""
    s, conf = site
    text = CONF.replace("DNS_FALLBACK=", "DNS_FALLBACK=https://8.8.8.8/dns-query")
    Path(conf).write_text(text, encoding="utf-8")
    s = dataclasses.replace(s, dns_fallback="https://8.8.8.8/dns-query")
    gw = Gateway()
    done = run((s, conf), lg, gw)
    assert done.code == 1 and "already an upstream" in done.lines[0] and "nothing changed" in done.lines[0]
    assert Path(conf).read_text(encoding="utf-8") == text and gw.applies == []


def test_no_settings_file_is_refused(site, lg, tmp_path):
    s, _ = site
    done = run((s, str(tmp_path / "none.conf")), lg, Gateway())
    assert done.code == 1 and "no settings file" in done.lines[0]


def test_upstreams_down_now_defers_with_exit_3_and_the_file_as_it_was(site, lg):
    s, conf = site
    gw = Gateway(apply_fail=adguardcfg.Deferred("deferred: upstream down (...)"))
    done = run(site, lg, gw)
    assert done.code == resolver.DEFERRED == 3
    assert "lookups through Cloudflare are failing right now" in done.lines[0]
    assert done.lines[-1] == "tvgw resolver: nothing changed; the TV's lookups still go to Cloudflare"
    assert Path(conf).read_text(encoding="utf-8") == CONF
    assert len(gw.applies) == 1 and spool(s) == []  # AdGuard was never touched, so not applied again


def test_an_apply_adguard_refused_puts_the_settings_back_and_applies_them_without_the_guard(site, lg):
    s, conf = site
    gw = Gateway(apply_fail=RuntimeError("AdGuardHome did not answer DNS after the change; put back"))
    done = run(site, lg, gw)
    assert done.code == 1 and "AdGuard Home did not take the change" in done.lines[0]
    assert done.lines[-1] == "tvgw resolver: put back; the TV's lookups go to Cloudflare as before"
    assert Path(conf).read_text(encoding="utf-8") == CONF
    assert gw.applies[1] == (s.dns_upstreams, s.dns_bootstrap, False)
    assert spool(s) == []


@pytest.mark.parametrize(
    ("gw", "why"),
    [
        (Gateway(state="down"), "a new lookup did not resolve through Google Public DNS (down)"),
        (Gateway(state="unknown"), "a new lookup did not resolve through Google Public DNS (unknown)"),
        (Gateway(names_ok=False), "names the TV needs did not resolve through Google Public DNS"),
    ],
    ids=["probe-down", "probe-unknown", "must-allow"],
)
def test_a_failed_test_after_the_apply_puts_everything_back(site, lg, gw, why):
    s, conf = site
    done = run(site, lg, gw)
    assert done.code == 1 and why in done.lines[0]
    assert Path(conf).read_text(encoding="utf-8") == CONF  # byte for byte
    # back to the old settings, and without the guard: it would see the new upstreams down and defer
    assert gw.applies == [
        (",".join(GOOGLE.upstreams), ",".join(GOOGLE.bootstrap), True),
        (s.dns_upstreams, s.dns_bootstrap, False),
    ]
    assert spool(s) == []


def test_a_test_that_cannot_run_and_an_interrupt_both_put_everything_back(site, lg):
    s, conf = site
    gw = Gateway()

    def broken(st):
        raise OSError("no socket")

    gw.state = broken
    done = run(site, lg, gw)
    assert done.code == 1 and "the new service could not be tested (no socket)" in done.lines[0]
    assert Path(conf).read_text(encoding="utf-8") == CONF and gw.applies[-1][2] is False
    gw = Gateway(apply_fail=KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt):
        run(site, lg, gw)
    assert Path(conf).read_text(encoding="utf-8") == CONF
    assert gw.applies == [
        (",".join(GOOGLE.upstreams), ",".join(GOOGLE.bootstrap), True),
        (s.dns_upstreams, s.dns_bootstrap, False),
    ]


def test_a_must_allow_name_that_answers_when_asked_again_passes(site, lg):
    """verify's retry: a transient miss is a WARN there, and a pass here."""
    gw = Gateway()
    calls = []

    def flaky(name):
        calls.append(name)
        return None if len(calls) == 1 else ["203.0.113.7"]

    gw.resolve = flaky
    assert run(site, lg, gw).code == 0


def test_a_way_back_that_fails_is_said_with_what_to_run(site, lg):
    _, conf = site
    gw = Gateway(state="down", restore_fail=RuntimeError("another tvgw adguard apply is running"))
    done = run(site, lg, gw)
    assert done.code == 1 and Path(conf).read_text(encoding="utf-8") == CONF
    assert "AdGuard Home could not be put back (another tvgw adguard apply is running)" in done.lines[-1]
    assert "sudo tvgw adguard apply" in done.lines[-1]


def test_a_settings_file_that_cannot_be_put_back_is_said(site, lg, monkeypatch):
    from tvgw import discover

    real, writes = discover.write_conf, []

    def broken(path, text):  # the change is written; putting it back is not
        writes.append(text)
        if len(writes) > 1:
            raise PermissionError("read-only")
        real(path, text)

    monkeypatch.setattr(discover, "write_conf", broken)
    gw = Gateway(state="down")
    done = run(site, lg, gw)
    assert done.code == 1 and "could not put the settings file back (read-only)" in done.lines[1]
    assert "back by hand" in done.lines[2] and len(gw.applies) == 1


def test_custom_keeps_the_bootstrap_and_records_custom_never_the_address(site, lg):
    s, conf = site
    gw = Gateway()
    done = run(site, lg, gw, "custom", "https://198.51.100.9/dns-query")
    assert done.code == 0, done.lines
    c = config.parse_conf(Path(conf).read_text(encoding="utf-8"))
    assert c["DNS_UPSTREAMS"] == "https://198.51.100.9/dns-query" and "DNS_BOOTSTRAP" not in c
    assert gw.applies == [("https://198.51.100.9/dns-query", s.dns_bootstrap, True)]
    assert spool(s) == [[f"{NOW:.0f}", "resolver", "set", "custom"]]
    assert done.lines[0].endswith("answered by your own resolver")


def test_from_your_own_the_way_back_names_its_addresses(site, lg):
    s, conf = site
    s = dataclasses.replace(s, dns_upstreams="https://198.51.100.9/dns-query")
    done = run((s, conf), lg, Gateway(), "cloudflare")
    assert done.code == 0
    assert done.lines[-1] == (
        "tvgw resolver: to go back: sudo tvgw resolver set custom https://198.51.100.9/dns-query"
    )


def test_a_lock_held_elsewhere_changes_nothing(site, lg):
    s, conf = site
    gw = Gateway()

    @contextlib.contextmanager
    def busy(st):
        yield "another install is running (waited)"

    done = resolver.change(
        s, lg, conf, resolver.target_for("google"), apply_fn=gw.apply, ask=gw.ask, lock=busy
    )
    assert done.code == 1 and "another install is running" in done.lines[0]
    assert Path(conf).read_text(encoding="utf-8") == CONF and gw.asked == [] and gw.applies == []


# ---- the pieces set uses ---------------------------------------------------------------------------------
def test_the_way_back_applies_without_the_restart_guard(lg, monkeypatch):
    """analyst.adguardcfg_apply hands its guard to adguardcfg.apply: none is the restart guard, a no-op
    is what `set` passes on its way back."""
    seen = []
    monkeypatch.setattr(adguardcfg, "apply", lambda path, d, ready, guard=None: seen.append(guard) or [])
    from tvgw import aghinstall

    monkeypatch.setattr(aghinstall, "takeover_evidence", lambda s, prof: None)
    s = Settings()
    resolver._apply_with(lg)(s, True)
    resolver._apply_with(lg)(s, False)
    assert seen[0] is None and callable(seen[1]) and seen[1]() is None


def test_the_probe_after_the_apply_is_the_guards_own_asked_where_the_tv_asks(lg, monkeypatch):
    got = {}

    def state(name, server="127.0.0.1", tries=3, port=53, wait=None, local=None):
        got.update(name=name, server=server, local=local)
        return "up"

    monkeypatch.setattr(adguardcfg, "upstream_state", state)
    s = Settings(adguard_yaml="/nonexistent/AdGuardHome.yaml")
    assert resolver._state_with(lg)(s) == "up"
    d = adguardcfg.desired(lg, s)
    assert (got["name"], got["local"], got["server"]) == (d.probe_name, d.local_name, s.gw_ip)
    assert adguardcfg.probe_targets(lg, s) == (d.probe_name, d.local_name)


@pytest.mark.parametrize("name", [p.name for p in resolver.PRESETS])
def test_the_plan_for_each_preset_sends_every_lookup_to_that_operator_alone(lg, name):
    p = resolver.by_name(name)
    s = Settings(dns_upstreams=",".join(p.upstreams), dns_bootstrap=",".join(p.bootstrap))
    planned = adguardcfg.plan({"schema_version": 34}, adguardcfg.desired(lg, s))
    dns = planned["dns"]
    assert dns["upstream_dns"] == list(p.upstreams) and dns["bootstrap_dns"] == list(p.bootstrap)
    assert dns["upstream_mode"] == "load_balance" and dns["fallback_dns"] == []  # one at a time, no other
    assert dns["upstream_dns_file"] == "" and all(
        c["upstreams"] == [] for c in planned["clients"]["persistent"]
    )


# ---- the ledger ------------------------------------------------------------------------------------------
def test_a_resolver_spool_line_is_a_class_a_change(site):
    s, _ = site
    row = ledger._spool_row([f"{NOW:.0f}", "resolver", "set", "google"], s, None)
    assert (row.source, row.kind, row.subject, row.detail) == (
        "resolver",
        "resolver_change",
        "google",
        {"action": "set"},
    )
    assert ledger.KINDS["resolver_change"][:2] == ("A", 1) and "resolver_change" in ledger.GROUPS["Gateway"]
    assert ledger._spool_row([f"{NOW:.0f}", "resolver", "set", "?"], s, None) is None
    assert ledger._spool_row([f"{NOW:.0f}", "resolver", "drop", "google"], s, None) is None


def test_the_ingest_loads_the_resolver_line_once(site):
    s, _ = site
    from tvgw import ingest

    ledger.append_spool(ledger.spool_path(s), ["resolver", "set", "adguard"], NOW)
    conn = db.connect(str(Path(s.state_dir) / "tvgw.db"))
    s2 = dataclasses.replace(s, db_path=str(Path(s.state_dir) / "tvgw.db"))
    assert ledger.load_spool(conn, s2, ingest._tail, lambda m: None) == 1
    assert ledger.load_spool(conn, s2, ingest._tail, lambda m: None) == 0
    conn.commit()
    assert conn.execute("SELECT kind, subject, effect_class FROM changes").fetchall() == [
        ("resolver_change", "adguard", "A")
    ]
    conn.close()


# ---- the brief -------------------------------------------------------------------------------------------
def coverage_line(o) -> str:
    buf = io.StringIO()
    cli.render_brief(o, buf)
    return next(line for line in buf.getvalue().splitlines() if line.startswith("Coverage:"))


def test_the_coverage_line_names_who_answers_and_never_an_address(gateway, lg):
    from conftest import fake_extract, fake_oddport

    from tvgw import ingest, queries

    ingest.run(
        gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, gate_lines=lambda since: [], lock=False
    )
    conn = db.connect(gateway.db_path)

    def brief_doc() -> dict:
        return queries.brief(conn, "2026-10-26", lg)

    o = brief_doc()
    assert "lookups answered by" not in coverage_line(o)  # queries.brief alone: the store has no settings
    cli._with_resolver(o, Settings())
    assert o["coverage"]["resolver"] == "Cloudflare"
    assert ", lookups answered by Cloudflare; last ingest" in coverage_line(o)
    own = brief_doc()
    cli._with_resolver(own, Settings(dns_upstreams="https://198.51.100.9/dns-query"))
    assert own["coverage"]["resolver"] == "your own resolver"
    assert "198.51.100.9" not in json.dumps(own) and "lookups answered by your own resolver" in coverage_line(
        own
    )
    bare = {"day": "x"}
    cli._with_resolver(bare, Settings())
    assert "coverage" not in bare


# ---- the command -----------------------------------------------------------------------------------------
@pytest.fixture
def conf_file(tmp_path):
    p = tmp_path / "tvgw.conf"
    p.write_text(
        f"STATE_DIR={tmp_path / 'state'}\nDNS_UPSTREAMS=https://198.51.100.9/dns-query\n", encoding="utf-8"
    )
    (tmp_path / "state").mkdir()
    return p


def test_cli_list_and_show(conf_file, capsys):
    assert cli.main(["--conf", str(conf_file), "resolver", "list"]) == 0
    assert "Now: your own choice" in capsys.readouterr().out
    assert cli.main(["--conf", str(conf_file), "resolver", "show"]) == 0
    assert capsys.readouterr().out.startswith("The TV's lookups are answered by your own choice")
    assert cli.main(["--conf", str(conf_file), "resolver", "show", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["upstreams"] == ["https://198.51.100.9/dns-query"]


def test_cli_set_needs_root_and_refuses_a_bad_choice_first(conf_file, capsys, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    assert cli.main(["--conf", str(conf_file), "resolver", "set", "google"]) == 1
    assert "run it with sudo: sudo tvgw resolver set google" in capsys.readouterr().out
    assert cli.main(["--conf", str(conf_file), "resolver", "set", "custom", "https://dns.example/x"]) == 1
    assert "not encrypted DNS by address" in capsys.readouterr().out
    assert cli.main(["--conf", str(conf_file), "resolver", "set", "quad9"]) == 1
    assert "not offered yet" in capsys.readouterr().out


def test_cli_set_as_root_runs_the_change(conf_file, capsys, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    seen = []
    monkeypatch.setattr(
        resolver,
        "change",
        lambda s, prof, conf, target: seen.append((conf, target)) or resolver.Outcome(3, ["x"]),
    )
    assert cli.main(["--conf", str(conf_file), "resolver", "set", "adguard"]) == 3
    assert seen == [(str(conf_file), resolver.target_for("adguard"))]


def test_cli_test_tries_a_held_candidate_and_changes_nothing(conf_file, capsys, monkeypatch):
    asked = []
    monkeypatch.setattr(resolver, "ask_doh", lambda url, name: asked.append(url) or (True, ""))
    before = conf_file.read_text(encoding="utf-8")
    assert cli.main(["--conf", str(conf_file), "resolver", "test", "quad9"]) == 0
    out = capsys.readouterr().out
    assert "9.9.9.10: answered" in out and "nothing was changed" in out
    assert asked == list(resolver.by_name("quad9", offered_only=False).upstreams)
    assert conf_file.read_text(encoding="utf-8") == before


# ---- setup's one question ---------------------------------------------------------------------------------
@pytest.fixture
def harness(tmp_path):
    """test_setup's Fake gateway, with a resolver test that records what it asked."""
    import test_setup as ts

    tested = []
    answers_ok = {"value": True}

    def make(replies=None, answers="", conf_text=None, dry_run=False, installed=False):
        fake = ts.Fake(tmp_path, installed=installed)
        (tmp_path / "state").mkdir(exist_ok=True)
        env = fake.env

        def env_with():
            e = env()

            def resolver_test(urls, name):
                tested.append((urls, name))
                return [] if answers_ok["value"] else [(urls[0], "no answer (TimeoutError)")]

            return dataclasses.replace(e, resolver_test=resolver_test)

        fake.env = env_with
        st, out, conf = ts.make(
            tmp_path, fake, answers=answers, replies=replies, dry_run=dry_run, conf_text=conf_text
        )
        return st, out, conf

    return make, tested, answers_ok


def conf_of(conf) -> dict:
    return config.parse_conf(conf.read_text(encoding="utf-8"))


def test_setup_asks_once_and_enter_keeps_cloudflare_writing_nothing(harness):
    make, tested, _ = harness
    st, out, conf = make(replies=[""] * 8)
    assert st.run() == 0, out.getvalue()
    text = out.getvalue()
    assert text.count("Who should answer the TV's lookups? (1-3) [1]: ") == 1
    assert "  [1] Cloudflare, United States (the default): it keeps no full address" in text
    assert "  [3] Google Public DNS, United States: it keeps your address" in text
    assert "DNS_UPSTREAMS" not in conf_of(conf) and tested == []


def test_setup_writes_the_owners_pick_after_asking_it_from_here(harness, lg):
    make, tested, _ = harness
    # pick, name, WAN_IF, WAN_GW, the lookups: 3, pair, write, apply
    st, out, conf = make(replies=["", "", "", "", "3", "", "", ""])
    assert st.run() == 0, out.getvalue()
    c = conf_of(conf)
    assert (c["DNS_UPSTREAMS"], c["DNS_BOOTSTRAP"]) == (
        ",".join(GOOGLE.upstreams),
        ",".join(GOOGLE.bootstrap),
    )
    assert tested == [(GOOGLE.upstreams, next(iter(lg.must_allow)))]


def test_setup_asks_again_when_the_pick_does_not_answer(harness):
    make, tested, ok = harness
    ok["value"] = False
    st, out, conf = make(replies=["", "", "", "", "3", "", "", "", ""])
    assert st.run() == 0, out.getvalue()
    text = out.getvalue()
    assert "Google Public DNS did not answer from this computer (8.8.8.8: no answer (TimeoutError))" in text
    assert text.count("Who should answer the TV's lookups?") == 2  # asked again; Enter then kept Cloudflare
    assert "DNS_UPSTREAMS" not in conf_of(conf) and [urls for urls, _ in tested] == [GOOGLE.upstreams]


def test_setup_unattended_takes_setup_resolver_and_stops_when_it_does_not_answer(harness):
    make, tested, ok = harness
    st, out, conf = make(answers="SETUP_RESOLVER=adguard\nSETUP_PAIR=no\n")
    assert st.run() == 0, out.getvalue()
    assert [urls for urls, _ in tested] == [resolver.by_name("adguard").upstreams]
    assert (
        "Who should answer the TV's lookups? AdGuard DNS (unfiltered) (SETUP_RESOLVER=adguard)"
        in out.getvalue()
    )
    assert conf_of(conf)["DNS_BOOTSTRAP"] == "94.140.14.140,94.140.14.141"
    conf.unlink()
    ok["value"] = False
    st, out, conf = make(answers="SETUP_RESOLVER=google\nSETUP_PAIR=no\n")
    assert st.run() == 1
    assert "SETUP_RESOLVER=google: Google Public DNS did not answer from this computer" in out.getvalue()
    assert "nothing was written" in out.getvalue() and not conf.exists()


def test_setup_unattended_without_setup_resolver_keeps_todays_behaviour(harness):
    make, tested, _ = harness
    st, out, conf = make(answers="SETUP_PAIR=no\n")
    assert st.run() == 0, out.getvalue()
    assert "Who should answer the TV's lookups? (1-3) [1]: 1" in out.getvalue()
    assert "DNS_UPSTREAMS" not in conf_of(conf) and tested == []


def test_a_rerun_keeps_the_stored_choice(harness):
    import test_setup as ts

    make, tested, _ = harness
    stored = config.update_conf(
        ts.EXAMPLE,
        {
            "TV_MAC": ts.MAC,
            "TV_IP": "10.10.10.12",
            "PROFILE": "lg-webos",
            "WAN_GW": ts.ROUTER,
            "DNS_UPSTREAMS": ",".join(GOOGLE.upstreams),
            "DNS_BOOTSTRAP": ",".join(GOOGLE.bootstrap),
        },
    )
    st, out, conf = make(answers="SETUP_PAIR=no\n", conf_text=stored, installed=True)
    assert st.run() == 0, out.getvalue()
    assert "Who should answer the TV's lookups? (1-3) [3]: 3" in out.getvalue()
    assert conf.read_text(encoding="utf-8") == stored and tested == []


def test_your_own_choice_is_offered_as_keep_and_is_the_default(harness):
    import test_setup as ts

    make, tested, _ = harness
    own = config.update_conf(ts.EXAMPLE, {"DNS_UPSTREAMS": "https://198.51.100.9/dns-query"})
    st, out, conf = make(replies=[""] * 8, conf_text=own)
    assert st.run() == 0, out.getvalue()
    text = out.getvalue()
    assert "  [4] keep your own: https://198.51.100.9/dns-query" in text
    assert "Who should answer the TV's lookups? (1-4) [4]: " in text
    assert conf_of(conf)["DNS_UPSTREAMS"] == "https://198.51.100.9/dns-query" and tested == []


def test_dns_upstreams_in_the_answers_is_the_owners_and_not_asked_about(harness):
    make, tested, _ = harness
    st, out, conf = make(answers="SETUP_PAIR=no\nDNS_UPSTREAMS=https://198.51.100.9/dns-query\n")
    assert st.run() == 0, out.getvalue()
    assert tested == []
    assert "Who should answer" not in out.getvalue()
    assert conf_of(conf)["DNS_UPSTREAMS"] == "https://198.51.100.9/dns-query"


def test_the_dry_run_asks_nobody_and_says_so(harness):
    make, tested, _ = harness
    st, out, _ = make(answers="SETUP_RESOLVER=google\n", dry_run=True)
    assert st.run() == 0, out.getvalue()
    assert (
        "(dry run) a real run first asks Google Public DNS for a lookup from this computer" in out.getvalue()
    )
    assert (
        tested == []
        and "+DNS_UPSTREAMS=https://8.8.8.8/dns-query,https://8.8.4.4/dns-query" in out.getvalue()
    )


@pytest.mark.parametrize(
    ("text", "why"),
    [
        ("SETUP_RESOLVER=nextdns\n", "SETUP_RESOLVER='nextdns': expected one of cloudflare, adguard, google"),
        ("SETUP_RESOLVER=custom\n", "your own service goes in the answers as DNS_UPSTREAMS"),
        ("SETUP_RESOLVER=quad9\n", "expected one of"),  # held: never written by setup
        (
            "SETUP_RESOLVER=google\nDNS_UPSTREAMS=https://1.1.1.1/dns-query\n",
            "SETUP_RESOLVER=google and DNS_UPSTREAMS=https://1.1.1.1/dns-query name different services",
        ),
        (
            "SETUP_RESOLVER=google\nDNS_BOOTSTRAP=1.1.1.1\n",
            "SETUP_RESOLVER=google and DNS_BOOTSTRAP=1.1.1.1 name different services",
        ),
    ],
)
def test_the_answers_file_refuses_a_resolver_it_cannot_write(text, why):
    with pytest.raises(ValueError, match=why.replace("(", r"\(").replace(")", r"\)")):
        setup.parse_answers(text)


def test_the_answers_file_takes_a_resolver_with_its_own_settings():
    a = setup.parse_answers(f"SETUP_RESOLVER=Google\nDNS_UPSTREAMS={','.join(reversed(GOOGLE.upstreams))}\n")
    assert a.resolver == "google" and "SETUP_RESOLVER" not in a.conf
    assert "SETUP_RESOLVER" in setup.SETUP_KEYS


def test_setup_checks_with_the_real_test_by_default():
    assert setup.live_env(Settings()).resolver_test is setup._resolver_test
    assert setup.Env.__dataclass_fields__["resolver_test"].default(("x",), "y") == []
