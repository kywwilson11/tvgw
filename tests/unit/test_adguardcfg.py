"""AdGuard Home config-as-code: planning, diffing and applying against a realistic YAML."""

import copy
import fcntl
import os
import re
import signal
import socket
import struct
import threading
import time

import pytest
import yaml

from tvgw import adguardcfg, profile
from tvgw.config import Settings

# trimmed from a real AdGuardHome.yaml (schema 34): the keys we manage plus some we must not touch
STOCK = """
http:
  address: 0.0.0.0:3000
  session_ttl: 30d
users:
  - name: admin
    password: $2a$10$hashhashhash
dns:
  bind_hosts:
    - 0.0.0.0
  port: 53
  anonymize_client_ip: true
  upstream_dns:
    - https://9.9.9.9/dns-query
  bootstrap_dns:
    - 9.9.9.9
  cache_optimistic: false
  enable_dnssec: true
querylog:
  interval: 24h
  enabled: true
  file_enabled: true
statistics:
  interval: 24h
  enabled: true
filters:
  - enabled: false
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
    name: AdGuard DNS filter
    id: 1
  - enabled: false
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_72.txt
    name: old name
    id: 1792975975
user_rules:
  - '||old.example^'
filtering:
  blocked_response_ttl: 300
  rewrites:
    - domain: ngfts.lge.com
      answer: 10.10.10.1
      enabled: false
  filtering_enabled: true
  protection_enabled: true
clients:
  runtime_sources:
    whois: true
  persistent: []
schema_version: 34
"""

SETTINGS = Settings(tv_ip="10.10.10.17", tv_mac="aa:bb:cc:dd:ee:ff", tv_name="lgcx")


def test_desired_from_profile_and_settings():
    lg = profile.load("lg-webos")
    d = adguardcfg.desired(lg, SETTINGS)
    assert [n for n, _ in d.filters] == ["HaGeZi LG webOS", "HaGeZi DoH/VPN bypass (DoH only)", "HaGeZi Pro"]
    assert len(d.user_rules) >= 60 and "||alphonso.tv^" in d.user_rules
    assert "||ngfts.lge.com^$dnsrewrite=10.10.10.1" in d.user_rules  # the default GW_IP
    moved = adguardcfg.desired(lg, Settings(gw_ip="192.0.2.1"))
    assert "||ngfts.lge.com^$dnsrewrite=192.0.2.1" in moved.user_rules  # the rewrites follow the setting
    assert not any(r.endswith("=10.10.10.1") for r in moved.user_rules)
    assert d.upstreams == ("https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query")
    assert d.bootstrap == ("1.1.1.1", "1.0.0.1") and d.tv_name == "lgcx"


def test_plan_sets_only_managed_keys_and_keeps_the_rest():
    current = yaml.safe_load(STOCK)
    d = adguardcfg.desired(profile.load("lg-webos"), SETTINGS)
    new = adguardcfg.plan(current, d)
    assert current["http"]["address"] == "0.0.0.0:3000"  # input untouched
    assert new["http"]["address"] == "127.0.0.1:3000" and new["http"]["session_ttl"] == "30d"
    assert new["users"][0]["password"].startswith("$2a$")  # never touched
    assert new["dns"]["upstream_dns"] == list(d.upstreams) and new["dns"]["enable_dnssec"] is True
    assert new["dns"]["cache_optimistic"] is True and new["dns"]["anonymize_client_ip"] is False
    assert new["querylog"]["interval"] == "90d" and new["statistics"]["interval"] == "90d"
    assert new["filtering"]["blocked_response_ttl"] == 60 and new["filtering"]["rewrites"] == []
    assert (
        new["filtering"]["blocking_mode"] == "default"
        and new["filtering"]["protection_disabled_until"] is None
    )
    assert new["dns"]["upstream_dns_file"] == ""
    assert new["schema_version"] == 34
    # filters: stock one left disabled, existing LG list re-enabled and renamed, two appended with fresh ids
    f = {x["url"]: x for x in new["filters"]}
    assert f["https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"]["enabled"] is False
    lg_list = f["https://adguardteam.github.io/HostlistsRegistry/assets/filter_72.txt"]
    assert lg_list["enabled"] is True and lg_list["name"] == "HaGeZi LG webOS" and lg_list["id"] == 1792975975
    ids = sorted(x["id"] for x in new["filters"])
    assert ids == [1, 1792975975, 1792975976, 1792975977]
    assert new["user_rules"] == list(d.user_rules)  # replaced wholesale
    tv = new["clients"]["persistent"][0]
    assert (
        tv["name"] == "lgcx"
        and tv["ids"] == ["10.10.10.17", "aa:bb:cc:dd:ee:ff"]
        and tv["tags"] == ["device_tv"]
    )
    assert tv["use_global_settings"] and tv["filtering_enabled"] and tv["use_global_blocked_services"]
    assert tv["upstreams"] == [] and tv["ignore_querylog"] is False


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("filtering.blocking_mode", "nxdomain"),  # verify and the brief read 0.0.0.0 as blocked
        ("filtering.protection_disabled_until", "2026-10-26T20:15:25Z"),  # the UI's pause button
        ("dns.upstream_dns_file", "/tmp/x"),  # replaces the upstream list
        ("dns.aaaa_disabled", False),  # AAAA answers would be fetched for the TV again
        ("dns.handle_ddr", False),  # the resolver-upgrade probe would go upstream
        ("clients.persistent.0.use_global_settings", False),
        ("clients.persistent.0.filtering_enabled", False),
        ("clients.persistent.0.use_global_blocked_services", False),
        ("clients.persistent.0.upstreams", ["192.0.2.53"]),  # a per-client bypass of our upstreams
    ],
)
def test_plan_owns_every_key_that_can_unfilter_the_tv(path, value):
    """Reproduced: with any one of these edited in the UI, changes() returned [] because plan() copied
    what it did not set, so the edit survived every deploy. verify probes from the Pi, so the
    per-client ones never reached it either."""
    d = adguardcfg.desired(profile.load("lg-webos"), SETTINGS)
    planned = adguardcfg.plan(yaml.safe_load(STOCK), d)
    mutated = copy.deepcopy(planned)
    *parents, leaf = path.split(".")
    node = mutated
    for key in parents:
        node = node[int(key)] if isinstance(node, list) else node[key]
    node[leaf] = value
    diff = adguardcfg.changes(mutated, adguardcfg.plan(mutated, d))
    assert diff and all(c.startswith(path + ":") for c in diff), diff
    assert adguardcfg.plan(mutated, d) == planned


def test_plan_is_idempotent_and_changes_describe_drift():
    current = yaml.safe_load(STOCK)
    d = adguardcfg.desired(profile.load("lg-webos"), SETTINGS)
    new = adguardcfg.plan(current, d)
    diff = adguardcfg.changes(current, new)
    assert any(c.startswith("http.address: '0.0.0.0:3000' -> '127.0.0.1:3000'") for c in diff)
    assert any(c.startswith("filtering.blocked_response_ttl: 300 -> 60") for c in diff)
    assert not any(c.startswith("users.") or c.startswith("schema_version") for c in diff)
    again = adguardcfg.plan(new, d)
    assert again == new and adguardcfg.changes(new, again) == []


def test_existing_tv_client_keeps_its_name_and_gets_exactly_our_ids():
    current = yaml.safe_load(STOCK)
    current["clients"]["persistent"] = [{"name": "LG CX", "ids": ["10.10.10.17"], "tags": ["device_tv"]}]
    new = adguardcfg.plan(current, adguardcfg.desired(profile.load("lg-webos"), SETTINGS))
    tv = new["clients"]["persistent"][0]
    assert tv["name"] == "LG CX" and tv["ids"] == ["10.10.10.17", "aa:bb:cc:dd:ee:ff"]
    assert tv["ignore_querylog"] is False and len(new["clients"]["persistent"]) == 1


def test_tv_that_changed_address_is_matched_by_mac_or_name_not_duplicated():
    current = yaml.safe_load(STOCK)
    current["clients"]["persistent"] = [{"name": "other", "ids": ["10.10.10.99", "aa:bb:cc:dd:ee:ff"]}]
    new = adguardcfg.plan(current, adguardcfg.desired(profile.load("lg-webos"), SETTINGS))
    assert [c["ids"] for c in new["clients"]["persistent"]] == [["10.10.10.17", "aa:bb:cc:dd:ee:ff"]]
    current["clients"]["persistent"] = [{"name": "lgcx", "ids": ["10.10.10.99"]}]
    new = adguardcfg.plan(current, adguardcfg.desired(profile.load("lg-webos"), SETTINGS))
    assert [c["ids"] for c in new["clients"]["persistent"]] == [["10.10.10.17", "aa:bb:cc:dd:ee:ff"]]


def load_text(tmp_path, text: str) -> dict:
    path = tmp_path / "a.yaml"
    path.write_text(text)
    return adguardcfg.load_yaml(str(path))


def test_two_clients_holding_our_ids_end_as_one_carrying_them():
    """AdGuard refuses to start on a duplicate client id, so after this every apply would have rolled
    back until the YAML was hand-edited. The other client keeps what is not ours or goes when empty."""
    d = adguardcfg.desired(profile.load("lg-webos"), SETTINGS)
    current = yaml.safe_load(STOCK)
    current["clients"]["persistent"] = [
        {"name": "old tv", "ids": ["10.10.10.17", "192.0.2.5"]},
        {"name": "wired", "ids": ["AA:BB:CC:DD:EE:FF", "192.0.2.9"]},
        {"name": "spare", "ids": ["aa:bb:cc:dd:ee:ff"]},
    ]
    new = adguardcfg.plan(current, d)
    assert [(c["name"], c["ids"]) for c in new["clients"]["persistent"]] == [
        ("old tv", ["10.10.10.17", "aa:bb:cc:dd:ee:ff"]),
        ("wired", ["192.0.2.9"]),
    ]
    assert adguardcfg.changes(new, adguardcfg.plan(new, d)) == []


def test_an_upper_cased_mac_is_the_same_client_and_ids_are_written_as_given():
    d = adguardcfg.desired(profile.load("lg-webos"), SETTINGS)
    current = yaml.safe_load(STOCK)
    current["clients"]["persistent"] = [{"name": "tv", "ids": [" AA:BB:CC:DD:EE:FF "]}]
    new = adguardcfg.plan(current, d)
    assert len(new["clients"]["persistent"]) == 1  # not a second entry carrying the same MAC
    assert new["clients"]["persistent"][0]["ids"] == ["10.10.10.17", "aa:bb:cc:dd:ee:ff"]


def test_filter_ids_tolerate_null_and_a_repeated_url_yields_one_entry():
    d = adguardcfg.desired(profile.load("lg-webos"), SETTINGS)
    current = yaml.safe_load(STOCK)
    current["filters"][0]["id"] = None  # raised TypeError from plan()
    new = adguardcfg.plan(current, d)
    assert new["filters"][0]["id"] is None  # not our list: left as it was
    assert sorted(f["id"] for f in new["filters"][1:]) == [1792975975, 1792975976, 1792975977]
    twice = adguardcfg.Desired(
        filters=(("A", "https://x.example/l.txt"), ("B", "https://x.example/l.txt")),
        user_rules=(), upstreams=("1.1.1.1",), bootstrap=(), tv_ip="10.10.10.17", tv_mac="", tv_name="tv",
    )  # fmt: skip
    new = adguardcfg.plan({}, twice)
    assert [(f["url"], f["name"]) for f in new["filters"]] == [("https://x.example/l.txt", "B")]


def test_upstreams_are_trimmed_and_an_empty_list_is_refused():
    lg = profile.load("lg-webos")
    d = adguardcfg.desired(
        lg,
        Settings(
            dns_upstreams="https://a.example/dns-query, https://b.example/dns-query",
            dns_bootstrap=" 1.1.1.1 ,",
        ),
    )
    assert d.upstreams == ("https://a.example/dns-query", "https://b.example/dns-query")
    assert d.bootstrap == ("1.1.1.1",)
    with pytest.raises(ValueError, match="DNS_UPSTREAMS is empty"):
        adguardcfg.desired(lg, Settings(dns_upstreams=","))


def test_yaml_1_2_scalars_survive_a_round_trip(tmp_path):
    # AdGuard writes YAML 1.2: an all-digit MAC and the word "on" are strings there, not an int / bool
    cfg = load_text(
        tmp_path,
        "clients:\n  persistent:\n    - name: tv\n      ids:\n        - 10:20:30:40:50:59\n"
        "        - on\nx: 0o17\ny: 1e3\nz: true\n",
    )
    assert cfg["clients"]["persistent"][0]["ids"] == ["10:20:30:40:50:59", "on"]
    assert cfg["x"] == 15 and cfg["y"] == 1000.0 and cfg["z"] is True
    text = adguardcfg.dump_yaml(cfg)
    assert "x: 15\n" in text  # the number, not the 1.2 spelling it was read from
    assert yaml.safe_load(text) == cfg and load_text(tmp_path, text) == cfg  # readable both ways


def test_rfc3339_scalars_stay_text_and_are_written_back_plain(tmp_path):
    """`filtering.protection_disabled_until` holds one of these while protection is paused. Read as a
    1.1 timestamp it came back as `2026-10-26 20:15:25.123456-05:00`: the form changed, the
    nanoseconds were lost, and yaml.v3 refuses a quoted scalar for a *time.Time."""
    line = "a: 2026-10-26T20:15:25.123456789-05:00\n"
    cfg = load_text(tmp_path, line)
    assert cfg == {"a": "2026-10-26T20:15:25.123456789-05:00"}
    assert adguardcfg.dump_yaml(cfg) == line


def test_strings_a_1_2_reader_would_take_for_numbers_are_quoted(tmp_path):
    """`0o17` and `1e3` are not numbers in 1.1, so PyYAML wrote them bare and a 1.2 reader got 15 and 1000."""
    cfg = {"c": "0o17", "d": "1e3", "e": "on", "f": "10:20:30:40:50:59", "g": ".inf"}
    text = adguardcfg.dump_yaml(cfg)
    assert all(re.fullmatch(r"\w: '.*'", line) for line in text.splitlines()), text
    assert yaml.safe_load(text) == cfg and load_text(tmp_path, text) == cfg


def test_plan_from_empty_config():
    new = adguardcfg.plan({}, adguardcfg.desired(profile.load("lg-webos"), SETTINGS))
    assert new["dns"]["upstream_dns"] and new["filters"][0]["id"] == 1792975975 and new["user_rules"]


def test_yaml_round_trip_quotes_rules_safely():
    d = adguardcfg.desired(profile.load("lg-webos"), SETTINGS)
    text = adguardcfg.dump_yaml(adguardcfg.plan(yaml.safe_load(STOCK), d))
    back = yaml.safe_load(text)
    assert back["user_rules"] == list(d.user_rules)
    assert back["user_rules"][0].startswith("@@||")
    assert "@@||us.lgtvsdp.com^$important" in back["user_rules"]
    assert "@@||us.nextlgsdp.com^$important" in back["user_rules"]


def test_apply_stops_backs_up_writes_and_starts(tmp_path):
    path = tmp_path / "AdGuardHome.yaml"
    path.write_text(STOCK)
    calls = []
    d = adguardcfg.desired(profile.load("lg-webos"), SETTINGS)
    checked = []
    diff = adguardcfg.apply(
        str(path),
        d,
        control=lambda *a: calls.append(a),
        ready=lambda: True,
        check=lambda p: checked.append(p) or (True, ""),
        now=1793020000,
    )
    assert calls == [("stop", "AdGuardHome"), ("start", "AdGuardHome")]
    (backup,) = tmp_path.glob("AdGuardHome.yaml.bak-*")
    assert diff and backup.name == f"AdGuardHome.yaml.bak-20261026130640Z-{os.getpid()}"  # UTC, no local zone
    assert backup.read_text() == STOCK
    assert (
        checked and checked[0] != str(path) and not list(tmp_path.glob(".AdGuardHome.*"))
    )  # tmp validated, gone
    written = yaml.safe_load(path.read_text())
    assert written["user_rules"] == list(d.user_rules)
    # second apply: nothing to do, service not touched
    calls.clear()
    assert adguardcfg.apply(str(path), d, control=lambda *a: calls.append(a), ready=lambda: True) == []
    assert calls == []


def test_apply_refuses_a_config_adguard_rejects_without_touching_the_service(tmp_path):
    import pytest

    path = tmp_path / "AdGuardHome.yaml"
    path.write_text(STOCK)
    d = adguardcfg.desired(profile.load("lg-webos"), SETTINGS)
    calls = []
    with pytest.raises(RuntimeError, match=r"rejected .*nothing changed\nduplicate client id") as e:
        adguardcfg.apply(
            str(path),
            d,
            control=lambda *a: calls.append(a),
            ready=lambda: True,
            check=lambda p: (False, "duplicate client id"),  # AdGuard's own words reach the operator
        )
    assert str(e.value).endswith("duplicate client id")
    assert calls == [] and path.read_text() == STOCK and not list(tmp_path.glob(".AdGuardHome.*"))
    assert not list(tmp_path.glob("AdGuardHome.yaml.bak-*"))  # nothing to roll back, so no backup


def test_parse_rules_drops_comments_blanks_and_duplicates():
    assert profile.parse_rules("! c\n\n||a^\n  ||b^  \n||a^\n@@||c^\n") == ["||a^", "||b^", "@@||c^"]


def test_apply_waits_for_the_resolver_and_reports_when_it_does_not_come_back(tmp_path):
    import pytest

    path = tmp_path / "AdGuardHome.yaml"
    path.write_text(STOCK)
    d = adguardcfg.desired(profile.load("lg-webos"), SETTINGS)
    calls = []
    with pytest.raises(RuntimeError, match=r"did not answer .* was put back"):
        adguardcfg.apply(
            str(path), d, control=lambda *a: calls.append(a), ready=lambda: False, check=lambda p: (True, "")
        )
    # written, started, found dead, rolled back to the backup and restarted
    assert calls == [
        ("stop", "AdGuardHome"),
        ("start", "AdGuardHome"),
        ("stop", "AdGuardHome"),
        ("start", "AdGuardHome"),
    ]
    assert path.read_text() == STOCK


def udp_responder(reply):
    """A UDP server on an ephemeral port answering every question with `reply(question)`; (port, stop)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(0.2)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                question, peer = sock.recvfrom(512)
            except TimeoutError:
                continue
            sock.sendto(reply(question), peer)
        sock.close()

    threading.Thread(target=serve, daemon=True).start()
    return sock.getsockname()[1], stop


def servfail(q: bytes) -> bytes:
    return q[:2] + struct.pack(">HHHHH", 0x8182, 1, 0, 0, 0) + q[12:]


def one_a_record(q: bytes) -> bytes:
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([10, 10, 10, 1])
    return q[:2] + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0) + q[12:] + answer


def test_dns_ready_needs_a_resolved_answer_not_any_datagram():
    """Reproduced: a resolver whose DoH upstreams were unreachable answered SERVFAIL to everything and
    dns_ready() returned True, so a config that left the TV without names passed apply."""
    port, stop = udp_responder(servfail)
    try:
        t0 = time.monotonic()
        assert adguardcfg.dns_ready(port=port, timeout=1.5) is False
        assert time.monotonic() - t0 < 3
    finally:
        stop.set()
    port, stop = udp_responder(one_a_record)
    try:
        assert adguardcfg.dns_ready(port=port, timeout=1.5) is True
    finally:
        stop.set()


def test_dns_ready_is_false_with_no_listener():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    assert adguardcfg.dns_ready(port=port, timeout=1.0) is False


# ---- apply() under fault injection ------------------------------------------------------------------
def flaky(calls: list, fail: tuple[str, int] | None):
    """A `control` that records every call and raises once, on the n-th call of one verb."""
    seen: dict[str, int] = {}

    def control(verb: str, unit: str) -> None:
        calls.append((verb, unit))
        seen[verb] = seen.get(verb, 0) + 1
        if fail == (verb, seen[verb]):
            raise RuntimeError(f"systemctl {verb} failed")

    return control


def live(tmp_path):
    path = tmp_path / "AdGuardHome.yaml"
    path.write_text(STOCK)
    return path, adguardcfg.desired(profile.load("lg-webos"), SETTINGS)


@pytest.mark.parametrize(
    ("fail", "ready", "calls_made", "message"),
    [
        (("stop", 1), True, ["stop", "stop", "start"], "stop failed; the previous config"),
        (("start", 1), True, ["stop", "start", "stop", "start"], "start failed; the previous config"),
        (("start", 2), False, ["stop", "start", "stop", "start"], "did not answer .* also failed"),
    ],
)
def test_apply_rolls_back_whatever_fails_after_the_stop(tmp_path, fail, ready, calls_made, message):
    """Reproduced before the fix: a raising start left the planned file live with the backup
    unrestored; a raising stop leaked the validated candidate; a raising rollback stop left the
    planned file in place."""
    path, d = live(tmp_path)
    calls: list = []
    with pytest.raises(RuntimeError, match=message) as e:
        adguardcfg.apply(
            str(path), d, control=flaky(calls, fail), ready=lambda: ready, check=lambda p: (True, "")
        )
    assert [verb for verb, _ in calls] == calls_made
    assert path.read_text() == STOCK
    assert not list(tmp_path.glob(".AdGuardHome.*"))
    (backup,) = tmp_path.glob("AdGuardHome.yaml.bak-*")
    assert str(backup) in str(e.value)


def test_a_rollback_that_cannot_write_leaves_a_whole_file_never_a_prefix(tmp_path, monkeypatch):
    """shutil.copy2 restored in place before: a kill or ENOSPC mid-copy truncated the live YAML."""
    path, d = live(tmp_path)
    real_replace, replaced = os.replace, []

    def replace(src, dst):
        replaced.append(src)
        if len(replaced) == 2:  # the first move is the candidate, the second the restore
            raise OSError(28, "No space left on device")
        real_replace(src, dst)

    monkeypatch.setattr(adguardcfg.os, "replace", replace)
    calls: list = []
    with pytest.raises(RuntimeError, match=r"did not answer .* also failed: .*No space left"):
        adguardcfg.apply(
            str(path), d, control=flaky(calls, None), ready=lambda: False, check=lambda p: (True, "")
        )
    planned = adguardcfg.dump_yaml(adguardcfg.plan(yaml.safe_load(STOCK), d))
    assert path.read_text() in (STOCK, planned)  # one of the two whole files, never part of one
    assert not list(tmp_path.glob(".AdGuardHome.*"))


def test_an_empty_or_truncated_config_is_refused_before_the_service_is_touched(tmp_path):
    """load_yaml gives {} for an empty file, and plan() would have completed a destroyed config from the
    template; AdGuard would then have started on a config without its admin user."""
    path = tmp_path / "AdGuardHome.yaml"
    d = adguardcfg.desired(profile.load("lg-webos"), SETTINGS)
    for text in ("", "http:\n  address: 0.0.0.0:3000\n"):
        path.write_text(text)
        calls: list = []
        with pytest.raises(RuntimeError, match=r"has no schema_version .*nothing changed"):
            adguardcfg.apply(
                str(path), d, control=flaky(calls, None), ready=lambda: True, check=lambda p: (True, "")
            )
        assert calls == [] and path.read_text() == text
    assert not list(tmp_path.glob(".AdGuardHome.*")) and not list(tmp_path.glob("AdGuardHome.yaml.bak-*"))


def test_one_apply_at_a_time(tmp_path):
    path, d = live(tmp_path)
    holder = open(tmp_path / ".tvgw-adguard.lock", "w")  # noqa: SIM115 - another apply, as far as this one knows
    fcntl.flock(holder, fcntl.LOCK_EX)
    calls: list = []
    try:
        with pytest.raises(RuntimeError, match="another tvgw adguard apply is running"):
            adguardcfg.apply(
                str(path), d, control=flaky(calls, None), ready=lambda: True, check=lambda p: (True, "")
            )
    finally:
        holder.close()
    assert calls == [] and path.read_text() == STOCK and not list(tmp_path.glob(".AdGuardHome.*"))
    assert adguardcfg.apply(
        str(path), d, control=flaky(calls, None), ready=lambda: True, check=lambda p: (True, "")
    )


def test_backups_are_utc_stamped_and_never_overwritten(tmp_path):
    """The name was local time with no zone, and now=0 meant the wall clock."""
    path, d = live(tmp_path)
    run = lambda desired: adguardcfg.apply(  # noqa: E731
        str(path), desired, control=lambda *a: None, ready=lambda: True, check=lambda p: (True, ""), now=0
    )
    assert run(d)
    assert run(adguardcfg.desired(profile.load("lg-webos"), Settings(tv_name="renamed")))
    backups = sorted(p.name for p in tmp_path.glob("AdGuardHome.yaml.bak-*"))
    assert len(backups) == 2 and all(
        b.startswith(f"AdGuardHome.yaml.bak-19700101000000Z-{os.getpid()}") for b in backups
    )


def test_apply_leaves_the_signal_mask_as_it_found_it(tmp_path):
    path, d = live(tmp_path)
    before = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    seen_inside = []
    adguardcfg.apply(
        str(path),
        d,
        control=lambda *a: seen_inside.append(signal.pthread_sigmask(signal.SIG_BLOCK, set())),
        ready=lambda: True,
        check=lambda p: (True, ""),
    )
    assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == before
    assert all(
        {signal.SIGTERM, signal.SIGHUP, signal.SIGINT} <= mask for mask in seen_inside
    )  # held off while down


def test_desired_withholds_https_records_from_the_tv_alone():
    d = adguardcfg.desired(profile.load("lg-webos"), SETTINGS)
    assert d.user_rules.count(f"||*^$dnstype=HTTPS|SVCB,client={SETTINGS.tv_ip}") == 1
    planned = adguardcfg.plan(yaml.safe_load(STOCK), d)
    assert planned["dns"]["aaaa_disabled"] is True and planned["dns"]["handle_ddr"] is True
