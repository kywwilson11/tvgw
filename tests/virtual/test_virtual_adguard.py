"""(lists) The real AdGuard Home, configured by `adguardcfg.plan`, asked from a namespace TV.

The HTTPS/SVCB strip and every blocked answer the gateway reads depend on `blocking_mode: default`
(design decision 6). The unit suite checks that the plan writes it; this checks what the binary then
says on the wire (report 02's test T4): a blocked HTTPS query is NOERROR with an empty answer and no
SOA, a blocked SVCB query is NODATA (NOERROR with an SOA), and a name a rule blocks answers 0.0.0.0. It
also runs the binary's own `--check-config` on the plan's output, which is the check `tvgw adguard
upgrade` relies on, (adguard) reads its check_host answer the way `tvgw check` does, (refused) reads its
query log through its API and its file the way `tvgw refused` does, and, after making AdGuard write its
own YAML through a settings save, checks that the file it wrote still matches the plan on every key the
plan owns.

It needs the AdGuard Home binary: CI's virtual job downloads the pinned release and names it in
TVGW_VIRTUAL_ADGUARD. Without it the tests skip, or fail under TVGW_VIRTUAL_REQUIRED=1. The two
namespaces are its own (`tvgwv-<pid>-agh` and `tvgwv-<pid>-aghtv`), separate from the gateway
topology, and nothing on the host is written outside a temporary directory."""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest
import vnet

from tvgw import adguard, adguardcfg, namecheck, profile, refused
from tvgw.config import Settings

pytestmark = pytest.mark.virtual

PROBE = Path(__file__).resolve().parent / "dnsprobe.py"
GW, TV = "10.10.10.1", "10.10.10.50"
# no upstream is reachable from the namespace: every answer below must come from AdGuard's own rules
SETTINGS = Settings(
    tv_ip=TV,
    gw_ip=GW,
    tv_name="tv",
    dns_upstreams="https://192.0.2.53/dns-query",
    dns_bootstrap="192.0.2.53",
)
BASE = {
    "http": {"address": "127.0.0.1:3000"},
    "users": [],
    "dns": {"bind_hosts": [GW], "port": 53},
    "schema_version": adguardcfg.SCHEMA_CEILING,
}


class Resolver:
    """AdGuard Home in its own namespace on GW, and a TV namespace beside it on TV."""

    def __init__(self, binary: str, artifacts: Path):
        tag = f"{vnet.PREFIX}{os.getpid()}"
        self.agh, self.tv = f"{tag}-agh", f"{tag}-aghtv"
        self.binary, self.artifacts = binary, artifacts
        self.work = Path(tempfile.mkdtemp(prefix="tvgw-virtual-agh-"))
        self.yaml = self.work / "AdGuardHome.yaml"
        self.proc: subprocess.Popen | None = None
        self.log = None
        self.made: list[str] = []
        self.desired = adguardcfg.desired(profile.load("lg-webos"), SETTINGS)
        self.planned = adguardcfg.plan(BASE, self.desired)

    def ns(self, name: str, *argv: str, **kw) -> subprocess.CompletedProcess:
        return vnet.run(["ip", "netns", "exec", name, *argv], **kw)

    def build(self) -> None:
        for name in (self.agh, self.tv):
            vnet.run(["ip", "netns", "add", name])
            self.made.append(name)
            vnet.run(["ip", "-n", name, "link", "set", "lo", "up"])
        veth = ["link", "add", "eth0", "type", "veth", "peer", "name", "eth0", "netns", self.tv]
        vnet.run(["ip", "-n", self.agh, *veth])
        for name, addr in ((self.agh, GW), (self.tv, TV)):
            vnet.run(["ip", "-n", name, "addr", "add", f"{addr}/24", "dev", "eth0"])
            vnet.run(["ip", "-n", name, "link", "set", "eth0", "up"])
        self.yaml.write_text(adguardcfg.dump_yaml(self.planned), encoding="utf-8")
        self.save("adguard/AdGuardHome.planned.yaml", self.yaml.read_text(encoding="utf-8"))

    def check_config(self) -> subprocess.CompletedProcess:
        """The binary's own check, with the argv adguardcfg.check_config uses, inside the namespace
        where the bind address exists."""
        argv = [
            self.binary,
            "--check-config",
            "-c",
            str(self.yaml),
            "-w",
            str(self.work),
            "--no-check-update",
        ]
        return self.ns(self.agh, *argv, check=False, timeout=120)

    def start(self) -> None:
        log_path = self.artifacts / "services" / "adguard.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log = log_path.open("w", encoding="utf-8")
        argv = ["ip", "netns", "exec", self.agh, self.binary, "-c", str(self.yaml), "-w", str(self.work)]
        self.proc = subprocess.Popen([*argv, "--no-check-update"], stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"AdGuard Home exited {self.proc.returncode}; see services/adguard.log")
            if self.ask("HTTPS", "ready.example.com") is not None:
                return
            time.sleep(0.5)
        raise RuntimeError("AdGuard Home did not answer within 45 s; see services/adguard.log")

    def ask(self, qtype: str, name: str) -> dict | None:
        out = self.ns(self.tv, sys.executable, "-I", str(PROBE), GW, qtype, name, check=False, timeout=30)
        return json.loads(out.stdout) if out.returncode == 0 and out.stdout.strip() else None

    def save_settings(self) -> int:
        """A settings save through AdGuard's own API, as the web UI does it: `POST /control/dns_config`
        with nothing to change. AdGuard then writes its whole YAML from memory, which is the
        serialization a UI save would leave behind. `users: []` means no authentication. Returns the
        HTTP status."""
        code = (
            "import sys, urllib.request\n"
            "r = urllib.request.Request('http://127.0.0.1:3000/control/dns_config', data=b'{}',"
            " headers={'Content-Type': 'application/json'}, method='POST')\n"
            "print(urllib.request.urlopen(r, timeout=20).status)\n"
        )
        out = self.ns(self.agh, sys.executable, "-I", "-c", code, check=False, timeout=30)
        self.save("adguard/dns_config.txt", out.stdout + out.stderr)
        return int(out.stdout.strip() or 0) if out.returncode == 0 else 0

    def save(self, relative: str, text: str) -> None:
        path = self.artifacts / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def destroy(self) -> None:
        if self.proc is not None:
            with contextlib.suppress(OSError):
                self.proc.terminate()
            with contextlib.suppress(OSError, subprocess.TimeoutExpired):
                self.proc.wait(timeout=10)
            with contextlib.suppress(OSError):
                self.proc.kill()
            self.proc = None
        if self.log is not None:
            self.log.close()
            self.log = None
        with contextlib.suppress(OSError):
            if self.yaml.exists():
                self.save("adguard/AdGuardHome.after.yaml", self.yaml.read_text(encoding="utf-8"))
        for name in reversed(self.made):
            vnet.run(["ip", "netns", "del", name], check=False)
        self.made = []
        shutil.rmtree(self.work, ignore_errors=True)


@pytest.fixture(scope="module")
def resolver(artifacts):
    binary = os.environ.get("TVGW_VIRTUAL_ADGUARD", "")
    if not (binary and os.access(binary, os.X_OK)):
        why = "TVGW_VIRTUAL_ADGUARD does not name an AdGuard Home binary"
        if os.environ.get("TVGW_VIRTUAL_REQUIRED") == "1":
            pytest.fail(why)
        pytest.skip(why)
    r = Resolver(binary, artifacts)
    try:
        r.build()
        checked = r.check_config()
        r.save("adguard/check-config.txt", checked.stdout + checked.stderr)
        r.checked = checked
        if checked.returncode == 0:
            r.start()
        yield r
    finally:
        r.destroy()


def blocked_name(d: adguardcfg.Desired) -> str:
    """A name one of the profile's own plain rules blocks (`||name^`, no modifier)."""
    for rule in d.user_rules:
        m = re.fullmatch(r"\|\|([a-z0-9.-]+)\^", rule)
        if m:
            return m.group(1)
    raise AssertionError("the profile has no plain block rule to probe")


def test_the_binary_accepts_the_plan(resolver):
    assert resolver.checked.returncode == 0, resolver.checked.stdout + resolver.checked.stderr


def test_https_from_the_tv_is_noerror_with_no_answer_and_no_soa(resolver):
    """Report 02's T4: the strip's answer in `default` mode. An SOA here would be the NODATA path, and
    an RCODE other than NOERROR an RFC 9460 resolution failure a client may give up on."""
    got = resolver.ask("HTTPS", "crypto.example.com")
    assert got is not None and got["rcode"] == 0, got
    assert got["answer"] == [] and got["authority"] == [], got


def test_svcb_from_the_tv_is_nodata_with_an_soa(resolver):
    got = resolver.ask("SVCB", "svc.example.com")
    assert got is not None and got["rcode"] == 0, got
    assert got["answer"] == [] and got["authority"][:1] == [6], got  # 6: SOA


def test_a_name_a_rule_blocks_answers_0_0_0_0(resolver):
    """The answer dnsmsg.is_blocked_answer, tvgw verify's sentinels and the hardware suite read."""
    got = resolver.ask("A", blocked_name(resolver.desired))
    assert got is not None and got["rcode"] == 0 and got["addresses"] == ["0.0.0.0"], got


def test_check_host_names_the_rule_tvgw_check_reads(resolver):
    """(adguard) `tvgw check` reads AdGuard's own check_host answer (`aghinstall.check_host()`): the
    reason, and each rule with its list id, 0 for the custom rules. The unit suite answers from a
    stand-in built from openapi.yaml and the handler; this is what the binary sends, asked for the TV,
    for a name a profile rule blocks, a must-allow name and a URL-filter name. `users: []`, so the page
    asks for no password here."""
    assert resolver.proc is not None and resolver.proc.poll() is None
    d = resolver.desired
    names = [blocked_name(d), d.probe_name, "ngfts.lge.com"]
    code = (
        "import json, sys, urllib.parse, urllib.request\n"
        "out = {}\n"
        "for name in sys.argv[2:]:\n"
        "    q = urllib.parse.urlencode({'name': name, 'client': sys.argv[1]})\n"
        "    url = 'http://127.0.0.1:3000/control/filtering/check_host?' + q\n"
        "    with urllib.request.urlopen(url, timeout=20) as r:\n"
        "        out[name] = json.load(r)\n"
        "print(json.dumps(out))\n"
    )
    got = resolver.ns(resolver.agh, sys.executable, "-I", "-c", code, TV, *names, check=False, timeout=60)
    resolver.save("adguard/check_host.json", got.stdout + got.stderr)
    assert got.returncode == 0, got.stdout + got.stderr
    answers = json.loads(got.stdout)
    lg = profile.load("lg-webos")
    groups = adguardcfg.rule_groups(lg, SETTINGS)
    expected = {
        names[0]: ("FilteredBlackList", None, namecheck.BLOCKED),
        names[1]: ("NotFilteredWhiteList", f"@@||{names[1]}^$important", namecheck.ALLOWED),
        "ngfts.lge.com": ("RewriteRule", f"||ngfts.lge.com^$dnsrewrite={GW}", namecheck.ALLOWED),
    }
    for name, (reason, text, status) in expected.items():
        answer = answers[name]
        rule, list_id = namecheck.first_rule(answer)
        assert answer["reason"] == reason and list_id == 0, answer
        assert rule in groups["profile"] and (text is None or rule == text), answer
        assert namecheck.explain(name, answer, lg, SETTINGS, groups, {}).code == status, answer


def test_the_query_log_page_and_file_give_tvgw_refused_the_same_lookups(resolver):
    """(refused) `tvgw refused` reads AdGuard's query log two ways: one page of its API, asked as
    `aghinstall.querylog()` asks it (`limit`, the TV's address as a quoted `search`), and the file, read
    back by `adguard.records_since()`. The unit suite answers from a stand-in built from the handler at
    the tag; this is the binary. Asked 20 times for a name a profile rule blocks, the page names each
    lookup for the TV, blocked, by its rule with list id 0, newest first, and holds nothing of another
    client. Its `oldest` is the oldest entry it returned, in a form `parse_time` reads; the next page,
    asked `older_than` it, holds only older entries; and `api_records()`, given the two pages, reports
    the window reached: the second page goes past it or ends the log with an empty `oldest`. Once
    AdGuard has written its batches (`querylog.size_memory`, 10 in the plan: at most 9 of the 20 are
    still in memory) the file holds at least 10 of them, and the two readers agree on each one but the
    answer, which the page's reader leaves out. `users: []`, so the page asks for no password here."""
    assert resolver.proc is not None and resolver.proc.poll() is None
    name = blocked_name(resolver.desired)
    start = time.time() - 1
    for _ in range(20):
        assert resolver.ask("A", name) is not None
    code = (
        "import json, sys, urllib.parse, urllib.request\n"
        "def page(older):\n"
        "    q = {'limit': '500', 'search': '\"' + sys.argv[1] + '\"'}\n"
        "    q.update({'older_than': older} if older else {})\n"
        "    url = 'http://127.0.0.1:3000/control/querylog?' + urllib.parse.urlencode(q)\n"
        "    with urllib.request.urlopen(url, timeout=20) as r:\n"
        "        return json.load(r)\n"
        "first = page('')\n"
        "print(json.dumps([first, page(first['oldest']) if first['oldest'] else None]))\n"
    )
    got = resolver.ns(resolver.agh, sys.executable, "-I", "-c", code, TV, check=False, timeout=60)
    resolver.save("adguard/querylog.json", got.stdout + got.stderr)
    assert got.returncode == 0, got.stdout + got.stderr
    page, after = json.loads(got.stdout)
    data = page["data"]
    assert all(e.get("client") == TV for e in data), "the quoted search let another client through"
    times = sorted(t for t in (adguard.parse_time(str(e.get("time"))) for e in data) if t is not None)
    oldest = adguard.parse_time(str(page.get("oldest") or ""))
    seen = {
        "entries": len(data),
        "oldest": page.get("oldest"),
        "oldest_entry": times[0] if times else None,
        "start": start,
        "next_page": None if after is None else [e.get("time") for e in after["data"]][:5],
    }
    resolver.save("adguard/querylog-paging.json", json.dumps(seen, indent=1))
    assert len(times) == len(data) and oldest is not None and abs(oldest - times[0]) < 1e-5, seen
    assert after is not None and all(adguard.parse_time(e["time"]) < oldest for e in after["data"]), seen
    served = iter([page, after])
    api, reached = refused.api_records(lambda older: next(served), start, TV, pages=2)
    mine = [r for r in api if r.qname == name and r.qtype == "A"]
    assert len(mine) >= 20, seen
    # the second page reaches past the window, or is the log's end (an empty `oldest`): either way the
    # read is complete, which `complete` in the JSON and the notes rest on
    assert reached, seen
    assert all(r.blocked and r.filter_id == 0 and r.rule in resolver.desired.user_rules for r in mine), mine[
        :2
    ]
    assert [r.t for r in api] == sorted((r.t for r in api), reverse=True)  # newest first
    log = resolver.work / "data" / "querylog.json"
    deadline = time.monotonic() + 15
    on_file: list = []
    while time.monotonic() < deadline:
        on_file, _ = adguard.records_since(str(log), start, TV)
        if len([r for r in on_file if r.qname == name]) >= 10:
            break
        time.sleep(0.5)
    resolver.save("adguard/querylog.file.txt", log.read_text(encoding="utf-8") if log.exists() else "")
    assert len([r for r in on_file if r.qname == name]) >= 10, "AdGuard wrote no batch of the lookups"
    by_key = {refused._key(r): r for r in api}
    for r in on_file:
        assert refused._key(r) in by_key, r
        same = by_key[refused._key(r)]
        assert (same.blocked, same.reason, same.rule, same.filter_id) == (
            r.blocked,
            r.reason,
            r.rule,
            r.filter_id,
        )


def test_adguard_keeps_the_owned_keys_as_the_plan_wrote_them(resolver):
    """AdGuard rewrites its YAML on every settings save, from its own in-memory config. The file it
    writes must not differ from the plan on a key the plan owns, or `tvgw adguard diff` would report
    drift for ever after a UI save: this is where `30s`, `12h` and `90d` meet AdGuard's own duration
    writer (report 06, F5). At schema 34 nothing migrates at start, so without the save the file would
    still be the plan's own text and the comparison would prove nothing."""
    assert resolver.proc is not None and resolver.proc.poll() is None
    written = resolver.yaml.read_text(encoding="utf-8")
    assert resolver.save_settings() == 200, "see adguard/dns_config.txt"
    deadline = time.monotonic() + 10
    while resolver.yaml.read_text(encoding="utf-8") == written and time.monotonic() < deadline:
        time.sleep(0.2)
    after = resolver.yaml.read_text(encoding="utf-8")
    resolver.save("adguard/AdGuardHome.saved.yaml", after)
    assert after != written, "AdGuard did not rewrite its YAML after the settings save"
    live = adguardcfg.load_yaml(str(resolver.yaml))
    assert adguardcfg.changes(live, adguardcfg.plan(live, resolver.desired)) == []  # what `diff` computes
    assert live["filtering"]["blocking_mode"] == "default"


# ---- (listguard) a subscribed list's exception against the profile's held blocks (design decision 68) ----
GUARD_LIST_ID = adguardcfg.FILTER_ID_BASE + 900  # an id of the test's own, past the plan's
# written for the test in the forms the published lists use; no list's text enters the repository
GUARD_LIST = (
    "@@||alphonso.tv^",  # a plain exception over the profile's ACR block, which carries $important: held off
    "||alphonso.tv^$badfilter",  # names the block as the file writes it, not as it is loaded: deletes nothing
    "@@||wurl.dev^",  # over a profile block outside the red-line categories: it lifts it
    "||us.lgtvsdp.com^$important",  # a list's $important block of a must-allow name: the exception wins
    "@@||us-ad-lgsmartad-com.aws-prd.net^",  # a plain exception under a held regex block: held off
    "@@||gfts.lge.com^",  # a plain exception over the URL filter's rewrite, which answers first
    "||guard-control.example^",  # the control: a block only this list holds, so the list is in force
)
# the held regex blocks, as the profile loads them: `/.../$important`, a form the binary must read whole
LG_ADS_REGEX = "/^[a-z]{2}-(ad|info)-lgsmartad-com\\.aws-prd\\.net$/$important"
NEVO_REGEX = "/^([a-z0-9]+-)?nevoai-iothub-[0-9]+-prod\\.azure-devices\\.net$/$important"


class ListedResolver(Resolver):
    """The resolver above, in namespaces of its own, subscribed to one more list whose file AdGuard has
    already downloaded (`data/filters/<id>.txt`, fresh, so no refresh is due)."""

    def __init__(self, binary: str, artifacts: Path):
        super().__init__(binary, artifacts)
        tag = f"{vnet.PREFIX}{os.getpid()}"
        self.agh, self.tv = f"{tag}-aghl", f"{tag}-aghlt"
        self.planned["filters"].append(
            {
                "enabled": True,
                "url": "https://lists.example/guard.txt",
                "name": "Guard test list",
                "id": GUARD_LIST_ID,
            }
        )

    def build(self) -> None:
        folder = self.work / "data" / "filters"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / f"{GUARD_LIST_ID}.txt").write_text(
            "! Title: the guard's test list\n" + "\n".join(GUARD_LIST) + "\n", encoding="utf-8"
        )
        super().build()


@pytest.fixture(scope="module")
def listed(artifacts):
    binary = os.environ.get("TVGW_VIRTUAL_ADGUARD", "")
    if not (binary and os.access(binary, os.X_OK)):
        why = "TVGW_VIRTUAL_ADGUARD does not name an AdGuard Home binary"
        if os.environ.get("TVGW_VIRTUAL_REQUIRED") == "1":
            pytest.fail(why)
        pytest.skip(why)
    r = ListedResolver(binary, artifacts / "listguard")
    try:
        r.build()
        r.start()
        yield r
    finally:
        r.destroy()


def test_a_subscribed_lists_plain_exception_does_not_lift_the_profiles_held_block(listed):
    """The real binary's answers, asked for the TV, agree with listguard's model of AdGuard's precedence:
    the profile's `||alphonso.tv^$important` holds against the list's `@@||alphonso.tv^`, and the list's
    `$badfilter` of the unheld form deletes nothing; the held regex blocks, written `/.../$important`, are
    read whole and block their names, one of them under a list's plain exception; the list's `@@||wurl.dev^`
    still lifts a block outside the red-line categories; the must-allow exception beats the list's
    `$important` block; the URL filter's rewrite answers under the list's plain exception; and the
    control shows the list is loaded at all."""
    from tvgw import listguard

    lg = profile.load("lg-webos")
    assert LG_ADS_REGEX in lg.custom_rules and NEVO_REGEX in lg.custom_rules  # the forms asked about
    names = [
        "alphonso.tv",
        "wurl.dev",
        "us.lgtvsdp.com",
        "us-ad-lgsmartad-com.aws-prd.net",
        "nevoai-iothub-54-prod.azure-devices.net",
        "gfts.lge.com",
        "guard-control.example",
    ]
    code = (
        "import json, sys, urllib.parse, urllib.request\n"
        "out = {}\n"
        "for name in sys.argv[2:]:\n"
        "    q = urllib.parse.urlencode({'name': name, 'client': sys.argv[1]})\n"
        "    url = 'http://127.0.0.1:3000/control/filtering/check_host?' + q\n"
        "    with urllib.request.urlopen(url, timeout=20) as r:\n"
        "        out[name] = json.load(r)\n"
        "print(json.dumps(out))\n"
    )
    got = listed.ns(listed.agh, sys.executable, "-I", "-c", code, TV, *names, check=False, timeout=60)
    listed.save("listguard/check_host.json", got.stdout + got.stderr)
    assert got.returncode == 0, got.stdout + got.stderr
    answers = json.loads(got.stdout)
    expected = {
        "alphonso.tv": ("FilteredBlackList", "||alphonso.tv^$important", 0),
        "wurl.dev": ("NotFilteredWhiteList", "@@||wurl.dev^", GUARD_LIST_ID),
        "us.lgtvsdp.com": ("NotFilteredWhiteList", "@@||us.lgtvsdp.com^$important", 0),
        "us-ad-lgsmartad-com.aws-prd.net": ("FilteredBlackList", LG_ADS_REGEX, 0),
        "nevoai-iothub-54-prod.azure-devices.net": ("FilteredBlackList", NEVO_REGEX, 0),
        "gfts.lge.com": ("RewriteRule", f"||gfts.lge.com^$dnsrewrite={GW}", 0),
        "guard-control.example": ("FilteredBlackList", "||guard-control.example^", GUARD_LIST_ID),
    }
    for name, (reason, text, list_id) in expected.items():
        rule, fid = namecheck.first_rule(answers[name])
        assert (answers[name]["reason"], rule, fid) == (reason, text, list_id), answers[name]
    model = listguard.Engine(
        [
            ("profile", [r for t in listed.desired.user_rules for r in listguard.parse(t) or []]),
            ("Guard test list", [r for t in GUARD_LIST for r in listguard.parse(t) or []]),
        ],
        listguard.Client(TV, SETTINGS.tv_name),
    )
    states = {
        "FilteredBlackList": listguard.BLOCKED,
        "NotFilteredWhiteList": listguard.ALLOWED,
        "RewriteRule": listguard.REWRITTEN,
    }
    for name, (reason, _, _) in expected.items():
        assert model.decide(name).state == states[reason], name
