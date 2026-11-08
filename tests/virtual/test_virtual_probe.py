"""(probe) `tvgw probe` and a confirmed apply on a kernel (design decision 65).

The gateway namespace runs the real `tvgw-apply` with `TV_PROBE=on`, and the real `tvgw probe` runs
inside it: it makes its own namespace and veth pair there, as on a gateway, and its client crosses the
probe's twin of the TV's rules. The stand-in filter answers the probe's allowed name with a server on the
internet side that completes a TLS handshake (tlspeer.py) and its blocked name with 0.0.0.0; the public
resolver answers both with an address, so a lookup that got past the redirect is seen.

What is proved here and nowhere else: the probe passes on a working gateway and moves no counter, makes
no flow-log event and leaves nothing behind; the listing an apply keeps as last-good loads again as the
same ruleset; an injected bad rule fails the probe, `report` changes nothing and `revert` puts a working
path back within REVERT_BOUND seconds; the 2026-10-26 fault (forwarding off on the TV's own port) is
caught; an apply that cuts a held connection is caught (the 2026-10-30 class); an apply killed halfway
is put right by the timer; an uplink that goes down gives unknown and no revert; a probe that crashes,
hangs or is missing changes nothing.

`tvgw-apply` calls `/usr/local/bin/tvgw`, which this machine need not have: the module runs a copy of
the script whose one `TVGW=` line names a shim that runs this checkout's `tvgw` with the sandbox's
settings file. Every other line of the copy is the script's own, except where a test says what it
injects. The module re-applies the default scenario when it ends."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
import vnet

pytestmark = pytest.mark.virtual

REVERT_BOUND = 50  # seconds from the start of a bad apply to a working path again, the apply alive
TIMER = 10  # the restore timer of the copies run here; 75 seconds in the script itself
DIRECT = {"UPLINK": "direct", "BLOCK_QUIC": "yes", "STRICT_PORTS": "no", "DNSGATE": "count"}
PROFILE = "/etc/tvgw/probe-test.toml"
SETTINGS = {
    **DIRECT,
    "CAPTURE_MODE": "headers",  # so the capture's counters are loaded, and must stay still too
    "TV_PROBE": "on",
    "PROFILE": PROFILE,
    "DNS_BOOTSTRAP": vnet.RESOLVER,  # the public resolver the walls are tried against
    "TV_PROBE_TARGET": vnet.PROBE_TARGET,  # the neutral server the one connection out goes to
}
INJECTED = '\t\ttcp dport 443 counter drop comment "an injected fault"\n'
TV_OUT = '\tchain tv_out {\n\t\toifname != "$OUT_IF" counter drop comment "only via the chosen uplink"\n'


def conf(**more: str) -> str:
    return vnet.render_conf({**SETTINGS, **more})


class Gateway:
    """What the tests share: the probe's profile, the shim, copies of the script, and one state directory
    so the change ledger's spool reads back."""

    def __init__(self, net: vnet.Net):
        self.net = net
        self.netns = f"{vnet.PREFIX}{net.gw.removeprefix(vnet.PREFIX).split('-')[0]}-rp"
        self.state = net.sandbox / "probe-state"
        self.state.mkdir()
        self.run_dir = net.sandbox / "probe-run"
        self.run_dir.mkdir()
        self.n = 0
        generic = (vnet.ROOT / "src" / "tvgw" / "profiles" / "generic-tv.toml").read_text(encoding="utf-8")
        self.files = {
            "probe-test.toml": generic + f'\n[must_allow]\n"{vnet.PROBE_ALLOW}" = "the test server"\n',
            "probe-test.rules": f"||{vnet.PROBE_BLOCK}^\n",
        }
        self.shim = self.write_shim(
            "tvgw", f'exec "{sys.executable}" -m tvgw --conf /etc/tvgw/tvgw.conf "$@" --netns {self.netns}'
        )

    def write_shim(self, name: str, body: str) -> Path:
        path = self.net.sandbox / name
        path.write_text(f"#!/bin/bash\n{body}\n", encoding="utf-8")
        path.chmod(0o755)
        return path

    def script(self, *edits: tuple[str, str], tvgw: Path | str | None = None) -> Path:
        """A copy of tvgw-apply that finds `tvgw` at the shim and whose timer is TIMER seconds; `edits`
        are (old, new) pairs a test injects, each of which must be found."""
        text = vnet.APPLY.read_text(encoding="utf-8")
        for old, new in (
            ("TVGW=/usr/local/bin/tvgw\n", f"TVGW={tvgw or self.shim}\n"),
            ("RESTORE_AFTER=75 ", f"RESTORE_AFTER={TIMER} "),
            # the script as it ships refuses to undo anything on a live gateway; the copies here may
            ("\nREVERT_SUPPORTED=no\n", "\nREVERT_SUPPORTED=yes\n"),
            *edits,
        ):
            assert text.count(old) == 1, old
            text = text.replace(old, new)
        self.n += 1
        path = self.net.sandbox / f"tvgw-apply-{self.n}"
        path.write_text(text, encoding="utf-8")
        return path

    def sandbox_dirs(self) -> list[str]:
        """The directories the sandbox binds over /etc/tvgw, /var/lib/tvgw and /run/tvgw, as net.apply
        binds them, with the module's settings and profile in place."""
        etc = self.net.sandbox / "probe-etc"
        etc.mkdir(exist_ok=True)
        (etc / "tvgw.conf").write_text(conf(), encoding="utf-8")
        (etc / "block4.txt").write_text(vnet.BLOCK4, encoding="utf-8")
        for name, text in self.files.items():
            (etc / name).write_text(text, encoding="utf-8")
        (self.state / "doh4.txt").write_text(vnet.DOH4, encoding="utf-8")
        return [str(etc), str(self.state), str(self.run_dir)]

    def apply(self, settings: str, script: Path | None = None) -> subprocess.CompletedProcess:
        out = self.net.apply(
            self.net.gw,
            settings,
            run_dir=self.run_dir,
            script=script or self.script(),
            state=self.state,
            files=self.files,
        )
        self.net.save(f"probe/apply-{self.n}.log", out.stdout + out.stderr)
        return out

    def probe(self, settings: str | None = None) -> tuple[int, dict]:
        """`tvgw probe --json` inside the gateway namespace, with the sandbox's settings."""
        out = self.net.apply(
            self.net.gw, settings or conf(), ("probe", "--json"), run_dir=self.run_dir, script=self.shim,
            state=self.state, files=self.files,
        )  # fmt: skip
        try:
            return out.returncode, json.loads(out.stdout)
        except ValueError:
            raise AssertionError(f"tvgw probe printed no verdict: {out.stdout!r} {out.stderr!r}") from None

    def spool(self) -> list[list[str]]:
        path = self.state / "changes.spool"
        lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        return [line.split("\t")[1:] for line in lines]

    def listing(self) -> str:
        return self.net.ns(self.net.gw, "nft", "-s", "list", "table", "inet", "tvgw").stdout

    def tv_reaches_the_web(self) -> str:
        return self.net.probe("tv", "tcp", vnet.WEB, 443)

    def stages(self, verdict: dict) -> dict[str, str]:
        return {s["name"]: s["outcome"] for s in verdict["stages"]}


@pytest.fixture(scope="module")
def gw(net, artifacts):
    openssl = shutil.which("openssl")
    if openssl is None:  # as for the tools vnet.prerequisites names: a skip here, a failure in CI
        why = "the probe's TLS stand-in needs the openssl command to make its certificate"
        if os.environ.get("TVGW_VIRTUAL_REQUIRED") == "1":
            pytest.fail(why)
        pytest.skip(why)
    g = Gateway(net)
    cert, key = net.sandbox / "tls.crt", net.sandbox / "tls.key"
    vnet.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-keyout", str(key),
              "-out", str(cert), "-subj", f"/CN={vnet.PROBE_ALLOW}"])  # fmt: skip
    vnet.run(["ip", "-n", net.wan, "addr", "add", f"{vnet.TLS_WEB}/32", "dev", "lo"])
    # as on the reference, where NetworkManager keeps the uplink's own default route in the main table
    # under the VPN client's: the gateway's own try by the uplink, for the probe's control, needs it
    vnet.run(
        [
            "ip",
            "-n",
            net.gw,
            "route",
            "add",
            "default",
            "via",
            vnet.WAN_GW,
            "dev",
            vnet.WAN_IF,
            "metric",
            "600",
        ]
    )
    log = (artifacts / "services").joinpath("tlspeer.log").open("w", encoding="utf-8")
    peer = subprocess.Popen(
        ["ip", "netns", "exec", net.wan, sys.executable, "-I", str(vnet.HERE / "tlspeer.py"), str(cert), str(key), vnet.TLS_WEB],
        stdout=subprocess.PIPE, stderr=log, text=True, encoding="utf-8",
    )  # fmt: skip
    try:
        assert peer.stdout.readline().strip() == "ready"
        out = g.apply(conf())
        assert out.returncode == 0, out.stderr
        yield g
    finally:
        peer.kill()
        peer.communicate(timeout=5)
        log.close()
        vnet.run(["ip", "-n", net.wan, "addr", "del", f"{vnet.TLS_WEB}/32", "dev", "lo"], check=False)
        vnet.run(
            [
                "ip",
                "-n",
                net.gw,
                "route",
                "del",
                "default",
                "via",
                vnet.WAN_GW,
                "dev",
                vnet.WAN_IF,
                "metric",
                "600",
            ],
            check=False,
        )
        net._delete_namespace(g.netns)
        net.ns(net.gw, "ip", "link", "del", vnet.PROBE_IF, check=False)
        net.ns(net.gw, "ip", "link", "set", vnet.WAN_IF, "up", check=False)
        net.ns(net.gw, "sysctl", "-qw", f"net.ipv4.conf.{vnet.TV_IF}.forwarding=1", check=False)
        # the default scenario again, with no probe, no capture table and no test profile
        net.ns(net.gw, "nft", "delete", "table", "inet", "tvgw_capture", check=False)
        net.apply(net.gw, vnet.render_conf(DIRECT))


@pytest.fixture
def clean(gw):
    """Each test starts from, and leaves, the plain apply of the module's settings, the probe passing
    and that pass fresh in /run/tvgw/probe.last, which is what lets an apply ask for a verdict before. A
    confirmed apply whose verdict after failed leaves that failure there, so a test that confirms again
    after it probes again first, as the 10-minute check would on a gateway (the first run of this round
    in CI found three tests that did not)."""
    rc, verdict = gw.probe()
    assert (rc, verdict["verdict"]) == (0, "pass"), verdict
    yield gw
    gw.net.ns(gw.net.gw, "ip", "link", "set", vnet.WAN_IF, "up", check=False)
    gw.net.ns(gw.net.gw, "sysctl", "-qw", f"net.ipv4.conf.{vnet.TV_IF}.forwarding=1", check=False)
    out = gw.apply(conf())
    assert out.returncode == 0, out.stderr


def test_the_probe_passes_and_is_in_none_of_the_tvs_counters_or_logs(clean, net):
    """Both halves of the promise from the TV's position, in seconds; and while it ran, no counter of any
    table moved (the brief's numbers, the gate's count, the capture's), the gate's set took no address,
    no flow-log event named it, and nothing it made is left."""
    gw = clean
    events = None
    if shutil.which("conntrack"):  # what tvgw-flowlog hears: only connections the firewall asked events for
        events = subprocess.Popen(
            ["ip", "netns", "exec", net.gw, "conntrack", "-E", "-e", "NEW,DESTROY", "-o", "timestamp"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding="utf-8",
        )  # fmt: skip
        time.sleep(0.5)
    before = net.counters()
    started = time.monotonic()
    rc, verdict = gw.probe()
    took = time.monotonic() - started
    after = net.counters()
    net.save("probe/verdict.json", json.dumps(verdict, indent=1))
    assert (rc, verdict["verdict"]) == (0, "pass"), verdict
    want = ("port", "lookup", "path", "blocked", "dot", "quic", "redirect")
    assert gw.stages(verdict) == dict.fromkeys(want, "pass"), verdict
    assert took < 15, f"the probe took {took:.1f} s"
    moved = {c: n for c, n in vnet.ticked(before, after).items() if c not in vnet.NOISY}
    assert moved == {}, f"the probe moved counters of the TV's: {moved}"
    assert "capture: the first packets of each TV connection" in after  # the capture's table was loaded
    if events is not None:
        # the must-allow name was looked up and its address never connected to: no entry of the
        # gateway's names that address, and the one connection out went to the neutral server
        made = net.ns(net.gw, "conntrack", "-L", "-s", vnet.PROBE_IP, check=False).stdout
        assert f"dst={vnet.PROBE_VENDOR} " not in made, made
        assert f"dst={vnet.TLS_WEB} " in made, made
    gate = net.ns(net.gw, "nft", "list", "table", "inet", "tvgw_gate").stdout
    assert vnet.PROBE_IP not in gate and vnet.TLS_WEB not in gate
    if events is not None:
        # a connection of the TV's, then every entry of both ended by hand: an entry the firewall asked
        # events for says so as it goes, and the probe's, which it asked none for, go in silence
        assert gw.tv_reaches_the_web() == f"pass:{vnet.GW_WLAN}"
        chosen = net.ns(
            net.gw, "sysctl", "-n", "net.netfilter.nf_conntrack_events", check=False
        ).stdout.strip()
        for address in (vnet.TV_IP, vnet.PROBE_IP):
            net.ns(net.gw, "conntrack", "-D", "-s", address, check=False)
        time.sleep(1.0)
        events.terminate()
        heard, _ = events.communicate(timeout=5)
        if chosen == "0":  # the kernel sends events only where a rule asks (design decision 43)
            assert f"src={vnet.TV_IP} " in heard, heard
            assert f"src={vnet.PROBE_IP} " not in heard, heard
    # nothing is left: no pair, no namespace, no route, no neighbour, on the TV's port or anywhere
    assert net.ns(net.gw, "ip", "link", "show", vnet.PROBE_IF, check=False).returncode != 0
    assert gw.netns not in vnet.run(["ip", "netns", "list"]).stdout
    routes = net.ns(net.gw, "ip", "route", "show", "table", "all").stdout
    assert vnet.PROBE_IP not in routes
    assert vnet.PROBE_IP not in net.ns(net.gw, "ip", "neigh", "show").stdout
    # and the TV's own probes are what they were
    assert gw.tv_reaches_the_web() == f"pass:{vnet.GW_WLAN}"
    assert net.probe("tv", "tcp", vnet.RESOLVER, 853) == "reject"


def test_the_probes_chain_is_the_tvs_chain_in_the_kernels_own_listing(clean, net):
    """What nft made of the twin: rule for rule, probe_out is tv_out without its counters, logs and
    comments, as the kernel lists both."""
    doc = json.loads(net.ns(net.gw, "nft", "-j", "list", "table", "inet", "tvgw").stdout)

    def rules(chain: str) -> list[list]:
        """The chain's rules without what records, and without a rule that then decides nothing."""
        out = []
        for obj in doc["nftables"]:
            rule = obj.get("rule")
            if not rule or rule["chain"] != chain:
                continue
            expr = [e for e in rule["expr"] if "counter" not in e and "log" not in e]
            if any(k in e for e in expr for k in ("accept", "drop", "reject", "jump")):
                out.append(expr)
        return out

    assert rules("probe_out") == rules("tv_out") and len(rules("probe_out")) >= 10
    mine = [o["rule"] for o in doc["nftables"] if o.get("rule", {}).get("chain", "").startswith("probe_")]
    assert mine and not [
        r for r in mine if r.get("comment") or any("counter" in e or "log" in e for e in r["expr"])
    ]


def test_what_an_apply_keeps_as_last_good_loads_again_as_the_same_ruleset(clean, net):
    """The restore rests on nft loading its own listing: each table an apply manages, listed without
    counters as save_state lists it, replaces itself in one transaction and lists the same afterwards."""
    for family, table in (
        ("inet", "tvgw"),
        ("netdev", "tvgw_l2"),
        ("inet", "tvgw_gate"),
        ("inet", "tvgw_capture"),
    ):
        listed = net.ns(net.gw, "nft", "-s", "list", "table", family, table).stdout
        assert listed.strip(), table
        saved = net.save(
            f"probe/last-good-{family}-{table}.nft",
            f"table {family} {table}\ndelete table {family} {table}\n{listed}",
        )
        checked = net.ns(net.gw, "nft", "-c", "-f", str(saved), check=False)
        assert checked.returncode == 0, checked.stderr
        loaded = net.ns(net.gw, "nft", "-f", str(saved), check=False)
        assert loaded.returncode == 0, loaded.stderr
        assert net.ns(net.gw, "nft", "-s", "list", "table", family, table).stdout == listed, table
    assert clean.tv_reaches_the_web() == f"pass:{vnet.GW_WLAN}"
    assert clean.probe()[1]["verdict"] == "pass"


def test_the_2026_10_26_fault_is_caught(clean, net):
    """Forwarding off on the TV's own port, as the stop path left it that day: the TV has no way out, the
    global switch still says 1, and the probe says fail, by the port it reads."""
    gw = clean
    net.ns(net.gw, "sysctl", "-qw", f"net.ipv4.conf.{vnet.TV_IF}.forwarding=0")
    assert net.ns(net.gw, "sysctl", "-n", "net.ipv4.ip_forward").stdout.strip() == "1"
    assert gw.tv_reaches_the_web() == "drop"
    rc, verdict = gw.probe()
    assert (rc, verdict["verdict"]) == (3, "fail"), verdict
    assert verdict["reason"] == "port: forwarding is off for the TV's port"
    assert gw.stages(verdict)["path"] == "fail"  # and its own packets were kept back as the TV's are
    net.ns(net.gw, "sysctl", "-qw", f"net.ipv4.conf.{vnet.TV_IF}.forwarding=1")
    assert gw.probe()[1]["verdict"] == "pass"


def test_a_bad_rule_fails_the_probe_report_changes_nothing_and_revert_restores(clean, net):
    gw = clean
    bad = gw.script((TV_OUT, TV_OUT + INJECTED))
    good = gw.listing()
    # report: the apply stands, bad rule and all, and says what it would have done
    out = gw.apply(conf(APPLY_CONFIRM="report"), bad)
    assert out.returncode == 0, out.stderr
    assert (
        "passed before this apply and fails after it (path); APPLY_CONFIRM=report: nothing was changed"
        in out.stderr
    )
    assert gw.spool()[-1] == ["confirm", "report", "would_revert", "path"]
    assert "an injected fault" in gw.listing() and gw.tv_reaches_the_web() == "drop"
    assert gw.probe()[1]["verdict"] == "fail"
    # back to a working gateway, then the same bad apply with revert
    assert gw.apply(conf()).returncode == 0 and gw.tv_reaches_the_web() == f"pass:{vnet.GW_WLAN}"
    # a confirmed apply asks for its verdict before only after a fresh pass (the failed verdict after the
    # bad apply stands in /run/tvgw/probe.last until a probe passes again): probe, as the 10-minute check would
    assert gw.probe()[1]["verdict"] == "pass"
    good = gw.listing()
    started = time.monotonic()
    out = gw.apply(conf(APPLY_CONFIRM="revert"), bad)
    took = time.monotonic() - started
    net.save("probe/revert.log", f"{took:.1f} s\n{out.stdout}{out.stderr}")
    assert out.returncode == 3, out.stderr
    assert "last-good was put back, and the probe now says: pass" in out.stderr
    assert took < REVERT_BOUND, f"a bad apply was undone only after {took:.1f} s"
    assert gw.tv_reaches_the_web() == f"pass:{vnet.GW_WLAN}"
    assert gw.listing() == good and "an injected fault" not in good
    assert gw.spool()[-1] == ["confirm", "revert", "reverted_pass", "path"]
    assert (gw.run_dir / "ruleset.applied").read_text(encoding="utf-8").strip() == good.strip()
    rule = net.ns(net.gw, "ip", "rule", "show", "priority", "60").stdout
    assert "from 10.10.10.0/24 lookup 100" in rule
    assert gw.probe()[1]["verdict"] == "pass"


def test_an_apply_that_cuts_a_held_connection_is_caught(clean, net):
    """The 2026-10-30 class: an apply after which a live connection's conntrack entry is gone. Here the
    cut is injected outright (the entries of the probe's own address are deleted during the apply); the
    probe's held connection, a keep-alive a second, is the same connection to its far end and a new one to
    the gateway, and the confirmation says so."""
    if shutil.which("conntrack") is None:
        pytest.skip("following the held connection needs the conntrack command")
    gw = clean
    cut = gw.script(
        (
            "\nmodprobe nf_conntrack\n",
            f"\nconntrack -D -s {vnet.PROBE_IP} >/dev/null 2>&1 || true\nmodprobe nf_conntrack\n",
        )
    )
    out = gw.apply(conf(APPLY_CONFIRM="report"), cut)
    assert out.returncode == 0, out.stderr
    assert "fails after it (held)" in out.stderr, out.stdout + out.stderr
    assert gw.spool()[-1] == ["confirm", "report", "would_revert", "held"]
    # and an apply that changes nothing keeps it: the same confirmation passes
    # a confirmed apply asks for its verdict before only after a fresh pass (the failed verdict after the
    # bad apply stands in /run/tvgw/probe.last until a probe passes again): probe, as the 10-minute check would
    assert gw.probe()[1]["verdict"] == "pass"
    out = gw.apply(conf(APPLY_CONFIRM="report"))
    assert out.returncode == 0 and "tvgw: confirm: pass (before the apply: pass)" in out.stdout, (
        out.stdout + out.stderr
    )


def test_the_2026_10_30_rewrite_of_rule_60_cuts_the_held_connection_every_time(clean, net):
    """The fault as it was: rule 60 deleted and added back on every apply. On the TV it met a stream's
    packets within milliseconds. The probe's held connection carries one packet a second, so here the
    rule stays out for two seconds, long enough for one to meet it: the kernel then destroys the
    connection's entry, and the confirmation says an apply cut a live connection. Three applies, three
    times: the first run of this test in CI passed on amd64 and arm64 while it was only recorded, and a
    result that depends on timing would not repeat."""
    if shutil.which("conntrack") is None:
        pytest.skip("following the held connection needs the conntrack command")
    gw = clean
    line = 'want_rule="from $TV_NET lookup $RT_TABLE"\n'
    old = gw.script((line, line + "ip rule del priority 60 2>/dev/null || true; sleep 2\n"))
    caught = []
    for _ in range(3):
        out = gw.apply(conf(APPLY_CONFIRM="report"), old)
        assert out.returncode == 0, out.stderr
        caught.append("fails after it (held)" in out.stderr)
        net.save(f"probe/rule60-rewrite-{len(caught)}.log", out.stdout + out.stderr)
        assert gw.apply(conf()).returncode == 0
        assert gw.probe()[1]["verdict"] == "pass"  # a fresh pass, so the next apply asks for a verdict before
    assert caught == [True, True, True], caught
    assert gw.tv_reaches_the_web() == f"pass:{vnet.GW_WLAN}"


def test_an_apply_that_moves_the_tv_to_the_other_uplink_is_confirmed_and_not_undone(clean, net):
    """The settings file names the tunnel while the gateway still sends the TV out by the uplink. The
    verdict before is taken of the gateway as it is (it passes, so last-good is kept and the timer
    armed), and the verdict after of the gateway as the apply made it: the TV's way out is the tunnel
    now, and that is a pass. The held connection ended with the address it was translated to, which is
    no cut of the apply's."""
    gw = clean
    out = gw.apply(conf(UPLINK="vpn", APPLY_CONFIRM="revert"))
    net.save("probe/uplink-switch.log", out.stdout + out.stderr)
    assert out.returncode == 0, out.stderr
    assert "tvgw: confirm: pass (before the apply: pass)" in out.stdout, out.stdout + out.stderr
    assert gw.spool()[-1][:3] == ["confirm", "revert", "pass"]
    assert gw.tv_reaches_the_web() == f"pass:{vnet.GW_TUN}"
    rc, verdict = gw.probe(conf(UPLINK="vpn"))
    assert (rc, verdict["verdict"]) == (0, "pass"), verdict
    # and back again, judged the same way
    out = gw.apply(conf(APPLY_CONFIRM="revert"))
    assert out.returncode == 0 and "tvgw: confirm: pass (before the apply: pass)" in out.stdout, (
        out.stdout + out.stderr
    )


def test_an_apply_killed_halfway_is_put_right_by_the_timer(clean, net):
    """The apply loads the table for another uplink and is killed before it rewrites the routes: the TV's
    packets still leave by the old uplink and the new table drops them there. Nothing is left running of
    the apply; the timer armed before its first change puts last-good back. (The first version of the
    probe judged the gateway by the settings file, which already named the other uplink: the verdict
    before was a failure, nothing was armed, and this test found it.)"""
    gw = clean
    good = gw.listing()
    killed = gw.script(
        ("\n# Policy routing: in direct mode", "\nkill -KILL $$\n# Policy routing: in direct mode")
    )
    out = gw.apply(conf(UPLINK="vpn", APPLY_CONFIRM="revert"), killed)
    assert out.returncode != 0 and "tvgw: applied" not in out.stdout
    assert (gw.run_dir / "last-good" / "armed").exists()
    assert gw.listing() != good and gw.tv_reaches_the_web() == "drop"
    deadline = time.monotonic() + TIMER + 40
    log = gw.run_dir / "last-good" / "restore.log"
    while not log.exists() and time.monotonic() < deadline:
        time.sleep(0.5)
    assert log.exists(), "the timer never ran the restore"
    assert "the apply did not finish; last-good was put back" in log.read_text(encoding="utf-8")
    assert gw.listing() == good and gw.tv_reaches_the_web() == f"pass:{vnet.GW_WLAN}"
    assert gw.spool()[-1] == ["confirm", "revert", "timer_restored", "timer"]
    assert not (gw.run_dir / "last-good" / "armed").exists()
    # the probe the apply had started noticed the apply was gone, so the next one runs at once
    assert gw.probe()[1]["verdict"] == "pass"


def test_an_uplink_that_goes_down_gives_unknown_and_no_revert(clean, net):
    """The uplink loses its carrier while the apply runs. From the TV's position everything now fails,
    and the gateway's own reading of its uplink says why: unknown, and nothing is undone."""
    gw = clean
    good = gw.listing()
    drops = gw.script(
        ("\nmodprobe nf_conntrack\n", f"\nip link set {vnet.WAN_IF} down\nmodprobe nf_conntrack\n")
    )
    out = gw.apply(conf(APPLY_CONFIRM="revert"), drops)
    assert out.returncode == 0, out.stderr
    assert "tvgw: confirm: unknown (before the apply: pass)" in out.stdout, out.stdout + out.stderr
    assert gw.spool()[-1][:3] == ["confirm", "revert", "unknown"]
    assert gw.listing() == good and not (gw.run_dir / "last-good" / "armed").exists()
    rc, verdict = gw.probe()
    assert (rc, verdict["verdict"]) == (4, "unknown"), verdict
    assert "the uplink is down" in verdict["reason"]
    assert "fail" not in gw.stages(verdict).values()
    net.ns(net.gw, "ip", "link", "set", vnet.WAN_IF, "up")
    assert gw.apply(conf()).returncode == 0
    assert gw.probe()[1]["verdict"] == "pass"


@pytest.mark.parametrize(
    ("what", "body", "said"),
    [
        ("missing", None, "is not there; this apply is not confirmed"),
        ("crashes", "echo boom >&2; exit 1", "tvgw: confirm: unknown (before the apply: unknown)"),
        ("hangs", "sleep 300", "tvgw: confirm: unknown (before the apply: unknown)"),
        ("ends-with-a-signal", None, None),  # a real probe, killed as `timeout` and a stopped unit kill it
    ],
)
def test_a_probe_that_is_missing_crashes_or_hangs_changes_nothing_but_its_verdict(
    clean, net, what, body, said
):
    """The TV's internet never hangs on the probe: the apply finishes, the TV's path works, nothing is
    undone, and the confirmation says only that it could not tell."""
    gw = clean
    good = gw.listing()
    if what == "ends-with-a-signal":
        return _a_probe_ended_by_a_signal_leaves_nothing(gw, net, good)
    tvgw = "/nonexistent/tvgw" if body is None else gw.write_shim(f"tvgw-{what}", body)
    started = time.monotonic()
    out = gw.apply(conf(APPLY_CONFIRM="revert"), gw.script(tvgw=tvgw))
    assert out.returncode == 0, out.stderr
    assert said in out.stdout + out.stderr
    assert "tvgw: applied (uplink=direct" in out.stdout
    assert time.monotonic() - started < 40  # a probe that hangs holds an apply for 8 seconds, no longer
    assert gw.listing() == good and gw.tv_reaches_the_web() == f"pass:{vnet.GW_WLAN}"
    assert not (gw.run_dir / "last-good" / "armed").exists()
    assert net.ns(net.gw, "ip", "link", "show", vnet.PROBE_IF, check=False).returncode != 0


def test_with_the_probe_off_nothing_of_it_is_loaded_or_run(clean, net):
    gw = clean
    out = gw.apply(vnet.render_conf({**SETTINGS, "TV_PROBE": "off", "APPLY_CONFIRM": "revert"}))
    assert out.returncode == 0 and "needs TV_PROBE=on; this apply is not confirmed" in out.stderr
    assert "probe_" not in gw.listing() and vnet.PROBE_IF not in gw.listing()
    rc, verdict = gw.probe(vnet.render_conf({**SETTINGS, "TV_PROBE": "off"}))
    assert (rc, verdict["verdict"]) == (4, "unknown") and "the probe is off" in verdict["reason"]
    # and with it on but no rules loaded yet, it sends nothing: the TV's "off the TV port" counter stays still
    before = net.counters()
    rc, verdict = gw.probe()
    assert rc == 4 and "no rules for the probe at this address yet" in verdict["reason"]
    assert vnet.ticked(before, net.counters()).get("TV subnet off the TV port", 0) == 0


def _a_probe_ended_by_a_signal_leaves_nothing(gw, net, good):
    """The real probe, started as tvgw-apply starts it and ended with SIGTERM while it holds its
    namespace open across a wait: `timeout`, an apply that gave up waiting and a unit being stopped all
    end it so. Its namespace, pair, routes and neighbour entry go with it."""
    d = net.sandbox / "across-signal"
    d.mkdir(exist_ok=True)
    held = subprocess.Popen(
        ["ip", "netns", "exec", net.gw, "unshare", "--mount", "--propagation", "private", "bash", "-c",
         'set -e; mount --bind "$1" /etc/tvgw; mount --bind "$2" /var/lib/tvgw; mount --bind "$3" /run/tvgw; '
         'mount -t tmpfs tmpfs /run/lock; shift 3; exec "$@"', "_", *gw.sandbox_dirs(), str(gw.shim),
         "probe", "--across", str(d)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )  # fmt: skip
    try:
        deadline = time.monotonic() + 40
        while not (d / "pre").exists() and time.monotonic() < deadline and held.poll() is None:
            time.sleep(0.2)
        assert (d / "pre").read_text(encoding="utf-8").startswith("pass -\n")
        assert net.ns(net.gw, "ip", "link", "show", vnet.PROBE_IF, check=False).returncode == 0  # held open
        held.terminate()
        held.wait(timeout=20)
    finally:
        if held.poll() is None:
            held.kill()
            held.wait(timeout=5)
    assert net.ns(net.gw, "ip", "link", "show", vnet.PROBE_IF, check=False).returncode != 0
    assert gw.netns not in vnet.run(["ip", "netns", "list"]).stdout
    assert vnet.PROBE_IP not in net.ns(net.gw, "ip", "route", "show", "table", "all").stdout
    assert vnet.PROBE_IP not in net.ns(net.gw, "ip", "neigh", "show").stdout
    assert gw.listing() == good and gw.tv_reaches_the_web() == f"pass:{vnet.GW_WLAN}"


def test_an_apply_that_repairs_a_lost_route_does_not_wait_for_the_probe(clean, net):
    """The Wi-Fi flapped: table 100 lost its default route, the uplink is back, and the dispatcher's
    apply is what puts the route back. With the TV's route broken the probe would take seconds to fail;
    the apply reads the kernel first, starts at once, and the TV is back within a few seconds."""
    gw = clean
    net.ns(net.gw, "ip", "route", "del", "default", "table", "100")
    assert gw.tv_reaches_the_web() == "drop"
    started = time.monotonic()
    out = gw.apply(conf(APPLY_CONFIRM="revert"))
    took = time.monotonic() - started
    assert out.returncode == 0, out.stderr
    assert "this apply starts at once and is not confirmed" in out.stderr
    assert took < 6, f"the repairing apply took {took:.1f} s"
    assert gw.tv_reaches_the_web() == f"pass:{vnet.GW_WLAN}"
    assert not (gw.run_dir / "last-good" / "armed").exists()
    # and with the route whole again, the next apply is confirmed, in a bounded time
    started = time.monotonic()
    out = gw.apply(conf(APPLY_CONFIRM="revert"))
    assert out.returncode == 0 and "tvgw: confirm: pass (before the apply: pass)" in out.stdout, out.stderr
    assert time.monotonic() - started < 40


def test_a_tv_connection_with_data_in_flight_survives_twenty_probes_and_a_restore(clean, net):
    """Each probe adds and removes a pair and its two routes (one of them in table 100, where the
    2026-10-30 incident lived); a restore reloads the tables and writes what differs. A translated TCP
    connection from the TV, carrying data the whole time, must keep its conntrack entry and never be
    reset through all of it."""
    gw = clean
    held = subprocess.Popen(
        net.agent_argv(net.tv, "probe", "hold", vnet.WEB, "443"),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8",
    )  # fmt: skip
    import threading

    stop, sent, echoed, trouble = threading.Event(), [0], [0], []

    def chatter():  # a line every few milliseconds, each one echoed, as a stream keeps packets in flight
        while not stop.is_set():
            try:
                held.stdin.write(f"line {sent[0]}\n")
                held.stdin.flush()
                reply = held.stdout.readline()
                if reply.strip() != f"echo:line {sent[0]}":
                    trouble.append(reply.strip() or "closed")
                    return
                sent[0] += 1
                echoed[0] += 1
            except OSError as e:
                trouble.append(str(e))
                return
            time.sleep(0.005)

    try:
        assert held.stdout.readline().strip() == f"connected:{vnet.GW_WLAN}"
        before = conntrack_ids(net)
        thread = threading.Thread(target=chatter, daemon=True)
        thread.start()
        for _ in range(20):
            rc, verdict = gw.probe()
            assert (rc, verdict["verdict"]) == (0, "pass"), verdict
            assert not trouble, trouble
        # a restore over the live state: the last-good a confirmed apply kept, armed again by hand
        out = gw.apply(conf(APPLY_CONFIRM="revert"))
        assert out.returncode == 0, out.stderr
        token = "held-connection-test"
        (gw.run_dir / "last-good" / "armed").write_text(token + "\n", encoding="utf-8")
        out = net.apply(net.gw, conf(), ("--restore", "/run/tvgw/last-good", token, "revert"),
                        run_dir=gw.run_dir, script=gw.script(), state=gw.state, files=gw.files)  # fmt: skip
        assert out.returncode == 0 and "last-good was put back" in out.stderr, out.stderr
        time.sleep(1.0)
        stop.set()
        thread.join(timeout=10)
        assert not trouble, trouble
        assert echoed[0] >= 200, echoed[0]  # data was in flight throughout
        if before is not None:
            assert conntrack_ids(net) == before
    finally:
        stop.set()
        held.kill()
        held.communicate(timeout=5)


def test_two_probes_at_once_take_turns(clean, net):
    """The lock: a second probe waits for the first and then runs; both pass, and nothing is left."""
    gw = clean
    both = gw.write_shim(
        "tvgw-two", f'"{gw.shim}" probe --json >"$1/one.json" & "{gw.shim}" probe --json >"$1/two.json"; wait'
    )
    d = net.sandbox / "two-probes"
    d.mkdir(exist_ok=True)
    out = net.apply(
        net.gw, conf(), (str(d),), run_dir=gw.run_dir, script=both, state=gw.state, files=gw.files
    )
    assert out.returncode == 0, out.stderr
    verdicts = [
        json.loads((d / name).read_text(encoding="utf-8"))["verdict"] for name in ("one.json", "two.json")
    ]
    assert verdicts == ["pass", "pass"], verdicts
    assert net.ns(net.gw, "ip", "link", "show", vnet.PROBE_IF, check=False).returncode != 0


def conntrack_ids(net) -> set[str] | None:
    """The ids of the gateway's conntrack entries for the TV's TCP to the web server, or None without the tool."""
    if shutil.which("conntrack") is None:
        return None
    out = net.ns(
        net.gw,
        "conntrack",
        "-L",
        "-p",
        "tcp",
        "-s",
        vnet.TV_IP,
        "-d",
        vnet.WEB,
        "--dport",
        "443",
        "-o",
        "id",
        check=False,
    )
    ids = {word.removeprefix("id=") for word in out.stdout.split() if word.startswith("id=")}
    assert ids, f"no conntrack entry for the held connection: {out.stdout} {out.stderr}"
    return ids
