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
        self.took = 0.0
        generic = (vnet.ROOT / "src" / "tvgw" / "profiles" / "generic-tv.toml").read_text(encoding="utf-8")
        self.files = {
            "probe-test.toml": generic + f'\n[must_allow]\n"{vnet.PROBE_ALLOW}" = "the test server"\n',
            "probe-test.rules": f"||{vnet.PROBE_BLOCK}^\n",
            "boot_id": "boot-1\n",  # (revert) the copies read the boot from here, so a test can reboot
        }
        # (ports) the apply also asks `tvgw profile --firewall`, which takes no --netns
        self.shim = self.write_shim(
            "tvgw",
            f'[ "$1" = probe ] || exec "{sys.executable}" -m tvgw --conf /etc/tvgw/tvgw.conf "$@"\n'
            f'exec "{sys.executable}" -m tvgw --conf /etc/tvgw/tvgw.conf "$@" --netns {self.netns}',
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
            # (revert) the boot as the sandbox says it, so that a reboot is one line of a test
            ("\nBOOT_ID=/proc/sys/kernel/random/boot_id ", "\nBOOT_ID=/etc/tvgw/boot_id "),
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

    def confirmed(
        self, settings: str, script: Path | None = None, tries: int = 3
    ) -> subprocess.CompletedProcess:
        """An apply that was asked for its verdict before (`APPLY_CONFIRM` set in `settings`). On a loaded
        runner the probe's one observation before an apply can miss a handshake or a refusal, and the
        apply then starts unconfirmed, as it must (its verdict before is `unknown`: the probe did not
        answer within the eight seconds an apply waits, or its handshake failed with nothing held);
        that is a verdict about the runner, not about the apply. Such an attempt is repaired (a clean apply, then a probe, as the 10-minute check would),
        and the apply is tried again, up to `tries`. The returned attempt was confirmed; `self.took` is
        how long it ran. An attempt that was confirmed is never retried: what it found stands."""
        for attempt in range(1, tries + 1):
            started = time.monotonic()
            out = self.apply(settings, script)
            self.took = time.monotonic() - started
            self.net.save(f"probe/confirmed-{self.n}-{attempt}.log", out.stdout + out.stderr)
            said = out.stdout + out.stderr
            if "(before the apply: pass)" in said or "passed before this apply and fails after it" in said:
                return out
            # the three ways an apply says it started unconfirmed: the probe refused or missing, the verdict
            # before not pass (a loaded runner: past the eight seconds the apply waits, `unknown`; or a
            # handshake that failed with nothing held, which judges to pass with the verdict before unknown)
            unconfirmed = ("not confirmed", "did not pass before this apply", "(before the apply: unknown)")
            assert any(word in said for word in unconfirmed), said
            assert self.apply(conf()).returncode == 0
            assert self.probe()[1]["verdict"] == "pass"
        raise AssertionError(f"no confirmed apply in {tries} attempts: {said}")

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

    def held(self) -> list[str]:
        """(revert) The hold tvgw-apply leaves in the state directory, split; [] for none."""
        path = self.state / "apply-held"
        return path.read_text(encoding="utf-8").split() if path.exists() else []

    def killed(self, settings: str, script: Path, tries: int = 3) -> subprocess.CompletedProcess:
        """(revert) An apply of `script` that kills itself before its routes (while /etc/tvgw/kill-me is
        there) after it kept last-good and armed its restore. An attempt the loaded runner left unconfirmed
        armed nothing: it is repaired and tried again, as `confirmed` does."""
        for _ in range(tries):
            self.files["kill-me"] = ""
            try:
                out = self.apply(settings, script)
            finally:
                del self.files["kill-me"]
            if (self.state / "last-good" / "armed").exists():
                return out
            assert self.apply(conf()).returncode == 0
            assert self.probe()[1]["verdict"] == "pass"
        raise AssertionError(f"no apply armed its restore in {tries} attempts: {out.stdout}{out.stderr}")

    def reboot(self, script: Path) -> None:
        """(revert) What a reboot does to the gateway: the restore timer (a detached process here, a systemd
        timer on a gateway) dies with it; every table, rule 60 and table 100 go; forwarding is off; /run is
        empty, the probe's last verdict with it; and the boot is another. /var/lib/tvgw is kept."""
        vnet.run(["pkill", "-KILL", "-f", str(script)], check=False)
        for family, table in (
            ("inet", "tvgw"), ("netdev", "tvgw_l2"), ("inet", "tvgw_gate"), ("inet", "tvgw_capture"),
            ("inet", "tvgw_ntp"),
        ):  # fmt: skip
            self.net.ns(self.net.gw, "nft", "delete", "table", family, table, check=False)
        self.net.ns(self.net.gw, "ip", "rule", "del", "priority", "60", check=False)
        self.net.ns(self.net.gw, "ip", "route", "flush", "table", "100", check=False)
        self.net.ns(self.net.gw, "sysctl", "-qw", "net.ipv4.ip_forward=0")
        for path in self.run_dir.iterdir():
            shutil.rmtree(path) if path.is_dir() else path.unlink()
        self.files["boot_id"] = f"boot-{int(self.files['boot_id'].split('-')[1]) + 1}\n"

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
    # (revert) and the must-allow name's address in none of the refused lists, and the gate only counting;
    # no adtech step: the test profile is not LG's, so its wall is not built
    want = (
        "port",
        "lookup",
        "lists",
        "path",
        "blocked",
        "dot",
        "quic",
        "redirect",
        "ports",
        "gate",
    )  # (ports)
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
    counters as save_state lists it, replaces itself in one transaction and lists the same afterwards.
    (revert) The gate's is listed terse, as save_state lists it: no element of its sets (the TV's answers
    and connections) is in it, and it loads again all the same."""
    net.ns(net.gw, "nft", "add", "element", "inet", "tvgw_gate", "resolved4", "{ 203.0.113.98 timeout 1h }")
    for family, table, how in (
        ("inet", "tvgw", ("-s",)),
        ("netdev", "tvgw_l2", ("-s",)),
        ("inet", "tvgw_gate", ("-s", "-t")),
        ("inet", "tvgw_capture", ("-s",)),
    ):
        listed = net.ns(net.gw, "nft", *how, "list", "table", family, table).stdout
        assert listed.strip(), table
        assert table != "tvgw_gate" or ("203.0.113.98" not in listed and "elements" not in listed), listed
        saved = net.save(
            f"probe/last-good-{family}-{table}.nft",
            f"table {family} {table}\ndelete table {family} {table}\n{listed}",
        )
        checked = net.ns(net.gw, "nft", "-c", "-f", str(saved), check=False)
        assert checked.returncode == 0, checked.stderr
        loaded = net.ns(net.gw, "nft", "-f", str(saved), check=False)
        assert loaded.returncode == 0, loaded.stderr
        assert net.ns(net.gw, "nft", *how, "list", "table", family, table).stdout == listed, table
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
    out = gw.confirmed(conf(APPLY_CONFIRM="report"), bad)
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
    out = gw.confirmed(conf(APPLY_CONFIRM="revert"), bad)
    took = gw.took
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
    # (revert) the hold: the dispatcher's next apply of the same (a renewal) puts last-good back, asks no
    # probe and changes nothing, and the TV keeps its path; an apply of something else is applied
    assert gw.held()[1:3] == ["reverted", "path"]
    out = gw.apply(conf(APPLY_CONFIRM="revert"), bad)
    net.save("probe/held.log", out.stdout + out.stderr)
    assert out.returncode == 0 and "tvgw: held: these settings were undone" in out.stdout, out.stderr
    assert gw.listing() == good and gw.tv_reaches_the_web() == f"pass:{vnet.GW_WLAN}"
    assert gw.spool()[-1] == ["confirm", "revert", "held", "path"]
    assert gw.apply(conf(APPLY_CONFIRM="revert")).returncode == 0  # the script fixed: another fingerprint
    assert gw.held() == [] and gw.tv_reaches_the_web() == f"pass:{vnet.GW_WLAN}"


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
    out = gw.confirmed(conf(APPLY_CONFIRM="report"), cut)
    assert out.returncode == 0, out.stderr
    assert "fails after it (held)" in out.stderr, out.stdout + out.stderr
    assert gw.spool()[-1] == ["confirm", "report", "would_revert", "held"]
    # and an apply that changes nothing keeps it: the same confirmation passes
    # a confirmed apply asks for its verdict before only after a fresh pass (the failed verdict after the
    # bad apply stands in /run/tvgw/probe.last until a probe passes again): probe, as the 10-minute check would
    assert gw.probe()[1]["verdict"] == "pass"
    out = gw.confirmed(conf(APPLY_CONFIRM="report"))
    assert out.returncode == 0 and "tvgw: confirm: pass (before the apply: pass)" in out.stdout, (
        out.stdout + out.stderr
    )


def test_the_2026_10_30_rewrite_of_rule_60_cuts_the_held_connection_every_time(clean, net):
    """The fault as it was: rule 60 deleted and added back on every apply. On the TV it met a stream's
    packets within milliseconds. The probe's held connection carries one keep-alive a second, so here the
    rule stays out for two seconds, long enough for one to meet it: routed out by the tunnel instead of
    the uplink the connection was translated on, the kernel kills the entry at postrouting
    (nf_nat_oif_changed), and the next keep-alive makes a new one. The confirmation must say an apply cut
    a live connection, three applies out of three. Until 2026-11-07 it said so in about half of them: the
    probe knew the entry by its id alone, which is a hash of the entry's address in memory, and the new
    entry often got the old one's address and so its id. It is known by its start and its count too now
    (probe.Entry), and the three must all be caught; one that is not is a defect, not a loaded runner."""
    if shutil.which("conntrack") is None:
        pytest.skip("following the held connection needs the conntrack command")
    gw = clean
    line = 'want_rule="from $TV_NET lookup $RT_TABLE"\n'
    old = gw.script((line, line + "ip rule del priority 60 2>/dev/null || true; sleep 2\n"))
    caught = []
    for _ in range(3):
        # a confirmed apply (one asked for its verdict before; an attempt the loaded runner left
        # unconfirmed is repaired and tried again, see `confirmed`), which must catch the cut
        out = gw.confirmed(conf(APPLY_CONFIRM="report"), old)
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
    out = gw.confirmed(conf(UPLINK="vpn", APPLY_CONFIRM="revert"))
    net.save("probe/uplink-switch.log", out.stdout + out.stderr)
    assert out.returncode == 0, out.stderr
    assert "tvgw: confirm: pass (before the apply: pass)" in out.stdout, out.stdout + out.stderr
    assert gw.spool()[-1][:3] == ["confirm", "revert", "pass"]
    assert gw.tv_reaches_the_web() == f"pass:{vnet.GW_TUN}"
    rc, verdict = gw.probe(conf(UPLINK="vpn"))
    assert (rc, verdict["verdict"]) == (0, "pass"), verdict
    # and back again, judged the same way
    out = gw.confirmed(conf(APPLY_CONFIRM="revert"))
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
    assert (gw.state / "last-good" / "armed").exists()
    assert gw.listing() != good and gw.tv_reaches_the_web() == "drop"
    deadline = time.monotonic() + TIMER + 40
    log = gw.state / "last-good" / "restore.log"
    while not log.exists() and time.monotonic() < deadline:
        time.sleep(0.5)
    assert log.exists(), "the timer never ran the restore"
    assert "the apply did not finish; last-good was put back" in log.read_text(encoding="utf-8")
    assert gw.listing() == good and gw.tv_reaches_the_web() == f"pass:{vnet.GW_WLAN}"
    assert gw.spool()[-1] == ["confirm", "revert", "timer_restored", "timer"]
    assert not (gw.state / "last-good" / "armed").exists()
    # (revert) the inputs of the apply that never finished are held: the next apply of them (here the
    # same copy, which the hold stops before it reaches its kill) puts last-good back and stops there
    assert gw.held()[1:3] == ["interrupted", "timer"]
    out = gw.apply(conf(UPLINK="vpn", APPLY_CONFIRM="revert"), killed)
    assert out.returncode == 0 and "tvgw: held: an apply of these settings did not finish" in out.stdout
    assert gw.listing() == good and gw.tv_reaches_the_web() == f"pass:{vnet.GW_WLAN}"
    # the probe the apply had started noticed the apply was gone, so the next one runs at once
    assert gw.probe()[1]["verdict"] == "pass"


KILL = (
    "\n# Policy routing: in direct mode",
    "\n[ ! -e /etc/tvgw/kill-me ] || kill -KILL $$\n# Policy routing: in direct mode",
)


def test_a_reboot_in_the_middle_of_an_apply_is_put_right_by_the_boots_own_apply(clean, net):
    """(revert) Decision 65's item 4: last-good and the timer lived under /run, so a reboot in the middle of
    an apply left the half-judged change standing, unconfirmed, from the boot's own apply on. Here the apply
    for the other uplink is killed before its routes, the reboot takes its timer, every table, the routes
    and /run with it; the boot's apply finds the mark of another boot on the disk, puts last-good back
    without waiting for any probe, and holds those inputs; the dispatcher's applies that follow are held
    too; once the ten-minute check has passed on the state put back, the next apply tries the change
    again, confirmed, and it stands."""
    gw = clean
    good = gw.listing()
    script = gw.script(KILL)
    settings = conf(UPLINK="vpn", APPLY_CONFIRM="revert")
    out = gw.killed(settings, script)
    assert out.returncode != 0 and "tvgw: applied" not in out.stdout
    assert gw.tv_reaches_the_web() == "drop"  # the new table, the old routes
    gw.reboot(script)
    assert gw.tv_reaches_the_web() == "drop"  # nothing loaded, forwarding off: the boot before tvgw.service
    started = time.monotonic()
    out = gw.apply(settings, script)  # tvgw.service at boot
    took = time.monotonic() - started
    net.save("probe/boot-after-a-reboot.log", f"{took:.1f} s\n{out.stdout}{out.stderr}")
    assert out.returncode == 0, out.stderr
    assert "an earlier apply did not finish (reboot); last-good was put back" in out.stderr
    assert "tvgw: held: an apply of these settings did not finish (reboot)" in out.stdout
    assert took < 15, f"the boot's apply took {took:.1f} s"  # it waits for no probe
    assert gw.listing() == good and gw.tv_reaches_the_web() == f"pass:{vnet.GW_WLAN}"
    assert gw.held()[1:3] == ["interrupted", "reboot"]
    assert [row[1:3] for row in gw.spool()[-2:]] == [["revert", "timer_restored"], ["revert", "held"]]
    # the dispatcher's apply when the uplink comes up: the same inputs, no probe since, held
    out = gw.apply(settings, script)
    assert out.returncode == 0 and "tvgw: held:" in out.stdout, out.stdout + out.stderr
    assert gw.listing() == good and gw.tv_reaches_the_web() == f"pass:{vnet.GW_WLAN}"
    # the ten-minute check passes on the state put back; the change is tried again, confirmed, and stands
    assert gw.probe()[1]["verdict"] == "pass"
    out = gw.confirmed(settings, script)
    assert out.returncode == 0 and "tvgw: confirm: pass (before the apply: pass)" in out.stdout, out.stderr
    assert gw.held() == [] and gw.tv_reaches_the_web() == f"pass:{vnet.GW_TUN}"


def test_a_revert_puts_the_gates_rules_back_and_keeps_its_addresses(clean, net):
    """(revert) Decision 65's item 6: a restore left the gate's table as it stood, which is wrong once a
    rule in it can hold a packet. The bad apply here also puts a rule of its own into the gate's chain, and
    the feeder adds an address while it runs: the revert takes the rule away and keeps the address."""
    gw = clean
    feeder = "nft add element inet tvgw_gate resolved4 '{ 203.0.113.99 timeout 1h }'"
    extra = 'nft add rule inet tvgw_gate forward counter comment \\"an injected gate rule\\"'
    bad = gw.script(
        (TV_OUT, TV_OUT + INJECTED),
        ("\n# ---- (ntp) begin:", f"\n{extra}\n{feeder}\n# ---- (ntp) begin:"),
    )
    out = gw.confirmed(conf(APPLY_CONFIRM="revert"), bad)
    net.save("probe/revert-gate.log", out.stdout + out.stderr)
    assert out.returncode == 3, out.stdout + out.stderr
    gate = net.ns(net.gw, "nft", "list", "table", "inet", "tvgw_gate").stdout
    assert "an injected gate rule" not in gate and "TV to an address DNS never returned" in gate
    assert "203.0.113.99" in gate  # the feeder's address stays
    assert gw.tv_reaches_the_web() == f"pass:{vnet.GW_WLAN}"
    # (revert) and last-good, on the disk, kept the gate's rules and none of its sets' elements
    kept = (gw.state / "last-good" / "inet-tvgw_gate.nft").read_text(encoding="utf-8")
    assert "TV to an address DNS never returned" in kept and "elements" not in kept, kept


def test_a_repair_during_a_confirmed_applys_wait_runs_at_once(clean, net):
    """(revert) Review of 2026-11-07, item 7: a confirmed apply held the lock through its wait for the
    verdict after, up to a minute, and a dispatcher's repair waited behind it. Here, in one sandbox (one
    lock), apply A's probe takes 30 seconds over its verdict after; apply B starts once A has said go and
    must finish long before that. A then finds it was superseded, and changes nothing."""
    gw = clean
    slow = gw.write_shim(
        "tvgw-slow",
        '[ "$1 $2" = "probe --across" ] || exit 4\nprintf "pass -\\n{}\\n" >"$3/pre"\n'
        'while [ ! -e "$3/go" ] && [ ! -e "$3/abort" ]; do sleep 0.1; done\nsleep 30\n'
        'printf "pass -\\n{}\\n" >"$3/post"',
    )
    a, b = gw.script(tvgw=slow), gw.script(tvgw="/nonexistent/tvgw")
    d = net.sandbox / "repair-during-wait"
    d.mkdir(exist_ok=True)
    driver = gw.write_shim(
        "tvgw-two-applies",
        f'bash "{a}" >"$1/a.out" 2>&1 &\npid=$!\n'
        "for _ in $(seq 1 300); do ls /run/tvgw/confirm.*/go >/dev/null 2>&1 && break; sleep 0.1; done\n"
        f'start=$(date +%s)\nbash "{b}" >"$1/b.out" 2>&1\necho "$? $(( $(date +%s) - start ))" >"$1/b.rc"\n'
        'wait "$pid"\necho "$?" >"$1/a.rc"',
    )
    out = net.apply(
        net.gw, conf(APPLY_CONFIRM="report"), (str(d),), run_dir=gw.run_dir, script=driver,
        state=gw.state, files=gw.files,
    )  # fmt: skip
    said = {name: (d / name).read_text(encoding="utf-8") for name in ("a.out", "b.out", "a.rc", "b.rc")}
    net.save("probe/repair-during-wait.log", json.dumps(said, indent=1))
    assert out.returncode == 0, out.stderr
    rc, took = (int(n) for n in said["b.rc"].split())
    assert rc == 0 and "is not there; this apply is not confirmed" in said["b.out"], said
    assert took < 20, f"the repair waited {took} s behind the confirmed apply"
    assert (
        said["a.rc"].strip() == "0" and "a later apply superseded this one while it waited" in said["a.out"]
    )
    assert gw.spool()[-1][:3] == ["confirm", "report", "superseded"]
    assert gw.tv_reaches_the_web() == f"pass:{vnet.GW_WLAN}"


@pytest.mark.parametrize(
    ("step", "settings", "fault"),
    [
        (
            "adtech",
            {"PROFILE": "lg-webos"},
            (
                'counter reject with tcp reset comment \\"LG adtech port\\"',
                'counter accept comment \\"LG adtech port\\"',
            ),
        ),
    ],
)
def test_the_port_walls_are_probed_where_they_stand(clean, net, step, settings, fault):
    """(revert) Decision 65's item 5: the probe did not exercise LG's adtech wall (STRICT_PORTS is the
    `ports` step's, package D). It is tried at the documentation address: refused where it stands, and a
    copy of the script whose wall lets the packet through fails the step. (With PROFILE=lg-webos the
    stand-in filter answers the profile's blocked name with an address, so that run's verdict is unknown
    at `blocked`; the step is what is read.)"""
    gw = clean
    try:
        assert gw.apply(conf(**settings)).returncode == 0
        rc, verdict = gw.probe(conf(**settings))
        net.save(f"probe/wall-{step}.json", json.dumps(verdict, indent=1))
        assert gw.stages(verdict)[step] == "pass", verdict
        assert gw.apply(conf(**settings), gw.script(fault)).returncode == 0
        rc, verdict = gw.probe(conf(**settings))
        net.save(f"probe/wall-{step}-missing.json", json.dumps(verdict, indent=1))
        assert gw.stages(verdict)[step] == "fail" and rc == 3, verdict
    finally:
        assert gw.apply(conf()).returncode == 0


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
    assert gw.listing() == good and not (gw.state / "last-good" / "armed").exists()
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
    assert not (gw.state / "last-good" / "armed").exists()
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


def test_an_answer_that_comes_after_the_probes_pair_is_gone_never_reaches_the_tvs_port(clean, net):
    """(revert) CI, 2026-11-08: a probe whose wall let its packet out (the adtech test's copy) had that packet
    answered, an ICMP error, after its pair was gone; the gateway routed the answer by the TV subnet's
    route and looked for the probe on the TV's cable (a FAILED neighbour entry on the TV's port, which the
    next test read). Packets to the probe's address that would leave by the TV's port are dropped, by the
    gateway's own forward and output chains, so nothing of the probe's is ever looked for there."""
    net.ns(net.gw, "ip", "neigh", "flush", "dev", vnet.TV_IF, check=False)
    # the gateway's own packet to the probe's address, which its TV-subnet route sends to the TV's port
    net.ns(net.gw, "ping", "-c", "1", "-W", "1", vnet.PROBE_IP, check=False)
    time.sleep(1.0)
    assert vnet.PROBE_IP not in net.ns(net.gw, "ip", "neigh", "show", "dev", vnet.TV_IF).stdout
    # and a forwarded one, a late answer the TV's chain would accept as related: dropped before that accept
    forward = net.ns(net.gw, "nft", "list", "chain", "inet", "tvgw", "forward").stdout
    drop = forward.index(f'oifname "{vnet.TV_IF}" ip daddr {vnet.PROBE_IP} drop')
    assert drop < forward.index("ct state established,related accept"), forward
    output = net.ns(net.gw, "nft", "list", "chain", "inet", "tvgw", "output").stdout
    assert f'oifname "{vnet.TV_IF}" ip daddr {vnet.PROBE_IP} drop' in output


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
    assert not (gw.state / "last-good" / "armed").exists()
    # and with the route whole again, the next apply is confirmed, in a bounded time
    out = gw.confirmed(conf(APPLY_CONFIRM="revert"))
    assert out.returncode == 0 and "tvgw: confirm: pass (before the apply: pass)" in out.stdout, out.stderr
    assert gw.took < 40


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
        out = gw.confirmed(conf(APPLY_CONFIRM="revert"))
        assert out.returncode == 0, out.stderr
        token = "held-connection-test"
        (gw.state / "last-good" / "armed").write_text(token + "\n", encoding="utf-8")
        out = net.apply(net.gw, conf(), ("--restore", "/var/lib/tvgw/last-good", token, "revert"),
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


# ---- (ports) the port steps (design decision 71) ----------------------------------------------------------
STRICT_REJECT = "ODDPORT_DROP=$(odd_ports 'counter reject with icmpx admin-prohibited comment"
WEB_REFUSED = '\t\ttcp dport 80 counter reject comment "an injected refusal of the web"\n'


def test_the_port_steps_follow_strict_ports_and_the_clock_port(clean, net):
    """The web passes and the unusual port is let through; with STRICT_PORTS=yes the unusual port is
    refused; with the clock port closed, UDP 123 is refused too. Each verdict passes, and each moves no
    counter of the TV's. The NTP count is emptied first, so that the apply closes the port as asked (the
    TV's NTP of earlier modules would hold it open, as it must)."""
    gw = clean
    net.ns(net.gw, "nft", "flush", "set", "inet", "tvgw_ntp", "ntp4", check=False)
    for settings, used in (({"STRICT_PORTS": "yes"}, "any"), ({"CLOCK_PORT": "none"}, "none")):
        out = gw.apply(conf(**settings))
        assert out.returncode == 0, out.stderr
        assert f"CLOCK_PORT_USED={used}" in (gw.run_dir / "settings.applied").read_text(encoding="utf-8")
        before = net.counters()
        rc, verdict = gw.probe(conf(**settings))
        net.save(f"probe/ports-{'-'.join(settings)}.json", json.dumps(verdict, indent=1))
        assert (rc, verdict["verdict"]) == (0, "pass"), verdict
        assert gw.stages(verdict)["ports"] == "pass"
        moved = {c: n for c, n in vnet.ticked(before, net.counters()).items() if c not in vnet.NOISY}
        assert moved == {}, moved
    # and the TV's own NTP is refused at the closed port, counted by the rule the probe's twin copies
    assert net.probe("tv", "udp", vnet.WEB, 123) == "reject"


def test_a_strict_wall_that_lets_the_unusual_port_through_fails_the_port_step(clean, net):
    gw = clean
    broken = gw.script((STRICT_REJECT, "ODDPORT_DROP=$(odd_ports 'counter accept comment"))
    out = gw.apply(conf(STRICT_PORTS="yes"), broken)
    assert out.returncode == 0, out.stderr
    rc, verdict = gw.probe(conf(STRICT_PORTS="yes"))
    assert (rc, verdict["verdict"]) == (3, "fail"), verdict
    assert verdict["reason"] == f"ports: UDP {5000}, an unusual port, was not refused, and STRICT_PORTS=yes"


def test_a_refused_web_port_fails_the_port_step(clean, net):
    gw = clean
    out = gw.apply(conf(), gw.script((TV_OUT, TV_OUT + WEB_REFUSED)))
    assert out.returncode == 0, out.stderr
    rc, verdict = gw.probe()
    assert (rc, verdict["verdict"]) == (3, "fail"), verdict
    assert verdict["reason"] == "ports: the gateway refuses TCP 80, which it must let through"


def conntrack_ids(net) -> set[str] | None:
    """The ids of the gateway's established conntrack entries for the TV's TCP to the web server, or None
    without the tool. Established only: an earlier test's connection there, closed and waiting out its
    TIME_WAIT, would expire in the middle of a test and read as an entry the test lost (CI, 2026-11-08)."""
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
        "--state",
        "ESTABLISHED",
        "-o",
        "id",
        check=False,
    )
    ids = {word.removeprefix("id=") for word in out.stdout.split() if word.startswith("id=")}
    assert ids, f"no conntrack entry for the held connection: {out.stdout} {out.stderr}"
    return ids
