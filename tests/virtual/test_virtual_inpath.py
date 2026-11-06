"""(inpath) The DNS gate's in-path filler on a kernel (design decision 64): tvgw-apply's queue rules, the
real `tvgw.inpath` process bound to the queue in the gateway namespace, and a namespace TV that looks
names up and connects the instant each answer arrives.

What only a kernel can say, and this module asks it:

- with the rules loaded and no filler, every lookup answers (`bypass`, and the empty `inpath_live`);
- with the filler bound, an answered address is in `resolved4_inpath`, with a day to live, before the
  answer reaches the TV: thousands of lookups each followed at once by a connection leave the in-path
  count where it was, while the passive feeder's count (where tcpdump is installed) rises;
- `0.0.0.0` and private addresses never enter the set; an answer over TCP is read; an address answered
  again by a new filler gets a fresh day (kernel 6.12 or later);
- a filler that is killed, stopped (SIGSTOP), or left with no table costs no later lookup: the kernel
  passes the answers itself. A stopped filler traps at most MAXLEN answers; under systemd, with the
  shipped unit's watchdog settings, it is killed and lookups answer again within seconds;
- the kernel drops what waits in a queue when any hook is removed, by anyone; tvgw-apply, which
  removes hooks at every run, takes the filler's switch away first, so three re-applies under load
  lose no lookup, and the filler switches itself on again within seconds;
- a clean stop loses no lookup at all, and DNSGATE_FILL=passive takes the rules and sets away.

The stand-in resolver of the gateway namespace answers a name `ip-A-B-C-D.<anything>` with A.B.C.D
(agent.py), so each test chooses the addresses its answers hand out. The module leaves the gateway as
the `direct` scenario of matrix.txt has it."""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest
import vnet

from tvgw import config, dnsgate, inpath, verify

pytestmark = pytest.mark.virtual

DIRECT = next(s for s in vnet.parse_matrix(vnet.MATRIX.read_text(encoding="utf-8")) if s.name == "direct")
INPATH = {**DIRECT.settings, "DNSGATE_FILL": "inpath"}
UNIT = (vnet.ROOT / "deploy" / "systemd" / "tvgw-dnsgate-inpath.service").read_text(encoding="utf-8")
REQUIRED = os.environ.get("TVGW_VIRTUAL_REQUIRED") == "1"
PASSIVE_RULE = "TV to an address DNS never returned"
RACE = 5000  # lookups, each followed at once by a connection to the address it returned
# the test fillers re-assert inpath_live as often as shipped, and write their status more often than
# the shipped 10 s, to keep the waits short
LIVE_EVERY, STATUS_EVERY = inpath.LIVE_EVERY, 0.5
# runs inside the gateway namespace with `python -I`: this checkout's filler, as its unit would run it
RUNNER = (
    "import sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from tvgw import config, inpath\n"
    "inpath.LIVE_EVERY, inpath.STATUS_EVERY = float(sys.argv[3]), float(sys.argv[4])\n"
    "sys.exit(inpath.main(config.Settings(dnsgate_fill='inpath'), status_path=sys.argv[2]))\n"
)
FEEDER = (  # the passive feeder beside it, for the contrast
    "import sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from tvgw import config, dnsgate\n"
    "sys.exit(dnsgate.main(config.Settings(tv_if=sys.argv[2], tv_ip=sys.argv[3])))\n"
)
_asked = [0]  # how many addresses `ask` has used so far, so every run asks for new ones


def unable(why: str) -> None:
    """The kernel cannot queue, or the filler cannot run: a failure where the suite is required (CI), a
    skip on a developer's machine."""
    if REQUIRED:
        pytest.fail(f"TVGW_VIRTUAL_REQUIRED=1 but {why}")
    pytest.skip(why)


def name_for(address: str) -> str:
    return f"ip-{address.replace('.', '-')}.inpath.tvgw.example"


def lookup(net, address: str, kind: str = "dns-udp", target: str = vnet.GW_TV) -> str:
    return net.probe("tv", kind, target, 53, name=name_for(address))


def elements(net, set_name: str) -> dict[str, int]:
    """address or port -> seconds left (0 for an element without a lifetime), from the kernel's listing."""
    out = net.ns(net.gw, "nft", "-j", "list", "set", "inet", "tvgw_gate", set_name, check=False).stdout
    found: dict[str, int] = {}
    for obj in (json.loads(out) if out.strip() else {}).get("nftables", []):
        for elem in (obj.get("set") or {}).get("elem") or []:
            e = elem.get("elem") if isinstance(elem, dict) else None
            if isinstance(e, dict):
                found[str(e["val"])] = int(e.get("expires", 0))
            else:
                found[str(elem)] = 0
    return found


def wait_switch(net, wait: float = 5 * LIVE_EVERY) -> None:
    """Until the filler has put its port into inpath_live (again): it looks every LIVE_EVERY seconds."""
    deadline = time.monotonic() + wait
    while elements(net, "inpath_live") != {"53": 0} and time.monotonic() < deadline:
        time.sleep(0.1)
    assert elements(net, "inpath_live") == {"53": 0}, f"the filler did not switch on within {wait:.0f} s"


def count(net, comment: str) -> int:
    return net.counters().get(comment, (0, ""))[0]


def queues(net) -> dict[int, dict[str, int]]:
    return inpath.bound_queues(net.ns(net.gw, "cat", inpath.PROC_QUEUES, check=False).stdout)


def ask(net, *args: str, span: int, timeout: float = 180) -> dict:
    """agent.py ask from the TV namespace, for addresses no earlier run asked for: `span` is the most
    this run can use (its --count, or more than its --seconds allow). 198.18.0.0/15 holds 64 000 of
    the addresses ask makes, and the module uses under half."""
    first = _asked[0]
    _asked[0] += span
    assert _asked[0] < 60000, "the module has used up the addresses ask can make"
    out = vnet.run(net.agent_argv(net.tv, "ask", vnet.GW_TV, "--first", str(first), *args), timeout=timeout)
    return json.loads(out.stdout)


def ask_in_background(net, *args: str, span: int = 5000) -> subprocess.Popen:
    first = _asked[0]
    _asked[0] += span
    assert _asked[0] < 60000, "the module has used up the addresses ask can make"
    return subprocess.Popen(
        net.agent_argv(net.tv, "ask", vnet.GW_TV, "--first", str(first), *args),
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )


class Filler:
    """One filler process in the gateway namespace, and its status file."""

    def __init__(self, net, tag: str):
        self.net, self.tag = net, tag
        self.status = net.sandbox / f"inpath-{tag}.json"
        self.log_path = net.artifacts / "inpath" / f"{tag}.log"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.proc: subprocess.Popen | None = None

    def argv(self) -> list[str]:
        timing = [str(LIVE_EVERY), str(STATUS_EVERY)]
        return [sys.executable, "-I", "-c", RUNNER, str(vnet.ROOT / "src"), str(self.status), *timing]

    def start(self, wait: float = 15.0) -> Filler:
        self.log = self.log_path.open("w", encoding="utf-8")
        # `ip netns exec` execs the command, so the pid is the filler's own
        self.proc = subprocess.Popen(
            ["ip", "netns", "exec", self.net.gw, *self.argv()], stdout=self.log, stderr=subprocess.STDOUT
        )
        self.wait_live(wait)
        return self

    def doc(self) -> dict | None:
        try:
            return json.loads(self.status.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def wait_live(self, wait: float = 15.0, pid: int | None = None) -> dict:
        pid = pid or self.proc.pid
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            doc = self.doc()
            if doc and doc.get("pid") == pid and doc.get("live"):
                return doc
            if self.proc is not None and self.proc.poll() is not None:
                break
            time.sleep(0.05)
        tail = ""
        with contextlib.suppress(OSError, AttributeError):
            self.log.flush()
        with contextlib.suppress(OSError):
            tail = self.log_path.read_text(encoding="utf-8")[-600:]
        unable(f"the in-path filler did not come up in {wait:.0f} s (status {self.doc()}): {tail!r}")
        raise AssertionError  # not reached

    def stats(self, settle: float = 0.0) -> dict:
        """The counts as the filler last wrote them; it writes every STATUS_EVERY seconds, so a caller
        that needs them current stops the filler first (a clean stop does not write) or waits."""
        if settle:
            time.sleep(settle)
        return (self.doc() or {}).get("stats", {})

    def signal(self, sig: int) -> None:
        self.proc.send_signal(sig)

    def end(self, sig: int = signal.SIGTERM, wait: float = 10.0) -> int | None:
        if self.proc is None:
            return None
        if self.proc.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                self.proc.send_signal(sig)
        try:
            rc = self.proc.wait(timeout=wait)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            rc = self.proc.wait(timeout=5)
        with contextlib.suppress(OSError):
            self.log.close()
        self.proc = None
        return rc


def fresh_stats(net, filler: Filler, received_at_least: int, wait: float = 15.0) -> dict:
    """The filler's counts once its status file has caught up with `received_at_least` packets."""
    deadline = time.monotonic() + wait
    stats = filler.stats()
    while stats.get("received", 0) < received_at_least and time.monotonic() < deadline:
        time.sleep(0.2)
        stats = filler.stats()
    return stats


def apply(net, settings: dict[str, str], tag: str) -> subprocess.CompletedProcess:
    out = net.apply(net.gw, vnet.render_conf(settings))
    net.save(f"inpath/apply-{tag}.log", out.stdout + out.stderr)
    assert out.returncode == 0, out.stderr
    return out


@pytest.fixture(scope="module")
def gw(net):
    """The gateway with DNSGATE_FILL=inpath applied and no filler yet. Whatever the tests leave running
    is ended, and the `direct` scenario put back, when the module is done."""
    if shutil.which("modprobe"):  # both modules load on demand too; a container has no modprobe
        subprocess.run(["modprobe", "-a", "nfnetlink_queue", "nft_queue"], capture_output=True, check=False)
    out = apply(net, INPATH, "inpath")
    if "in-path gate rules not loaded" in out.stderr:
        unable(f"this kernel does not load the queue rules: {out.stderr.strip()[-300:]}")
    fillers: list[Filler] = []
    net.inpath_fillers = fillers
    try:
        yield net
    finally:
        for f in fillers:
            f.end(signal.SIGKILL)
        apply(net, DIRECT.settings, "restore")
        net.save("inpath/ruleset-after.nft", net.ns(net.gw, "nft", "list", "ruleset").stdout)


def start(net, tag: str) -> Filler:
    f = Filler(net, tag)
    net.inpath_fillers.append(f)  # before it starts: one that does not come up is still ended
    return f.start()


@pytest.fixture
def filler(gw, request):
    """A fresh filler for one test, ended (a clean stop) after it."""
    f = start(gw, re.sub(r"\W+", "-", request.node.name)[:60])
    yield f
    f.end()


# ---- the rules, with no filler ---------------------------------------------------------------------------


def test_the_rules_load_beside_the_gate_and_every_lookup_still_answers(gw):
    net = gw
    table = net.ns(net.gw, "nft", "list", "table", "inet", "tvgw_gate").stdout
    net.save("inpath/table.nft", table)
    for needle, what in verify.INPATH_NEEDLES:
        assert needle in table, what
    assert f"queue flags bypass to {inpath.QUEUE}" in table
    assert "tvgw-inpath: " in table and 'log prefix "tvgw-gate: "' in table
    assert "set resolved4 {" in table and PASSIVE_RULE in table  # the gate's own half is as it was
    assert elements(net, "inpath_live") == {} and inpath.QUEUE not in queues(net)
    # nobody is bound and the switch is off: the answers never reach the queue rules' counters
    before = sum(count(net, rule) for rule in inpath.OFFERED_RULES)
    assert lookup(net, "203.0.113.61") == "answer:203.0.113.61"
    assert lookup(net, "203.0.113.61", "dns-tcp") == "answer:203.0.113.61"
    assert lookup(net, "203.0.113.61", target=vnet.RESOLVER) == "answer:203.0.113.61"  # redirected
    assert sum(count(net, rule) for rule in inpath.OFFERED_RULES) == before
    assert elements(net, inpath.SET) == {}


def test_a_switch_left_on_with_nobody_bound_is_passed_by_the_kernel(gw):
    """What a killed filler leaves: port 53 in inpath_live and no queue. The rules match, and `bypass`
    has the kernel accept each answer."""
    net = gw
    net.ns(net.gw, "nft", "add", "element", "inet", "tvgw_gate", "inpath_live", "{ 53 }")
    try:
        before = count(net, inpath.OFFERED_RULES[0])
        got = ask(net, "--count", "200", "--timeout", "1", span=200)
        assert (got["answered"], got["lost"], got["wrong"]) == (200, 0, 0), got
        assert lookup(net, "203.0.113.62", "dns-tcp") == "answer:203.0.113.62"
        assert count(net, inpath.OFFERED_RULES[0]) - before >= 200
        assert count(net, inpath.OFFERED_RULES[1]) >= 1
    finally:
        net.ns(net.gw, "nft", "flush", "set", "inet", "tvgw_gate", "inpath_live")


# ---- the filler bound -------------------------------------------------------------------------------------


def test_an_answered_address_is_in_the_set_with_a_day_to_live(gw, filler):
    net = gw
    q = queues(net)[inpath.QUEUE]
    assert q["copy_mode"] == 2 and q["waiting"] == 0  # whole packets, nothing held back
    assert elements(net, "inpath_live") == {"53": 0}
    assert lookup(net, "203.0.113.71") == "answer:203.0.113.71"
    found = elements(net, inpath.SET)
    assert dnsgate.TTL - 60 <= found["203.0.113.71"] <= dnsgate.TTL
    # over TCP, whole in one segment, and aimed at another resolver (the redirect brings it here)
    assert lookup(net, "203.0.113.72", "dns-tcp") == "answer:203.0.113.72"
    assert lookup(net, "203.0.113.73", target=vnet.RESOLVER) == "answer:203.0.113.73"
    assert {"203.0.113.72", "203.0.113.73"} <= set(elements(net, inpath.SET))
    stats = fresh_stats(net, filler, 3)
    assert stats["held"] >= 3 and stats["unparsed_tcp"] == stats["unparsed_udp"] == stats["failed"] == 0


@pytest.mark.parametrize("address", ["0.0.0.0", "10.20.30.40", "192.168.1.1", "100.64.0.9", "127.0.0.1"])
def test_the_blocked_answer_and_local_addresses_reach_the_tv_and_never_the_set(gw, filler, address):
    assert lookup(gw, address) == f"answer:{address}"
    assert lookup(gw, "203.0.113.74") == "answer:203.0.113.74"  # the filler has read on past it
    found = elements(gw, inpath.SET)
    assert address not in found and "203.0.113.74" in found


def test_an_address_answered_again_gets_a_fresh_day(gw):
    """A new filler knows nothing, so the next answer naming the address adds it again; the add carries
    `expires`, which is what moves an existing element's expiry from kernel 6.12 on (decision 43)."""
    net = gw
    address = "203.0.113.75"
    net.ns(
        net.gw,
        "nft",
        "add",
        "element",
        "inet",
        "tvgw_gate",
        inpath.SET,
        f"{{ {address} timeout 1d expires 1h }}",
    )
    assert 3500 <= elements(net, inpath.SET)[address] <= 3600
    f = start(net, "fresh-day")
    try:
        assert lookup(net, address) == f"answer:{address}"
        left = elements(net, inpath.SET)[address]
    finally:
        f.end()
    m = re.match(r"(\d+)\.(\d+)", os.uname().release)
    if (int(m.group(1)), int(m.group(2))) < (6, 12):
        pytest.skip(f"kernel {os.uname().release} keeps the first expiry; the refresh needs 6.12")
    assert left > dnsgate.TTL - 120


def test_a_client_that_connects_the_instant_its_answer_arrives_never_beats_the_filler(gw, filler):
    """The race the passive feeder loses on nearly every new address. Every miss the in-path rule counts
    must be an answer the filler itself reports it did not hold; with none of those, there is no miss."""
    net = gw
    before = count(net, inpath.MISS_RULE)
    got = ask(net, "--count", str(RACE), "--connect", "443", "--timeout", "2", span=RACE)
    net.save("inpath/race.json", json.dumps(got))
    assert (got["answered"], got["lost"], got["wrong"]) == (RACE, 0, 0), got
    assert got["connected"] == RACE, got
    stats = fresh_stats(net, filler, RACE)
    net.save("inpath/race-status.json", json.dumps(filler.doc()))
    misses = count(net, inpath.MISS_RULE) - before
    not_held = stats["late"] + stats["failed"] + stats["kernel_passed"] + stats["unparsed_udp"]
    assert stats["held"] >= RACE - not_held, stats
    assert misses <= not_held, f"{misses} in-path misses, but the filler held all but {not_held}: {stats}"
    assert not_held <= RACE // 1000, f"the filler did not hold {not_held} of {RACE} answers: {stats}"
    assert queues(net)[inpath.QUEUE]["dropped"] == queues(net)[inpath.QUEUE]["user_dropped"] == 0
    # the hold itself, as the filler measured it: far below the bound even on a shared runner
    assert 0 < filler.doc()["hold_us"]["p50"] < 10_000, filler.doc()["hold_us"]


def test_the_passive_feeder_loses_the_same_race_the_filler_wins(gw, filler):
    """Both fillers at once, as on a gateway with DNSGATE_FILL=inpath: the feeder adds an address after
    its answer has left, the filler before."""
    net = gw
    if shutil.which("tcpdump") is None:
        pytest.skip("the passive feeder needs tcpdump")
    log = (net.artifacts / "inpath" / "feeder.log").open("w", encoding="utf-8")
    feeder = subprocess.Popen(
        [
            "ip",
            "netns",
            "exec",
            net.gw,
            sys.executable,
            "-I",
            "-c",
            FEEDER,
            str(vnet.ROOT / "src"),
            vnet.TV_IF,
            vnet.TV_IP,
        ],
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    try:
        deadline = time.monotonic() + 20
        while "203.0.113.76" not in elements(net, "resolved4") and time.monotonic() < deadline:
            assert feeder.poll() is None, "the passive feeder ended"
            lookup(net, "203.0.113.76")
            time.sleep(0.5)
        assert "203.0.113.76" in elements(net, "resolved4"), "the passive feeder added nothing in 20 s"
        passive, mine = count(net, PASSIVE_RULE), count(net, inpath.MISS_RULE)
        got = ask(net, "--count", "500", "--connect", "443", "--timeout", "2", span=500)
        assert got["answered"] == 500, got
        stats = fresh_stats(net, filler, 500)
        not_held = stats["late"] + stats["failed"] + stats["kernel_passed"] + stats["unparsed_udp"]
        lost_by_passive = count(net, PASSIVE_RULE) - passive
        lost_by_filler = count(net, inpath.MISS_RULE) - mine
        net.save(
            "inpath/contrast.txt", f"passive feeder: {lost_by_passive} misses, in-path: {lost_by_filler}\n"
        )
        assert lost_by_filler <= not_held, stats
        assert lost_by_passive > lost_by_filler and lost_by_passive >= 50
    finally:
        feeder.kill()
        feeder.wait(timeout=10)
        log.close()


def test_verify_reads_the_filler_from_the_kernel_and_its_status(gw, filler):
    net = gw
    s = config.Settings(dnsgate_fill="inpath")

    def run(cmd):
        return net.ns(net.gw, *cmd, check=False).stdout

    def read(path):
        if path == inpath.STATUS:
            return filler.status.read_text(encoding="utf-8")
        return net.ns(net.gw, "cat", path, check=False).stdout

    lookup(net, "203.0.113.77")
    check, series = verify.inpath_check(s, run, read, time.time())
    assert check.ok and not check.warn and check.detail.startswith("bound; "), check.detail
    assert {rule for rule, _, _ in series} == {rule for _, _, rule in inpath.SERIES}
    filler.end(signal.SIGKILL)
    check, series = verify.inpath_check(s, run, read, time.time())
    assert check.ok and check.warn and "no process is bound" in check.detail and series == []
    off, _ = verify.inpath_check(config.Settings(), run, read, time.time())
    assert off.ok and not off.warn and "not in use" in off.detail


# ---- the filler failing ---------------------------------------------------------------------------------


def test_a_killed_filler_costs_no_later_lookup(gw):
    net = gw
    f = start(net, "killed")
    assert lookup(net, "203.0.113.81") == "answer:203.0.113.81"
    f.end(signal.SIGKILL)
    assert inpath.QUEUE not in queues(net)
    assert elements(net, "inpath_live") == {"53": 0}  # left on: the kernel's bypass is what answers now
    got = ask(net, "--count", "300", "--timeout", "1", span=300)
    assert (got["answered"], got["lost"]) == (300, 0), got
    assert lookup(net, "203.0.113.82", "dns-tcp") == "answer:203.0.113.82"
    assert "203.0.113.82" not in elements(net, inpath.SET)  # nobody held it: the second count would say so
    # and the next filler takes over under load without a lookup lost: it empties the switch before it binds
    load = ask_in_background(net, "--seconds", "4", "--interval", "0.002", "--timeout", "1")
    time.sleep(0.5)
    g = start(net, "after-kill")
    try:
        out, _ = load.communicate(timeout=60)
        got = json.loads(out)
        assert got["lost"] == 0 and got["answered"] > 300, got
        assert fresh_stats(net, g, 100)["held"] >= 100
    finally:
        g.end()


def test_a_stopped_filler_traps_at_most_the_queue_and_the_rest_flow(gw):
    """SIGSTOP with no watchdog: the kernel queues MAXLEN answers behind a process that reads nothing,
    then fails open. Those MAXLEN lookups time out (the TV would ask again); every later one answers."""
    net = gw
    f = start(net, "stopped")
    try:
        f.signal(signal.SIGSTOP)
        got = ask(net, "--count", str(inpath.MAXLEN + 300), "--timeout", "0.03", span=inpath.MAXLEN + 300)
        net.save("inpath/stopped.json", json.dumps(got))
        assert inpath.MAXLEN - 2 <= got["lost"] <= inpath.MAXLEN + 2, got
        assert got["answered_after_last_lost"] >= 290, got
        q = queues(net)[inpath.QUEUE]
        assert q["waiting"] == inpath.MAXLEN and q["dropped"] == q["user_dropped"] == 0, q
    finally:
        f.end(signal.SIGKILL)
    got = ask(net, "--count", "100", "--timeout", "1", span=100)
    assert (got["answered"], got["lost"]) == (100, 0), got


def unit_value(key: str) -> str:
    (value,) = re.findall(rf"^{key}=(.*)$", UNIT, re.M)
    return value


def test_under_the_units_watchdog_a_stopped_filler_is_killed_and_lookups_answer_again(gw):
    """The shipped unit's Type, NotifyAccess, WatchdogSec and WatchdogSignal on a transient unit in the
    gateway namespace: the filler says READY, pings, is stopped, and systemd kills it within WatchdogSec.
    From then on the kernel passes the answers itself."""
    net = gw
    if shutil.which("systemd-run") is None or not os.path.isdir("/run/systemd/system"):
        pytest.skip("needs a running systemd for a transient unit")
    unit = f"tvgwv-{os.getpid()}-inpath"
    f = Filler(net, "watchdog")
    props = [f"{k}={unit_value(k)}" for k in ("Type", "NotifyAccess", "WatchdogSec", "WatchdogSignal")]
    props.append(f"NetworkNamespacePath=/run/netns/{net.gw}")
    argv = ["systemd-run", "--quiet", "--unit", unit, *[x for p in props for x in ("-p", p)], "--", *f.argv()]
    started = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", timeout=60)
    try:
        if started.returncode != 0:
            unable(f"systemd-run could not start the filler: {started.stderr.strip()[-300:]}")

        def show(prop: str) -> str:
            out = subprocess.run(
                ["systemctl", "show", "-p", prop, "--value", unit], capture_output=True, text=True
            )
            return out.stdout.strip()

        pid = int(show("MainPID"))
        f.wait_live(pid=pid)
        assert show("ActiveState") == "active"
        time.sleep(2 * float(unit_value("WatchdogSec")))  # it outlives its watchdog only by pinging
        assert show("ActiveState") == "active" and int(show("MainPID")) == pid
        limit = float(unit_value("WatchdogSec"))
        os.kill(pid, signal.SIGSTOP)
        got = ask(net, "--seconds", str(limit + 5), "--interval", "0.03", "--timeout", "0.1", span=500)
        net.save("inpath/watchdog.json", json.dumps(got))
        assert got["lost"] >= 1 and got["first_lost_s"] < 0.5, got  # the stop did hold answers
        assert got["last_lost_s"] <= limit + 1.5, got  # and the watchdog ended that
        assert got["answered_after_last_lost"] >= 50, got
        assert show("Result") == "watchdog", show("Result")
        assert inpath.QUEUE not in queues(net)
    finally:
        subprocess.run(["systemctl", "stop", unit], capture_output=True, check=False)
        subprocess.run(["systemctl", "reset-failed", unit], capture_output=True, check=False)


def test_with_the_table_gone_answers_flow_and_the_filler_takes_up_again_when_it_is_back(gw, filler):
    """The table deleted by hand under load, with none of tvgw-apply's care: the kernel drops what
    waits in the queue at that instant (one answer, or none), and every answer after it flows. Applied
    again, the table's sets are new and empty, and the filler notices by its port being gone."""
    net = gw
    assert lookup(net, "203.0.113.83") == "answer:203.0.113.83"
    load = ask_in_background(net, "--seconds", "6", "--interval", "0.005", "--timeout", "1")
    time.sleep(0.5)
    net.ns(net.gw, "nft", "delete", "table", "inet", "tvgw_gate")  # DNSGATE=off, without the apply
    time.sleep(1.0)
    assert lookup(net, "203.0.113.84") == "answer:203.0.113.84"
    apply(net, INPATH, "table-back")  # the table again, its sets empty, inpath_live too
    out, _ = load.communicate(timeout=60)
    got = json.loads(out)
    assert got["lost"] <= 2 and got["answered"] > 300, got
    wait_switch(net)
    # 203.0.113.83 was known to the filler a moment ago; its set is new, so it must be added again
    assert lookup(net, "203.0.113.83") == "answer:203.0.113.83"
    assert "203.0.113.83" in elements(net, inpath.SET)
    assert filler.proc.poll() is None


def test_a_hook_removed_by_anyone_drops_what_waits_and_the_filler_carries_on(gw):
    """The kernel's own rule, which the design is built around (nf_queue_nf_hook_drop): when any
    netfilter hook goes, every packet waiting in every queue is dropped. Made certain here by stopping
    the filler so that answers wait, then deleting a base chain that has nothing to do with it. The
    filler, continued, finds its verdicts refused, counts them, and holds the next answer as before."""
    net = gw
    f = start(net, "hook-removed")
    try:
        f.signal(signal.SIGSTOP)
        net.ns(net.gw, "nft", "add", "table", "ip", "tvgwv_scratch")
        net.ns(
            net.gw,
            "nft",
            "add",
            "chain",
            "ip",
            "tvgwv_scratch",
            "c",
            "{ type filter hook input priority 0; }",
        )
        waiting = subprocess.Popen(
            net.agent_argv(
                net.tv, "ask", vnet.GW_TV, "--first", "59000", "--count", "20", "--timeout", "0.4"
            ),
            stdout=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        deadline = time.monotonic() + 5
        while queues(net)[inpath.QUEUE]["waiting"] < 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert queues(net)[inpath.QUEUE]["waiting"] >= 1
        net.ns(net.gw, "nft", "delete", "table", "ip", "tvgwv_scratch")  # a hook goes: the queue is emptied
        f.signal(signal.SIGCONT)
        out, _ = waiting.communicate(timeout=60)
        got = json.loads(out)
        assert got["lost"] >= 1 and got["answered"] >= 10, got  # the first was dropped; the later ones flow
        assert lookup(net, "203.0.113.87") == "answer:203.0.113.87"
        assert "203.0.113.87" in elements(net, inpath.SET)
        stats = fresh_stats(net, f, 2)
        assert stats["verdict_errors"] >= 1 and stats["errors"] == 0, stats
        assert f.proc.poll() is None
    finally:
        net.ns(net.gw, "nft", "delete", "table", "ip", "tvgwv_scratch", check=False)
        f.end()


def test_a_reapply_under_a_live_filler_keeps_the_set_and_loses_no_lookup(gw, filler):
    """Every apply removes hooks (`delete table inet tvgw`), and the kernel drops what waits in a queue
    when one goes. tvgw-apply takes the filler's switch away first and waits for the queue to empty, so
    three applies under load lose nothing; while one runs, answers pass unheld, and the filler switches
    itself on again when the last load has made its set anew."""
    net = gw
    assert lookup(net, "203.0.113.85") == "answer:203.0.113.85"
    load = ask_in_background(net, "--seconds", "8", "--interval", "0.003", "--timeout", "1")
    time.sleep(0.5)
    for n in range(3):
        apply(net, INPATH, f"reapply-{n}")
        time.sleep(0.3)
    out, _ = load.communicate(timeout=60)
    got = json.loads(out)
    assert got["lost"] == 0 and got["wrong"] == 0 and got["answered"] > 300, got
    assert "203.0.113.85" in elements(net, inpath.SET)  # `add set` kept what the filler had put in
    wait_switch(net)
    assert lookup(net, "203.0.113.86") == "answer:203.0.113.86"
    assert "203.0.113.86" in elements(net, inpath.SET)
    q = queues(net)[inpath.QUEUE]
    assert q["dropped"] == q["user_dropped"] == 0, q
    assert fresh_stats(net, filler, 1)["verdict_errors"] == 0  # no verdict found its packet gone


def test_a_clean_stop_under_load_loses_no_lookup(gw):
    net = gw
    f = start(net, "clean-stop")
    load = ask_in_background(net, "--seconds", "4", "--interval", "0.001", "--timeout", "1")
    time.sleep(1.5)
    rc = f.end(signal.SIGTERM)
    out, _ = load.communicate(timeout=60)
    got = json.loads(out)
    net.save("inpath/clean-stop.json", json.dumps(got))
    assert rc == 0
    assert got["lost"] == 0 and got["wrong"] == 0 and got["answered"] > 500, got
    assert inpath.QUEUE not in queues(net)
    assert elements(net, "inpath_live") == {}  # it took its port out before it let go
    assert "stopped after" in f.log_path.read_text(encoding="utf-8")


# ---- back to passive -----------------------------------------------------------------------------------


def test_passive_takes_the_in_path_rules_and_sets_away_and_leaves_the_gate(gw):
    """Last in the module: DNSGATE_FILL=passive after inpath. The gate's own table, set and rule stay,
    with the addresses the passive set held; nothing of the in-path block is left, and what is loaded
    is what a passive conf renders."""
    net = gw
    net.ns(net.gw, "nft", "add", "element", "inet", "tvgw_gate", "resolved4", "{ 203.0.113.90 timeout 1d }")
    apply(net, DIRECT.settings, "passive")
    table = net.ns(net.gw, "nft", "list", "table", "inet", "tvgw_gate").stdout
    assert (
        "inpath" not in table and "in-path" not in table and "queue" not in table and "answers" not in table
    )
    assert "set resolved4 {" in table and PASSIVE_RULE in table and "203.0.113.90" in table
    rendered = net.apply(net.gw, vnet.render_conf(DIRECT.settings), ("--check",))
    assert rendered.returncode == 0, rendered.stderr
    assert set(net.counters()) == vnet.counted_comments(rendered.stdout)
    assert lookup(net, "203.0.113.91") == "answer:203.0.113.91"
    apply(net, INPATH, "inpath-again")  # and on again, for whatever runs after in this module
    assert elements(net, "inpath_live") == {}


def test_the_shipped_unit_carries_the_watchdog_the_test_above_ran_with():
    assert (unit_value("Type"), unit_value("NotifyAccess")) == ("notify", "main")
    assert (unit_value("WatchdogSec"), unit_value("WatchdogSignal")) == ("2", "SIGKILL")
    assert Path(inpath.STATUS).parent.name == unit_value("RuntimeDirectory")
