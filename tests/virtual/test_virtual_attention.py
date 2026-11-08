"""(attention) The attention count on a kernel (design decision 69): tvgw-apply's table `inet tvgw_attn`, the
real holder (`tvgw.attention.main`) in the gateway namespace, a word written as the live reading writes it,
and a namespace TV that connects.

What only a kernel can say, and this module asks it:

- the dead-man entry: with the holder killed (SIGKILL, no goodbye), the TV's address leaves the state's
  set within HOLD seconds by the kernel's own clock, and the counting rule then matches nothing; with the
  live reading silent, the holder empties the set within FRESH seconds;
- a change of state reaches the kernel by event, within a second, in one transaction: the TV is never in
  two states' sets;
- in the screen-saver state a new connection to an address outside the essentials is counted once and
  sampled; one to an essential, to the clock's port, or in no state, is not;
- the shipped script refuses ATTENTION_WALL=refuse and counts; a copy with the line set to yes refuses in
  the screen-saver and input states alone, lets the essentials and the clock through, refuses a
  connection tried again from the same port, never refuses in live TV, and refuses nothing once the
  holder is gone: the gateway can fail to protect, never fail closed.

The module leaves the gateway as the `direct` scenario of matrix.txt has it."""

from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
import sys
import threading
import time

import pytest
import vnet

from tvgw import attention

pytestmark = pytest.mark.virtual

DIRECT = next(s for s in vnet.parse_matrix(vnet.MATRIX.read_text(encoding="utf-8")) if s.name == "direct")
LIVE = {**DIRECT.settings, "LIVE_READING": "on"}
REQUIRED = os.environ.get("TVGW_VIRTUAL_REQUIRED") == "1"
SCRIPT = vnet.APPLY.read_text(encoding="utf-8")
SUPPORTED = SCRIPT.replace("\nATTENTION_REFUSE_SUPPORTED=no\n", "\nATTENTION_REFUSE_SUPPORTED=yes\n", 1)
WEB = vnet.WEB  # outside the essentials until a test puts it in
RUNNER = (
    "import sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from tvgw import attention, config\n"
    "s = config.Settings(live_reading='on', tv_ip=sys.argv[4])\n"
    "sys.exit(attention.main(s, status_path=sys.argv[2], state_path=sys.argv[3]))\n"
)


def unable(why: str) -> None:
    if REQUIRED:
        pytest.fail(f"TVGW_VIRTUAL_REQUIRED=1 but {why}")
    pytest.skip(why)


def held(net) -> list[str]:
    """The states whose set holds the TV's address now, by the kernel's listing."""
    out = []
    for state, name in attention.STATE_SETS.items():
        text = net.ns(net.gw, "nft", "-j", "list", "set", "inet", attention.TABLE, name, check=False).stdout
        for obj in (json.loads(text) if text.strip() else {}).get("nftables", []):
            for e in (obj.get("set") or {}).get("elem") or []:
                val = e.get("elem", {}).get("val") if isinstance(e, dict) else e
                if val == vnet.TV_IP:
                    out.append(state)
    return out


def counted(net, state: str = attention.IDLE) -> int:
    return net.counters().get(attention.RULES[state], (0, ""))[0]


def samples(net) -> list[attention.Sample]:
    text = net.ns(net.gw, "nft", "-j", "list", "table", "inet", attention.TABLE, check=False).stdout
    return attention.samples_from_listing(text, time.time())


def tcp(net, target: str = WEB, port: int = 443) -> str:
    return net.probe("tv", "tcp", target, port)


def wait_for(what, want, wait: float) -> float:
    """Seconds until `what()` == want, failing after `wait`."""
    t0 = time.monotonic()
    while time.monotonic() - t0 < wait:
        if what() == want:
            return time.monotonic() - t0
        time.sleep(0.05)
    raise AssertionError(
        f"{what.__name__ if hasattr(what, '__name__') else what} did not become {want!r} within {wait} s"
    )


class Reading:
    """The live reading's side: the word, rewritten every half second while `speaking`."""

    def __init__(self, path):
        self.path, self.state, self.speaking = path, None, True
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def say(self, state):
        self.state = state
        attention.write_word(str(self.path), state, time.monotonic())

    def _run(self):
        while not self._stop.wait(0.5):
            if self.speaking:
                attention.write_word(str(self.path), self.state, time.monotonic())

    def stop(self):
        self._stop.set()
        self._t.join(2)


class Holder:
    def __init__(self, net, tag: str, word):
        self.net, self.status = net, net.sandbox / f"attention-{tag}.json"
        log = net.artifacts / "attention" / f"{tag}.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        self.log = log.open("w", encoding="utf-8")
        argv = [
            sys.executable,
            "-I",
            "-c",
            RUNNER,
            str(vnet.ROOT / "src"),
            str(self.status),
            str(word),
            vnet.TV_IP,
        ]
        self.proc = subprocess.Popen(
            ["ip", "netns", "exec", net.gw, *argv], stdout=self.log, stderr=subprocess.STDOUT
        )
        deadline = time.monotonic() + 15
        while not self.status.exists() and time.monotonic() < deadline:
            if self.proc.poll() is not None:
                break
            time.sleep(0.05)
        if not self.status.exists():
            self.end(signal.SIGKILL)
            unable(f"the holder did not come up: {log.read_text(encoding='utf-8')[-400:]!r}")

    def end(self, sig: int = signal.SIGTERM) -> None:
        if self.proc.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                self.proc.send_signal(sig)
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        with contextlib.suppress(OSError):
            self.log.close()


def apply(net, settings: dict[str, str], tag: str, script: str | None = None) -> subprocess.CompletedProcess:
    path = None
    if script is not None:
        path = net.sandbox / f"tvgw-apply-{tag}"
        path.write_text(script, encoding="utf-8")
    out = net.apply(net.gw, vnet.render_conf(settings), script=path)
    net.save(f"attention/apply-{tag}.log", out.stdout + out.stderr)
    assert out.returncode == 0, out.stderr
    return out


@pytest.fixture(scope="module")
def gw(net):
    out = apply(net, LIVE, "count")
    if "attention count table not loaded" in out.stderr:
        unable(f"this kernel does not load the attention table: {out.stderr.strip()[-300:]}")
    try:
        yield net
    finally:
        apply(net, DIRECT.settings, "restore")
        assert net.ns(net.gw, "nft", "list", "table", "inet", attention.TABLE, check=False).returncode != 0
        net.save("attention/ruleset-after.nft", net.ns(net.gw, "nft", "list", "ruleset").stdout)


@pytest.fixture
def live(gw, request):
    """A live reading and a holder for one test; the essentials emptied before it."""
    gw.ns(gw.gw, "nft", "flush", "set", "inet", attention.TABLE, attention.PLATFORM_SET)
    tag = request.node.name[:50].replace("[", "-").replace("]", "")
    word = gw.sandbox / f"word-{tag}"
    reading = Reading(word)
    holder = Holder(gw, tag, word)
    try:
        yield gw, reading, holder
    finally:
        reading.stop()
        holder.end(signal.SIGKILL)
        for name in attention.STATE_SETS.values():
            gw.ns(gw.gw, "nft", "flush", "set", "inet", attention.TABLE, name, check=False)


# ---- the table ----------------------------------------------------------------------------------------
def test_the_table_loads_where_the_live_reading_runs_with_nothing_in_any_state(gw):
    table = gw.ns(gw.gw, "nft", "list", "table", "inet", attention.TABLE).stdout
    gw.save("attention/table.nft", table)
    for name in [attention.PLATFORM_SET, *attention.STATE_SETS.values(), *attention.SAMPLE_SETS.values()]:
        assert f"set {name} " in table, name
    for state in attention.COUNTED:
        assert attention.RULES[state] in table
    assert "reject" not in table and held(gw) == []
    # nobody holds a state: a connection is counted nowhere
    before = counted(gw)
    assert tcp(gw) == "pass:wlan0" and counted(gw) == before


def test_a_reapply_keeps_the_essentials_and_the_samples(gw):
    gw.ns(
        gw.gw,
        "nft",
        "add",
        "element",
        "inet",
        attention.TABLE,
        attention.PLATFORM_SET,
        "{ 198.51.100.200 timeout 1d }",
    )
    apply(gw, LIVE, "again")
    listing = gw.ns(gw.gw, "nft", "list", "set", "inet", attention.TABLE, attention.PLATFORM_SET).stdout
    assert "198.51.100.200" in listing


# ---- the dead-man entries -----------------------------------------------------------------------------
def test_the_screen_saver_counts_a_connection_outside_the_essentials_once_and_samples_it(live):
    net, reading, _ = live
    reading.say(attention.IDLE)
    wait_for(lambda: held(net), [attention.IDLE], 2)
    before = counted(net)
    assert tcp(net) == "pass:wlan0"  # counted, never refused
    assert counted(net) == before + 1
    assert any(s.dst == WEB and s.dport == 443 and s.state == attention.IDLE for s in samples(net))
    # an essential, the clock's port, and the input state's own rule untouched
    net.ns(
        net.gw,
        "nft",
        "add",
        "element",
        "inet",
        attention.TABLE,
        attention.PLATFORM_SET,
        f"{{ {WEB} timeout 1h }}",
    )
    assert tcp(net) == "pass:wlan0" and net.probe("tv", "udp", "203.0.113.53", 123).startswith("pass")
    assert counted(net) == before + 1 and counted(net, attention.INPUT) == 0


def test_a_change_of_state_reaches_the_kernel_within_a_second_and_never_holds_two(live):
    net, reading, _ = live
    reading.say(attention.INPUT)
    wait_for(lambda: held(net), [attention.INPUT], 2)
    reading.say(attention.APP)
    took = wait_for(lambda: held(net), [attention.APP], 2)
    assert took < 1.0
    before = counted(net, attention.INPUT)
    assert tcp(net) == "pass:wlan0" and counted(net, attention.INPUT) == before  # an app: nothing counted


def test_a_holder_killed_outright_lets_the_entry_expire_by_the_kernels_clock(live):
    net, reading, holder = live
    reading.say(attention.IDLE)
    wait_for(lambda: held(net), [attention.IDLE], 2)
    holder.end(signal.SIGKILL)  # no goodbye: nobody empties the set
    assert held(net) == [attention.IDLE]
    took = wait_for(lambda: held(net), [], attention.HOLD + 2)
    assert took <= attention.HOLD + 1
    before = counted(net)
    assert tcp(net) == "pass:wlan0" and counted(net) == before  # the rule matches nothing now


def test_a_silent_live_reading_leaves_the_tv_in_no_state(live):
    net, reading, _ = live
    reading.say(attention.IDLE)
    wait_for(lambda: held(net), [attention.IDLE], 2)
    reading.speaking = False  # the live reading died or lost the TV
    took = wait_for(lambda: held(net), [], attention.FRESH + 2)
    assert took <= attention.FRESH + 1


def test_a_clean_stop_empties_every_set(live):
    net, reading, holder = live
    reading.say(attention.LIVETV)
    wait_for(lambda: held(net), [attention.LIVETV], 2)
    holder.end(signal.SIGTERM)
    assert held(net) == []


# ---- refuse --------------------------------------------------------------------------------------------
def test_the_shipped_script_refuses_refuse_and_counts(gw):
    out = apply(gw, {**LIVE, "ATTENTION_WALL": "refuse"}, "refuse-shipped")
    assert "ATTENTION_WALL=refuse is not supported on a live gateway yet" in out.stderr
    assert "reject" not in gw.ns(gw.gw, "nft", "list", "table", "inet", attention.TABLE).stdout
    apply(gw, LIVE, "count-again")


@pytest.fixture
def walled(gw, request):
    apply(gw, {**LIVE, "ATTENTION_WALL": "refuse"}, "refuse-supported", script=SUPPORTED)
    try:
        yield
    finally:
        apply(gw, LIVE, "count-after")


def again_from_one_port(net, port: int = 41234) -> list[str]:
    """Two connections from one source port, the second as a retransmission is: the same tuple."""
    code = (
        "import socket, sys\n"
        "out = []\n"
        "for _ in range(2):\n"
        "    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.settimeout(3)\n"
        f"    s.bind(('{vnet.TV_IP}', {port}))\n"
        "    try:\n"
        f"        s.connect(('{WEB}', 443)); out.append('pass')\n"
        "    except OSError as e:\n"
        "        out.append('drop' if isinstance(e, TimeoutError) else 'refused')\n"
        "    finally:\n"
        "        s.close()\n"
        "print(' '.join(out))\n"
    )
    return net.ns(net.tv, sys.executable, "-I", "-c", code).stdout.split()


def test_the_wall_refuses_in_the_screen_saver_lets_the_essentials_through_and_opens_when_the_holder_dies(
    walled, live
):
    net, reading, holder = live
    reading.say(attention.IDLE)
    wait_for(lambda: held(net), [attention.IDLE], 2)
    before = counted(net)
    assert tcp(net) == "reject"
    assert again_from_one_port(net) == ["refused", "refused"]  # a retransmission is refused again
    assert counted(net) >= before + 2
    assert net.probe("tv", "udp", "203.0.113.53", 123).startswith("pass")  # the clock
    net.ns(
        net.gw,
        "nft",
        "add",
        "element",
        "inet",
        attention.TABLE,
        attention.PLATFORM_SET,
        f"{{ {WEB} timeout 1h }}",
    )
    assert tcp(net) == "pass:wlan0"  # an essential
    net.ns(net.gw, "nft", "flush", "set", "inet", attention.TABLE, attention.PLATFORM_SET)
    reading.say(attention.LIVETV)
    wait_for(lambda: held(net), [attention.LIVETV], 2)
    assert tcp(net) == "pass:wlan0"  # live TV is counted, never refused
    reading.say(attention.INPUT)
    wait_for(lambda: held(net), [attention.INPUT], 2)
    assert tcp(net) == "reject"
    holder.end(signal.SIGKILL)
    wait_for(lambda: held(net), [], attention.HOLD + 2)
    assert tcp(net) == "pass:wlan0"  # fail open: nobody renews the entry, and nothing is refused
