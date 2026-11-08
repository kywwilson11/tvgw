"""(drills) Fail-closed drills on a kernel (design decision 75): each tvgw part that runs beside the firewall
is killed in turn on the namespace gateway, and the TV must keep what the safe-state table says it keeps
(docs/how-it-works/architecture.md#when-a-part-fails).

The TV's internet is three probes from the namespace TV: a lookup answered by the gateway, a lookup aimed
at a public resolver, which the firewall redirects to the gateway and the gateway answers, and a
connection to a web server by its address, out by the uplink. Each drill takes them before the part
starts, while it runs and after it is killed with SIGKILL, which no part can catch or clean up after.

- the in-path filler (`tvgw.inpath`, with `DNSGATE_FILL=inpath`): every lookup still answers, since the
  kernel passes the answers itself when nobody holds the queue;
- the passive feeder (`tvgw.dnsgate`, where tcpdump is installed): nothing changes, since the gate counts;
- the live reading (`tvgw.tvlive`, `LIVE_READING=on`, a key file with no key): nothing changes, and the
  firewall's rules are what they were;
- the hourly job (a copy of `deploy/bin/tvgw-analyze` that calls this checkout's `tvgw`, with
  `tvgw ingest` reading a large flow log): killed while it runs, nothing changes, the firewall's rules
  are what they were, the store passes SQLite's integrity check, and the next run completes;
- the filter (the stand-in for AdGuard Home that answers the TV's lookups): the TV's lookups get no
  answer, from the gateway or from the resolver it aims at (no other resolver answers it, which is the
  fail-closed half), while its connection by address goes on; with the filter back, lookups answer again.

Every process runs inside the gateway namespace, and every file it writes is in the run's own temporary
directories, bind-mounted in a private mount namespace where a path is fixed (as `vnet.Net.apply` does):
the host's own files are never written. The module leaves the gateway as the `direct` scenario has it,
with the stand-in filter running."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest
import vnet

pytestmark = pytest.mark.virtual

DIRECT = next(s for s in vnet.parse_matrix(vnet.MATRIX.read_text(encoding="utf-8")) if s.name == "direct")
INPATH = {**DIRECT.settings, "DNSGATE_FILL": "inpath"}
REQUIRED = os.environ.get("TVGW_VIRTUAL_REQUIRED") == "1"
SRC = str(vnet.ROOT / "src")
ANALYZE = vnet.ROOT / "deploy" / "bin" / "tvgw-analyze"
# the TV's internet, as each probe prints it when the TV has it
LOOKUP = f"answer:{vnet.GW_ANSWER}"
WEB = f"pass:{vnet.GW_WLAN}"
KEPT = {"lookup": LOOKUP, "aimed_elsewhere": LOOKUP, "web": WEB}
UNFILTERED = f"answer:{vnet.WAN_ANSWER}"  # the public resolver's own answer: an unfiltered path
FLOW_LINES = 80_000  # conntrack lines for the hourly job: enough that ingest is still at work when killed
KILL_AFTER = 1.0  # seconds the hourly job runs before it is killed
INPATH_RUNNER = (  # the status file written every half second, as tests/virtual/test_virtual_inpath.py does
    "import sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from tvgw import config, inpath\n"
    "inpath.STATUS_EVERY = 0.5\n"
    "sys.exit(inpath.main(config.Settings(dnsgate_fill='inpath'), status_path=sys.argv[2]))\n"
)
FEEDER_RUNNER = (
    "import sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from tvgw import config, dnsgate\n"
    "sys.exit(dnsgate.main(config.Settings(tv_if=sys.argv[2], tv_ip=sys.argv[3])))\n"
)
TVLIVE_RUNNER = (
    "import sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from tvgw import config, tvlive\n"
    "d = sys.argv[2]\n"
    "s = config.Settings(live_reading='on', profile='lg-webos', state_dir=d, tv_ip=sys.argv[3],"
    " tv_if=sys.argv[4], tvcheck_history=d + '/tvcheck-history.log')\n"
    "sys.exit(tvlive.main(s, d + '/lgtv-keys.sqlite'))\n"
)


def unable(why: str) -> None:
    """A part that cannot run here: a failure where the suite is required (CI), a skip elsewhere."""
    if REQUIRED:
        pytest.fail(f"TVGW_VIRTUAL_REQUIRED=1 but {why}")
    pytest.skip(why)


def internet(net) -> dict[str, str]:
    """The TV's three probes, as each prints its verdict."""
    return {
        "lookup": net.probe("tv", "dns-udp", vnet.GW_TV, 53),
        "aimed_elsewhere": net.probe("tv", "dns-udp", vnet.RESOLVER, 53),
        "web": net.probe("tv", "tcp", vnet.WEB, 443),
    }


def ruleset(net) -> str:
    return net.ns(net.gw, "nft", "list", "ruleset").stdout


def apply(net, settings: dict[str, str], tag: str) -> subprocess.CompletedProcess:
    out = net.apply(net.gw, vnet.render_conf(settings))
    net.save(f"drills/apply-{tag}.log", out.stdout + out.stderr)
    assert out.returncode == 0, out.stderr
    return out


class Part:
    """One tvgw process in the gateway namespace, with its log in the artifacts."""

    def __init__(self, net, tag: str, argv: list[str], new_session: bool = False):
        self.net, self.tag, self.group = net, tag, new_session
        self.log_path = net.artifacts / "drills" / f"{tag}.log"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log = self.log_path.open("w", encoding="utf-8")
        # `ip netns exec` execs the command, so the pid is the part's own (or its session's leader)
        self.proc = subprocess.Popen(
            ["ip", "netns", "exec", net.gw, *argv],
            stdout=self.log,
            stderr=subprocess.STDOUT,
            start_new_session=new_session,
        )
        net.drill_parts.append(self)

    def wait_for(self, ready, what: str, wait: float = 20.0) -> None:
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            if ready():
                return
            if self.proc.poll() is not None:
                break
            time.sleep(0.05)
        self.log.flush()
        tail = self.log_path.read_text(encoding="utf-8", errors="replace")[-600:]
        unable(f"{self.tag} did not reach {what} in {wait:.0f} s (exit {self.proc.poll()}): {tail!r}")

    def running(self) -> bool:
        return self.proc.poll() is None

    def kill(self) -> None:
        """SIGKILL, to the whole session for a part started in one (a script and its children)."""
        with contextlib.suppress(ProcessLookupError):
            if self.group:
                os.killpg(self.proc.pid, signal.SIGKILL)
            else:
                self.proc.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            self.proc.wait(timeout=10)
        with contextlib.suppress(OSError):
            self.log.close()


@pytest.fixture(scope="module")
def gw(net):
    """The gateway with the `direct` scenario applied. Whatever a drill leaves running is killed, the
    stand-in filter is running again, and `direct` is applied once more when the module is done."""
    net.drill_parts = []
    apply(net, DIRECT.settings, "direct")
    try:
        yield net
    finally:
        for part in net.drill_parts:
            part.kill()
        if not any(p.poll() is None and net.gw in p.args for p, _log in net.services):
            net.serve(net.gw, vnet.GW_SERVE)
        apply(net, DIRECT.settings, "restore")
        net.save("drills/ruleset-after.nft", ruleset(net))


def scratch(net, prefix: str) -> Path:
    path = Path(tempfile.mkdtemp(dir=net.sandbox, prefix=prefix))
    path.chmod(0o755)
    return path


# ---- the drills --------------------------------------------------------------------------------------
def test_the_tv_has_its_internet_before_any_drill(gw):
    assert internet(gw) == KEPT


def test_a_killed_in_path_filler_leaves_every_lookup_answered(gw):
    net = gw
    out = apply(net, INPATH, "inpath")
    if "in-path gate rules not loaded" in out.stderr:
        unable(f"this kernel does not load the queue rules: {out.stderr.strip()[-300:]}")
    try:
        status = scratch(net, "inpath-") / "status.json"
        part = Part(net, "inpath", [sys.executable, "-I", "-c", INPATH_RUNNER, SRC, str(status)])
        part.wait_for(lambda: _status(status).get("live") is True, "its live state")
        assert internet(net) == KEPT
        part.kill()
        assert internet(net) == KEPT
    finally:
        apply(net, DIRECT.settings, "after-inpath")


def test_a_killed_passive_feeder_changes_nothing(gw):
    net = gw
    if shutil.which("tcpdump") is None:
        pytest.skip("tcpdump is not installed: the passive feeder cannot run")
    part = Part(net, "feeder", [sys.executable, "-I", "-c", FEEDER_RUNNER, SRC, vnet.TV_IF, vnet.TV_IP])
    time.sleep(2.0)
    if not part.running():
        unable(f"the passive feeder ended at once: {part.log_path.read_text(encoding='utf-8')[-400:]!r}")
    before = ruleset(net)
    assert internet(net) == KEPT
    part.kill()
    assert internet(net) == KEPT
    # the feeder only adds addresses to the gate's set; the rules themselves are untouched
    assert vnet.rules_only(ruleset(net)) == vnet.rules_only(before)


def test_a_killed_live_reading_changes_nothing_and_touches_no_rule(gw):
    net = gw
    state = scratch(net, "tvlive-")
    argv = [sys.executable, "-I", "-c", TVLIVE_RUNNER, SRC, str(state), vnet.TV_IP, vnet.TV_IF]
    before = ruleset(net)
    part = Part(net, "tvlive", argv)
    part.wait_for(lambda: (state / "tvlive-attempts").exists(), "its attempts file")
    time.sleep(1.0)
    assert part.running(), part.log_path.read_text(encoding="utf-8")[-400:]
    assert internet(net) == KEPT
    part.kill()
    assert internet(net) == KEPT
    assert vnet.rules_only(ruleset(net)) == vnet.rules_only(before)
    # with no key it asked the TV nothing: the attempts file holds no attempt
    assert (state / "tvlive-attempts").read_text(encoding="utf-8").strip() == ""


def test_a_killed_hourly_job_changes_nothing_and_its_store_survives(gw):
    net = gw
    if run_quiet(["getent", "group", "adm"]) != 0:
        unable("the system has no adm group, which tvgw-analyze gives its reports")
    etc, state, log = scratch(net, "etc-"), scratch(net, "state-"), scratch(net, "log-")
    (etc / "tvgw.conf").write_text(
        f"PROFILE=generic-tv\nTV_IP={vnet.TV_IP}\nTV_IF={vnet.TV_IF}\nWAN_IF={vnet.WAN_IF}\n",
        encoding="utf-8",
    )
    ended = time.time() - 29 * 3600  # 30 hours ago: the job's next 24-hour report has none of them to read
    (log / "flows.log").write_text(
        vnet.conntrack_lines(FLOW_LINES, vnet.TV_IP, vnet.GW_WLAN, ended), encoding="utf-8"
    )
    script = vnet.wrapped_script(ANALYZE, scratch(net, "bin-"), vnet.ROOT / "src", sys.executable)
    before = ruleset(net)
    part = Part(net, "analyze-killed", sandboxed(net, etc, state, log, script), new_session=True)
    time.sleep(KILL_AFTER)
    caught = part.running()
    assert internet(net) == KEPT
    part.kill()
    net.save("drills/analyze-killed-mid-run.txt", f"still running when killed: {caught}\n")
    assert internet(net) == KEPT
    assert vnet.rules_only(ruleset(net)) == vnet.rules_only(before)
    db = state / "tvgw.db"
    if db.exists():
        with contextlib.closing(sqlite3.connect(str(db))) as conn:  # a hot journal rolls back here
            assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    again = Part(net, "analyze-again", sandboxed(net, etc, state, log, script), new_session=True)
    try:
        rc = again.proc.wait(timeout=600)
    except subprocess.TimeoutExpired:
        again.kill()
        raise AssertionError("tvgw-analyze did not finish within 600 s after the drill") from None
    again.log.close()
    assert rc == 0, again.log_path.read_text(encoding="utf-8")[-800:]
    assert (state / "reports" / "latest.txt").exists()
    with contextlib.closing(sqlite3.connect(str(db))) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0] == FLOW_LINES
    assert internet(net) == KEPT and vnet.rules_only(ruleset(net)) == vnet.rules_only(before)


def test_a_killed_filter_leaves_no_unfiltered_resolver_and_keeps_connections_by_address(gw):
    net = gw
    filters = [(p, log) for p, log in net.services if p.poll() is None and net.gw in p.args]
    assert len(filters) == 1, "the stand-in filter of the gateway namespace is not running"
    proc, log = filters[0]
    try:
        proc.kill()
        proc.wait(timeout=10)
        got = internet(net)
        assert got["lookup"] in ("reject", "drop") and got["aimed_elsewhere"] in ("reject", "drop"), got
        assert UNFILTERED not in got.values()
        assert got["web"] == WEB
        assert net.probe("tv", "dns-tcp", vnet.RESOLVER, 53) in ("reject", "drop")
    finally:
        net.services.remove((proc, log))
        with contextlib.suppress(OSError):
            log.close()
        net.serve(net.gw, vnet.GW_SERVE)
    assert internet(net) == KEPT


# ---- helpers -----------------------------------------------------------------------------------------
def _status(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def run_quiet(argv: list[str]) -> int:
    return subprocess.run(argv, capture_output=True, check=False).returncode


def sandboxed(net, etc: Path, state: Path, log: Path, script: Path) -> list[str]:
    """`script` in a private mount namespace: the run's directories over /etc/tvgw, /var/lib/tvgw and
    /var/log/tvgw, and a tmpfs over /run/lock, as `vnet.Net.apply` runs tvgw-apply."""
    for path in ("/etc/tvgw", "/var/lib/tvgw", "/var/log/tvgw", "/run/lock"):
        net.mount_point(path)
    sandbox = (
        'set -e; mount --bind "$1" /etc/tvgw; mount --bind "$2" /var/lib/tvgw; mount --bind "$3" /var/log/tvgw;'
        ' mount -t tmpfs tmpfs /run/lock; shift 3; exec "$@"'
    )
    return ["unshare", "--mount", "--propagation", "private", "bash", "-c", sandbox, "_", str(etc), str(state),
            str(log), "bash", str(script)]  # fmt: skip
