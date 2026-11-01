"""The virtual gateway: three network namespaces, the stand-in services, and tvgw-apply run in a sandbox.

    tv                         gw                                  wan
    eth0 10.10.10.50/24  ----  eth0  10.10.10.1/24
         +10.99.0.5/32         wlan0 198.51.100.2/24  ----  up0  198.51.100.1/24
         (a foreign source)    tun0  192.0.2.2/24     ----  vpn0 192.0.2.1/24
                               main default via tun0        lo:  203.0.113.10 web, .20 DoH,
                                                                 .30 blocked, .53 resolver,
                                                                 10.20.30.40 a home-LAN host,
                                                                 156.147.69.32 LG's fallback

The gateway namespace uses the names tvgw-apply hardcodes (`eth0` for the TV, `wlan0` for the uplink,
`tun0` for the VPN); a namespace has its own interface names, so nothing is renamed on the host. Its
main table's default route points at tun0, as PIA's routes do on the Pi, so the policy route is what
must send the TV out by wlan0 in direct mode. Both uplinks end in the same `wan` namespace, and the
stand-in services there report the source address they saw, which says which uplink a connection used.

tvgw-apply sources /etc/tvgw/tvgw.conf and writes /run/tvgw, and it has no override for either, so it
runs in a private mount namespace inside the gateway namespace with a temporary directory bind-mounted
over each of /etc/tvgw, /var/lib/tvgw and /run/tvgw, and a tmpfs over /run/lock (design decision
27): the host's own files are never written, so the suite cannot clobber a real gateway's settings or
the baseline `tvgw verify` compares against, even when it is run on one by mistake.

The pure helpers here (the matrix file, the conf, the variants, the counted comments) are unit-tested
in tests/unit/test_virtual_harness.py; everything that needs root runs only in tests/virtual."""

from __future__ import annotations

import atexit
import contextlib
import dataclasses
import itertools
import json
import os
import re
import select
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
APPLY = ROOT / "deploy" / "nftables" / "tvgw-apply"
AGENT = HERE / "agent.py"
MATRIX = HERE / "matrix.txt"
PREFIX = "tvgwv-"  # every namespace this suite creates; a crashed run's are recognised by it

TV_IP, TV_FOREIGN = "10.10.10.50", "10.99.0.5"
# (guard) a second address inside the TV subnet, as a rooted TV could add one: once the TV is pinned
# (TV_MAC known), only TV_IP may forward
TV_ALIAS = "10.10.10.200"
TV_MAC = "02:00:00:00:00:50"  # locally administered: a placeholder, not any device's address
GW_TV, GW_WLAN, GW_TUN = "10.10.10.1", "198.51.100.2", "192.0.2.2"
WAN_GW, WAN_TUN = "198.51.100.1", "192.0.2.1"
WEB, DOH, BLOCKED, RESOLVER = "203.0.113.10", "203.0.113.20", "203.0.113.30", "203.0.113.53"
LAN_HOST, LG_FALLBACK = "10.20.30.40", "156.147.69.32"
GW_ANSWER, WAN_ANSWER = "198.51.100.153", "203.0.113.153"  # what each resolver answers to everything
# the symbolic verdicts of matrix.txt, as the probes print them
NAMES = {
    "tv": TV_IP,
    "tv-alias": TV_ALIAS,  # (guard)
    "wlan0": GW_WLAN,
    "tun0": GW_TUN,
    "gw": GW_TV,
    "gateway": GW_ANSWER,
    "wan": WAN_ANSWER,
}
BLOCK4 = f"# the virtual gateway's manual block\n{BLOCKED}\n"
DOH4 = f"{DOH}\n# a comment, which ip_elements drops\n"
# the gateway's own services: AdGuard on the TV address, nginx on 80/443, and one other Pi service
GW_SERVE = ["--dns", GW_ANSWER, "--tcp", "80,443,8000", "--udp", "5000"]
# every address of the internet side gets sockets of its own (agent.serve says why); the first six
# live on its loopback, the last two are its ends of the two uplinks
WAN_ADDRS = (WEB, DOH, BLOCKED, RESOLVER, LAN_HOST, LG_FALLBACK, WAN_GW, WAN_TUN)
WAN_SERVE = [
    "--bind",
    ",".join(WAN_ADDRS),
    "--dns",
    WAN_ANSWER,
    "--tcp",
    "80,443,853,4431,8000,8080",  # (acr) 4431: the adtech port wall's row
    "--udp",
    "123,443,784,853,5000,8853",
    "--gre",
]
TV_SERVE = ["--tcp", "8000"]
# counters that tick on their own (IPv6 neighbour discovery and MLD on the TV link) and so cannot be
# required to stay still while another row is probed
NOISY = {"no IPv6 from the TV"}
# The TV subnet in table 100. Rule 60 (`from 10.10.10.0/24 lookup 100`) also matches what the gateway
# itself sends to the TV from 10.10.10.1 (a DNS answer, nginx, a TCP handshake, the ICMP of a reject),
# and table 100 holds only the default route, so on a kernel with nothing else those leave by wlan0
# and the TV never gets them. tvgw-apply does not add this route; the Pi answers the TV regardless, by
# a route or rule from outside tvgw (the VPN client's, probably) that this suite cannot see. The
# scenario fixture adds it only when the apply left the gap, and the strict xfail
# test_the_gateway_reaches_the_tv_by_the_apply_alone turns red once tvgw-apply closes it itself.
HELPER_ROUTE = ["route", "replace", "10.10.10.0/24", "dev", "eth0", "table", "100"]
# what tvgw-apply reads from the conf, and the topology's fixed half of it
CONF_SWITCHES = ("UPLINK", "BLOCK_QUIC", "STRICT_PORTS", "DNSGATE")
# the switches `tvgw-apply --check` is run over: the matrix's, plus CAPTURE_MODE (capture), whose
# headers table only counts and logs, so the probes need no scenario of their own for it
CHECK_SWITCHES = (*CONF_SWITCHES, "CAPTURE_MODE", "ADTECH_PORT_WALL")  # (acr) the wall: probed at its default
CONF_FIXED = {"WAN_IF": "wlan0", "WAN_GW": WAN_GW, "TV_IP": TV_IP, "TV_MAC": TV_MAC}  # (guard) the pin
# comments appear bare in the heredoc and as \"...\" inside shell variables (as in test_fw_lines.py)
COUNTED = re.compile(r'counter\b[^\n]*?comment \\?"([^"\\]+)\\?"')


# --- the matrix file ---------------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Row:
    source: str  # tv, tv-foreign, tv-alias (guard) or wan
    kind: str  # an agent.py probe
    target: str
    port: int | None
    verdict: str  # symbolic, as written: pass:wlan0, answer:gateway, reject, drop, sent
    counter: str | None  # the comment of the rule that must tick, or None

    @property
    def id(self) -> str:
        return f"{self.source}-{self.kind}-{self.target}" + (f"-{self.port}" if self.port is not None else "")

    def expected(self) -> str:
        """The verdict as the probe prints it: symbolic names become addresses."""
        head, _, name = self.verdict.partition(":")
        return f"{head}:{NAMES.get(name, name)}" if name else head

    def line(self, verdict: str | None = None) -> str:
        """The row in the file's own layout, with an observed verdict in place of the expected one."""
        port = "-" if self.port is None else str(self.port)
        return (
            f"{self.source:<11} {self.kind:<8} {self.target:<14} {port:<5} "
            f"{verdict or self.verdict:<16} {self.counter or '-'}"
        )


@dataclasses.dataclass(frozen=True)
class Scenario:
    name: str
    settings: dict[str, str]
    rows: tuple[Row, ...]


def parse_matrix(text: str) -> list[Scenario]:
    """`[name] KEY=value ...` opens a scenario; each row after it is `source probe target port verdict
    counter`, the counter being the rest of the line (a rule comment has spaces) or `-`."""
    scenarios: list[Scenario] = []
    name, settings, rows = None, {}, []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #", 1)[0].strip() if not raw.lstrip().startswith("#") else ""
        if not line:
            continue
        if line.startswith("["):
            if name is not None:
                scenarios.append(Scenario(name, settings, tuple(rows)))
            head, _, rest = line.partition("]")
            name, rows = head[1:].strip(), []
            settings = dict(kv.split("=", 1) for kv in rest.split())
            unknown = set(settings) - set(CONF_SWITCHES)
            if unknown or not name:
                raise ValueError(f"matrix line {n}: bad scenario header {raw!r}")
            continue
        parts = line.split(None, 5)
        if name is None or len(parts) != 6:
            raise ValueError(f"matrix line {n}: expected six fields under a scenario: {raw!r}")
        source, kind, target, port, verdict, counter = parts
        rows.append(
            Row(
                source,
                kind,
                target,
                None if port == "-" else int(port),
                verdict,
                None if counter == "-" else counter,
            )
        )
    if name is not None:
        scenarios.append(Scenario(name, settings, tuple(rows)))
    names = [s.name for s in scenarios]
    if len(set(names)) != len(names):
        raise ValueError(f"matrix: a scenario name is used twice: {names}")
    return scenarios


def render_conf(settings: dict[str, str]) -> str:
    """The tvgw.conf of the virtual topology: its uplink, plus the scenario's switches."""
    return "".join(f"{k}={v}\n" for k, v in {**CONF_FIXED, **settings}.items())


# --- what the script itself says ---------------------------------------------------------------------


def script_choices(text: str) -> dict[str, list[str]]:
    """Every value each switch may take, read from tvgw-apply's own `case` arms, so a value added there
    (a DNSGATE=enforce, say) is checked here without anyone remembering to list it."""
    choices: dict[str, list[str]] = {}
    arm = re.compile(r"^\s*([a-z]+(?: \| [a-z]+)*)\)", re.M)
    for key, body in re.findall(r'case "?\$\{?([A-Z_]+)\}?"? in\n(.*?)\n\s*esac', text, re.S):
        choices[key] = [v for a in arm.findall(body) for v in a.split(" | ")]
    for keys, body in re.findall(r"for k in ([A-Z_ ]+); do\s*case \$\{!k\} in\n(.*?)\n\s*esac", text, re.S):
        for key in keys.split():
            choices[key] = [v for a in arm.findall(body) for v in a.split(" | ")]
    return {k: v for k, v in choices.items() if k in CHECK_SWITCHES}


def variants(choices: dict[str, list[str]]) -> list[dict[str, str]]:
    """Every combination of the switches: what `tvgw-apply --check` must accept."""
    keys = [k for k in CHECK_SWITCHES if k in choices]
    return [dict(zip(keys, combo, strict=True)) for combo in itertools.product(*(choices[k] for k in keys))]


def variant_name(settings: dict[str, str]) -> str:
    return "-".join(f"{k.lower()}={v}" for k, v in settings.items())


def counted_comments(text: str) -> set[str]:
    """The comment of every rule with a counter, in the script or in a rendered ruleset."""
    return {m.group(1) for line in text.splitlines() if "counter" in line for m in COUNTED.finditer(line)}


def counters(listing: str) -> dict[str, tuple[int, str]]:
    """comment -> (packets, verdict) from `nft -j list ruleset`; rules sharing a comment are summed. The
    verdict is drop, reject or other, so a probe's row can say which drops must stay still."""
    out: dict[str, tuple[int, str]] = {}
    for obj in (json.loads(listing) if listing.strip() else {}).get("nftables", []):
        rule = obj.get("rule") if isinstance(obj, dict) else None
        if not rule or not rule.get("comment"):
            continue
        exprs = [e for e in rule.get("expr", []) if isinstance(e, dict)]
        packets = [e["counter"].get("packets", 0) for e in exprs if isinstance(e.get("counter"), dict)]
        if not packets:
            continue
        verdict = (
            "drop"
            if any("drop" in e for e in exprs)
            else "reject"
            if any("reject" in e for e in exprs)
            else "other"
        )
        before = out.get(rule["comment"], (0, verdict))
        out[rule["comment"]] = (before[0] + int(packets[0]), verdict)
    return out


def ticked(before: dict[str, tuple[int, str]], after: dict[str, tuple[int, str]]) -> dict[str, int]:
    """comment -> packets gained between two counter snapshots."""
    return {c: n - before.get(c, (0, ""))[0] for c, (n, _) in after.items() if n > before.get(c, (0, ""))[0]}


# --- root: namespaces, services, the sandboxed apply ---------------------------------------------------


def prerequisites() -> list[str]:
    """What is missing for the root half of the suite; empty when it can run."""
    missing = [] if sys.platform.startswith("linux") else ["Linux"]
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        missing.append("root")
    missing += [tool for tool in ("nft", "ip", "unshare", "mount", "bash") if shutil.which(tool) is None]
    return missing


def run(argv: list[str], check: bool = True, timeout: float = 60, **kw) -> subprocess.CompletedProcess:
    out = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", timeout=timeout, **kw)
    if check and out.returncode != 0:
        raise RuntimeError(f"{' '.join(argv)} exited {out.returncode}: {out.stderr.strip()}")
    return out


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def stale_namespaces(listing: str, alive=_pid_alive) -> list[str]:
    """Namespaces a crashed run of this suite left, from `ip netns list`: ours, and their run gone."""
    stale = []
    for line in listing.splitlines():
        name = line.split()[0] if line.split() else ""
        m = re.fullmatch(re.escape(PREFIX) + r"(\d+)-[a-z]+", name)
        if m and not alive(int(m.group(1))):
            stale.append(name)
    return stale


class Net:
    """The three namespaces and their services. destroy() is safe to call at any point, and twice."""

    def __init__(self, artifacts: Path):
        tag = f"{PREFIX}{os.getpid()}"
        self.tv, self.gw, self.wan, self.chk = (f"{tag}-{n}" for n in ("tv", "gw", "wan", "chk"))
        self.artifacts = artifacts
        self.sandbox = Path(tempfile.mkdtemp(prefix="tvgw-virtual-"))
        self.services: list[tuple[subprocess.Popen, object]] = []
        self.made_dirs: list[Path] = []
        self.namespaces: list[str] = []
        atexit.register(self.destroy)

    # plumbing

    def ns(
        self, name: str, *argv: str, check: bool = True, timeout: float = 60, **kw
    ) -> subprocess.CompletedProcess:
        return run(["ip", "netns", "exec", name, *argv], check=check, timeout=timeout, **kw)

    def agent_argv(self, name: str, *args: str) -> list[str]:
        return ["ip", "netns", "exec", name, sys.executable, "-I", str(AGENT), *args]

    def probe(self, source: str, kind: str, target: str, port: int | None, **opts: str) -> str:
        """Run one probe from `source` (tv, tv-foreign, tv-alias, wan, gw) and return its verdict line."""
        name = {"tv": self.tv, "tv-foreign": self.tv, "tv-alias": self.tv, "wan": self.wan, "gw": self.gw}[
            source
        ]
        args = ["probe", kind, target] + ([] if port is None else [str(port)])
        if source == "tv-foreign":
            args += ["--src", TV_FOREIGN]
        if source == "tv-alias":  # (guard)
            args += ["--src", TV_ALIAS]
        for key, value in opts.items():
            args += [f"--{key}", value]
        return run(self.agent_argv(name, *args), timeout=30).stdout.strip()

    def reply_dev(self) -> str | None:
        """The interface the gateway would send a packet from 10.10.10.1 to the TV by."""
        out = self.ns(self.gw, "ip", "-j", "route", "get", TV_IP, "from", GW_TV, check=False).stdout
        route = json.loads(out) if out.strip() else []
        return route[0].get("dev") if route else None

    def counters(self) -> dict[str, tuple[int, str]]:
        return counters(self.ns(self.gw, "nft", "-j", "list", "ruleset").stdout)

    # building and tearing down

    def build(self) -> None:
        self.clean_stale()
        for name in (self.tv, self.gw, self.wan, self.chk):
            run(["ip", "netns", "add", name])
            self.namespaces.append(name)
            run(["ip", "-n", name, "link", "set", "lo", "up"])
        tv, gw, wan = self.tv, self.gw, self.wan
        # created from inside gw, so each name is looked up only in the two namespaces it lands in (the
        # host has an eth0 of its own)
        run(["ip", "-n", gw, "link", "add", "eth0", "type", "veth", "peer", "name", "eth0", "netns", tv])
        run(["ip", "-n", gw, "link", "add", "wlan0", "type", "veth", "peer", "name", "up0", "netns", wan])
        run(["ip", "-n", gw, "link", "add", "tun0", "type", "veth", "peer", "name", "vpn0", "netns", wan])
        # the TV: no duplicate address detection, so its IPv6 link-local address exists at once
        self.ns(tv, "sysctl", "-qw", "net.ipv6.conf.eth0.accept_dad=0")
        for argv in (
            ["addr", "add", f"{TV_IP}/24", "dev", "eth0"],
            ["addr", "add", f"{TV_FOREIGN}/32", "dev", "eth0"],
            ["addr", "add", f"{TV_ALIAS}/32", "dev", "eth0"],  # (guard)
            ["link", "set", "eth0", "up"],
            ["route", "add", "default", "via", GW_TV],
        ):
            run(["ip", "-n", tv, *argv])
        # the gateway: reverse-path filtering loose, as systemd's 50-default.conf leaves it on the Pi, so a
        # foreign source reaches the firewall rule that must drop it rather than a kernel check the Pi
        # does not make. (guard) tvgw-apply sets the TV port's own value to 1, and the kernel uses the
        # larger of conf.all and the port's: all=2 keeps that at loose here, as there
        for key in ("all", "default"):
            self.ns(gw, "sysctl", "-qw", f"net.ipv4.conf.{key}.rp_filter=2")
        # forwarding off, as at boot: a new namespace can inherit the host's 1, and the apply is what must
        # switch it on (an interface created later inherits the global value)
        for name in (gw, self.chk):
            self.ns(name, "sysctl", "-qw", "net.ipv4.ip_forward=0")
        for argv in (
            ["addr", "add", f"{GW_TV}/24", "dev", "eth0"],
            ["addr", "add", f"{GW_WLAN}/24", "dev", "wlan0"],
            ["addr", "add", f"{GW_TUN}/24", "dev", "tun0"],
            ["link", "set", "eth0", "up"],
            ["link", "set", "wlan0", "up"],
            ["link", "set", "tun0", "up"],
            ["route", "add", "default", "via", WAN_TUN, "dev", "tun0"],
        ):
            run(["ip", "-n", gw, *argv])
        self.ns(gw, "sysctl", "-qw", "net.ipv4.conf.eth0.rp_filter=0")
        # the internet, and the home LAN host the TV must never reach
        for argv in (
            ["addr", "add", f"{WAN_GW}/24", "dev", "up0"],
            ["addr", "add", f"{WAN_TUN}/24", "dev", "vpn0"],
            *(["addr", "add", f"{a}/32", "dev", "lo"] for a in WAN_ADDRS[:6]),
            ["link", "set", "up0", "up"],
            ["link", "set", "vpn0", "up"],
            ["route", "add", "10.10.10.0/24", "via", GW_WLAN],
        ):
            run(["ip", "-n", wan, *argv])
        # the scratch namespace for `--check`: the interfaces the netdev table names, nothing else
        for dev in ("eth0", "wlan0"):
            run(["ip", "-n", self.chk, "link", "add", dev, "type", "dummy"])
            run(["ip", "-n", self.chk, "link", "set", dev, "up"])
        self.serve(gw, GW_SERVE)
        self.serve(wan, WAN_SERVE)
        self.serve(tv, TV_SERVE)

    def serve(self, name: str, args: list[str]) -> None:
        """Start a stand-in service and wait for its `ready`; its stderr goes to services/<ns>.log."""
        log_path = self.artifacts / "services" / f"{name}.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log = log_path.open("w", encoding="utf-8")
        p = subprocess.Popen(
            self.agent_argv(name, "serve", *args),
            stdout=subprocess.PIPE,
            stderr=log,
            text=True,
            encoding="utf-8",
        )
        self.services.append((p, log))
        ready, _, _ = select.select([p.stdout], [], [], 15)
        line = p.stdout.readline().strip() if ready else ""
        if line != "ready":
            p.kill()
            log.flush()
            tail = log_path.read_text(encoding="utf-8")[-500:]
            raise RuntimeError(f"agent serve in {name} did not start: {line!r} {tail!r}")

    def clean_stale(self) -> None:
        for name in stale_namespaces(run(["ip", "netns", "list"], check=False).stdout):
            self._delete_namespace(name)

    def _delete_namespace(self, name: str) -> None:
        pids = run(["ip", "netns", "pids", name], check=False).stdout.split()
        for pid in pids:
            with contextlib.suppress(ProcessLookupError, ValueError):
                os.kill(int(pid), 9)
        run(["ip", "netns", "del", name], check=False)

    def destroy(self) -> None:
        for p, log in self.services:
            with contextlib.suppress(OSError):
                p.kill()
            with contextlib.suppress(OSError, subprocess.TimeoutExpired):
                p.wait(timeout=5)
            for f in (p.stdout, log):
                with contextlib.suppress(OSError):
                    f.close()
        self.services = []
        for name in reversed(self.namespaces):
            self._delete_namespace(name)
        self.namespaces = []
        for d in reversed(self.made_dirs):  # mount points this run created, and only if still empty
            with contextlib.suppress(OSError):
                d.rmdir()
        self.made_dirs = []
        shutil.rmtree(self.sandbox, ignore_errors=True)

    # tvgw-apply

    def mount_point(self, path: str) -> None:
        p = Path(path)
        missing = [q for q in (p, *p.parents) if not q.exists()]
        for q in reversed(missing):
            q.mkdir(mode=0o755)
            self.made_dirs.append(q)

    def apply(
        self, name: str, conf: str, args: tuple[str, ...] = (), run_dir: Path | None = None
    ) -> subprocess.CompletedProcess:
        """tvgw-apply in namespace `name`, reading `conf` as /etc/tvgw/tvgw.conf, with the suite's block4
        and DoH lists, writing /run/tvgw into `run_dir` (a fresh directory when none is given)."""
        etc = Path(tempfile.mkdtemp(dir=self.sandbox, prefix="etc-"))
        state = Path(tempfile.mkdtemp(dir=self.sandbox, prefix="state-"))
        run_dir = run_dir or Path(tempfile.mkdtemp(dir=self.sandbox, prefix="run-"))
        (etc / "tvgw.conf").write_text(conf, encoding="utf-8")
        (etc / "block4.txt").write_text(BLOCK4, encoding="utf-8")
        (state / "doh4.txt").write_text(DOH4, encoding="utf-8")
        for path in ("/etc/tvgw", "/var/lib/tvgw", "/run/tvgw", "/run/lock"):
            self.mount_point(path)
        sandbox = (
            'set -e; mount --bind "$1" /etc/tvgw; mount --bind "$2" /var/lib/tvgw; '
            'mount --bind "$3" /run/tvgw; mount -t tmpfs tmpfs /run/lock; shift 3; exec "$@"'
        )
        argv = ["unshare", "--mount", "--propagation", "private", "bash", "-c", sandbox, "_"]
        argv += [str(etc), str(state), str(run_dir), "bash", str(APPLY), *args]
        return self.ns(name, *argv, check=False, timeout=120)

    def save(self, relative: str, text: str) -> Path:
        path = self.artifacts / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path


def iter_rows(scenarios: list[Scenario]) -> Iterator[tuple[Scenario, Row]]:
    for s in scenarios:
        for r in s.rows:
            yield s, r
