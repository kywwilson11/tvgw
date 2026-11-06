"""The virtual gateway: three network namespaces, the stand-in services, and tvgw-apply run in a sandbox.

    tv                         gw                                  wan
    eth0 10.10.10.50/24  ----  eth0  10.10.10.1/24
         +10.99.0.5/32         wlan0 198.51.100.2/24  ----  up0  198.51.100.1/24
         (a foreign source)    tun0  192.0.2.2/24     ----  vpn0 192.0.2.1/24
                               main default via tun0        lo:  203.0.113.10 web, .20 DoH,
                                                                 .30 blocked, .53 resolver,
                                                                 10.20.30.40 a home-LAN host,
                                                                 156.147.69.32 LG's fallback

The gateway namespace's interfaces have the names of the default settings (`eth0` for the TV, `wlan0`
for the uplink, and `tun0` for the VPN, the first name `VPN_IF=auto` looks for), or, with
TVGW_VIRTUAL_IFNAMES=alt, names a gateway may have instead (`tvport0`, `uplink0` and a tunnel `wg0`),
which the settings then name, so the templating of design decision 24 is run end to end and not only
read by the literal-name lint. The drawing above shows the default names; a namespace has its own
interface names, so nothing is renamed on the host. Its main table's default route points at the
tunnel, as PIA's routes do on the Pi, so the policy route is what must send the TV out by the uplink in
direct mode. Both uplinks end in the same `wan` namespace, and the stand-in services there report the
source address they saw, which says which uplink a connection used.

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

# The gateway's three interfaces, by TVGW_VIRTUAL_IFNAMES: unset or `default`, the default settings'
# names, left unnamed in the conf so the script's own defaults are what runs (TV_IF eth0, VPN_IF auto
# finding tun0); `alt`, names that are none of those (the TV on tvport0, a name a .link file gives a USB
# adapter; the uplink on uplink0; a WireGuard tunnel wg0, which VPN_IF names). The matrix's verdicts
# `pass:wlan0` and `pass:tun0` mean the uplink and the tunnel whatever they are called.
IFNAMES = {
    "default": {"TV_IF": "eth0", "WAN_IF": "wlan0", "VPN_IF": "tun0"},
    "alt": {"TV_IF": "tvport0", "WAN_IF": "uplink0", "VPN_IF": "wg0"},
}


def ifnames(choice: str | None) -> dict[str, str]:
    """The interface names TVGW_VIRTUAL_IFNAMES chooses; a value that names no set is refused, so a
    misspelt one cannot quietly run the default names twice."""
    if (choice or "default") not in IFNAMES:
        raise ValueError(f"TVGW_VIRTUAL_IFNAMES={choice!r}: it is one of {', '.join(IFNAMES)}")
    return IFNAMES[choice or "default"]


IFNAMES_CHOICE = os.environ.get("TVGW_VIRTUAL_IFNAMES") or "default"
TV_IF, WAN_IF, VPN_IF = (ifnames(IFNAMES_CHOICE)[k] for k in ("TV_IF", "WAN_IF", "VPN_IF"))
# the TV's own end of its cable: the TV's name, not the gateway's, so the same whatever IFNAMES_CHOICE says
TV_END = "eth0"
TV_IP, TV_FOREIGN = "10.10.10.50", "10.99.0.5"
# (guard) a second address inside the TV subnet, as a rooted TV could add one: once the TV is pinned
# (TV_MAC known), only TV_IP may forward
TV_ALIAS = "10.10.10.200"
TV_MAC = "02:00:00:00:00:50"  # locally administered: a placeholder, not any device's address
# (probe) the probe's port (design decision 65): its own address in the TV subnet, the settings' default,
# and a second address on the same port, which nothing may take; the pair's names are tvgw-apply's and
# `tvgw probe`'s (probe.GW_IF, probe.NS_IF), the same whatever the gateway's own ports are called
PROBE_IP, PROBE_ALIAS = "10.10.10.30", "10.10.10.31"
PROBE_IF, PROBE_END = "tvgw-probe", "tvgw-probe0"
PROBE_MACS = ("02:74:76:67:77:01", "02:74:76:67:77:02")
# what `tvgw probe` asks for by name in this topology. The stand-in filter answers the must-allow name
# with PROBE_VENDOR, an address nothing here answers at (the probe looks the name up and must never
# connect to it); the neutral target's name with the TLS server's address; and the blocked name with
# 0.0.0.0. The public resolver answers all three with its one address
PROBE_ALLOW, PROBE_BLOCK = "allow.tvgw-probe.example", "blocked.tvgw-probe.example"
PROBE_TARGET, PROBE_VENDOR = "target.tvgw-probe.example", "203.0.113.77"
TLS_WEB = "203.0.113.44"  # a server that completes a TLS handshake (tlspeer.py), on the internet side
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
    "probe": PROBE_IP,  # (probe)
}
BLOCK4 = f"# the virtual gateway's manual block\n{BLOCKED}\n"
DOH4 = f"{DOH}\n# a comment, which ip_elements drops\n"
# the gateway's own services: AdGuard on the TV address, nginx on 80/443, and one other Pi service
GW_SERVE = ["--dns", GW_ANSWER, "--tcp", "80,443,8000", "--udp", "5000"]
GW_SERVE += ["--dns-name", f"{PROBE_ALLOW}={PROBE_VENDOR}", "--dns-name", f"{PROBE_BLOCK}=0.0.0.0"]  # (probe)
GW_SERVE += ["--dns-name", f"{PROBE_TARGET}={TLS_WEB}"]
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
# what tvgw-apply reads from the conf, and the topology's fixed half of it
CONF_SWITCHES = ("UPLINK", "BLOCK_QUIC", "STRICT_PORTS", "DNSGATE")
# the switches `tvgw-apply --check` is run over: the matrix's, plus CAPTURE_MODE (capture), whose
# headers table only counts and logs, so the probes need no scenario of their own for it
# (acr) the wall: probed at its default; (inpath) DNSGATE_FILL: its own module probes the in-path rules;
# (probe) TV_PROBE: the probe's rules are checked with every other switch, and probed in one scenario
CHECK_SWITCHES = (*CONF_SWITCHES, "CAPTURE_MODE", "ADTECH_PORT_WALL", "DNSGATE_FILL", "TV_PROBE")
CONF_FIXED = {
    "WAN_IF": WAN_IF,
    **({} if IFNAMES_CHOICE == "default" else {"TV_IF": TV_IF, "VPN_IF": VPN_IF}),
    "WAN_GW": WAN_GW,
    "TV_IP": TV_IP,
    "TV_MAC": TV_MAC,  # (guard) the pin
}
# what the input chain drops new connections from: both PIA names always, and VPN_IF when it names a third
VPN_DROP = 'iifname { "tun0", "wgpia0"' + ("" if VPN_IF in ("tun0", "wgpia0") else f', "{VPN_IF}"') + " }"
# comments appear bare in the heredoc and as \"...\" inside shell variables (as in test_fw_lines.py)
COUNTED = re.compile(r'counter\b[^\n]*?comment \\?"([^"\\]+)\\?"')


# --- the matrix file ---------------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Row:
    source: str  # tv, tv-foreign, tv-alias (guard), wan, or (probe) probe, probe-alias
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


# (profile) a scenario may also name the profile, which decides whether LG's port wall is built
SCENARIO_KEYS = (*CONF_SWITCHES, "PROFILE", "TV_PROBE")  # (probe) and whether the probe's port has rules


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
            unknown = set(settings) - set(SCENARIO_KEYS)
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


# The kernel's ICMP rate limits (Linux 6.0 on counts them in /proc/net/snmp): a reject's refusal of a UDP
# probe, and of a TCP one where the rule names no reset, is an ICMP error to the TV, and one the kernel
# held back reaches the probe as silence, a drop the firewall did not make
ICMP_HELD = ("OutRateLimitGlobal", "OutRateLimitHost")


def icmp_held(snmp: str) -> dict[str, int]:
    """The ICMP errors the kernel's rate limits held back so far, from /proc/net/snmp's two `Icmp:`
    lines (the names, then the values); empty on a kernel that does not count them."""
    rows = [line.split()[1:] for line in snmp.splitlines() if line.startswith("Icmp:")]
    if len(rows) < 2:
        return {}
    counts = dict(zip(rows[0], rows[1], strict=False))
    return {k: int(counts[k]) for k in ICMP_HELD if counts.get(k, "").isdigit()}


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
        self.prb = f"{tag}-prb"  # (probe) the matrix's client on the probe's port (probe_port)
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
        """Run one probe from `source` (tv, tv-foreign, tv-alias, wan, gw, probe, probe-alias) and return
        its verdict line."""
        if source.startswith("probe"):  # (probe) the probe's port is made when a row first needs it
            self.probe_port()
        name = {
            "tv": self.tv,
            "tv-foreign": self.tv,
            "tv-alias": self.tv,
            "wan": self.wan,
            "gw": self.gw,
            "probe": self.prb,
            "probe-alias": self.prb,
        }[source]
        args = ["probe", kind, target] + ([] if port is None else [str(port)])
        if source == "probe":  # its two addresses are equals on the link: name the one that is meant
            args += ["--src", PROBE_IP]
        if source == "probe-alias":
            args += ["--src", PROBE_ALIAS]
        if source == "tv-foreign":
            args += ["--src", TV_FOREIGN]
        if source == "tv-alias":  # (guard)
            args += ["--src", TV_ALIAS]
        for key, value in opts.items():
            args += [f"--{key}", value]
        return run(self.agent_argv(name, *args), timeout=30).stdout.strip()

    def probe_port(self) -> None:
        """(probe) A client on the probe's port, as `tvgw probe` makes one for each run (probe.Namespace:
        the same pair, addresses, routes and neighbours), kept for the matrix's rows: a namespace joined
        to the gateway by the pair tvgw-apply's probe rules name. It holds the probe's address and a
        second one, with a way back for both, so a refusal of the second is the firewall's and not a
        missing route. `tvgw probe` removes the pair when it runs; the next row makes it again."""
        gw, ns = self.gw, self.prb
        fresh = ns not in self.namespaces
        if fresh:
            run(["ip", "netns", "add", ns])
            self.namespaces.append(ns)
            run(["ip", "-n", ns, "link", "set", "lo", "up"])
        elif run(["ip", "-n", gw, "link", "show", PROBE_IF], check=False).returncode == 0:
            return
        gw_mac, ns_mac = PROBE_MACS
        run(["ip", "-n", gw, "link", "add", PROBE_IF, "address", gw_mac, "type", "veth",
             "peer", "name", PROBE_END, "address", ns_mac, "netns", ns])  # fmt: skip
        self.ns(gw, "sysctl", "-qw", f"net.ipv6.conf.{PROBE_IF}.disable_ipv6=1", check=False)
        self.ns(
            gw,
            "sysctl",
            "-qw",
            f"net.ipv4.conf.{PROBE_IF}.rp_filter=1",
            f"net.ipv4.conf.{PROBE_IF}.forwarding=1",
        )
        self.ns(ns, "sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1", check=False)
        run(["ip", "-n", gw, "link", "set", PROBE_IF, "up"])
        for address in (PROBE_IP, PROBE_ALIAS):
            run(["ip", "-n", gw, "route", "replace", f"{address}/32", "dev", PROBE_IF, "src", GW_TV])
            run(["ip", "-n", gw, "route", "replace", f"{address}/32", "dev", PROBE_IF, "src", GW_TV, "table", "100"],
                check=False)  # fmt: skip
            run(
                [
                    "ip",
                    "-n",
                    gw,
                    "neigh",
                    "replace",
                    address,
                    "lladdr",
                    ns_mac,
                    "dev",
                    PROBE_IF,
                    "nud",
                    "permanent",
                ]
            )
            run(["ip", "-n", ns, "addr", "add", f"{address}/32", "dev", PROBE_END])
        for argv in (
            ["link", "set", PROBE_END, "up"],
            ["route", "add", f"{GW_TV}/32", "dev", PROBE_END],
            ["route", "add", "default", "via", GW_TV, "dev", PROBE_END],
            ["neigh", "replace", GW_TV, "lladdr", gw_mac, "dev", PROBE_END, "nud", "permanent"],
        ):
            run(["ip", "-n", ns, *argv])
        if fresh:
            self.serve(ns, ["--tcp", "8000"])  # something that would answer the row from the internet

    def reply_dev(self, to: str = TV_IP) -> str | None:
        """The interface the gateway would send a packet from 10.10.10.1 to `to` (the TV) by."""
        out = self.ns(self.gw, "ip", "-j", "route", "get", to, "from", GW_TV, check=False).stdout
        route = json.loads(out) if out.strip() else []
        return route[0].get("dev") if route else None

    def counters(self) -> dict[str, tuple[int, str]]:
        return counters(self.ns(self.gw, "nft", "-j", "list", "ruleset").stdout)

    def icmp_held(self) -> dict[str, int]:
        """The gateway namespace's own count (each namespace keeps its own) of ICMP errors held back."""
        return icmp_held(self.ns(self.gw, "cat", "/proc/net/snmp", check=False).stdout)

    # building and tearing down

    def build(self) -> None:
        self.clean_stale()
        for name in (self.tv, self.gw, self.wan, self.chk):
            run(["ip", "netns", "add", name])
            self.namespaces.append(name)
            run(["ip", "-n", name, "link", "set", "lo", "up"])
        tv, gw, wan = self.tv, self.gw, self.wan
        # created from inside gw, so each name is looked up only in the two namespaces it lands in (the
        # host has an eth0 of its own). The TV's own end is eth0 whatever the gateway calls its port
        run(["ip", "-n", gw, "link", "add", TV_IF, "type", "veth", "peer", "name", TV_END, "netns", tv])
        run(["ip", "-n", gw, "link", "add", WAN_IF, "type", "veth", "peer", "name", "up0", "netns", wan])
        run(["ip", "-n", gw, "link", "add", VPN_IF, "type", "veth", "peer", "name", "vpn0", "netns", wan])
        # the TV: no duplicate address detection, so its IPv6 link-local address exists at once
        self.ns(tv, "sysctl", "-qw", "net.ipv6.conf.eth0.accept_dad=0")
        for argv in (
            ["addr", "add", f"{TV_IP}/24", "dev", TV_END],
            ["addr", "add", f"{TV_FOREIGN}/32", "dev", TV_END],
            ["addr", "add", f"{TV_ALIAS}/32", "dev", TV_END],  # (guard)
            ["link", "set", TV_END, "up"],
            ["route", "add", "default", "via", GW_TV],
        ):
            run(["ip", "-n", tv, *argv])
        # the gateway: reverse-path filtering loose, as systemd's 50-default.conf leaves it on the Pi, so a
        # foreign source reaches the firewall rule that must drop it rather than a kernel check the Pi
        # does not make. (guard) tvgw-apply sets the TV port's own value to 1, and the kernel uses the
        # larger of conf.all and the port's: all=2 keeps that at loose here, as there
        for key in ("all", "default"):
            self.ns(gw, "sysctl", "-qw", f"net.ipv4.conf.{key}.rp_filter=2")
        # the kernel's per-destination ICMP limit off (net.ipv4.icmp_ratelimit: 1000 ms with a burst of six
        # at its default, as on the gateway). A reject's refusal of a UDP probe, and of a TCP one where the
        # rule names no reset, is an ICMP error to the TV, so a refused probe within seconds of six others
        # would see silence, a drop the firewall did not make; each row is judged by its own probe alone
        self.ns(gw, "sysctl", "-qw", "net.ipv4.icmp_ratelimit=0")
        # forwarding off, as at boot: a new namespace can inherit the host's 1, and the apply is what must
        # switch it on (an interface created later inherits the global value)
        for name in (gw, self.chk):
            self.ns(name, "sysctl", "-qw", "net.ipv4.ip_forward=0")
        for argv in (
            ["addr", "add", f"{GW_TV}/24", "dev", TV_IF],
            ["addr", "add", f"{GW_WLAN}/24", "dev", WAN_IF],
            ["addr", "add", f"{GW_TUN}/24", "dev", VPN_IF],
            ["link", "set", TV_IF, "up"],
            ["link", "set", WAN_IF, "up"],
            ["link", "set", VPN_IF, "up"],
            ["route", "add", "default", "via", WAN_TUN, "dev", VPN_IF],
        ):
            run(["ip", "-n", gw, *argv])
        self.ns(gw, "sysctl", "-qw", f"net.ipv4.conf.{TV_IF}.rp_filter=0")
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
        for dev in (TV_IF, WAN_IF):
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
        self,
        name: str,
        conf: str,
        args: tuple[str, ...] = (),
        run_dir: Path | None = None,
        script: Path | None = None,
        state: Path | None = None,
        files: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess:
        """tvgw-apply in namespace `name`, reading `conf` as /etc/tvgw/tvgw.conf, with the suite's block4
        and DoH lists, writing /run/tvgw into `run_dir` (a fresh directory when none is given). (probe)
        `script` is a copy of the script to run in its place, `state` a directory to keep /var/lib/tvgw
        in (the change ledger's spool is read back from it), and `files` more files for /etc/tvgw."""
        etc = Path(tempfile.mkdtemp(dir=self.sandbox, prefix="etc-"))
        state = state or Path(tempfile.mkdtemp(dir=self.sandbox, prefix="state-"))
        for file_name, text in (files or {}).items():
            (etc / file_name).write_text(text, encoding="utf-8")
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
        argv += [str(etc), str(state), str(run_dir), "bash", str(script or APPLY), *args]
        return self.ns(name, *argv, check=False, timeout=300)

    def save(self, relative: str, text: str) -> Path:
        path = self.artifacts / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path


def iter_rows(scenarios: list[Scenario]) -> Iterator[tuple[Scenario, Row]]:
    for s in scenarios:
        for r in s.rows:
            yield s, r
