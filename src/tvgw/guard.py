"""The guard's Python half (design decision 42): the co-tenant drop-ins, avahi's interface deny, and
the reads `tvgw verify` makes of the guard and of dnsmasq.

The firewall half is `deploy/nftables/guard.nft.template`, loaded by `tvgw-guard.service` and never
unloaded. It only holds while nftables does, so the Pi's other services get a second wall that does
not depend on it: systemd's `IPAddressDeny=`, a cgroup BPF filter on every socket of the unit, which
checks ingress by source and egress by destination. None of those services ever talks to the TV, so
denying the TV subnet costs them nothing. The functions here are pure where they can be (a plan of
which files to write, a conf text in and out); the CLI and install.sh do the writing and the
`systemctl daemon-reload`, and every system call is a parameter, so the logic is tested away from a Pi.
"""

from __future__ import annotations

import contextlib
import ipaddress
import os
import re
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

Runner = Callable[[list[str]], str]

UNIT_DIR = "/etc/systemd/system"
DROPIN = "10-tvgw-not-from-tv.conf"
# templates matched whenever they are installed, whatever CO_TENANT_UNITS says: qBittorrent's WebUI
# listens on every address by default, and its instances are named after the user who runs them
TEMPLATES = ("qbittorrent-nox@",)
AVAHI_CONF = "/etc/avahi/avahi-daemon.conf"
AVAHI_BACKUP_SUFFIX = ".tvgw-backup"
AVAHI_MARK = "# tvgw: avahi neither answers nor announces on the TV port (deploy/install.sh)"
# the comment of the guard's last input rule: it counts only what inet tvgw let through (guard_quiet)
FINAL_DROP = "guard: TV may not reach other Pi services"
# rules whose absence means the guard does not hold the line it exists for (guard_present)
KEY_RULES = (
    FINAL_DROP,
    "guard: spoofed source",
    "guard: the gateway address only (weak host)",
    "guard: TV never to the LAN",
    "guard: TV API from root only",
)
CHAINS = ("input", "forward", "output")
# Linux's capability numbers (include/uapi/linux/capability.h), for reading /proc/PID/status
CAP_NAMES = [
    "chown",
    "dac_override",
    "dac_read_search",
    "fowner",
    "fsetid",
    "kill",
    "setgid",
    "setuid",
    "setpcap",
    "linux_immutable",
    "net_bind_service",
    "net_broadcast",
    "net_admin",
    "net_raw",
    "ipc_lock",
    "ipc_owner",
    "sys_module",
    "sys_rawio",
    "sys_chroot",
    "sys_ptrace",
    "sys_pacct",
    "sys_admin",
    "sys_boot",
    "sys_nice",
    "sys_resource",
    "sys_time",
    "sys_tty_config",
    "mknod",
    "lease",
    "audit_write",
    "audit_control",
    "setfcap",
    "mac_override",
    "mac_admin",
    "syslog",
    "wake_alarm",
    "block_suspend",
    "audit_read",
    "perfmon",
    "bpf",
    "checkpoint_restore",
]


def run_cmd(cmd: list[str]) -> str:
    """stdout of a command, '' when it fails or is missing (as verify.run_cmd)."""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


# ---- the co-tenant drop-ins ---------------------------------------------------------------------


def dropin(tv_net: str, gw_ip: str, section: str = "Service") -> str:
    """The drop-in for one unit. GW_IP stays allowed: the kernel drops a packet arriving on the TV
    port with one of the Pi's own addresses as its source (a martian), so only the Pi itself can use
    that address, and a co-tenant that resolves through the resolver on GW_IP keeps working."""
    return (
        "# tvgw (design decision 42): this service never talks to the TV subnet, so it may neither be\n"
        "# reached from it nor send to it, whatever nftables holds. Written by deploy/install.sh from\n"
        "# CO_TENANT_UNITS in /etc/tvgw/tvgw.conf; edits here are replaced on the next install.\n"
        f"[{section}]\n"
        f"IPAddressDeny={tv_net}\n"
        f"IPAddressAllow={gw_ip}/32\n"
    )


def wanted_units(units: Iterable[str]) -> tuple[str, ...]:
    """CO_TENANT_UNITS plus the templates always matched, in order and once each."""
    return tuple(dict.fromkeys((*units, *TEMPLATES)))


def parse_unit_files(listing: str) -> set[str]:
    """`systemctl list-unit-files --no-legend --plain NAMES...` -> the unit files that exist and are
    not masked (a masked unit cannot run, so it needs no filter)."""
    found = set()
    for line in listing.splitlines():
        parts = line.split()
        if parts and not (len(parts) > 1 and parts[1].startswith("masked")):
            found.add(parts[0])
    return found


def parse_active_units(listing: str) -> set[str]:
    """`systemctl list-units --no-legend --plain --state=active ...` -> the unit names."""
    return {line.split()[0] for line in listing.splitlines() if line.split()}


@dataclass
class Plan:
    """What `tvgw guard cotenants` would change: the drop-ins to write (path -> text) and the ones to
    remove (a unit taken out of CO_TENANT_UNITS, or no longer installed)."""

    writes: dict[str, str] = field(default_factory=dict)
    removes: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.writes or self.removes)

    def lines(self, dry_run: bool = False) -> list[str]:
        wrote, removed = ("would write", "would remove") if dry_run else ("wrote", "removed")
        return [f"{wrote} {p}" for p in sorted(self.writes)] + [f"{removed} {p}" for p in self.removes]


def plan(
    units: Iterable[str],
    unit_files: set[str],
    active_sockets: set[str],
    present: dict[str, str],
    tv_net: str,
    gw_ip: str,
    unit_dir: str = UNIT_DIR,
) -> Plan:
    """The drop-ins the settings ask for against the ones on disk. A unit that is not installed is
    skipped without a word (the default list names software a given Pi may not run). A listed unit
    whose socket unit is active gets the [Socket] variant too: a socket unit's filter does not cover
    the sockets its service opens, and the service's does not cover the socket systemd listens on."""
    want: dict[str, str] = {}
    for name in wanted_units(units):
        if f"{name}.service" in unit_files:
            want[os.path.join(unit_dir, f"{name}.service.d", DROPIN)] = dropin(tv_net, gw_ip)
        if not name.endswith("@") and f"{name}.socket" in active_sockets:
            want[os.path.join(unit_dir, f"{name}.socket.d", DROPIN)] = dropin(tv_net, gw_ip, "Socket")
    return Plan(
        writes={p: text for p, text in want.items() if present.get(p) != text},
        removes=sorted(p for p in present if p not in want),
    )


def present_dropins(unit_dir: str = UNIT_DIR) -> dict[str, str]:
    """Every drop-in of ours on disk, by path."""
    out = {}
    try:
        entries = sorted(os.listdir(unit_dir))
    except OSError:
        return out
    for entry in entries:
        path = os.path.join(unit_dir, entry, DROPIN)
        if entry.endswith((".service.d", ".socket.d")) and os.path.isfile(path):
            with open(path, encoding="utf-8", errors="replace") as fh:
                out[path] = fh.read()
    return out


def gather(units: Iterable[str], run: Runner | None = None) -> tuple[set[str], set[str]]:
    """(unit files installed, socket units active) for the units the settings name."""
    run = run or run_cmd  # looked up now, so tests can patch the module's run_cmd
    names = wanted_units(units)
    if not names:
        return set(), set()
    files = parse_unit_files(
        run(
            [
                "systemctl",
                "list-unit-files",
                "--no-legend",
                "--plain",
                "--full",
                *(f"{n}.service" for n in names),
            ]
        )
    )
    # with no name at all, list-units would list every active unit on the box
    patterns = [f"{n}.socket" for n in names if not n.endswith("@")]
    cmd = ["systemctl", "list-units", "--no-legend", "--plain", "--full", "--state=active", *patterns]
    sockets = parse_active_units(run(cmd)) if patterns else set()
    return files, sockets


def write_atomic(path: str, text: str, mode: int = 0o644) -> None:
    """A new file beside the old one, fsynced and renamed over it, so a power cut leaves either."""
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o755, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tvgw-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def apply(p: Plan) -> None:
    for path, text in p.writes.items():
        write_atomic(path, text)
    for path in p.removes:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)
        with contextlib.suppress(OSError):  # the directory goes only when nothing else is in it
            os.rmdir(os.path.dirname(path))


# ---- avahi ----------------------------------------------------------------------------------------


def _owned(lines: list[str]) -> int | None:
    """The index of the deny-interfaces line tvgw wrote itself (the one right under AVAHI_MARK)."""
    for i in range(len(lines) - 1):
        if lines[i].rstrip("\r\n") == AVAHI_MARK and re.match(r"^\s*deny-interfaces\s*=", lines[i + 1]):
            return i + 1
    return None


def avahi_deny(text: str, tv_if: str | None) -> str | None:
    """avahi-daemon.conf with TV_IF in [server]'s deny-interfaces, or None when it is there already.
    deny-interfaces "takes precedence over allow-interfaces" (avahi-daemon.conf(5)), so avahi neither
    answers on the TV port nor announces the Pi's name and services there. An existing list keeps its
    entries; a commented-out example line is left alone. The line tvgw added itself (under
    AVAHI_MARK) is tvgw's: it names exactly TV_IF, so a TV_IF change replaces the old port, and
    tv_if None (avahi-daemon no longer in CO_TENANT_UNITS) takes it and its mark out again. A name
    tvgw appended to the owner's own list stays there; the .tvgw-backup is the file before tvgw."""
    lines = text.splitlines(keepends=True)
    own = _owned(lines)
    if tv_if is None:
        if own is None:
            return None
        del lines[own - 1 : own + 1]
        return "".join(lines)
    if own is not None:
        newline = lines[own][len(lines[own].rstrip("\r\n")) :] or "\n"
        want = f"deny-interfaces={tv_if}{newline}"
        if lines[own] == want:
            return None
        lines[own] = want
        return "".join(lines)
    server = next((i for i, ln in enumerate(lines) if ln.strip().lower() == "[server]"), None)
    if server is None:
        tail = "" if not text or text.endswith("\n") else "\n"
        return f"{text}{tail}\n[server]\n{AVAHI_MARK}\ndeny-interfaces={tv_if}\n"
    end = next((i for i in range(server + 1, len(lines)) if lines[i].lstrip().startswith("[")), len(lines))
    for i in range(server + 1, end):
        m = re.match(r"^(\s*deny-interfaces\s*=\s*)(.*?)(\s*)$", lines[i].rstrip("\r\n"))
        if m:
            items = [x.strip() for x in m.group(2).split(",") if x.strip()]
            if tv_if in items:
                return None
            newline = lines[i][len(lines[i].rstrip("\r\n")) :] or "\n"
            lines[i] = m.group(1) + ", ".join([*items, tv_if]) + newline
            return "".join(lines)
    lines.insert(server + 1, f"{AVAHI_MARK}\ndeny-interfaces={tv_if}\n")
    return "".join(lines)


def edit_avahi(path: str, tv_if: str | None) -> bool:
    """Apply avahi_deny to the file at `path`, keeping its mode and owner, with a one-time backup of
    the file as it was before tvgw first touched it. False when there is no file or nothing to do."""
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        st = os.stat(path)
    except FileNotFoundError:
        return False
    new = avahi_deny(text, tv_if)
    if new is None:
        return False
    backup = path + AVAHI_BACKUP_SUFFIX
    if not os.path.exists(backup):
        shutil.copy2(path, backup)
    write_atomic(path, new, stat.S_IMODE(st.st_mode))
    with contextlib.suppress(PermissionError):
        os.chown(path, st.st_uid, st.st_gid)
    return True


# ---- what verify reads ----------------------------------------------------------------------------


def chains_hooked(listing: str) -> list[str]:
    """The guard's base chains in `nft -s list table inet tvgw_guard`, each at filter + 10 on its own
    hook (nft prints the priority by name: `priority filter + 10`)."""
    return [
        chain
        for chain in CHAINS
        if re.search(rf"chain {chain} \{{\s*type filter hook {chain} priority filter \+ 10;", listing, re.S)
    ]


def show_blocks(text: str) -> list[dict[str, str]]:
    """`systemctl show -p A -p B UNIT...`: one {property: value} per unit, blocks split by blank lines."""
    blocks, cur = [], {}
    for line in [*text.splitlines(), ""]:
        if not line.strip():
            if cur:
                blocks.append(cur)
            cur = {}
            continue
        key, _, value = line.partition("=")
        cur[key] = value
    return blocks


def denies(value: str, tv_net: str) -> bool:
    """Does an IPAddressDeny value (space-separated prefixes, or `any`) cover the whole TV subnet?"""
    net = ipaddress.ip_network(tv_net)
    for word in value.split():
        if word == "any":
            return True
        with contextlib.suppress(ValueError):
            got = ipaddress.ip_network(word, strict=False)
            if got.version == net.version and net.subnet_of(got):  # type: ignore[arg-type]
                return True
    return False


def cap_mask(status: str, field: str) -> int | None:
    """A capability mask (CapEff, CapBnd, ...) from /proc/PID/status, or None when there is none."""
    m = re.search(rf"^{field}:\s*([0-9a-fA-F]+)\s*$", status, re.M)
    return int(m.group(1), 16) if m else None


def cap_eff(status: str) -> int | None:
    """The effective capability mask from /proc/PID/status, or None when there is none."""
    return cap_mask(status, "CapEff")


def cap_names(mask: int) -> list[str]:
    """The capabilities in a mask, by their capsh names without the cap_ prefix."""
    return [CAP_NAMES[i] if i < len(CAP_NAMES) else f"cap{i}" for i in range(64) if mask >> i & 1]
