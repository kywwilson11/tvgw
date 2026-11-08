"""`tvgw doctor`: what is wrong with the gateway, in plain words, and the fix for it.

It runs every `tvgw verify` check, prints the plain paragraph (verify.PLAIN) of each check that did not
pass, and offers that check's fix on a `[y/N]` question. `--fix` asks once for every fix, `--yes` asks
nothing; without a terminal and without `--yes` it only explains. It needs root, and it takes the install
lock (`/run/tvgw/install.lock`, the one install.sh and CI's deploy take) before any fix, so a fix never
runs while a deploy does; under the lock it checks again and does only what is still needed.

The fixes are the ones each unit tolerates (design 9, E-F29): the firewall is set again with tvgw-apply,
or tvgw.service is started when it is stopped, because a restart of an active tvgw.service runs its stop
and darkens the TV; the guard is reloaded, since it refuses a manual stop; AdGuard Home goes through
`tvgw adguard service`, which defers during an upstream outage instead of emptying the cache, then a
start, which does nothing to an AdGuard that runs; dnsmasq, nginx and the recording units are restarted
and their last journal lines shown. Before a lookup check is fixed, three probes say whether the internet
connection is down, AdGuard Home is not answering, or the blocklist service could not be reached; an
AdGuard that runs but answers no lookup while the internet works is restarted, since it holds no cache a
restart could lose. Some findings are explained only: another firewall, an uplink with no IPv4 address,
the TV's own settings. Each run's verdict replaces `/run/tvgw/status.txt`, as a `tvgw verify` run's does,
and every run ends with the one step that always gets the TV back online.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import re
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field

from tvgw import backup, config, dnsq, scrub, setup, verify
from tvgw.config import Settings
from tvgw.profile import Profile

TVGW_APPLY = "/usr/local/sbin/tvgw-apply"  # where install.sh puts it
DOH_UPDATE = "/usr/local/sbin/tvgw-doh-update"  # (listguard) likewise
# the last line of every run: the two-minute way back to a TV with internet, whatever the gateway does
BYPASS = (
    "If the TV still has no internet: move its cable from the gateway to your router; tvgw keeps its"
    " settings."
)
TRIM_KEEP = 2  # copies of the store a disk fix keeps
JOURNAL_LINES = "5"  # journal lines shown after a restart
OUTPUT_LINES = 20  # lines of a fix's own output shown
# the checks whose fix is to set the firewall and routing again (tvgw-apply, or starting tvgw.service)
APPLY_CHECKS = frozenset(
    {
        "ruleset",
        "ruleset_unchanged",
        "applied_current",
        "forwarding",
        "ipv6_off",
        "ipv6_guard",
        "tv_route",
        "gw_reply_route",
        "policy_rule",
        "vpn_dnat_idle",
        "dnsgate",
    }
)
RESTARTED = ("dnsmasq", "nginx", "tvgw-pcap", "tvgw-pcap-headers", "tvgw-flowlog", "tvgw-dnsgate")
RESOLVER_CHECKS = ("resolver_rewrite", "resolver_must_allow", "list_sentinels")
NEIGH_UP = frozenset({"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"})
# the probes' findings, in the words the design gives them
NET_DOWN = "Your internet connection is down"
AGH_DOWN = "AdGuard Home is not answering"
LISTS_DOWN = "The blocklist service could not be reached"
_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# a candidate IPv6 address (with a zone, such as fe80::1%eth0); ipaddress decides, so a time such as
# 20:18:01 stays as it is
_IPV6 = re.compile(
    r"(?<![0-9A-Za-z:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:%[0-9A-Za-z_.-]+)?(?![0-9A-Za-z:])"
)
_ENX = re.compile(r"\benx[0-9A-Fa-f]{12}\b")  # an interface name that embeds its MAC address


@dataclass(frozen=True)
class Step:
    """One command of a fix. Two names are the doctor's own: `apply` (tvgw-apply on an active
    tvgw.service, else starting it) and `trim-backups`; `tvgw ...` runs this tvgw with the same settings
    file. `show` marks a command whose output is the point (a journal), shown whatever its status.
    `always` marks a command that runs even after an earlier step of its fix failed, because it is
    harmless whatever that step left (starting a unit that may be stopped)."""

    argv: tuple[str, ...]
    show: bool = False
    always: bool = False


APPLY = Step(("apply",))
TRIM = Step(("trim-backups",))


@dataclass(frozen=True)
class Fix:
    """What the doctor offers for one finding: the plain sentence it asks with, and its steps."""

    what: str
    steps: tuple[Step, ...]


@dataclass
class Plan:
    """A check that did not pass, what the doctor can do about it, and what it says besides."""

    check: verify.Check
    fixes: list[Fix] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class Env:
    """Every way the doctor touches the machine (setup.Env's pattern): live_env() is the real system, and
    the tests pass a fake of each."""

    check: Callable[[], verify.Result]
    run: Callable[[list[str]], tuple[int, str]]  # (exit status, output); 127 when it cannot start
    read: Callable[[str], str]
    resolve: Callable[[str], list[str] | None]  # an A lookup at the gateway's own resolver
    say: Callable[[str], None]
    ask: Callable[[str], bool]  # a [y/N] question; False without an answer
    interactive: Callable[[], bool]
    is_root: Callable[[], bool]
    lock: Callable[[], contextlib.AbstractContextManager]
    trim_backups: Callable[[], list[str]]
    # each run's verdict, as `tvgw verify` leaves it in /run/tvgw/status.txt (verify.write_status)
    status: Callable[[verify.Result], None] = lambda r: None
    # this gateway's scrubber (scrub.scrub_for) for the lines a fix prints: the host, TV and Wi-Fi names
    # and the home's domain go before redact() takes the addresses, so the output can go into a public log
    scrub: Callable[[str], str] | None = None


def redact(text: str, tv_net: str, scrubber: Callable[[str], str] | None = None) -> str:
    """A journal line as the doctor prints it: first through this gateway's scrubber when one is given (the
    host, TV and Wi-Fi names, the home's domain, a UUID or serial: design decision 63), then MAC addresses,
    interface names that embed one, every IPv6 address and the IPv4 addresses outside the TV subnet
    replaced, so output pasted into an issue or a CI log carries no home identifier. The TV's own subnet
    is the gateway's, the same on every install, and stays readable."""
    if scrubber is not None:
        text = scrubber(text)
    try:
        net = ipaddress.ip_network(tv_net, strict=False)
    except ValueError:
        net = ipaddress.ip_network(config.Settings().tv_net)

    def address(m: re.Match) -> str:
        try:
            return m[0] if ipaddress.ip_address(m[0]) in net else "<address>"
        except ValueError:
            return m[0]

    def address6(m: re.Match) -> str:
        try:
            ipaddress.IPv6Address(m[0].split("%", 1)[0])
        except ValueError:
            return m[0]
        return "<address>"

    text = _ENX.sub("usb-ethernet", _MAC.sub("<mac>", text))
    return _IPV4.sub(address, _IPV6.sub(address6, text))


# ---- what to do about each finding -----------------------------------------------------------------------
APPLY_FIX = Fix("Set the gateway's firewall and routing again (tvgw-apply).", (APPLY,))
ADGUARD_JOURNAL = Step(("journalctl", "-u", "AdGuardHome", "-n", JOURNAL_LINES, "-o", "cat"), True)
# `tvgw adguard service` restarts AdGuard only when its service lacks --no-check-update, under the restart
# guard, and leaves a stopped AdGuard stopped; the start after it brings a stopped one up (no cache to
# lose) and does nothing to one that runs, so it follows even a deferred or failed first step
ADGUARD_FIX = Fix(
    "Start the filter, AdGuard Home, the safe way (tvgw adguard service, which waits while the internet"
    " is down, then systemctl start, which leaves a running filter alone).",
    (
        Step(("tvgw", "adguard", "service")),
        Step(("systemctl", "start", "AdGuardHome"), always=True),
        ADGUARD_JOURNAL,
    ),
)
# AdGuard runs but answers no lookup while the probes reach the router and the encrypted upstream: it holds
# no cache the TV is served from, which is the one thing the restart guard protects (it lets a restart
# through itself when AdGuard is silent, adguardcfg.upstream_state), and `tvgw adguard service` would
# not restart it
ADGUARD_RESTART_FIX = Fix(
    "Restart the filter, AdGuard Home: it answers no lookup, so a restart loses nothing it serves.",
    (Step(("systemctl", "restart", "AdGuardHome")), ADGUARD_JOURNAL),
)


def restart(unit: str) -> Fix:
    return Fix(
        f"Restart {unit}, then show its last log lines.",
        (
            Step(("systemctl", "restart", unit)),
            Step(("journalctl", "-u", unit, "-n", JOURNAL_LINES, "-o", "cat"), True),
        ),
    )


def down_units(c: verify.Check) -> list[str]:
    """The units a failed services check names (`down: a, b`)."""
    head, _, rest = c.detail.partition(":")
    return [u.strip() for u in rest.split(",") if u.strip()] if head == "down" else []


def unit_fixes(units: list[str]) -> tuple[list[Fix], list[str]]:
    fixes, notes = [], []
    for unit in units:
        if unit == "tvgw":
            # a stopped tvgw.service is started; an active one is never restarted (its stop darkens the TV)
            fixes.append(APPLY_FIX)
        elif unit == "AdGuardHome":
            fixes.append(ADGUARD_FIX)
        elif unit in RESTARTED:
            fixes.append(restart(unit))
        elif unit.endswith(".timer"):
            fixes.append(
                Fix(
                    f"Switch the scheduled job {unit} back on.",
                    (Step(("systemctl", "enable", "--now", unit)),),
                )
            )
        else:
            notes.append(
                f"The doctor has no fix of its own for {unit}:"
                f" see why it stopped with journalctl -u {unit} -n 20."
            )
    return fixes, notes


def ufw_lines(s: Settings, out_if: str) -> list[str]:
    """The commands setup's ufw step runs (design 4.14), for this gateway's TV port and the interface the
    TV's traffic leaves by."""
    return [
        f"sudo ufw allow in on {s.tv_if} proto udp to any port 67",
        f"sudo ufw allow in on {s.tv_if} to {s.gw_ip} port 53 proto udp",
        f"sudo ufw allow in on {s.tv_if} to {s.gw_ip} port 53 proto tcp",
        f"sudo ufw allow in on {s.tv_if} to {s.gw_ip} port 80,443 proto tcp",
        f"sudo ufw route allow in on {s.tv_if} out on {out_if}",
    ]


def firewall_notes(c: verify.Check, s: Settings, env: Env) -> list[str]:
    """forward_policy and input_policy are explained, never fixed: tvgw does not edit another firewall. The
    route command names the interface tvgw-apply sends the TV out by: WAN_IF, or the VPN's tunnel."""
    out_if = config.uplink_interface(
        s, lambda dev: env.read(f"/proc/sys/net/ipv4/conf/{dev}/forwarding") != ""
    )
    notes = ["The doctor does not change another firewall. To open the TV's port in it:"]
    notes.append("- If it is ufw, run these, which open the TV's port and nothing else:")
    notes += [f"  {line}" for line in ufw_lines(s, out_if)]
    if c.name == "forward_policy":
        notes.append(
            '- If it is Docker\'s, add "ip-forward-no-drop": true to /etc/docker/daemon.json and restart'
            " Docker; every container on this computer restarts with it."
        )
    notes.append("- If it is firewalld, tvgw does not support it yet: use a separate computer for tvgw.")
    return notes


def probe(s: Settings, profile: Profile, env: Env, lists: bool) -> tuple[str, str]:
    """(finding, why) for the lookup checks, or ('', '') when every probe passes: the uplink's link, the
    router on it (one ping to wake its neighbour entry, then `ip neigh`), the first encrypted upstream with
    curl, the gateway's own resolver, and with `lists` the first subscribed blocklist's address."""
    if env.read(f"/sys/class/net/{s.wan_if}/carrier").strip() != "1":
        return NET_DOWN, f"this computer's connection to your router ({s.wan_if}) has no link"
    routes = _json(env.run(["ip", "-j", "route", "show", "default", "dev", s.wan_if])[1])
    router = next((r.get("gateway") for r in routes if isinstance(r, dict) and r.get("gateway")), None)
    if router:
        env.run(["ping", "-c", "1", "-W", "2", "-I", s.wan_if, router])
        neigh = _json(env.run(["ip", "-j", "neigh", "show", "dev", s.wan_if, router])[1])
        states = set()
        for n in neigh:
            st = n.get("state") if isinstance(n, dict) else None
            states |= {st} if isinstance(st, str) else set(st) if isinstance(st, list) else set()
        if not states & NEIGH_UP:
            return NET_DOWN, "your router does not answer this computer"
    upstream = next((u.strip() for u in s.dns_upstreams.split(",") if u.strip().startswith("https://")), "")
    if upstream:
        rc, _ = env.run(["curl", "--max-time", "5", "-sS", "-o", "/dev/null", upstream])
        if rc not in (0, 127):  # 127: no curl here, so the doctor cannot tell
            return NET_DOWN, "this computer cannot reach the encrypted lookup service past your router"
    name = next(iter(profile.must_allow), "example.com")
    if env.resolve(name) is None:
        return AGH_DOWN, "the filter did not answer a lookup from this computer"
    if lists and profile.adguard_filters:
        rc, _ = env.run(
            ["curl", "--max-time", "5", "-sS", "-o", "/dev/null", "-I", profile.adguard_filters[0][1]]
        )
        if rc not in (0, 127):
            return LISTS_DOWN, "the filter keeps the lists it has and downloads them again on its own"
    return "", ""


def plan_for(
    c: verify.Check,
    s: Settings,
    profile: Profile,
    env: Env,
    probed: dict,
    down: frozenset[str] = frozenset(),
) -> Plan:
    """The doctor's plan for one check that did not pass. `down` is the units this run's services check
    found down, so a lookup check whose cause is a stopped AdGuard gets the same fix as the unit."""
    p = Plan(c)
    name = c.name
    if name == "dnsgate" and c.ok:
        # the warning that the list is more than half full: an apply would empty what the gate has seen
        p.notes.append("A warning alone needs no fix: it says the TV is doing something new.")
    elif name == "doh4_held":
        # (listguard) never an outage, and never accepted by the doctor: a list that shrank overnight may be a
        # broken source, which only a person can tell from an intended change (design decision 68)
        p.notes.append(
            "A warning alone needs no fix: the gateway keeps blocking what it blocked before, and blocks what"
            " the update adds. If the list's source meant the change, sudo tvgw-doh-update --accept takes it."
        )
    elif name == "dnsgate_inpath":
        # (inpath) never an outage: without the filler the TV's lookups are answered all the same
        # (design decision 64). Missing rules are tvgw-apply's to load; anything else is the filler's
        p.notes.append("The TV's lookups are answered whether this part works or not.")
        p.fixes.append(APPLY_FIX if "missing:" in c.detail else restart("tvgw-dnsgate-inpath"))
    elif name in APPLY_CHECKS:
        p.fixes.append(APPLY_FIX)
    elif name == "wan_gateway":
        if "has no default route" in c.detail:
            p.fixes.append(APPLY_FIX)
    elif name == "services":
        fixes, notes = unit_fixes(down_units(c))
        p.fixes += fixes
        p.notes += notes
    elif name == "guard_present":
        p.fixes.append(
            Fix(
                "Load the second firewall again (it refuses to be stopped, so it is reloaded).",
                (Step(("systemctl", "reload-or-restart", "tvgw-guard.service")),),
            )
        )
    elif name == "adguard_pinned":
        p.fixes.append(ADGUARD_FIX)
    elif name == "capture":
        p.fixes += [restart("tvgw-pcap"), APPLY_FIX]
    elif name == "flowlog_events":
        p.fixes += [APPLY_FIX, restart("tvgw-flowlog")]
    elif name == "doh4_fresh" and "held back" in c.detail:
        # (listguard) a week of held refreshes: the source has said the same all week, and a hold does not end
        # on its own once the source has drifted that far from the last refresh taken (design decision 68)
        p.fixes.append(
            Fix(
                "Take the update of the list of encrypted lookup services the gateway has held back for over"
                " a week, then show its last log lines.",
                (
                    Step((DOH_UPDATE, "--accept")),
                    Step(("journalctl", "-u", "tvgw-doh-update", "-n", JOURNAL_LINES, "-o", "cat"), True),
                ),
            )
        )
    elif name in ("doh4_loaded", "doh4_fresh"):
        p.fixes.append(
            Fix(
                "Download the list of encrypted lookup services again, then show its last log lines.",
                (
                    Step(("systemctl", "start", "tvgw-doh-update.service")),
                    Step(("journalctl", "-u", "tvgw-doh-update", "-n", JOURNAL_LINES, "-o", "cat"), True),
                ),
            )
        )
    elif name == "disk":
        if "read-only" in c.detail:
            p.notes.append("A disk that cannot be written to is not something the doctor can fix.")
        else:
            p.fixes.append(
                Fix(
                    "Delete recordings the record already holds,"
                    f" and keep only the newest {TRIM_KEEP} copies of the record.",
                    (Step(("tvgw", "prune-pcaps")), TRIM),
                )
            )
    elif name == "store_backup":
        p.fixes.append(
            Fix("Make a checked copy of the record now (tvgw backup).", (Step(("tvgw", "backup")),))
        )
    elif name == "ingest_fresh":
        p.fixes.append(
            Fix("Add the TV's latest traffic to the record now (tvgw ingest).", (Step(("tvgw", "ingest")),))
        )
    elif name == "tv_paths" and c.ok:
        # (W12) the warning that the TV refused the gateway's key: the way back is a pairing, which puts
        # a prompt on the TV, so the owner does it with the TV on, never the doctor
        p.notes.append(
            "The TV no longer accepts the gateway's key, so nothing has been read from it since the date"
            " shown. With the TV on, run: sudo tvgw tv pair, and accept the prompt on the TV."
        )
    elif name == "resolver_must_allow" and c.ok:
        # a transient: the name answered when asked again (verify.must_allow_check)
        p.notes.append(
            "It answered when asked again: a one-off. There is nothing to do unless it comes back."
        )
    elif name in RESOLVER_CHECKS:
        key = "lists" if name == "list_sentinels" else "dns"
        if key not in probed:
            probed[key] = probe(s, profile, env, lists=name == "list_sentinels")
        finding, why = probed[key]
        if finding:
            p.notes.append(f"{finding}: {why}.")
        if finding == AGH_DOWN:
            p.fixes.append(ADGUARD_FIX if "AdGuardHome" in down else ADGUARD_RESTART_FIX)
        elif not finding and name != "list_sentinels":
            p.fixes.append(
                Fix(
                    "Write the filter's settings again (tvgw adguard apply).",
                    (Step(("tvgw", "adguard", "apply")),),
                )
            )
    elif name in ("forward_policy", "input_policy"):
        if c.ok and c.detail != verify.NO_RULESET and not c.detail.endswith(verify.HELD):
            # the warning that another firewall drops by default and lets the TV's traffic through: the
            # commands that would open the TV's port in it are already in effect
            p.notes.append(
                "That firewall lets the TV's traffic through, so there is nothing to open:"
                " the warning only says it is there."
            )
        else:
            p.notes += firewall_notes(c, s, env)
    if not p.fixes and not p.notes:
        p.notes.append("The doctor cannot do this for you: the fix above says what to do.")
    return p


# ---- doing it -------------------------------------------------------------------------------------------
def _json(text: str) -> list:
    try:
        data = json.loads(text) if text.strip() else []
    except ValueError:
        return []
    return data if isinstance(data, list) else []


def execute(step: Step, s: Settings, env: Env) -> bool:
    """Run one step, print it and what it printed; True when it succeeded."""
    if step == TRIM:
        try:
            removed = env.trim_backups()
        except OSError as e:
            env.say(f"  the older copies could not be removed: {e.strerror or e}")
            return False
        env.say(f"  removed {len(removed)} older {'copy' if len(removed) == 1 else 'copies'} of the record")
        return True
    if step == APPLY:
        active = env.run(["systemctl", "is-active", "tvgw.service"])[1].strip() == "active"
        argv = [TVGW_APPLY] if active else ["systemctl", "start", "tvgw.service"]
    else:
        argv = list(step.argv)
    env.say(f"  $ {' '.join(argv)}")
    rc, out = env.run(argv)
    lines = [redact(line, s.tv_net, env.scrub) for line in out.splitlines() if line.strip()]
    for line in lines[-OUTPUT_LINES:]:
        env.say(f"    {line}")
    if rc != 0 and not step.show:
        env.say(f"  it failed (exit {rc})")
    return rc == 0 or step.show


def say_check(c: verify.Check, env: Env) -> None:
    env.say("")
    env.say(c.line())
    what, notice, fix = verify.PLAIN.get(c.name, ("", "", ""))
    for label, text in (("What it means", what), ("What you notice", notice), ("The fix", fix)):
        if text:
            env.say(f"  {label}: {text}")


def main(s: Settings, profile: Profile, env: Env, fix: bool = False, yes: bool = False) -> int:
    """0 when no check fails at the end (a WARN may remain), 1 when one does or the doctor was refused."""
    if not env.is_root():
        env.say("tvgw doctor: run it as root, with: sudo tvgw doctor")
        env.say(BYPASS)
        return 1
    r = env.check()
    env.status(r)
    found = [c for c in r.checks if not c.ok or c.warn]
    if not found:
        env.say(f"tvgw doctor: all {len(r.checks)} checks pass. The gateway holds.")
        env.say(BYPASS)
        return 0
    failed, look = sum(1 for c in found if not c.ok), sum(1 for c in found if c.ok)
    wants = f"want{'s' if look == 1 else ''} a look"
    if failed:
        env.say(
            f"tvgw doctor: {failed} of {len(r.checks)} checks failed"
            + (f"; {look} more {wants}." if look else ".")
        )
    else:
        env.say(f"tvgw doctor: no check failed; {look} of {len(r.checks)} {wants}.")
    probed: dict = {}
    down = frozenset(u for c in r.checks if c.name == "services" for u in down_units(c))
    plans = [plan_for(c, s, profile, env, probed, down) for c in found]
    asking = not yes and not fix and env.interactive()
    chosen: list[tuple[str, Fix]] = []
    for p in plans:
        say_check(p.check, env)
        for note in p.notes:
            env.say(f"  {note}")
        for f in p.fixes:
            env.say(f"  The doctor can: {f.what}")
            # --yes and --fix take every fix (--fix asks once below); otherwise each is asked on a terminal
            if yes or fix or (asking and env.ask("  Do it now?")):
                chosen.append((p.check.name, f))
    offered = [f for p in plans for f in p.fixes]
    env.say("")
    if (
        fix
        and not yes
        and chosen
        and (
            not env.interactive()
            or not env.ask(f"Do the {len(_unique([f for _, f in chosen]))} fixes above now?")
        )
    ):
        chosen = []
    if offered and not chosen:
        if not env.interactive() and not yes:
            env.say(
                "Nothing was changed. To let the doctor do the fixes above, run: sudo tvgw doctor --fix --yes"
            )
        else:
            env.say("Nothing was changed.")
    after = apply_fixes(chosen, s, env) if chosen else None
    still = [c.name for c in (after or r).checks if not c.ok]
    if after is not None:
        env.say("Now: no check fails." if not still else f"Still failing: {', '.join(still)}.")
        if any(n in verify.SETTLING for n in still):
            env.say(
                "Some of these can take a few minutes after a restart: check again with sudo tvgw verify."
            )
    env.say(BYPASS)
    return 0 if not still else 1


def _unique(fixes: list[Fix]) -> list[Fix]:
    out: list[Fix] = []
    for f in fixes:
        if f not in out:
            out.append(f)
    return out


def apply_fixes(chosen: list[tuple[str, Fix]], s: Settings, env: Env) -> verify.Result | None:
    """Under the install lock: check again, then do each chosen fix whose check still does not pass, once
    each, the firewall first so the restarts after it start under the rules in force. Returns the run after
    the fixes, or None when the lock was not had."""
    with contextlib.ExitStack() as held:
        try:
            held.enter_context(env.lock())
        except (setup.SetupError, OSError) as e:  # another install held it for 10 minutes, or no /run/tvgw
            env.say(f"tvgw doctor: {e}; nothing was changed. Try again when it has finished.")
            return None
        now = {c.name: c for c in env.check().checks}
        todo = _unique([f for name, f in chosen if name not in now or not now[name].ok or now[name].warn])
        todo.sort(key=lambda f: 0 if f == APPLY_FIX else 1)
        if not todo:
            env.say("Every chosen fix is already done: the checks pass now.")
        for f in todo:
            env.say(f"Doing: {f.what}")
            failed = False
            for step in f.steps:
                # after a step that failed, only what shows why (a journal) or cannot hurt still runs
                if not failed or step.show or step.always:
                    failed = not execute(step, s, env) or failed
        env.say("")
        after = env.check()
        env.status(after)
        return after


# ---- the real system -------------------------------------------------------------------------------------
def live_env(s: Settings, profile: Profile, conf: str) -> Env:
    def run(argv: list[str]) -> tuple[int, str]:
        if argv and argv[0] == "tvgw":  # this tvgw, with the same settings file
            argv = [sys.executable, "-m", "tvgw", "--conf", conf, *argv[1:]]
        try:
            p = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=600,
                stdin=subprocess.DEVNULL,
                check=False,
            )
        except FileNotFoundError:
            return 127, ""
        except (OSError, subprocess.TimeoutExpired) as e:
            return 1, str(e)
        return p.returncode, p.stdout + p.stderr

    def ask(question: str) -> bool:
        try:
            return input(f"{question} [y/N] ").strip().lower() in ("y", "yes")
        except EOFError:
            return False

    return Env(
        check=lambda: verify.check(s, profile),
        run=run,
        read=verify.read_file,
        resolve=lambda name: dnsq.a_records(name, s.gw_ip),
        say=print,
        ask=ask,
        interactive=lambda: sys.stdin.isatty(),
        is_root=lambda: os.geteuid() == 0,
        lock=lambda: setup.install_lock(say=print),
        trim_backups=lambda: backup.trim(backup.directory(s.state_dir), TRIM_KEEP),
        status=lambda r: verify.write_status(r, verify.STATUS),
        scrub=scrub.scrub_for(s),
    )
