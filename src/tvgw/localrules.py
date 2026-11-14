"""Site rules (design decision 59): the owner's own allow and block rules for AdGuard Home.

A gateway installed from the package has no checkout to edit, so when an app stops working the owner
needs a supported way to let one name through, and a way to block one the lists miss. That is
`LOCAL_RULES` (default `/etc/tvgw/local.rules`), a file only `tvgw allow`, `tvgw block`, `tvgw unallow`
and `tvgw unblock` write. Absent, it changes nothing: `tvgw adguard apply` plans exactly what it planned
before the file existed.

The file holds two forms only, each under a dated comment line the command writes:

- `@@||<host>^$important`, an allow: it outranks every list's block, `$important` ones included, and
  the machine's (AdGuard's precedence, not the order of the lines), and (listguard) the profile's own red-line
  blocks, which carry `$important` so that a list's plain exception cannot lift them (design decision 68);
- `||<host>^`, a block.

No regex, no wildcard, no other modifier: what a rule reaches must be readable at a glance and by the
lint. `lint()` holds the file to the profile's rules: a block of a name the TV needs (a must-allow host,
or a name above one), one at the apex of a zone that mixes delivery with telemetry, one over the file
service the URL filter answers, or one a broader allow makes dead is refused. An allow at or under a
blocked name is what an allow is for, so the profile lint's exception-over-block refusal does not apply
to it. An allow of a whole registered domain that the profile files under tracking (ads, telemetry,
fingerprinting, ACR) is taken only with `--force`, after the command says what it unblocks.

`tvgw adguard apply` puts the file between the profile and the machine: profile rules (generated and
written), then these, then the machine's (`adguardcfg.rule_groups`). A local allow keeps the machine
from proposing or applying a block under it (`autoblock.gate`), and a local block stays when the machine
reverts its own copy of it. `tvgw forget` keeps the file: it is policy, not a viewing record.
"""

from __future__ import annotations

import contextlib
import dataclasses
import grp
import os
import re
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from fnmatch import fnmatchcase

from tvgw import durable
from tvgw.config import Settings
from tvgw.names import is_public_name, normalize, registrable_domain
from tvgw.profile import Profile, covers, reaches

ALLOW, BLOCK = "allow", "block"
_FORMS = {
    ALLOW: re.compile(r"@@\|\|([a-z0-9_.-]+)\^\$important"),
    BLOCK: re.compile(r"\|\|([a-z0-9_.-]+)\^"),
}
HEADER = (
    "! the owner's own rules for AdGuard Home (design decision 59): written by sudo tvgw allow and"
    " sudo tvgw block, undone by tvgw unallow and tvgw unblock"
)
COMMENT_PREFIXES = ("!", "#")  # AdGuard's comment and the hosts-file one: neither reaches AdGuard
REASON_CAP = 200  # characters of --reason kept in the comment line
MODE = 0o640  # root:adm, as the settings file: the admin group may read what the owner decided
LOCK_WAIT = 30.0  # seconds the command waits for the hourly check or the analyst to finish a step
# exit statuses: done (or nothing to do), refused or failed with nothing changed, AdGuard held its restart
# back because the upstreams are down (cli.DEFERRED_EXIT) with nothing changed
OK, REFUSED, DEFERRED = 0, 1, 3


@dataclass(frozen=True)
class Rule:
    kind: str  # ALLOW | BLOCK
    host: str

    @property
    def text(self) -> str:
        return f"@@||{self.host}^$important" if self.kind == ALLOW else f"||{self.host}^"


@dataclass(frozen=True)
class Entry:
    """One rule line of the file, with the comment line written above it ('' when there is none)."""

    line: str
    note: str
    rule: Rule | None  # None: a line in neither form (a hand edit), which the plan never takes


@dataclass
class Outcome:
    """What a command did: the exit status and the lines it prints."""

    code: int
    lines: list[str] = dataclasses.field(default_factory=list)


# ---- names and lines ---------------------------------------------------------------------------------
def host_of(name: str) -> str:
    """The name as a rule's host: lower case, no trailing dot. ValueError, with the reason in plain
    words, for anything a site rule cannot hold (a wildcard, an address, a name with no dot, a local
    name such as printer.lan)."""
    host = normalize(name)
    if "*" in host or "/" in host or "|" in host or "^" in host or "$" in host:
        raise ValueError(f"{name!r} is not one name: a site rule takes a plain name such as ads.example")
    if not is_public_name(host):
        raise ValueError(
            f"{name!r} is not an internet name: a site rule takes a name such as ads.example, never an"
            " address or a local name"
        )
    return host


def parse(line: str) -> Rule | None:
    """The rule a line holds, in one of the two forms exactly, or None."""
    text = line.strip()
    for kind, form in _FORMS.items():
        m = form.fullmatch(text)
        if m and is_public_name(m.group(1)) and normalize(m.group(1)) == m.group(1):
            return Rule(kind, m.group(1))
    return None


def _is_comment(line: str) -> bool:
    return line.lstrip().startswith(COMMENT_PREFIXES)


def entries_of(text: str) -> list[Entry]:
    """The file's rule lines in order, each with the comment line directly above it."""
    out: list[Entry] = []
    note = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            note = ""
        elif _is_comment(line):
            note = line if line != HEADER else ""
        else:
            out.append(Entry(line, note, parse(line)))
            note = ""
    return out


def read_text(path: str) -> str | None:
    """The file's text, or None when there is none. Any other failure to read it is raised: a plan
    made without the owner's allows would block again what the owner let through."""
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        return None


def entries(path: str) -> list[Entry]:
    text = read_text(path)
    return entries_of(text) if text is not None else []


def owner_allows(path: str) -> tuple[str, ...]:
    """The hosts the owner allows. Unreadable or absent: none, so a reader without access (the analyst's
    pack, a non-root `tvgw`) never stops for it; the gate's caller runs as root and reads it whole."""
    try:
        found = entries(path)
    except OSError:
        return ()
    return tuple(e.rule.host for e in found if e.rule is not None and e.rule.kind == ALLOW)


def allowed_by_owner(name: str | None, allows: tuple[str, ...]) -> str | None:
    """The owner's allow that covers `name` (the name itself or a parent), or None."""
    if not name:
        return None
    n = normalize(name)
    return next((a for a in allows if covers(a, n)), None)


# ---- the lint ----------------------------------------------------------------------------------------
def _block_problem(rule: Rule, prof: Profile, others: list[Rule]) -> str | None:
    host = rule.host
    for needed, why in prof.must_allow.items():
        if covers(host, needed):
            where = "is" if host == needed else f"is under {host}, and"
            return f"{needed} {where} kept reachable on purpose: {why}"
        if covers(needed, host):
            return (
                f"{host} is under {needed}, which is kept reachable on purpose, so the block would do nothing"
            )
    for pattern in prof.clock_hosts:
        if fnmatchcase(host, pattern) or fnmatchcase(host, "*." + pattern):
            return f"the TV sets its clock from {host}"
        if reaches(host, pattern):
            return f"the TV sets its clock from names under {host}"
    if prof.url_filter:
        for served in prof.url_filter.hosts:
            if covers(host, served) or covers(served, host):
                return f"{served} goes through the URL filter, which a block of {host} would undo"
    for apex in prof.never_block_apex:
        if covers(host, apex):
            return (
                f"{apex} mixes what the TV needs with what it reports; block single names under it,"
                f" never {host}"
            )
    for other in others:
        if other.kind == ALLOW and covers(other.host, host):
            return f"your own allow of {other.host} covers it, so the block would do nothing"
    return None


def problems(rules: list[str], prof: Profile) -> list[tuple[str, str]]:
    """(rule, why) for every line of the owner's rules that may not reach AdGuard, in file order.
    Each rule is held against the profile's lint (decision 59: the same lint), in this file's mode:
    an allow may sit at or over a blocked name; everything else that lint refuses, it refuses here."""
    parsed = [(r, parse(r)) for r in rules]
    good = [p for _, p in parsed if p is not None]
    out: list[tuple[str, str]] = []
    base = set(prof.lint())
    for text, rule in parsed:
        if rule is None:
            out.append((text, "a site rule is @@||name^$important (allow) or ||name^ (block), nothing else"))
            continue
        why = _block_problem(rule, prof, good) if rule.kind == BLOCK else None
        if why is None:
            lifts = frozenset({rule.host}) if rule.kind == ALLOW else frozenset()
            extra = dataclasses.replace(prof, custom_rules=(*prof.custom_rules, rule.text)).lint(lifts)
            new = [p for p in extra if p not in base]
            why = new[0] if new else None
        if why is not None:
            out.append((text, why))
    return out


def admissible(path: str, prof: Profile) -> tuple[list[str], list[str]]:
    """(the owner's rules that pass the lint, in file order and once each; the lines refused, with the
    reason). Raises OSError when the file is there and cannot be read."""
    text = read_text(path)
    lines = [e.line for e in entries_of(text)] if text is not None else []
    lines = list(dict.fromkeys(lines))
    refused = dict(problems(lines, prof))
    return [r for r in lines if r not in refused], [f"{r}: {why}" for r, why in refused.items()]


def unblocks(host: str, prof: Profile) -> list[str]:
    """The tracking categories (ACR, ads, telemetry, fingerprinting: `plain.is_tracking`) an allow of
    `host` lets through: the host's own category and those of every profile pattern under it."""
    from tvgw import plain  # here, not at module level: plain imports queries

    cats = [prof.categorize(host)]
    cats += [cat for pat, cat in prof.rules if pat == host or pat.endswith("." + host)]
    return [c for c in dict.fromkeys(cats) if plain.is_tracking(c)]


def held_blocks(host: str, prof: Profile) -> list[str]:
    """(listguard) What of the profile's red-line blocks (those it loads with `$important`, design decision
    68) an allow of `host` lifts, in words for the allow's message: the name of a block at, above or under
    `host`, and, for a regex block, `the names <rule> matches` when it matches `host` or a name under it
    that the profile's categories describe (`profile.filled_names`). A list's plain exception cannot lift
    them; the owner's allow, `@@||host^$important`, outranks them all the same."""
    from tvgw.profile import filled_names, regex_body, rule_target

    out = []
    for rule in prof.custom_rules:
        if not rule.endswith("$important"):
            continue
        kind, target = rule_target(rule)
        if kind == BLOCK and target and (covers(host, target) or covers(target, host)):
            out.append(target)
        elif kind == "regex":
            body = regex_body(rule[: -len("$important")])
            try:
                rx = re.compile(body or "(?!)", re.IGNORECASE)
            except re.error:
                continue
            if rx.search(host) or any(rx.search(n) for n in filled_names(prof) if covers(host, n)):
                out.append(f"the names {rule} matches")
    return list(dict.fromkeys(out))


def whole_domain(host: str) -> bool:
    """An allow of `host` covers a whole registered domain: the host is one, or stands above one."""
    return covers(host, registrable_domain(host))


def needs_force(host: str, prof: Profile) -> bool:
    """`tvgw allow` takes this name only with --force: it would unblock tracking for a whole domain."""
    return whole_domain(host) and bool(unblocks(host, prof))


def plain_categories(cats: list[str], prof: Profile) -> str:
    from tvgw import plain

    labels = list(dict.fromkeys(plain.category_label(c, prof) for c in cats))
    return labels[0] if len(labels) == 1 else ", ".join(labels[:-1]) + " and " + labels[-1]


# ---- the file ----------------------------------------------------------------------------------------
def render(found: list[Entry]) -> str:
    out = [HEADER]
    for e in found:
        if e.note:
            out.append(e.note)
        out.append(e.line)
    return "\n".join(out) + "\n"


def _clean_reason(reason: str) -> str:
    text = " ".join("".join(ch if ch.isprintable() else " " for ch in reason).split())
    return text[:REASON_CAP]


def note(verb: str, reason: str, now: float, forced: bool = False) -> str:
    """The comment line a command writes above its rule: the date, the command and why."""
    day = time.strftime("%Y-%m-%d", time.localtime(now))
    why = _clean_reason(reason) or "by the owner"
    return f"! {day} tvgw {verb}{' --force' if forced else ''}: {why}"


def write(path: str, text: str) -> None:
    """The whole file, atomically: a new file beside it (MODE, root:adm when root writes it), fsynced
    and renamed over it, the directory fsynced."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, mode=0o755, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".local.rules.", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, MODE)
        if os.geteuid() == 0:
            with contextlib.suppress(KeyError, OSError):
                os.chown(tmp, 0, grp.getgrnam("adm").gr_gid)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    dfd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _put_back(path: str, before: str | None) -> None:
    """The file as it was: its old text, or no file."""
    if before is None:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)
    else:
        write(path, before)


# ---- the commands ------------------------------------------------------------------------------------
@dataclass
class _Run:
    s: Settings
    prof: Profile
    verb: str
    apply_fn: Callable[[], object]
    now: float
    wait: float
    sleep: Callable[[float], None]


def _default_apply(s: Settings, prof: Profile) -> Callable[[], object]:
    def apply() -> object:
        from tvgw import analyst  # the apply the machine's rules go through: lint, guard, readiness

        return analyst.adguardcfg_apply(s, prof)

    return apply


def _locked(run: _Run, body: Callable[[], Outcome]) -> Outcome:
    """`body` under the autonomy's lock (`autoblock.exclusive`), waiting up to `run.wait` seconds for
    the hourly check or the analyst to finish the step they hold it for."""
    from tvgw import autoblock

    deadline = time.monotonic() + run.wait
    while True:
        with autoblock.exclusive(run.s.state_dir) as free:
            if free:
                try:
                    return body()
                except OSError as e:  # a file the command reads before it changes anything
                    return Outcome(REFUSED, [f"tvgw {run.verb}: {e}; nothing changed; run it with sudo"])
        if time.monotonic() >= deadline:
            return Outcome(
                REFUSED,
                [
                    f"tvgw {run.verb}: the gateway's hourly check or the analyst is changing rules right"
                    " now; nothing changed; run it again in a few minutes"
                ],
            )
        run.sleep(1.0)


def _commit(
    run: _Run, before: str | None, after: str, host: str, machine: list[str] | None = None
) -> Outcome:
    """Write `after` (and take `machine`'s rules out of the machine's file), apply AdGuard, and on any
    failure put both files back as they were: all or nothing."""
    from tvgw import adguardcfg, autoblock, ledger

    path, auto_before = run.s.local_rules, None
    try:
        if machine:
            auto_before = read_text(run.s.auto_rules)
        write(path, after)
        for r in machine or []:
            autoblock.remove_rule(run.s.auto_rules, r)
    except OSError as e:
        _restore(run, before, auto_before)
        return Outcome(REFUSED, [f"tvgw {run.verb}: cannot write {path} ({e}); run it with sudo"])
    try:
        run.apply_fn()
    except adguardcfg.Deferred as e:
        _restore(run, before, auto_before)
        return Outcome(DEFERRED, [f"tvgw {run.verb}: {e}; your rules are as they were"])
    except (RuntimeError, OSError, ValueError) as e:
        _restore(run, before, auto_before)
        return Outcome(
            REFUSED,
            [f"tvgw {run.verb}: AdGuard Home did not take the change ({e}); your rules are as they were"],
        )
    with contextlib.suppress(OSError):  # (ledger) one spool line; a failed write never undoes the change
        ledger.append_spool(ledger.spool_path(run.s), ["owner", run.verb, host], run.now)
    return Outcome(OK)


def _restore(run: _Run, before: str | None, auto_before: str | None) -> None:
    """Both files as they were; a file that cannot be put back is said, never left unsaid."""
    try:
        if read_text(run.s.local_rules) != before:
            _put_back(run.s.local_rules, before)
        if auto_before is not None and read_text(run.s.auto_rules) != auto_before:
            write_auto(run.s.auto_rules, auto_before)
    except OSError as e:
        print(f"tvgw {run.verb}: could not put the rules files back ({e})", file=sys.stderr)


def write_auto(path: str, text: str) -> None:
    """The machine's file put back as it was, as autoblock writes it: 0640, whole (durable.replace)."""
    durable.replace(path, text, 0o640)


def _start(
    s: Settings,
    prof: Profile,
    verb: str,
    apply_fn: Callable[[], object] | None,
    now: float | None,
    wait: float,
    sleep: Callable[[float], None] | None,
) -> _Run:
    return _Run(
        s,
        prof,
        verb,
        apply_fn or _default_apply(s, prof),
        time.time() if now is None else now,
        wait,
        sleep or time.sleep,
    )


def allow(
    s: Settings,
    prof: Profile,
    name: str,
    reason: str = "",
    force: bool = False,
    apply_fn: Callable[[], object] | None = None,
    now: float | None = None,
    wait: float = LOCK_WAIT,
    sleep: Callable[[float], None] | None = None,
) -> Outcome:
    """`tvgw allow NAME`: let the name (and every name under it) through, whatever a list or the machine
    blocks. Replaces the owner's own block of the same name. A whole registered domain of tracking takes
    --force. A machine rule the allow covers leaves the machine's file in the same step, so the record
    shows it reverted by the owner at the next hourly check rather than judged while it does nothing."""
    run = _start(s, prof, ALLOW, apply_fn, now, wait, sleep)
    try:
        host = host_of(name)
    except ValueError as e:
        return Outcome(REFUSED, [f"tvgw allow: {e}"])
    rule = Rule(ALLOW, host)
    if rule.text in prof.adguard_rules():
        return Outcome(OK, [f"tvgw allow: the TV's profile already keeps {host} reachable; nothing changed"])
    lines: list[str] = []
    cats = unblocks(host, prof)
    if cats:
        lines.append(
            f"tvgw allow: this lets {host} and every name under it through for the TV, which the profile"
            f" files under {plain_categories(cats, prof)}"
        )
        if needs_force(host, prof) and not force:
            lines += [
                f"tvgw allow: {host} is a whole domain of known tracking; nothing changed.",
                f"tvgw allow: to allow it anyway: sudo tvgw allow {host} --force",
            ]
            return Outcome(REFUSED, lines)

    def body() -> Outcome:
        from tvgw import autoblock

        before = read_text(s.local_rules)
        found = entries_of(before) if before is not None else []
        if any(e.rule == rule for e in found):
            return Outcome(
                OK, [*lines, f"tvgw allow: {host} is already allowed by your rules; nothing changed"]
            )
        # the owner's own blocks of the name, or under it, would be dead beside the allow: they go
        replaced = [e for e in found if e.rule and e.rule.kind == BLOCK and covers(host, e.rule.host)]
        kept = [e for e in found if e not in replaced]
        forced = force and needs_force(host, prof)
        new = [*kept, Entry(rule.text, note(ALLOW, reason, run.now, forced=forced), rule)]
        refused = [why for text, why in problems([e.line for e in new], prof) if text == rule.text]
        if refused:
            return Outcome(REFUSED, [*lines, f"tvgw allow: refused: {refused[0]}; nothing changed"])
        machine = [r for r in autoblock.read_rules(s.auto_rules) if _machine_target(r, host)]
        done = _commit(run, before, render(new), host, machine)
        if done.code != OK:
            return Outcome(done.code, [*lines, *done.lines])
        out = [*lines]
        out += [
            f"tvgw allow: the profile keeps {b} blocked against a blocklist's plain exception; your own"
            " allow lets it through all the same"
            for b in held_blocks(host, prof)
        ]
        out += [f"tvgw allow: your block of {e.rule.host} is gone" for e in replaced if e.rule]
        out += [
            f"tvgw allow: the gateway's own rule {r} is out too; the hourly check records it as undone by you"
            for r in machine
        ]
        out += [
            f"tvgw allow: {host} is allowed for the TV (in {s.local_rules}); AdGuard Home re-applied",
            f"tvgw allow: to undo it: sudo tvgw unallow {host}",
        ]
        return Outcome(OK, out)

    return _locked(run, body)


def _machine_target(rule: str, host: str) -> bool:
    """A machine rule the owner's allow of `host` lifts: a block, or one that withholds record types
    (`$dnstype`, which an `$important` exception lifts as well), of the host or a name under it."""
    from tvgw.profile import rule_target

    kind, target = rule_target(rule)
    return kind in (BLOCK, "typed") and bool(target) and covers(host, target)


def block(
    s: Settings,
    prof: Profile,
    name: str,
    reason: str = "",
    apply_fn: Callable[[], object] | None = None,
    now: float | None = None,
    wait: float = LOCK_WAIT,
    sleep: Callable[[float], None] | None = None,
) -> Outcome:
    """`tvgw block NAME`: block the name and every name under it. Refused for anything the TV needs
    (`problems`). Replaces the owner's own allow of the same name."""
    run = _start(s, prof, BLOCK, apply_fn, now, wait, sleep)
    try:
        host = host_of(name)
    except ValueError as e:
        return Outcome(REFUSED, [f"tvgw block: {e}"])
    rule = Rule(BLOCK, host)

    def body() -> Outcome:
        before = read_text(s.local_rules)
        found = entries_of(before) if before is not None else []
        if any(e.rule == rule for e in found):
            return Outcome(OK, [f"tvgw block: {host} is already blocked by your rules; nothing changed"])
        replaced = [e for e in found if e.rule == Rule(ALLOW, host)]
        kept = [e for e in found if e.rule != Rule(ALLOW, host)]
        new = [*kept, Entry(rule.text, note(BLOCK, reason, run.now), rule)]
        refused = [why for text, why in problems([e.line for e in new], prof) if text == rule.text]
        if refused:
            return Outcome(REFUSED, [f"tvgw block: refused: {refused[0]}; nothing changed"])
        done = _commit(run, before, render(new), host)
        if done.code != OK:
            return done
        out = [f"tvgw block: your allow of {host} is gone"] if replaced else []
        out += [
            f"tvgw block: {host} is blocked for the TV (in {s.local_rules}); AdGuard Home re-applied",
            f"tvgw block: to undo it: sudo tvgw unblock {host}",
        ]
        return Outcome(OK, out)

    return _locked(run, body)


def remove(
    s: Settings,
    prof: Profile,
    name: str,
    kind: str,
    apply_fn: Callable[[], object] | None = None,
    now: float | None = None,
    wait: float = LOCK_WAIT,
    sleep: Callable[[float], None] | None = None,
) -> Outcome:
    """`tvgw unallow NAME` (kind ALLOW) or `tvgw unblock NAME` (kind BLOCK): take the owner's own rule
    for the name out, with its comment line. A name the owner never ruled on is left as it is."""
    verb = "unallow" if kind == ALLOW else "unblock"
    run = _start(s, prof, verb, apply_fn, now, wait, sleep)
    try:
        host = host_of(name)
    except ValueError as e:
        return Outcome(REFUSED, [f"tvgw {verb}: {e}"])
    rule = Rule(kind, host)

    def body() -> Outcome:
        before = read_text(s.local_rules)
        found = entries_of(before) if before is not None else []
        if not any(e.rule == rule for e in found):
            out = [f"tvgw {verb}: your rules have no {kind} of {host}; nothing changed"]
            if kind == BLOCK:
                out.append(f"tvgw unblock: if the lists block it, sudo tvgw allow {host} lets it through")
            return Outcome(OK, out)
        kept = [e for e in found if e.rule != rule]
        done = _commit(run, before, render(kept), host)
        if done.code != OK:
            return done
        gone = "allowed" if kind == ALLOW else "blocked"
        return Outcome(
            OK,
            [f"tvgw {verb}: {host} is no longer {gone} by your rules; AdGuard Home re-applied"],
        )

    return _locked(run, body)


def warn_refused(refused: list[str], out=sys.stderr) -> None:
    for line in refused:
        print(f"tvgw adguard: site rule left out: {line}", file=out)
