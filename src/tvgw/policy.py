"""(admit) One check of effects at the one place every change of the TV's DNS policy passes (design decision
104): what AdGuard would answer before and after the change, for the names the TV must reach and the names
it used, against what the change says it does.

Four pieces of code keep the promise that the filter never blocks a must-allow host, the clock, the store
or streaming (`Profile.lint`, `localrules`, the analyst's vetting, the autonomy's gate), and each reads the
text of a rule. Between each two there was a gap: a parent of a never-block zone, a rule wider than the name
it was proposed for, a regex Python and Go read differently. This check asks what AdGuard would answer
instead, with the model of AdGuard's precedence the list guard uses (`listguard.Engine`), so how a rule is
spelt makes no difference.

- `adguardcfg.apply` writes AdGuardHome.yaml for every change, and each path to it says what it means to
  change (`Declared`): the name a machine rule, a revert or an undo acts on, or `tvgw allow` and `block`
  name; the tracker lists for a pause; nothing for a deploy, a resolver change or a plain re-apply.
- `admit` names each change of a verdict that a protected name suffers (`protected.names`), whatever was
  declared, and, when something was declared, each change to a name the TV used in the last 14 days that
  the declaration does not cover.
- `reporter` is the hook `adguardcfg.apply` runs before it stages the file, with ADMIT=report: it writes
  what `admit` found, or that it could not judge and why, to the change ledger and to stderr.

It reports, and can never change or stop an apply: the hook sees copies of the YAML as it is and as
planned, catches whatever the check raises, and returns nothing the apply reads. Refusing is a later owner
decision, after two weeks of reports with no line that should not be there.
"""

from __future__ import annotations

import contextlib
import os
import sys
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from tvgw import db, ledger, listguard, protected
from tvgw.config import Settings
from tvgw.listguard import BLOCKED, REWRITTEN, Client, Engine, Hit, Rule, Verdict
from tvgw.profile import Profile, covers, rule_target

REPORT = "report"  # ADMIT's one value that runs the check; `off`, the default, runs nothing
# what a change declares, by the path it came from
DEPLOY, MACHINE, REVERT, UNDO, OWNER, PAUSE, RESOLVER = (
    "deploy", "machine", "revert", "undo", "owner", "pause", "resolver",
)  # fmt: skip
CUSTOM = "custom rules"  # the source of AdGuard's `user_rules` in the two engines
STORE_WAIT = 5.0  # seconds the check waits for a busy store before it says it could not judge
SHOWN = 10  # lines printed for one change; the ledger keeps ledger.ADMIT_KEEP
# what each kind of protected name is, after its name in a line
WHY = {
    protected.MUST_ALLOW: "which the profile must let through",
    protected.CLOCK: "which the TV sets its clock from",
    protected.URL_FILTER: "which must stay rewritten to the URL filter",
    protected.ZONE: "a zone the profile never blocks whole",
    protected.EXPECTED: "which the TV used in the last 14 days, in a category it needs",
}


@dataclass(frozen=True)
class Declared:
    """What a change says it does: the names it acts on, each with every name under it, and the URLs of the
    lists it switches on or off. One that names neither is judged on the protected names alone."""

    kind: str
    names: tuple[str, ...] = ()
    lists: tuple[str, ...] = ()

    def covers(self, name: str, source: str) -> bool:
        """Does the declaration take in a change to `name` made by a rule from `source`?"""
        return source in self.lists or any(covers(d, name) for d in self.names)


def of_rules(kind: str, rules: Iterable[str]) -> Declared:
    """A declaration of the names some machine rules block, each once. A rule of another shape, which the
    machine's lint keeps out, declares nothing, so what it changes is judged as undeclared."""
    names = (target for k, target in map(rule_target, rules) if k == "block")
    return Declared(kind, tuple(dict.fromkeys(names)))


@dataclass(frozen=True)
class Admission:
    """What the check found: the lines it would refuse the change for, and the rules the change adds that
    the model cannot read, whose effect it did not judge."""

    lines: tuple[str, ...] = ()
    unread: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.lines


def _effect(v: Verdict) -> tuple[str, str]:
    """What the TV gets: blocked, rewritten (by which rule: two rewrites may answer differently) or an
    answer from upstream, whether an exception or nothing at all let it through."""
    if v.state == REWRITTEN:
        return REWRITTEN, v.hit.rule.text if v.hit else ""
    return (BLOCKED, "") if v.state == BLOCKED else ("passes", "")


def _cause(was: Verdict, now: Verdict) -> Hit:
    """The rule a changed answer comes from: the one that blocks or rewrites the name now, else the one that
    did before and the change took away. The answers differ, so one of the two holds a rule."""
    hit = now.hit if now.state in (BLOCKED, REWRITTEN) else was.hit
    assert hit is not None
    return hit


def _what(now: Verdict, hit: Hit, name: str) -> str:
    """The change to one name in words, naming the rule that made it."""
    if now.state == BLOCKED:
        return f"`{hit.rule.text}` blocks {name}"
    if now.state == REWRITTEN:
        return f"`{hit.rule.text}` rewrites {name}"
    return f"the change lifts `{hit.rule.text}` from {name}"


def admit(
    before: Engine, after: Engine, declared: Declared, guarded: dict[str, str], recent: Iterable[str]
) -> Admission:
    """The lines that would refuse a change from `before` to `after`: each protected name (`guarded`, name
    to reason) that the change blocks or rewrites, or for a URL-filter host takes out of its rewrite, but by
    a list it declares; and, when `declared` names something, each name of `recent` whose answer changes by
    a rule the declaration does not cover. A name whose answer stays the same is never a line, so a change
    that changes nothing has none."""
    lines: list[str] = []
    for name, why in guarded.items():
        was, now = before.decide(name), after.decide(name)
        if _effect(was) == _effect(now):
            continue
        # a URL-filter host is hurt when it leaves its rewrite, any other when it is blocked or rewritten
        hurt = was.state == REWRITTEN if why == protected.URL_FILTER else now.state in (BLOCKED, REWRITTEN)
        hit = _cause(was, now)
        # a list the change switches back on is the profile's own: what the list itself blocks is the list
        # guard's to judge (decision 68), and the end of a pause is no change to refuse
        if hurt and hit.source not in declared.lists:
            shown = name.removeprefix(protected.ZONE_PROBE) if why == protected.ZONE else name
            lines.append(f"would refuse: {_what(now, hit, shown)}, {WHY[why]}")
    if declared.names or declared.lists:
        for name in dict.fromkeys(recent):
            if name in guarded:
                continue
            was, now = before.decide(name), after.decide(name)
            if _effect(was) == _effect(now):
                continue
            hit = _cause(was, now)
            if not declared.covers(name, hit.source):
                lines.append(f"would refuse: {_what(now, hit, name)}, which the change did not declare")
    return Admission(tuple(dict.fromkeys(lines)))


# ---- the two engines --------------------------------------------------------------------------------------
def _user_rules(cfg: dict) -> list[str]:
    rules = cfg.get("user_rules")
    return [str(r) for r in rules] if isinstance(rules, list) else []


def _list_rules(path: str, interest: set[str]) -> list[Rule]:
    """A list's rules that can match one of the names judged; none for a file AdGuard has not downloaded,
    from which it holds nothing either."""
    try:
        lines = listguard._lines(path)
    except FileNotFoundError:
        return []
    return listguard.read_rules(lines, interest)[0]


def engines(
    current: dict, planned: dict, folder: str, client: Client, names: Iterable[str]
) -> tuple[Engine, Engine]:
    """AdGuard's model for the YAML as it is and as planned: its custom rules and its enabled lists, each
    list's file in `folder` read once for both and kept to the rules that can match one of `names`."""
    interest = listguard.interest_of(names)
    read: dict[str, list[Rule]] = {}

    def engine(cfg: dict) -> Engine:
        sources = [(CUSTOM, [r for t in _user_rules(cfg) for r in listguard.parse(t) or []])]
        for lf in listguard.enabled(cfg, folder):
            if lf.path not in read:
                read[lf.path] = _list_rules(lf.path, interest)
            sources.append((lf.url, read[lf.path]))
        return Engine(sources, client)

    return engine(current), engine(planned)


def recent_names(s: Settings, now: float | None = None) -> list[str]:
    """The names the TV looked up in the last 14 days, the most looked up first, from the store opened
    read-only; none on a gateway whose store does not exist yet."""
    if not os.path.exists(s.db_path):
        return []
    conn = db.connect(s.db_path, readonly=True, timeout=STORE_WAIT)
    try:
        return [n for n, _ in listguard.tv_names(conn, time.time() if now is None else now)]
    finally:
        conn.close()


def judge(
    s: Settings,
    prof: Profile,
    declared: Declared,
    current: dict,
    planned: dict,
    recent: list[str] | None = None,
) -> Admission:
    """The check of one change from AdGuardHome.yaml `current` to `planned`, for the TV of `s`: `recent` is
    the TV's names of the last 14 days, read from the store when None."""
    recent = recent_names(s) if recent is None else recent
    guarded = protected.names(prof, recent)
    before, after = engines(
        current, planned, listguard.filters_dir(s), Client(s.tv_ip, s.tv_name), [*guarded, *recent]
    )
    found = admit(before, after, declared, guarded, recent)
    had = set(_user_rules(current))
    unread = [t for t in _user_rules(planned) if t not in had and listguard.parse(t) is None]
    return Admission(found.lines, tuple(unread))


# ---- the hook ---------------------------------------------------------------------------------------------
def reporter(s: Settings, prof: Profile, declared: Declared | None) -> Callable[[dict, dict], None] | None:
    """The hook `adguardcfg.apply` runs before it stages a change, with ADMIT=report; None with ADMIT=off,
    so the check is not even built. A caller that passes no declaration declares nothing."""
    if s.admit != REPORT:
        return None
    said = declared or Declared(DEPLOY)

    def report(current: dict, planned: dict) -> None:
        try:
            found = judge(s, prof, said, current, planned)
        except Exception as e:  # report only: a fault of the check is a line, never a stop
            note(s, said.kind, ledger.ADMIT_UNJUDGED, [f"could not judge: {type(e).__name__}: {e}"])
            return
        lines = [*found.lines, *(f"could not judge `{t}`: the model does not read it" for t in found.unread)]
        if lines:
            note(s, said.kind, ledger.ADMIT_REFUSE if found.lines else ledger.ADMIT_UNJUDGED, lines)

    return report


def note(s: Settings, kind: str, outcome: str, lines: list[str]) -> None:
    """Say what the check found: the first SHOWN lines on stderr, and one line of the change spool, which
    the hourly ingest loads into the change ledger. A spool that cannot be written loses the record, not
    the apply."""
    for line in lines[:SHOWN]:
        print(f"tvgw adguard: admission check (report only): {line}", file=sys.stderr)
    if len(lines) > SHOWN:
        print(f"tvgw adguard: admission check (report only): and {len(lines) - SHOWN} more", file=sys.stderr)
    with contextlib.suppress(OSError):
        ledger.append_spool(ledger.spool_path(s), ledger.admit_fields(kind, outcome, lines))
