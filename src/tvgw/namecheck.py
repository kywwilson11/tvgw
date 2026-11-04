"""(adguard) `tvgw check NAME`: what AdGuard Home does with one name for the TV, and why, in plain words.

AdGuard Home answers the question itself, through its check_host API (`aghinstall.check_host()`), so the
verdict is the one the TV's own lookups get, from the same lists and rules, even for a name the TV has
never asked for. This module says where the rule that decided comes from: the profile (its generated
exceptions and rewrites, then its `.rules` file), the owner's site rules, the gateway's own rules, a
shared list by its name, one of AdGuard's own features, or no rule at all. It adds what the profile says
of the name (its kind, whether it is kept reachable on purpose, whether the URL filter answers it) and
the one fix a blocked name has. An answer that contradicts the plan, a must-allow name or a URL-filter
name blocked, gets the way back to the plan instead of an allow.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

import yaml

from tvgw import adguardcfg, aghinstall, localrules, plain
from tvgw.config import Settings
from tvgw.profile import Profile, covers

# exit statuses: allowed (an answer a rewrite gives included), blocked, could not ask
ALLOWED, BLOCKED, UNASKED = 0, 1, 2

# AdGuard's reasons as its API names them (internal/filtering/reason.go at v0.107.79)
BLOCK_REASONS = frozenset(
    {
        "FilteredBlackList",
        "FilteredSafeBrowsing",
        "FilteredParental",
        "FilteredInvalid",
        "FilteredSafeSearch",
        "FilteredBlockedService",
    }
)
ALLOW_REASONS = frozenset({"NotFilteredNotFound", "NotFilteredWhiteList"})
REWRITE_REASONS = frozenset({"Rewrite", "RewriteEtcHosts", "RewriteRule"})
# the list ids AdGuard gives its own sources (internal/filtering/rulelist at v0.107.79): 0 is the custom
# rules, which hold every rule tvgw plans; a positive id is one of the YAML's `filters`
CUSTOM = 0
OWN_FEATURES = {
    -1: "the gateway's /etc/hosts file",
    -2: "AdGuard Home's blocked services",
    -3: "AdGuard Home's parental control",
    -4: "AdGuard Home's safe browsing",
    -5: "AdGuard Home's safe search",
}
# a reason that comes with no rule text, by the source it names
FEATURE_REASONS = {
    "RewriteEtcHosts": -1,
    "FilteredBlockedService": -2,
    "FilteredParental": -3,
    "FilteredSafeBrowsing": -4,
    "FilteredSafeSearch": -5,
}
DOCTOR_FIX = "a must-allow name cannot be blocked; run sudo tvgw doctor"
FILTER_FIX = "the URL filter's names are never blocked; run sudo tvgw doctor"
DRIFT_FIX = "sudo tvgw adguard diff shows that rule, and sudo tvgw adguard apply takes it out"
FEATURE_FIX = (
    "it is a setting of AdGuard Home's own, which tvgw does not use: switch it off on AdGuard Home's page"
    " (sudo tvgw adguard ui says how to open it)"
)


@dataclass
class Outcome:
    """What the command prints and its exit status."""

    code: int
    lines: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Source:
    """Where the rule that decided comes from. `kind` is profile, local, machine, list, feature,
    unplanned, unnamed (a block AdGuard gave no rule for) or none; `line` is the "Rule:" line's text;
    `rule` is the rule's own text, when it has one."""

    kind: str
    line: str
    rule: str | None = None


def list_names(cfg: dict, prof: Profile) -> dict[int, str]:
    """The YAML's lists by AdGuard's id, each by the name the profile gives its URL, else AdGuard's."""
    by_url = {url: name for name, url in prof.adguard_filters}
    out: dict[int, str] = {}
    for key in ("filters", "whitelist_filters"):
        entries = cfg.get(key) if isinstance(cfg, dict) else None
        for f in entries if isinstance(entries, list) else []:
            fid = f.get("id") if isinstance(f, dict) else None
            if isinstance(fid, int) and not isinstance(fid, bool):
                out[fid] = str(by_url.get(f.get("url")) or f.get("name") or f.get("url") or f"number {fid}")
    return out


def first_rule(answer: dict) -> tuple[str | None, int | None]:
    """The text and list id of the first rule AdGuard names: `rules`, else the older `rule` and
    `filter_id` the API still sends."""
    rules = answer.get("rules")
    first = next((r for r in rules if isinstance(r, dict)), None) if isinstance(rules, list) else None
    if first is None:
        first = {"text": answer.get("rule"), "filter_list_id": answer.get("filter_id")}
    text, fid = first.get("text"), first.get("filter_list_id")
    text = text if isinstance(text, str) and text else None
    fid = fid if isinstance(fid, int) and not isinstance(fid, bool) else None
    return text, fid


def source(answer: dict, groups: dict[str, list[str]], lists: dict[int, str], s: Settings) -> Source:
    """Where the rule in `answer` comes from; `groups` is `adguardcfg.rule_groups()`, the plan's rules by
    the file each comes from."""
    text, fid = first_rule(answer)
    reason = str(answer.get("reason") or "")
    if text is None and fid in (None, CUSTOM):
        fid = FEATURE_REASONS.get(reason)
        if fid is None and reason == "Rewrite":
            return Source("unplanned", "an entry of AdGuard Home's own DNS rewrites, which tvgw keeps empty")
        if fid is None and reason in BLOCK_REASONS:
            return Source("unnamed", "one AdGuard Home did not name")
        if fid is None:
            return Source("none", "none, so it is allowed")
    if fid in OWN_FEATURES:
        line = OWN_FEATURES[fid]
        service = answer.get("service_name")
        if isinstance(service, str) and service:
            line += f" ({service[:60]})"
        return Source("feature", line, text)
    if fid is not None and fid > CUSTOM:
        said = text or "a rule"
        return Source("list", f"{said}, from the shared list {lists.get(fid, f'number {fid}')}", text)
    where = {
        "profile": f"from the profile ({s.profile})",
        "local": f"from your own rules ({s.local_rules})",
        "machine": f"from the rules the gateway added on its own ({s.auto_rules})",
    }
    for group in adguardcfg.RULE_GROUPS:
        if text in groups.get(group, ()):
            return Source(group, f"{text}, {where[group]}", text)
    return Source("unplanned", f"{text}, in AdGuard Home but in none of tvgw's rules", text)


def fix(name: str, src: Source, needed: bool, served: bool, reason: str, prof: Profile) -> str:
    """The one line that undoes a block, or the way back to the plan when the block contradicts it. An
    allow `tvgw allow` takes only with --force (a whole site the profile files under tracking) says so,
    with what it would unblock."""
    if needed:
        return DOCTOR_FIX
    if served:
        return FILTER_FIX
    if src.kind == "unplanned":
        return DRIFT_FIX
    if src.kind == "feature":
        return FEATURE_FIX
    if reason == "FilteredInvalid":
        return "none: AdGuard Home refuses it as a name that is not valid"
    if src.kind == "local" and src.rule == f"||{name}^":
        return f"sudo tvgw unblock {name}"
    if localrules.needs_force(name, prof):
        what = localrules.plain_categories(localrules.unblocks(name, prof), prof)
        return f"sudo tvgw allow {name} --force, only if you mean it: it unblocks {what} for the whole site"
    return f"sudo tvgw allow {name}"


def explain(
    name: str, answer: dict, prof: Profile, s: Settings, groups: dict[str, list[str]], lists: dict[int, str]
) -> Outcome:
    """`tvgw check`'s lines for AdGuard's `answer` about `name`, with the exit status."""
    reason = str(answer.get("reason") or "")
    if reason == "NotFilteredError":
        return Outcome(UNASKED, [f"tvgw check: AdGuard Home could not check {name} (NotFilteredError)"])
    if reason not in BLOCK_REASONS | ALLOW_REASONS | REWRITE_REASONS:
        return Outcome(
            UNASKED, [f"tvgw check: AdGuard Home answered a reason tvgw does not know: {reason[:80]!r}"]
        )
    src = source(answer, groups, lists, s)
    must = next(((host, why) for host, why in prof.must_allow.items() if covers(host, name)), None)
    served = prof.url_filter is not None and any(covers(h, name) for h in prof.url_filter.hosts)
    rewrite = (
        served and reason == "RewriteRule" and src.kind == "profile" and "$dnsrewrite=" in (src.rule or "")
    )
    blocked = reason in BLOCK_REASONS
    if blocked:
        head = f"{name} is blocked for the TV."
    elif rewrite:
        head = f"{name} is allowed for the TV, through the URL filter."
    else:
        head = f"{name} is allowed for the TV."
    if rewrite:
        through = (
            "yes: AdGuard Home answers it with the gateway's address, and the filter decides each download"
        )
    else:
        through = "yes in the profile, but AdGuard Home's answer is not the filter's" if served else "no"
    lines = [
        head,
        f"  Rule: {src.line}",
        f"  Kind: {plain.category_label(prof.categorize(name), prof)}",
        "  Kept reachable on purpose: "
        + (f"yes, on the profile's must-allow list: {must[1]}" if must else "no"),
        f"  Through the URL filter: {through}",
    ]
    if blocked:
        lines.append(f"  Fix: {fix(name, src, must is not None, served, reason, prof)}")
        return Outcome(BLOCKED, lines)
    exception = f"@@||{must[0]}^$important" if must else None
    if exception and src.rule != exception:
        lines.append(
            f"  Note: AdGuard Home did not answer with the profile's {exception}; run sudo tvgw adguard diff"
        )
    elif served and not rewrite:
        lines.append("  Note: the URL filter's rewrite did not answer it; run sudo tvgw doctor")
    elif src.kind == "unplanned":
        lines.append(f"  Note: {DRIFT_FIX}")
    return Outcome(ALLOWED, lines)


def run(
    s: Settings,
    prof: Profile,
    name: str,
    ask: Callable[[str, bool], str] | None = None,
    check: Callable[..., dict] | None = None,
    admin: str | None = None,
) -> Outcome:
    """Ask AdGuard Home about `name` for the TV (`TV_IP`) and explain the answer. `ask` prompts for
    AdGuard's password when tvgw keeps none (None: no terminal, so nothing is asked); `check` stands in
    for `aghinstall.check_host()` and `admin` for its credentials file. Nothing is written."""
    try:
        host = localrules.host_of(name)
    except ValueError as e:
        return Outcome(UNASKED, [f"tvgw check: {e}"])
    try:
        cfg = adguardcfg.load_yaml(s.adguard_yaml)
    except FileNotFoundError:
        return Outcome(
            UNASKED,
            ["tvgw check: AdGuard Home is not set up on this computer yet: sudo tvgw adguard install"],
        )
    except (OSError, yaml.YAMLError) as e:
        return Outcome(UNASKED, [f"tvgw check: cannot read {s.adguard_yaml}: {e}"])
    try:
        groups = adguardcfg.rule_groups(prof, s)
    except OSError as e:
        return Outcome(UNASKED, [f"tvgw check: cannot read the rules tvgw plans: {e}"])
    try:
        user, password = aghinstall.credentials(cfg, admin=admin or aghinstall.ADMIN_FILE, ask=ask)
        answer = (check or aghinstall.check_host)(aghinstall.page_base(cfg), host, s.tv_ip, user, password)
    except aghinstall.AskError as e:
        return Outcome(UNASKED, [f"tvgw check: {e}"])
    return explain(host, answer, prof, s, groups, list_names(cfg, prof))
