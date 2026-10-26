"""AdGuard Home: its on-disk query log and its user rules.

The query log is JSON lines (`querylog.json`); each record carries the client, question, the
base64 DNS answer, the filtering result with the rule that matched, the upstream used and the
elapsed time. This is the authoritative DNS record: unlike a packet capture it says *why* a
name was blocked.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime

from tvgw import dnsmsg

REASONS = {
    0: "NotFilteredNotFound",
    1: "NotFilteredAllowList",
    2: "NotFilteredError",
    3: "FilteredBlockList",
    4: "FilteredSafeBrowsing",
    5: "FilteredParental",
    6: "FilteredInvalid",
    7: "FilteredSafeSearch",
    8: "FilteredBlockedService",
    9: "Rewritten",
    10: "RewrittenAutoHosts",
    11: "RewrittenRule",
}

_TIME_RE = re.compile(r"(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|[+-]\d\d:?\d\d)?$")


def parse_time(s: str) -> float | None:
    """RFC 3339 with any number of fraction digits (AdGuard writes nine) -> epoch seconds."""
    m = _TIME_RE.match(s.strip())
    if not m:
        return None
    frac = (m.group(2) or "0")[:6].ljust(6, "0")
    tz = (m.group(3) or "").replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(f"{m.group(1)}.{frac}{tz}").timestamp()
    except ValueError:
        return None


@dataclass(frozen=True)
class DnsRecord:
    t: float
    client: str
    qname: str
    qtype: str
    answers: str | None  # "A:1.2.3.4,CNAME:x" or None
    blocked: bool
    reason: str
    rule: str | None
    filter_id: int | None
    upstream: str | None
    cached: bool
    elapsed_ms: float


def parse_querylog_line(line: str, client: str | None = None) -> DnsRecord | None:
    """One query-log record, or None if it is malformed or (when `client` is given) from another client."""
    try:
        e = json.loads(line)
    except ValueError:
        return None
    if not isinstance(e, dict):
        return None
    if client is not None and e.get("IP") != client:
        return None
    t = parse_time(str(e.get("T", "")))
    if t is None:
        return None
    res = e.get("Result") or {}
    rules = res.get("Rules") or []
    first = rules[0] if rules and isinstance(rules[0], dict) else {}
    reason_code = res.get("Reason", 0)
    return DnsRecord(
        t=t,
        client=str(e.get("IP", "")),
        qname=str(e.get("QH", "")).lower().rstrip("."),
        qtype=str(e.get("QT", "")),
        answers=dnsmsg.answers_text(e["Answer"]) if e.get("Answer") else None,
        blocked=bool(res.get("IsFiltered")),
        reason=REASONS.get(reason_code, str(reason_code)),
        rule=first.get("Text"),
        filter_id=first.get("FilterListID"),
        upstream=e.get("Upstream") or None,
        cached=bool(e.get("Cached")),
        elapsed_ms=(e.get("Elapsed") or 0) / 1e6,
    )


_RULE_LINE = re.compile(r"^  - '(.*)'$")


def user_rules_from_yaml(text: str) -> list[str]:
    """The `user_rules:` list of an AdGuardHome.yaml, in order."""
    out: list[str] = []
    in_rules = False
    for line in text.splitlines():
        if line.startswith("user_rules:"):
            in_rules = True
            continue
        if in_rules:
            m = _RULE_LINE.match(line)
            if m:
                out.append(m.group(1))
            else:
                break
    return out


def replace_user_rules(text: str, rules: list[str]) -> str:
    """Return the YAML with its `user_rules:` list replaced (AdGuard must be stopped while editing)."""
    lines = text.splitlines(keepends=True)
    start = next(i for i, ln in enumerate(lines) if ln.startswith("user_rules:"))
    end = start + 1
    while end < len(lines) and _RULE_LINE.match(lines[end].rstrip("\n")):
        end += 1
    body = [f"  - '{r}'\n" for r in rules] or []
    return "".join(lines[: start + 1] + body + lines[end:])
