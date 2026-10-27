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

import yaml

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
    reason_code = res.get("Reason")
    # Filtered* reasons (3-8) are blocks; Rewritten* (9-11) answer with our address and are not
    blocked = 3 <= reason_code <= 8 if isinstance(reason_code, int) else bool(res.get("IsFiltered"))
    if reason_code is None:
        reason_code = 3 if blocked else 0
    return DnsRecord(
        t=t,
        client=str(e.get("IP", "")),
        qname=str(e.get("QH", "")).lower().rstrip("."),
        qtype=str(e.get("QT", "")),
        answers=dnsmsg.answers_text(e["Answer"]) if e.get("Answer") else None,
        blocked=blocked,
        reason=REASONS.get(reason_code, str(reason_code)),
        rule=first.get("Text"),
        filter_id=first.get("FilterListID"),
        upstream=e.get("Upstream") or None,
        cached=bool(e.get("Cached")),
        elapsed_ms=_number(e.get("Elapsed")) / 1e6,
    )


def _number(v) -> float:
    try:
        return float(v or 0)
    except (TypeError, ValueError):
        return 0.0


def user_rules_from_yaml(text: str) -> list[str] | None:
    """The `user_rules:` list of an AdGuardHome.yaml, in order; None if the text is not YAML we
    can read (callers must not take that for "no rules")."""
    try:
        cfg = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    if not isinstance(cfg, dict):
        return None
    rules = cfg.get("user_rules") or []
    return [str(r) for r in rules] if isinstance(rules, list) else []
