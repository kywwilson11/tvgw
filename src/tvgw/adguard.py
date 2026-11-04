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
    """One query-log record; None when `client` is given and the record is another client's.

    Raises ValueError for a line that is not a record: not JSON, not an object, no readable time
    (a truncated or NUL-filled line after a power loss). Every other field is coerced to its
    column's type, so an oddly typed record is stored, never rejected by the database: one
    unbindable row in a batch would roll back the whole hour and every hour after it."""
    try:
        e = json.loads(line)
    except ValueError:
        e = None
    if not isinstance(e, dict):
        raise ValueError("not a query-log record")
    if client is not None and e.get("IP") != client:
        return None
    t = parse_time(str(e.get("T", "")))
    if t is None:
        raise ValueError("not a query-log record")
    res = e.get("Result") if isinstance(e.get("Result"), dict) else {}
    rules = res.get("Rules") if isinstance(res.get("Rules"), list) else []
    first = rules[0] if rules and isinstance(rules[0], dict) else {}
    blocked, reason = _verdict(res)
    fid = first.get("FilterListID")
    return DnsRecord(
        t=t,
        client=str(e.get("IP", "")),
        qname=str(e.get("QH", "")).lower().rstrip("."),
        qtype=str(e.get("QT", "")),
        answers=dnsmsg.answers_text(e["Answer"]) if isinstance(e.get("Answer"), str) else None,
        blocked=blocked,
        reason=reason,
        rule=None if first.get("Text") is None else str(first["Text"])[:2000],
        filter_id=fid if isinstance(fid, int) and not isinstance(fid, bool) else None,
        upstream=str(e["Upstream"]) if e.get("Upstream") else None,
        cached=bool(e.get("Cached")),
        elapsed_ms=_number(e.get("Elapsed")) / 1e6,
    )


# (adguard) at most this much of each query-log file is read, from its end, to see whom AdGuard answered
# lately: AdGuard writes a few hundred bytes a lookup, so 16 MB is tens of thousands of the newest ones
CLIENTS_MAX_BYTES = 16 * 1024 * 1024


def clients_since(
    path: str, since: float, max_bytes: int = CLIENTS_MAX_BYTES
) -> tuple[dict[str, float], bool]:
    """(adguard) The clients of the query log's records from `since` on, each with the time of its newest
    one, read backwards from the end of `path` and then of the copy AdGuard rotated away (`path.1`), at
    most `max_bytes` of each: the newest lookups come last, so the read stops at the first record older
    than `since`, or where the bytes run out. The flag says whether any record of the window was read,
    which an empty or switched-off log never gives. A line that is not a record (a torn last line, NULs
    after a power loss) is skipped, as the ingest skips it; a file that is not there reads as empty."""
    clients: dict[str, float] = {}
    seen = False
    for name in (path, path + ".1"):
        try:
            with open(name, "rb") as f:
                size = f.seek(0, 2)
                start = max(0, size - max_bytes)
                f.seek(start)
                data = f.read()
        except OSError:
            if name == path:
                continue  # rotated away a moment ago: the older copy may still hold the window
            break
        lines = data.split(b"\n")
        if start:
            lines = lines[1:]  # the cut went through a line
        older = False
        for raw in reversed(lines):
            try:
                e = json.loads(raw)
            except ValueError:
                continue
            t = parse_time(str(e.get("T", ""))) if isinstance(e, dict) else None
            if t is None:
                continue
            if t < since:
                older = True
                break
            seen = True
            ip = str(e.get("IP", ""))
            clients[ip] = max(t, clients.get(ip, t))
        if older or start:  # the window ends in this file, or the read stopped before its start
            break
    return clients, seen


def _verdict(res: dict) -> tuple[bool, str]:
    """(blocked, reason name) from a record's Result. Filtered* reasons (3-8) are blocks; Rewritten*
    (9-11) answer with our address and are not. Without a numeric reason the IsFiltered flag decides
    (older records), and a reason of another type is kept as text."""
    code = res.get("Reason")
    if isinstance(code, int) and not isinstance(code, bool):
        return 3 <= code <= 8, REASONS.get(code, str(code))
    blocked = bool(res.get("IsFiltered"))
    return blocked, REASONS[3 if blocked else 0] if code is None else str(code)[:50]


def _number(v) -> float:
    try:
        return float(v or 0)
    except (TypeError, ValueError):
        return 0.0


def user_rules_from_yaml(text: str) -> list[str] | None:
    """The `user_rules:` list of an AdGuardHome.yaml, in order. AdGuard always writes the key (an
    empty list when there are no rules), so a missing key or a value that is not a list is a file
    we do not understand: None, like unparseable YAML, and callers must not retire anything on it."""
    import yaml  # (setup) here, not at the top: `python3 -m tvgw setup` must start without PyYAML

    try:
        cfg = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    if not isinstance(cfg, dict):
        return None
    rules = cfg.get("user_rules")
    if rules is None:
        return [] if "user_rules" in cfg else None
    return [str(r) for r in rules] if isinstance(rules, list) else None
