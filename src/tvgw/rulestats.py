"""(rule use) What the owner's own rules and each list did for the TV, from the store (design decision 82).

AdGuard Home records, for every lookup, the first rule that decided it and the list that rule came from;
the ingest keeps both (`dns.rule`, `dns.filter_id`). This module counts them, and changes nothing:

- `owner()`: each rule in `LOCAL_RULES` with the lookups it decided in a window (a block: the lookups
  refused under its text; an allow: the lookups answered under it, reason `NotFilteredAllowList`), the
  distinct names among them, and the last time it decided anything in the record. `tvgw rules --local`
  prints it (`owner_lines()`).
- `owner()` also names each allow that let nothing through in the last `STALE_DAYS` days although it was
  in force for all of them, with the command that removes it (`STALE_LINE`). An allow is a hole in the
  protection only when no app needs it any more, which only the owner knows, so nothing here or anywhere
  else removes one on its own.
- `lists()`: per subscribed list (named from AdGuard's settings through `namecheck.list_names`), the
  lookups it refused in a window, the distinct names and its `TOP` most refused names with their
  companies; then the profile's own rules, the owner's and the machine's as three more rows. Every
  refused lookup of the window lands in exactly one row, so the rows add up to the window's refusals.
  `tvgw lists` prints it after the list guard's findings (`list_lines()`), and `--json` under `use`.
- `weekly()`: both for the weekly report's Rule use section (`weekly_lines()`).

How a rule is matched: the store's `rule` is the text of the rule AdGuard names first, cut at 2,000
characters, and AdGuard names a custom rule by the text the plan wrote into `user_rules`, which is the
file's line with its spaces stripped. So an owner's rule matches on that exact text, case and modifier
(`$important`) included, and only among AdGuard's custom rules (`filter_id` 0, or NULL before
2026-11-07): a list that carries the same text never counts as the owner's.
"""

from __future__ import annotations

import contextlib
import json
import re
import sqlite3
from datetime import datetime, timedelta

from tvgw import localrules
from tvgw.config import Settings
from tvgw.names import is_public_name
from tvgw.profile import Profile

DAY = 86400
WINDOWS = (7, 30)  # days: the two windows `tvgw rules --local` shows without --since
STALE_DAYS = 30  # an allow that let nothing through this long, in force all along, is named
TOP = 5  # the names a row of `tvgw lists` gives
FRESH = 7200  # seconds: the record must have been read this close to a window's end (queries.STALE)
ALLOW_REASON = "NotFilteredAllowList"  # adguard.REASONS[1]: an exception rule decided the lookup
# AdGuard's custom rules, every rule tvgw plans: 0, or NULL for a line the log file wrote before
# 2026-11-07 (adguard.list_id)
CUSTOM = "(filter_id IS NULL OR filter_id = 0)"
STALE_LINE = (
    "Your allow of {host} let nothing through in {days} days. If no app needs it any more, remove it:"
    " sudo tvgw unallow {host}"
)
# the rows of `tvgw lists` after the lists, in the plan's order, then the two that appear only when they
# counted something
GROUPS = (
    ("profile", "The profile's own rules"),
    ("local", "Your own rules"),
    ("machine", "The gateway's own rules"),
    ("unplanned", "Rules none of tvgw's files hold now"),
    ("other", "AdGuard Home's own features, or no rule named"),
)
ALWAYS = ("profile", "local", "machine")
# the owner's commands as the change ledger records them (ledger.OWNER_VERBS), by the kind of rule each
# writes or takes out
OWNER_VERBS = {
    "allow": localrules.ALLOW,
    "unallow": localrules.ALLOW,
    "block": localrules.BLOCK,
    "unblock": localrules.BLOCK,
}
_NOTE_DAY = re.compile(r"[!#]\s*(\d{4}-\d{2}-\d{2})\b")


# ---- times and words ---------------------------------------------------------------------------------
def when(t: float | None) -> str:
    return datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M") if t else "-"


def span(seconds: float) -> str:
    """A window's length in words: whole days as days, else hours, else minutes."""
    minutes = round(seconds / 60)
    if minutes and minutes % 1440 == 0:
        n, unit = minutes // 1440, "day"
    elif minutes >= 60:
        n, unit = round(minutes / 60), "hour"
    else:
        n, unit = max(minutes, 1), "minute"
    return f"{n} {unit}{'' if n == 1 else 's'}"


def plural(n: int, word: str) -> str:
    return f"{n:,} {word}{'' if n == 1 else 's'}"


def shown_name(name: str) -> bool:
    """A name a report may print: an internet name, or a title's zone (NAME_HMAC). The home network's own
    names, addresses and malformed names are counted and never printed, as `tvgw refused` does."""
    return is_public_name(name) or name.startswith("<title>.")


# ---- the record --------------------------------------------------------------------------------------
def record(conn: sqlite3.Connection, until: float, db_days: int) -> dict:
    """When the store's record starts and when it was last read, and why it cannot judge an allow unused
    over the `STALE_DAYS` before `until` (`why_not`, plain words), or None when it can."""
    start, last = conn.execute("SELECT MIN(t), MAX(t) FROM ingest_runs").fetchone()
    end = when(until)
    if start is None:
        why = "the gateway has no record yet"
    elif db_days < STALE_DAYS:
        why = f"the gateway keeps only {plural(db_days, 'day')} of its record"
    elif start > until - STALE_DAYS * DAY:
        why = f"the gateway's record starts {when(start)}, less than {STALE_DAYS} days before {end}"
    elif last < until - FRESH:
        why = f"the gateway's record stops at {when(last)}, more than {span(FRESH)} before {end}"
    else:
        why = None
    return {"start": start, "last": last, "why_not": why}


def decided(conn: sqlite3.Connection, texts: list[str], starts: list[float], until: float) -> dict[str, dict]:
    """For each owner's rule text that decided a lookup before `until`: per start in `starts`, the
    lookups it decided in [start, until) and the distinct names among them, and the last time it decided
    one. A block decides a lookup it refused; an allow (`@@`) one AdGuard answered under it. One pass
    over the custom rules' rows: the store has no index on `rule`."""
    if not texts:
        return {}
    cols = ", ".join(
        "COALESCE(SUM(t >= ?), 0), COUNT(DISTINCT CASE WHEN t >= ? THEN qname END)" for _ in starts
    )
    marks = ",".join("?" * len(texts))
    sql = (
        f"SELECT rule, MAX(t), {cols} FROM dns WHERE rule IN ({marks}) AND {CUSTOM} AND t < ?"
        " AND CASE WHEN substr(rule, 1, 2) = '@@' THEN blocked = 0 AND reason = ? ELSE blocked = 1 END"
        " GROUP BY rule"
    )
    params = [x for start in starts for x in (start, start)] + list(texts) + [until, ALLOW_REASON]
    out: dict[str, dict] = {}
    for row in conn.execute(sql, params):
        counts = [{"lookups": row[2 + 2 * i], "names": row[3 + 2 * i]} for i in range(len(starts))]
        out[row[0]] = {"last": row[1], "windows": counts}
    return out


def held_since(conn: sqlite3.Connection, text: str) -> float | None:
    """When AdGuard last took the rule, by the rule history: the first ingest run of its open row."""
    return conn.execute(
        "SELECT MAX(first_seen) FROM rules WHERE kind = 'adguard' AND text = ? AND removed_at IS NULL",
        (text,),
    ).fetchone()[0]


def written_by(note: str) -> float | None:
    """The latest moment the dated comment line above a rule says it was written: the end of its local
    day. None for a line with no date (a hand edit)."""
    m = _NOTE_DAY.match(note.strip())
    if not m:
        return None
    try:
        day = datetime.strptime(m.group(1), "%Y-%m-%d")
    except ValueError:
        return None
    return (day + timedelta(days=1)).timestamp()


def in_force_since(conn: sqlite3.Connection | None, entry: localrules.Entry) -> float | None:
    """From when the rule has been in force at the latest, by every source that dates it (its comment
    line, the rule history), so an allow is never called unused for longer than it can be proven to have
    been there; None when neither dates it."""
    known = [written_by(entry.note)]
    if conn is not None and entry.rule is not None:
        known.append(held_since(conn, entry.rule.text))
    known = [t for t in known if t is not None]
    return max(known) if known else None


# ---- the owner's rules -------------------------------------------------------------------------------
def owner(
    s: Settings, prof: Profile, conn: sqlite3.Connection | None, now: float, since: float | None = None
) -> dict:
    """`tvgw rules --local` as data: every line of `LOCAL_RULES` with its counts, and the allows that let
    nothing through in the `STALE_DAYS` before `now`. `conn` None: no store yet, so no counts. Raises
    PermissionError when the file is there and cannot be read."""
    text = localrules.read_text(s.local_rules)
    starts = [since] if since is not None else [now - days * DAY for days in WINDOWS]
    labels = [f"since {when(since)}"] if since is not None else [f"{days} days" for days in WINDOWS]
    out: dict = {
        "file": s.local_rules,
        "exists": text is not None,
        "until": now,
        "windows": [{"since": t, "label": label} for t, label in zip(starts, labels, strict=True)],
        "stale_days": STALE_DAYS,
        "record": None,
        "rules": [],
        "stale_allows": [],
    }
    if text is None:
        return out
    found = list({e.line: e for e in localrules.entries_of(text)}.values())
    refused = dict(localrules.problems([e.line for e in found], prof))
    stale_start = now - STALE_DAYS * DAY
    use: dict[str, dict] = {}
    if conn is not None:
        texts = [e.rule.text for e in found if e.rule is not None]
        use = decided(conn, texts, [*starts, stale_start], now)
        out["record"] = record(conn, now, s.db_days)
    judged = out["record"] is not None and out["record"]["why_not"] is None
    for e in found:
        rule = e.rule
        counts = use.get(rule.text) if rule is not None else None
        windows = None
        if conn is not None and rule is not None:
            got = counts["windows"] if counts else [{"lookups": 0, "names": 0}] * (len(starts) + 1)
            windows = [{"since": t, **c} for t, c in zip(starts, got, strict=False)]
        since_t = in_force_since(conn, e) if rule is not None else None
        stale = bool(
            judged
            and rule is not None
            and rule.kind == localrules.ALLOW
            and e.line not in refused
            and not (counts and counts["windows"][-1]["lookups"])
            and since_t is not None
            and since_t <= stale_start
        )
        row = {
            "kind": rule.kind if rule else None,
            "name": rule.host if rule else None,
            "line": e.line,
            "written": e.note.lstrip("!# ").strip(),
            "applied": e.line not in refused,
            "not_applied": refused.get(e.line),
            "windows": windows,
            "last": counts["last"] if counts else None,
            "in_force_since": since_t,
            "stale": stale,
        }
        out["rules"].append(row)
        if stale and rule is not None:
            out["stale_allows"].append(
                {
                    "name": rule.host,
                    "line": STALE_LINE.format(host=rule.host, days=STALE_DAYS),
                    "remove": f"sudo tvgw unallow {rule.host}",
                }
            )
    return out


def _table(rows: list[tuple[str, ...]], headers: tuple[str, ...]) -> list[str]:
    widths = [max(len(str(x)) for x in col) for col in zip(headers, *rows, strict=True)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    return [fmt.format(*headers).rstrip(), *(fmt.format(*r).rstrip() for r in rows)]


def owner_lines(rep: dict) -> list[str]:
    """`tvgw rules --local`'s lines: the table, what the counts are, and each unused allow's line."""
    path = rep["file"]
    if not rep["exists"]:
        return [
            f"No site rules: {path} does not exist. sudo tvgw allow NAME lets a name through;"
            " sudo tvgw block NAME blocks one."
        ]
    if not rep["rules"]:
        return [f"No site rules in {path}."]
    labels = tuple(w["label"] for w in rep["windows"])
    rows = []
    for r in rep["rules"]:
        if r["windows"] is None:
            counts = ["-"] * len(labels) + ["-"]
        else:
            counts = [f"{w['lookups']:,}" for w in r["windows"]] + [f"{r['windows'][-1]['names']:,}"]
        last = when(r["last"]) if r["last"] else ("not seen" if r["windows"] is not None else "-")
        if r["not_applied"]:
            state = f"not applied: {r['not_applied']}"
        elif r["stale"]:
            state = f"nothing let through in {rep['stale_days']} days"
        else:
            state = ""
        name = r["name"] if r["name"] else r["line"]
        rows.append((r["kind"] or "?", name, *counts, last, r["written"], state))
    out = _table(rows, ("kind", "name", *labels, "names", "last decided", "written", ""))
    rec = rep["record"]
    if rec is None:
        out += ["", "The gateway has no record yet, so the counts are not known."]
        return out
    names_in = rep["windows"][-1]["label"]
    names_in = f"in the last {names_in}" if not names_in.startswith("since") else names_in
    up_to = f" up to {when(rec['last'])}" if rec["last"] else ""
    out += [
        "",
        f"The counts are the TV's lookups each rule decided, in the gateway's record{up_to}: what a block"
        f" refused and what an allow let through. Names are the different names {names_in}.",
    ]
    out += [x["line"] for x in rep["stale_allows"]]
    allows = [r for r in rep["rules"] if r["kind"] == localrules.ALLOW and r["applied"]]
    if allows and rec["why_not"]:
        out.append(f"No allow is called unused yet: {rec['why_not']}.")
    return out


# ---- what each list did ------------------------------------------------------------------------------
def _adguard(s: Settings) -> tuple[dict | None, str | None]:
    """AdGuard's settings, or None with why in plain words."""
    import yaml

    from tvgw import adguardcfg

    try:
        cfg = adguardcfg.load_yaml(s.adguard_yaml)
    except FileNotFoundError:
        return None, f"AdGuard Home's settings file {s.adguard_yaml} is not there"
    except PermissionError:
        return None, "this account cannot read AdGuard Home's settings file; run it with sudo for the names"
    except (OSError, yaml.YAMLError) as e:
        return None, f"AdGuard Home's settings file could not be read ({type(e).__name__})"
    if not isinstance(cfg, dict):
        return None, "AdGuard Home's settings file holds no settings"
    return cfg, None


def subscribed(cfg: dict) -> list[tuple[int, str]]:
    """(id, URL) of each list AdGuard's settings have switched on, in their order."""
    out = []
    entries = cfg.get("filters")
    for f in entries if isinstance(entries, list) else []:
        fid = f.get("id") if isinstance(f, dict) else None
        if isinstance(fid, int) and not isinstance(fid, bool) and f.get("enabled") is True:
            out.append((fid, str(f.get("url") or "")))
    return out


def owner_texts(s: Settings, conn: sqlite3.Connection, notes: list[str]) -> list[str]:
    """Every rule text the owner's commands wrote: the file's lines now, and each one the change ledger
    says an owner's command wrote or took out, so a rule removed within the window still counts as the
    owner's."""
    out: list[str] = []
    try:
        out += [e.line for e in localrules.entries(s.local_rules)]
    except OSError as e:
        notes.append(
            f"Your own rules file could not be read ({type(e).__name__}), so the record alone names them."
        )
    rows = conn.execute(
        "SELECT subject, detail FROM changes WHERE source = 'owner' AND kind = 'owner_rule_change'"
    ).fetchall()
    for host, detail in rows:
        try:
            action = json.loads(detail or "{}").get("action")
        except (ValueError, AttributeError):
            continue
        kind = OWNER_VERBS.get(action) if isinstance(action, str) else None
        rule = localrules.parse(localrules.Rule(kind, str(host)).text) if kind else None
        if rule is not None:
            out.append(rule.text)
    return out


def machine_texts(s: Settings, conn: sqlite3.Connection, notes: list[str]) -> list[str]:
    """Every rule the machine applied: its file now, and every one the store records (reverted ones
    included)."""
    from tvgw import autoblock

    out: list[str] = []
    try:
        out += autoblock.read_rules(s.auto_rules)
    except OSError as e:
        notes.append(
            f"The gateway's own rules file could not be read ({type(e).__name__}), so the record alone"
            " names them."
        )
    out += [r for (r,) in conn.execute("SELECT rule FROM auto_rules")]
    return out


def groups(s: Settings, prof: Profile, conn: sqlite3.Connection, notes: list[str]) -> dict[str, str]:
    """Each custom rule text by whose it is, in the plan's order: a text an earlier group holds stays
    that group's, as `adguardcfg.rule_groups` keeps it."""
    out: dict[str, str] = {}
    for name, texts in (
        ("profile", prof.adguard_rules(s.gw_ip, s.tv_ip)),
        ("local", owner_texts(s, conn, notes)),
        ("machine", machine_texts(s, conn, notes)),
    ):
        for text in texts:
            out.setdefault(text, name)
    return out


def _has_sentinel(url: str, prof: Profile) -> bool:
    from tvgw import verify

    return bool(prof.filter_sentinels.get(url)) or any(piece in url for piece, _ in verify.SENTINELS)


@contextlib.contextmanager
def _one_read(conn: sqlite3.Connection):
    """One read transaction around the statements inside, unless the caller holds one already."""
    if conn.in_transaction:
        yield
        return
    conn.execute("BEGIN")
    try:
        yield
    finally:
        conn.rollback()  # it only read


def lists(s: Settings, prof: Profile, conn: sqlite3.Connection, since: float, until: float) -> dict:
    """`tvgw lists` as data: per subscribed list, then the profile's, the owner's and the machine's
    rules, the lookups refused in [since, until), the distinct names and the most refused names."""
    from tvgw import companies, namecheck

    notes: list[str] = []
    cfg, why = _adguard(s)
    names = namecheck.list_names(cfg, prof) if cfg is not None else {}
    on = subscribed(cfg) if cfg is not None else []
    by_text = groups(s, prof, conn, notes)
    tally: dict[tuple, dict[str, int]] = {}
    with _one_read(conn):  # the total and the rows from one state of the store, while the ingest writes
        lookups, total = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(blocked), 0) FROM dns WHERE t >= ? AND t < ?", (since, until)
        ).fetchone()
        for fid, rule, qname, n in conn.execute(
            "SELECT filter_id, CASE WHEN filter_id > 0 THEN NULL ELSE rule END, qname, COUNT(*) FROM dns"
            " WHERE t >= ? AND t < ? AND blocked = 1 GROUP BY 1, 2, 3",
            (since, until),
        ):
            if isinstance(fid, int) and fid > 0:
                key: tuple = ("list", fid)
            elif rule is None or (isinstance(fid, int) and fid < 0):
                key = ("other",)
            else:
                key = (by_text.get(rule, "unplanned"),)
            per = tally.setdefault(key, {})
            per[qname] = per.get(qname, 0) + n
    rows = []

    def row(key: tuple, source: str, label: str, **extra) -> dict:
        per = tally.get(key, {})
        ranked = sorted(((n, q) for q, n in per.items() if shown_name(q)), key=lambda x: (-x[0], x[1]))
        top = [{"name": q, "lookups": n, "company": companies.company(q)} for n, q in ranked[:TOP]]
        return {
            "source": source,
            "label": label,
            **extra,
            "refused": sum(per.values()),
            "names": len(per),
            "top": top,
        }

    seen_ids = {k[1] for k in tally if k[0] == "list"}
    for fid, url in on:
        rows.append(
            row(
                ("list", fid),
                "list",
                names.get(fid, f"list {fid}"),
                id=fid,
                sentinel=_has_sentinel(url, prof),
            )
        )
    for fid in sorted(
        seen_ids - {fid for fid, _ in on}, key=lambda f: (-sum(tally[("list", f)].values()), f)
    ):
        label = f"{names[fid]} (no longer subscribed)" if fid in names and cfg is not None else f"list {fid}"
        rows.append(row(("list", fid), "list", label, id=fid, sentinel=False))
    for name, label in GROUPS:
        if name in ALWAYS or (name,) in tally:
            rows.append(row((name,), name, label))
    if cfg is None:
        notes.insert(
            0,
            f"The lists are shown by AdGuard Home's number for them, and a list that refused nothing is"
            f" not shown: {why}.",
        )
    if companies.trouble():
        notes.append(f"The company names could not be read, so none is shown ({companies.trouble()}).")
    return {
        "since": since,
        "until": until,
        "lookups": lookups,
        "refused": total,
        "named": cfg is not None,
        "rows": rows,
        "notes": notes,
    }


def list_lines(rep: dict) -> list[str]:
    """`tvgw lists`' lines: the window, then one sentence per row, each with its most refused names."""
    out = [
        f"From {when(rep['since'])} to {when(rep['until'])} ({span(rep['until'] - rep['since'])}),"
        f" the filter refused {plural(rep['refused'], 'lookup')} of the TV's {rep['lookups']:,}."
    ]
    for r in rep["rows"]:
        if not r["refused"]:
            hint = " sudo tvgw verify checks that it is loaded." if r.get("sentinel") else ""
            out.append(f"{r['label']} refused nothing the TV asked for.{hint}")
            continue
        out.append(f"{r['label']} refused {plural(r['refused'], 'lookup')} of {plural(r['names'], 'name')}.")
        width = max(len(f"{t['lookups']:,}") for t in r["top"]) if r["top"] else 0
        for t in r["top"]:
            company = f" ({t['company']})" if t["company"] else ""
            out.append(f"  {t['lookups']:>{width},}  {t['name']}{company}")
    return out + rep["notes"]


# ---- the weekly report -------------------------------------------------------------------------------
def weekly(s: Settings, prof: Profile, conn: sqlite3.Connection, since: float, until: float) -> dict:
    """The weekly report's Rule use: the owner's allows unused in the `STALE_DAYS` before the week's
    end, and what each list did in the week."""
    rep = owner(s, prof, conn, until)
    allows = [r for r in rep["rules"] if r["kind"] == localrules.ALLOW and r["applied"]]
    why = rep["record"]["why_not"] if rep["record"] else None
    return {
        "allows": len(allows),
        # the allows that let something through in the 30 days (the last window `owner` counted)
        "allows_used": sum(1 for r in allows if r["windows"] and r["windows"][-1]["lookups"]),
        "stale_allows": rep["stale_allows"],
        "stale_not_judged": why if allows else None,
        "lists": lists(s, prof, conn, since, until),
    }


def weekly_lines(sec: dict) -> list[str]:
    out = [x["line"] for x in sec["stale_allows"]]
    if sec["stale_not_judged"]:
        out.append(f"No allow is called unused yet: {sec['stale_not_judged']}.")
    elif sec["allows"] and sec["allows_used"] == sec["allows"]:
        out.append(f"Each of your allows let something through in the last {STALE_DAYS} days.")
    return out + list_lines(sec["lists"])
