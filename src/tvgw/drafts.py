"""(requests) `tvgw requests`: the companies the TV reached, against the ones it only tried to reach, and
plain-text drafts of a data-access request to each company it reached, for the owner to send, or not,
themselves (design decision 75).

What counts as reached is what the record shows: a connection whose TLS hello named one of the company's
names, or a plain-HTTP request to one. A company whose every lookup the filter refused, with no such
connection, was only attempted: the TV sent it nothing through this gateway, so no request is drafted
for it. A company whose names were looked up and answered with no named connection is listed apart,
since the record cannot say whether the TV reached it (a connection with no captured hello, or none).
The company behind a name is the shipped snapshot's (`companies.company()`); a name it does not know is
counted under its registrable domain, never guessed.

A draft identifies the household to the company it is sent to: to answer, the company must find the
data, and so must be told who is asking. Each draft says so before anything else, names what would
identify the household, and fills nothing in: every identifier is a placeholder the owner chooses to
replace. tvgw never sends a draft, never looks up a company's address, and opens no connection; the
drafts are files under `<STATE_DIR>/requests/` (0600 in 0700 directories), which `tvgw forget` deletes,
or in a directory `--out` names, which it does not reach.
"""

from __future__ import annotations

import os
import re
import sqlite3
from datetime import datetime

from tvgw import companies
from tvgw.names import is_public_name, registrable_domain
from tvgw.profile import Profile

DIR = "requests"  # under STATE_DIR; forget.STATE_ENTRIES deletes it
DEFAULT_DAYS = 30
SHOWN_NAMES = 12  # names a draft lists per company before "and N more"
REACHED, ANSWERED, ATTEMPTED = "reached", "answered", "attempted"
NOTICE = "README.txt"


def _company_key(name: str) -> tuple[str, bool]:
    """(company, known): the snapshot's company, or the registrable domain when it knows none."""
    who = companies.company(name)
    return (who, True) if who else (registrable_domain(name), False)


def observed(conn: sqlite3.Connection, profile: Profile, a: float, b: float) -> dict:
    """Per company, over [a, b): the domains the TV reached (named connections and plain-HTTP requests, by
    local day), and its lookups answered and refused. Three lists: `reached`, `answered` (looked up and
    answered, no named connection) and `attempted` (every lookup refused, no named connection); and
    `unknown`, the reached registrable domains no company in the snapshot covers."""
    acc: dict[str, dict] = {}

    def entry(name: str) -> dict | None:
        if not name or not is_public_name(name):
            return None
        who, known = _company_key(name)
        return acc.setdefault(
            who,
            {"company": who, "known": known, "domains": {}, "connections": 0, "answered": 0, "refused": 0,
             "categories": set()},
        )  # fmt: skip

    for t, sni in conn.execute("SELECT t, sni FROM tls WHERE t >= ? AND t < ?", (a, b)):
        e = entry(sni)
        if e is None:
            continue
        d = registrable_domain(sni)
        e["connections"] += 1
        e["domains"].setdefault(d, set()).add(datetime.fromtimestamp(t).strftime("%Y-%m-%d"))
        e["categories"].add(profile.categorize(sni))
    for t, host in conn.execute("SELECT t, host FROM http WHERE t >= ? AND t < ?", (a, b)):
        e = entry(host or "")
        if e is None:
            continue
        e["connections"] += 1
        e["domains"].setdefault(registrable_domain(host), set()).add(
            datetime.fromtimestamp(t).strftime("%Y-%m-%d")
        )
        e["categories"].add(profile.categorize(host))
    refused_names: dict[str, set[str]] = {}
    for qname, blocked, n in conn.execute(
        "SELECT qname, blocked, COUNT(*) FROM dns WHERE t >= ? AND t < ? GROUP BY qname, blocked", (a, b)
    ):
        e = entry(qname)
        if e is None:
            continue
        e["refused" if blocked else "answered"] += n
        e["categories"].add(profile.categorize(qname))
        if blocked:
            refused_names.setdefault(e["company"], set()).add(registrable_domain(qname))
    out: dict[str, list] = {REACHED: [], ANSWERED: [], ATTEMPTED: [], "unknown": []}
    for e in acc.values():
        e["refused_domains"] = sorted(refused_names.get(e["company"], set()) - set(e["domains"]))
        e["categories"] = sorted(e["categories"])
        e["domains"] = {d: sorted(days) for d, days in sorted(e["domains"].items())}
        if e["connections"] and e["known"]:
            out[REACHED].append(e)
        elif e["connections"]:
            out["unknown"].append(e)
        elif not e["known"]:
            continue
        elif e["answered"]:
            out[ANSWERED].append(e)
        elif e["refused"]:
            out[ATTEMPTED].append(e)
    out[REACHED].sort(key=lambda e: (-e["connections"], e["company"]))
    out["unknown"].sort(key=lambda e: (-e["connections"], e["company"]))
    out[ANSWERED].sort(key=lambda e: (-e["answered"], e["company"]))
    out[ATTEMPTED].sort(key=lambda e: (-e["refused"], e["company"]))
    return {"since": a, "until": b, **out}


def _n(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _day(t: float) -> str:
    return datetime.fromtimestamp(t).strftime("%Y-%m-%d")


def render(r: dict) -> list[str]:
    """The lists, in plain words."""
    a, b = _day(r["since"]), _day(r["until"])
    lines = [
        f"Companies the TV reached, {a} to {b}, from the gateway's own record. Nothing was sent anywhere."
    ]
    if not r[REACHED]:
        lines.append("Reached: none the gateway's list of companies knows.")
    else:
        lines.append(f"Reached ({len(r[REACHED])}): a connection named one of the company's names.")
        for e in r[REACHED]:
            lines.append(f"  {e['company']}: {_n(e['connections'], 'connection')}, {', '.join(e['domains'])}")
    if r[ATTEMPTED]:
        lines.append(
            f"Only attempted ({len(r[ATTEMPTED])}): the filter refused every lookup and the gateway saw no"
            " connection, so the TV sent these nothing through it."
        )
        for e in r[ATTEMPTED]:
            lines.append(f"  {e['company']}: {_n(e['refused'], 'lookup')} refused")
    if r[ANSWERED]:
        lines.append(
            f"Looked up, no connection seen ({len(r[ANSWERED])}): the filter answered, and the record shows"
            " no named connection, so it cannot say whether the TV reached these."
        )
        for e in r[ANSWERED]:
            lines.append(f"  {e['company']}: {_n(e['answered'], 'lookup')} answered")
    if r["unknown"]:
        lines.append(
            f"The TV also reached {_n(len(r['unknown']), 'site')} whose company the gateway's list does not"
            " know; --json lists them."
        )
    return lines


# ---- the drafts --------------------------------------------------------------------------------------
BEFORE = """Before you send it

- tvgw wrote this draft from what your gateway recorded. tvgw never sends a draft. Send it
  yourself only if you want to.
- To answer, {company} has to find your data, so it has to know who is asking. Anything you add
  below tells {company} who you are and that this household owns this TV: your name, your email
  address, the account you signed in with on the TV, and the TV's model and serial number. tvgw
  filled in none of them. Replace only the ones you choose to give.
- The paragraph that begins "What my TV did" tells {company} that a gateway watched your TV's
  traffic. Delete it if you would rather not say that.
- Companies may ask you to prove who you are, and may answer in part or not at all.
- Find {company}'s privacy contact on its own website. tvgw does not know it.
- This is a template, not legal advice.
"""

LETTER = """To: <the privacy contact of {company}>
Subject: Request for a copy of my personal data

Hello,

I ask for a copy of the personal data you hold about me and my television, under the data
protection law that applies to me (for example, the California Consumer Privacy Act or the EU
General Data Protection Regulation). Please tell me:

1. what personal data you hold about me or my television, including viewing, usage and device data;
2. where you got it, and why you use it;
3. who you have shared or sold it to;
4. how long you keep it.

What my TV did: from {since} to {until}, my television connected to these names of yours on the
days shown:
{names}
{refused}
To find my data, you may use: <your name>, <the email address of your account>, <the TV's model and
serial number>.

Thank you,
<your name>
"""


def draft(e: dict, since: str, until: str) -> str:
    """One company's draft: the warning first, then the letter. Placeholders only, never an identifier."""
    shown = list(e["domains"].items())[:SHOWN_NAMES]
    names = "\n".join(f"- {d} ({len(days)} {'day' if len(days) == 1 else 'days'})" for d, days in shown)
    if len(e["domains"]) > SHOWN_NAMES:
        names += f"\n- and {len(e['domains']) - SHOWN_NAMES} more"
    refused = ""
    if e["refused_domains"]:
        listed = ", ".join(e["refused_domains"][:SHOWN_NAMES])
        refused = f"\nIt also tried to look up these names of yours, which my gateway refused: {listed}.\n"
    head = f"DRAFT: a request to {e['company']} for the personal data it holds about you\n\n"
    body = LETTER.format(company=e["company"], since=since, until=until, names=names, refused=refused)
    return head + BEFORE.format(company=e["company"]) + "\n----------\n\n" + body


def notice(r: dict, paths: list[str]) -> str:
    """The README.txt beside the drafts: what they are, and the warning, once more."""
    since, until = _day(r["since"]), _day(r["until"])
    out = [
        f"Drafts of data-access requests, written by tvgw from your gateway's record of {since} to {until}.",
        "",
        "tvgw never sends a draft. Each draft identifies your household to its company once you add",
        "your details and send it. Read the warning at the top of each one before you do.",
        "",
        "Drafts, one per company the TV reached:",
        *[f"  {os.path.basename(p)}" for p in paths],
    ]
    if r[ATTEMPTED]:
        out += [
            "",
            "No draft for these companies: the gateway refused every lookup of their names and saw no",
            "connection to them, so the TV sent them nothing through it:",
            *[f"  {e['company']}" for e in r[ATTEMPTED]],
        ]
    return "\n".join(out) + "\n"


def slug(company: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", company.lower()).strip("-")[:40] or "company"


def default_dir(state_dir: str, now: float) -> str:
    """`<STATE_DIR>/requests/<day>`, or `<day>-2`, `-3` ... when a run that day already wrote one."""
    base = os.path.join(state_dir, DIR, _day(now))
    path, n = base, 1
    while os.path.exists(path):
        n += 1
        path = f"{base}-{n}"
    return path


class NotEmpty(Exception):
    """The directory to write into holds files already: tvgw writes drafts only into a new or empty one."""


def write(r: dict, out_dir: str) -> list[str]:
    """Write one draft per reached company and the notice into `out_dir`, made 0700 when absent and refused
    when it holds anything; each file 0600. Returns the drafts' paths."""
    if os.path.isdir(out_dir) and os.listdir(out_dir):
        raise NotEmpty(out_dir)
    parent = os.path.dirname(os.path.abspath(out_dir))
    if not os.path.isdir(parent):  # `requests/` itself: its day names say when drafts were made
        os.makedirs(parent, mode=0o700)
    os.makedirs(out_dir, mode=0o700, exist_ok=True)
    since, until = _day(r["since"]), _day(r["until"])
    paths = []
    for i, e in enumerate(r[REACHED], 1):
        path = os.path.join(out_dir, f"{i:02d}-{slug(e['company'])}.txt")
        _write(path, draft(e, since, until))
        paths.append(path)
    _write(os.path.join(out_dir, NOTICE), notice(r, paths))
    return paths


def _write(path: str, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
