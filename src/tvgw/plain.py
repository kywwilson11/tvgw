"""(plain) The plain brief: one day in plain words, for a reader who gives it five seconds.

`plain_brief(o, activity, update)` turns the dict `queries.brief()` returns into seven lines: a title,
Protection, The TV, Blocked most, New, Action, and a footer pointing at the engineering brief (design
decision 58), with a `Not checked:` line after the Action for each sentence of a report that carries a
`not_checked` list. It reads nothing but its arguments and (companies) the snapshot of AdGuard's companies
database shipped in the package, which names the company behind a new service where it knows it, so
the same day gives the same lines. After the TV notes come (tripwire) a `While off:` line on a day the
TV went online between two readings that found it off, and (budget) an `Uploads:` line on a day with an
hour over the upload budget (design decision 66); neither is ever an action.

Red lines come in three tiers (`TIERS`): `act` needs a person at the TV or the router, `doctor` is the
gateway's own trouble, which `sudo tvgw doctor` explains where this version has it (`doctor_action()`),
and `detail` stays in the full brief. Every line `queries.red_lines()` writes has a row in
`RED_LINE_PLAIN` (tests/unit/test_plain.py holds the two to each other); a line no row matches is
`doctor`, never `detail`, so a red line added later can never vanish from the plain view. The full brief
keeps every line as it was.
"""

from __future__ import annotations

import argparse
import functools
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta

from tvgw import companies, threats
from tvgw.lgwebos import ACR_KEY
from tvgw.namebound import named_shares
from tvgw.names import registrable_domain
from tvgw.profile import OTHER, PrivacySetting, Profile
from tvgw.queries import AWAKE, REPEAT_DAYS

TIERS = ("act", "doctor", "detail")
UNKNOWN_TIER = "doctor"  # a red line no row names: the gateway's own trouble until a row says otherwise
DOCTOR = "doctor"  # the action of the gateway's own trouble: doctor_action() says it
# an action that is the profile's menu path for its ACR switch ([[privacy_setting]] records)
MENU_ACR = "menu:acr"
GENERIC_SETTING = "On the TV: turn this setting off (tvgw brief --full names it)."
FOOTER = "Engineering report: tvgw brief --full"
FIRST_DAY = "Your first brief is ready tomorrow morning."
NOTHING = "nothing needs your attention."
STORE_DAY = 86400  # seconds: a store younger than this has no whole day to tell about
# the sources a profile without a LAN-API reader never has (ingest.OPTIONAL_SOURCES), and verify, which
# the Protection line already reports: neither makes the record "missing"
NOT_A_GAP = ("tvstate", "verify")
SHOWN_NAMES = 3  # registrable domains named on the New line before "and N more"
HELD_ALL_DAY = 0.9  # share of the owed self-checks that makes "all day" true
# power readings that say nothing about the TV: nobody asked (not paired), or the answer had none
NO_READING = ("unknown", "", None)

# (red-line prefix, tier, plain sentence, action), in the order queries.red_lines() writes them. An
# action is a sentence, DOCTOR (doctor_action()), MENU_ACR (the profile's menu path for its ACR switch),
# or "" for detail.
RED_LINE_PLAIN: tuple[tuple[str, str, str, str], ...] = (
    ("must-allow name blocked:", "doctor", "Something the TV needs in order to work was blocked.", DOCTOR),
    (
        "a list update newly blocks",
        "act",
        "A blocklist update started blocking a service the TV downloaded from, so an app may have"
        " stopped working.",
        "If one did, the full report names the service and how to let it through (tvgw brief --full).",
    ),
    # (listguard) a subscribed list's line that acts on the TV's own rules (design decision 68): nothing at
    # the TV or the router puts it right, so it stays in the engineering brief with the list and the rule
    ("a list can refuse what the TV needs:", "detail", "", ""),
    ("a list lifts", "detail", "", ""),
    ("Live Plus (ACR) is", "act", "Live Plus (LG's viewing-data collection) is on.", MENU_ACR),
    (
        "TV has a second network path:",
        "act",
        "The TV's Wi-Fi, or another of its radios, is on, so it can reach the internet around the gateway.",
        # the words of verify.PLAIN["tv_paths"]: the same fix wherever the reader meets it (test_plain.py)
        "On the TV: switch Wi-Fi off, forget every saved network, and switch off Wi-Fi Direct and any"
        " tethering.",
    ),
    # (threats) a name on a threat list that the filter answered (design decision 80): what the household
    # can do is at the TV, and the plain brief's Known-bad line names the name, never action.txt
    (
        threats.RED_LINE,
        "act",
        "The TV looked up a name on a list of known malware and botnet servers, and the gateway let it"
        " through. This can mean the TV or an app on it is infected, but such lists are sometimes wrong.",
        "If you installed an app recently, remove it. Look for a TV software update. If this is an"
        " inexpensive streaming box, unplug it until you know more.",
    ),
    # (threats) the list names a service the TV uses on purpose, or many at once: the list's error, which the
    # doctor explains (threats.doctor_notes()), never a reason to send the household to the TV
    (
        "threat list may be wrong:",
        "doctor",
        "A list of malware servers names services the TV uses on purpose, or many at once, so the list is"
        " probably wrong. Nothing was blocked.",
        DOCTOR,
    ),
    # (pass 4) the clock rows say what the gateway saw, a lookup blocked or none at all, never what the TV
    # did with its clock, which the gateway cannot see: a TV may also set it by NTP, which the count of its
    # clock servers shows, and the line then says so
    (
        "clock host lookups blocked:",
        "doctor",
        "The gateway blocked the TV's lookups of its clock service, so its clock may be wrong and its apps"
        " may fail to connect.",
        DOCTOR,
    ),
    (
        "TV was on but never looked up its clock host, though it sent",
        "doctor",
        "The gateway saw no lookup of the TV's clock service while the TV was on, though the TV asked a time"
        " server, so its clock may still be right.",
        DOCTOR,
    ),
    (
        "TV was on but never looked up its clock host",
        "doctor",
        "The gateway saw no lookup of the TV's clock service while the TV was on.",
        DOCTOR,
    ),
    ("firewall checks failed", "doctor", "The gateway's self-check failed at least once.", DOCTOR),
    ("firewall checks ran", "doctor", "The gateway's self-check did not run as often as it should.", DOCTOR),
    (
        "ACR-shaped upload:",
        "act",
        "The TV sent what looks like screen fingerprints to the internet.",
        MENU_ACR,
    ),
    (
        "ACR port attempts:",
        "act",
        "The TV tried to send viewing data on ports the gateway keeps closed, and was stopped.",
        MENU_ACR,
    ),
    ("Encrypted ClientHello in", "detail", "", ""),
    ("the Pi's own lookups left outside the VPN:", "detail", "", ""),
    # (reliability) the gateway's own hardware (design decision 73): never the TV's trouble, the doctor's
    (
        "gateway hardware:",
        "doctor",
        "The gateway's own hardware reported trouble: it slowed itself down, or a disk or a USB device"
        " reported errors.",
        DOCTOR,
    ),
    (
        "TV agreement ",
        "act",
        # (W12) the per-document record names the agreement; accepted at the remote or by a software update
        "One of the TV's data agreements was accepted, at the remote or by a software update.",
        "On the TV: open its privacy or user-agreement settings and decline it again (tvgw brief --full"
        " names it).",
    ),
    (
        "TV consent flag",
        "act",
        # the red line's own words: accepted at the remote or by a software update, never only "someone"
        "One of the TV's data agreements was accepted, at the remote or by a software update.",
        "On the TV: open its privacy or user-agreement settings and decline it again (tvgw brief --full"
        " names it).",
    ),
    ("machine rule ", "detail", "", ""),
    ("TV was on but no ", "doctor", "Part of the gateway's record stopped while the TV was on.", DOCTOR),
    ("ingest warnings:", "detail", "", ""),
)
MISSING_RECORD = ("doctor", "Part of the day's record was not read, so this brief may be incomplete.", DOCTOR)
# (uplink) the router handed the gateway a new address (the change ledger's wan_addr_change): every stream the
# TV had open was cut (2026-11-02, 19:46), and a reservation on the router is the fix, so a person at the
# router acts. No name, address or time goes into it: it can be the login message's action
RESERVE_ACTION = "To stop this, reserve this computer's address in your router's settings."

# plain names for the categories every profile shares; a profile's [category_labels] overrides any
CATEGORY_PLAIN: dict[str, str] = {
    "ACR": "viewing trackers (ACR)",
    "3rd-party ads": "other advertisers",
    "Voice": "voice services",
    "Streaming": "streaming",
    "FAST": "free channels",
    "Infra": "internet plumbing",
    OTHER: "other services",
}
# a vendor's own categories by their last word: "LG telemetry" is "LG usage reporting"
SUFFIX_PLAIN: dict[str, str] = {
    "ads": "{vendor} advertising",
    "telemetry": "{vendor} usage reporting",
    "fingerprint": "device fingerprinting",
    "IoT": "smart-home links",
    "core": "{vendor}'s own services",
}
# the categories that are "known tracking services": blocked by definition, never the TV's job
TRACKING_SUFFIXES = ("ads", "telemetry", "fingerprint")
_ACR_WORDS = re.compile(r"\bACR\b|content recognition", re.IGNORECASE)
WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
MONTHS = (
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
)  # fmt: skip


@dataclass(frozen=True)
class Activity:
    """How long the TV was on in the day: from its own hourly readings, or estimated from its traffic."""

    hours: float
    estimated: bool = False


def tier(line: str) -> tuple[str, str, str]:
    """(tier, plain sentence, action) for one red line; a line no row names is UNKNOWN_TIER, with a
    sentence that says the full brief has it."""
    for prefix, t, sentence, action in RED_LINE_PLAIN:
        if line.startswith(prefix):
            return t, sentence, action
    return UNKNOWN_TIER, "The gateway raised an alarm this brief has no plain words for.", DOCTOR


def category_label(cat: str, prof: Profile | None = None) -> str:
    """A category in plain words: the profile's [category_labels] first, then the shared names, then a
    vendor category by its last word; anything else as the profile names it."""
    if prof is not None and cat in prof.category_labels:
        return prof.category_labels[cat]
    if cat in CATEGORY_PLAIN:
        return CATEGORY_PLAIN[cat]
    vendor, _, last = cat.rpartition(" ")
    if vendor and last in SUFFIX_PLAIN:
        return SUFFIX_PLAIN[last].format(vendor=vendor)
    return cat


def is_tracking(cat: str) -> bool:
    """Whether a category is known tracking: ACR (and a suspected ACR category), ads, telemetry and
    fingerprinting, the vendor's own and everyone else's."""
    return cat.startswith("ACR") or cat == "3rd-party ads" or cat.rpartition(" ")[2] in TRACKING_SUFFIXES


def acr_setting(prof: Profile | None) -> PrivacySetting | None:
    """The profile's ACR switch: the record the LAN API reads by `ACR_KEY`, else the first whose
    `controls` names ACR; a verified one before the rest, then the file's order (on LG, the reference
    generation's menu)."""
    records = prof.privacy_settings if prof is not None else ()
    pool = [r for r in records if r.key == ACR_KEY] or [r for r in records if _ACR_WORDS.search(r.controls)]
    verified = [r for r in pool if r.provenance.status == "verified"]
    return (verified or pool or [None])[0]


@functools.lru_cache(maxsize=1)
def doctor_action() -> str:
    """`Run sudo tvgw doctor.` once this version has the command, which explains each check that did not
    pass and offers its fix; until then `Run sudo tvgw verify.`, whose FAIL lines say what is wrong. The
    plain brief names only commands this version has (tests/unit/test_plain.py)."""
    from tvgw import cli  # here: cli imports this module inside its commands

    commands = next(
        (a.choices for a in cli.build_parser()._actions if isinstance(a, argparse._SubParsersAction)), {}
    )
    return "Run sudo tvgw doctor." if "doctor" in commands else "Run sudo tvgw verify."


def action_text(action: str, prof: Profile | None) -> str:
    """The action as the reader gets it: a menu path from the profile, the command for the gateway's
    own trouble, or the row's own sentence."""
    if action == DOCTOR:
        return doctor_action()
    if action != MENU_ACR:
        return action
    setting = acr_setting(prof)
    if setting is None:
        return GENERIC_SETTING
    return f"On the TV: {setting.menu[0][1]}: {setting.recommended}."


def activity_from_readings(o: dict) -> Activity | None:
    """Hours on from the TV's hourly readings in the brief (`tvstate`): the clock hours with a reading
    that says the TV was on. A deploy or a reading by hand adds readings between the hourly ones, so
    readings count by their hour, never one by one. None when no reading says anything (no LAN-API
    reader, or nothing was asked)."""
    known = [r for r in o.get("tvstate") or [] if r.get("power") not in NO_READING]
    if not known:
        return None
    return Activity(hours=float(len({_hour(r) for r in known if r["power"] in AWAKE})))


def _hour(reading: dict) -> str:
    """A reading's clock hour, from the time the report formats for it (`HH:MM`, or `MM-DD HH:MM` in a
    window over a day): the readings of one hour share it."""
    return str(reading.get("time", "")).rpartition(":")[0]


def first_day(first_ingest: float | None, now: float) -> bool:
    """A store younger than a day, or one nothing has ingested yet, has no whole day to tell about."""
    return first_ingest is None or now - first_ingest < STORE_DAY


def _n(x: int) -> str:
    return f"{x:,}"


def _plural(n: int, word: str) -> str:
    return f"{_n(n)} {word if n == 1 else word + 's'}"


def _title(o: dict) -> str:
    day = o.get("day")
    if not day:
        return f"tvgw brief, {o.get('label', '')}"
    d = date.fromisoformat(day)
    hours = round((o.get("until", 0) - o.get("since", 0)) / 3600) if "until" in o else 24
    made = o.get("generated")
    yesterday = made is not None and d == datetime.fromtimestamp(made).date() - timedelta(days=1)
    when = f"{WEEKDAYS[d.weekday()]} {d.day} {MONTHS[d.month - 1]}"
    if yesterday:
        return f"tvgw brief, {when} (yesterday, {_plural(hours, 'hour')})"
    return f"tvgw brief, {when} {d.year} ({_plural(hours, 'hour')})"


def _gaps(o: dict) -> list[str]:
    return [s for s in (o.get("coverage") or {}).get("not_assessed", []) if s not in NOT_A_GAP]


def _protection(o: dict) -> str:
    fw = o.get("firewall") or {}
    runs, failed, expected = fw.get("runs", 0), fw.get("failed", 0), fw.get("expected", 0)
    if not runs:
        line = "Protection: not checked (the gateway recorded no self-checks)."
    elif not failed:
        held = "held all day" if runs >= HELD_ALL_DAY * expected else "held whenever it was checked"
        line = f"Protection: {held} ({_n(runs)} of {_plural(runs, 'check')} passed)."
    elif failed * 2 > runs:
        line = f"Protection: failed for most of the day ({_n(failed)} of {_plural(runs, 'check')} failed)."
    else:
        line = f"Protection: held most of the day ({_n(failed)} of {_plural(runs, 'check')} failed)."
    if _gaps(o):
        line += " Part of the day's record is missing."
    return line


def _the_tv(o: dict, activity: Activity | None) -> str:
    """The TV line. Its tracking half counts lookups of names in the known tracking categories, which is
    all the wire shows: ads a server stitches into the stream, an app's own logging and matching by the
    home's address never reach it (docs/what-it-stops.md), so a day with none says "by name" and never
    that there was no tracking (tests/unit/test_plain.py holds every form of the brief to that)."""
    cats = o.get("categories") or []
    asked = sum(c.get("lookups", 0) for c in cats if is_tracking(c["category"]))
    refused = sum(c.get("blocked", 0) for c in cats if is_tracking(c["category"]))
    if not asked:
        tracking = "asked for no known tracking service by name."
    elif refused == asked:
        tracking = f"asked for known tracking services {_plural(asked, 'time')}; every one was refused."
    else:
        tracking = (
            f"asked for known tracking services {_plural(asked, 'time')}; {_n(refused)} were refused and"
            f" {_n(asked - refused)} answered (tvgw brief --full lists them)."
        )
    named = _named(o)
    if activity is None:
        return f"The TV: {tracking}{named}"
    hours = round(activity.hours)
    if not hours:
        on = "off at every hourly check"
    else:
        on = f"on about {_plural(hours, 'hour')}"
        if activity.estimated:
            on += " (estimated from its traffic)"
    return f"The TV: {on}. It {tracking}{named}"


def _named(o: dict) -> str:
    """(namebound) The clause that says how much of what the TV sent the gateway could put a name to: by
    the name in the connection's own hello, and apart from it, the share only the TV's lookups point to
    (a single service's answers for the address; design decision 70). Rounded down, so it never claims
    more; nothing on a day with nothing sent, or with a connection the record could not assess."""
    shares = named_shares((o.get("names") or {}).get("named"))
    if shares is None:
        return ""
    read, matched = shares
    if read >= 1:
        return " The gateway could read the server's name for everything it sent."
    said = f" The gateway could read the server's name for {int(read * 100)}% of what it sent"
    if int(matched * 100):
        said += f", and match {int(matched * 100)}% more to the TV's lookups"
    return said + "."


def _blocked_most(o: dict, prof: Profile | None) -> str:
    cats = [c for c in o.get("categories") or [] if c.get("blocked")]
    top = sorted(enumerate(cats), key=lambda ic: (-ic[1]["blocked"], ic[0]))[:3]
    if not top:
        return "Blocked most: nothing was blocked."
    return "Blocked most: " + ", ".join(category_label(c["category"], prof) for _, c in top) + "."


def _new(o: dict, update: str | None) -> str:
    news = []
    fwc = o.get("firmware_changes") or []
    if fwc:
        news.append(f"the TV's software updated to {fwc[-1]['firmware']}")
    # a new name under a known domain is churn (a rotating video node); only a new domain is news
    domains = list(
        dict.fromkeys(
            registrable_domain(h["name"]) for h in o.get("new_hosts") or [] if h.get("new_domain", True)
        )
    )
    if domains:
        young = _newly_registered(o)  # (threats) a new service on a list of newly registered domains
        tags = [named(d) + young.get(d, "") for d in domains[:SHOWN_NAMES]]
        shown = ("; " if any(d in young for d in domains[:SHOWN_NAMES]) else ", ").join(tags)
        more = f" and {len(domains) - SHOWN_NAMES} more" if len(domains) > SHOWN_NAMES else ""
        news.append(f"the TV used {_plural(len(domains), 'new service')} ({shown}{more})")
    took = [x["name"] for x in (o.get("list_changes") or {}).get("newly_blocked", []) if x.get("content")]
    if took:
        names = ", ".join(named(n) for n in took[:SHOWN_NAMES])
        more = f" and {len(took) - SHOWN_NAMES} more" if len(took) > SHOWN_NAMES else ""
        news.append(f"a blocklist update now blocks {names}{more}, which the TV downloaded from")
    if update:
        news.append(f"tvgw {update} is available")
    return "New: " + ("; ".join(news) + "." if news else "nothing new.")


def _newly_registered(o: dict) -> dict[str, str]:
    """(threats) Registrable domain -> the New line's tag, for each one on a list of newly registered
    domains in the window, worded by the day of the list's copy and its band (`threats.band()`):
    `, registered in the 7 days before 7 November`, `, registered 8 to 14 days before 7 November`, or
    `, on a list of newly registered names of 7 November`."""
    out = {}
    for h in (o.get("threats") or {}).get("hits") or []:
        if h["list"] == threats.NRD and h.get("copy"):
            out[registrable_domain(h["name"])] = ", " + threats.band_words(
                h.get("band"), _day_words(h["copy"])
            )
    return out


def _day_words(day: str) -> str:
    """(threats) An ISO day as the plain brief writes one: `7 November`."""
    d = date.fromisoformat(day)
    return f"{d.day} {MONTHS[d.month - 1]}"


def named(name: str) -> str:
    """(companies) A name with the company behind it, `alphonso.tv (LG Group)`, where the snapshot knows
    one; the name alone where it does not, so a day with no known company reads as it did before."""
    owner = companies.company(name)
    return f"{name} ({owner})" if owner else name


def items(o: dict, prof: Profile | None = None) -> list[tuple[str, str, str]]:
    """What needs a person, as (tier, sentence, action) once each: the act tier in red-line order, then
    the doctor tier, then a record with a source missing. Detail-tier lines are left out."""
    rows = [tier(line) for line in o.get("red_lines") or []] + ([MISSING_RECORD] if _gaps(o) else [])
    rows += [moved] if (moved := uplink_moved(o)) else []
    rows = [(t, sentence, action_text(action, prof)) for t, sentence, action in rows if t != "detail"]
    ordered = [r for r in rows if r[0] == "act"] + [r for r in rows if r[0] == "doctor"]
    return list(dict.fromkeys(ordered))


def uplink_moved(o: dict) -> tuple[str, str, str] | None:
    """(uplink) The act-tier item for a day on which the router gave the gateway a new address, with the
    count of the TV's connections that change cut (`changes_in_effect`'s evidence), or None."""
    sec = o.get("changes_in_effect") or {}
    events = ((sec.get("groups") or {}).get("Uplink") or {}).get("events") or []
    if not any(e.get("kind") == "wan_addr_change" for e in events):
        return None
    cut = ((sec.get("evidence") or {}).get("by_cause") or {}).get("uplink address changed", 0)
    if cut:
        verb = "was" if cut == 1 else "were"
        sentence = (
            f"Your router gave the gateway a new address, and {_n(cut)} of the TV's connections {verb} cut."
        )
    else:
        sentence = "Your router gave the gateway a new address, which cuts the TV's streams when it is on."
    return "act", sentence, RESERVE_ACTION


def action(o: dict, prof: Profile | None = None) -> tuple[str, str] | None:
    """(tier, the Action line's text) for the first thing that needs a person, or None: what
    reports/action.txt and the login message carry, never a name or a time from the record."""
    found = items(o, prof)
    if not found:
        return None
    t, sentence, act = found[0]
    rest = len(found) - 1
    more = (
        f" {_n(rest)} more {'thing needs' if rest == 1 else 'things need'} a look: tvgw brief --full."
        if rest
        else ""
    )
    return t, f"{sentence} {act}{more}"


def plain_brief(
    o: dict,
    activity: Activity | None = None,
    update: str | None = None,
    *,
    profile: Profile | None = None,
    first: bool = False,
) -> list[str]:
    """The plain brief of one day, line by line. `activity` is how long the TV was on (None when nothing
    says), `update` a newer tvgw's version when the update check found one, `profile` the TV's profile
    (menu paths and category names), and `first` a store younger than a day, which gets FIRST_DAY
    in place of a day of NOT ASSESSED."""
    if first:
        return [_title(o), f"  {FIRST_DAY}", FOOTER]
    found = action(o, profile)
    return [
        _title(o),
        f"  {_protection(o)}",
        f"  {_the_tv(o, activity)}",
        f"  {_blocked_most(o, profile)}",
        f"  {_new(o, update)}",
        f"  Action: {found[1] if found else NOTHING}",
        *_not_checked(o),
        *_threat_note(o),  # (threats)
        *_tv_notes(o),
        *_off_note(o),  # (tripwire)
        *_upload_note(o),  # (budget)
        *_starts_note(o),  # (did it work)
        *_counting_note(o),  # (counting)
        *_names_note(o),  # (namebound)
        *_receipt_line(o),
        FOOTER,
    ]


def _mb(n: int) -> str:
    """(budget) A size in plain words, MB of 1024 x 1024 bytes as the brief counts them."""
    return f"{n / 1024**2:.1f} MB"


def _names(found: list[str]) -> str:
    """Up to SHOWN_NAMES names, then how many more."""
    more = f" and {len(found) - SHOWN_NAMES} more" if len(found) > SHOWN_NAMES else ""
    return ", ".join(found[:SHOWN_NAMES]) + more


def _repeats(run: int) -> str:
    """(tripwire, budget) The once-only sentence of a line on its REPEAT_DAYS-th day running."""
    if run != REPEAT_DAYS:
        return ""
    return (
        f" This has come {REPEAT_DAYS} days running, so the short brief leaves it out until it changes"
        " (tvgw brief --full keeps it)."
    )


def _off_note(o: dict) -> list[str]:
    """(tripwire) The TV went online between two hourly readings that both found it off (the While
    off/asleep line with traffic): its lookups and connections and the services behind them. Left out
    when the TV port's own traffic says the TV was in use then, and after REPEAT_DAYS days running
    with no new name; never an action (design decision 66)."""
    sb = o.get("standby") or {}
    counts = ((sb.get("lookups", 0), "lookup"), (sb.get("conns", 0), "connection"))
    parts = [_plural(n, word) for n, word in counts if n]
    notice = o.get("standby_notice") or {}
    run = notice.get("days_running") or 1
    if not parts or notice.get("port") == "active" or (run > REPEAT_DAYS and not notice.get("new_names")):
        return []
    seen = list(
        dict.fromkeys(
            x["name"] if _is_address(x["name"]) else registrable_domain(x["name"])
            for x in o.get("standby_names") or []
        )
    )
    shown = f" ({_names(seen)})" if seen else ""
    if notice.get("port") == "quiet":
        why = " The gateway saw too little traffic for anyone to have been watching"
        why += ", so it goes online while off."
    else:
        why = " Either it was switched on in between, or it goes online while it is off."
    return [
        "  While off: Between two hourly checks that found it switched off, the TV went online:"
        f" {' and '.join(parts)}{shown}.{why}{_repeats(run)}"
    ]


def _upload_note(o: dict) -> list[str]:
    """(budget) The destination-hours over the upload budget's ceiling, late ones included, in one line:
    what the TV sent beyond what came back on the same connections, in how many clock hours, to which
    services, and why when the TV's own uploads reached the cap. Left out after REPEAT_DAYS days running
    with no new service; count-only, never an action (design decision 66)."""
    sec = o.get("upload_budget") or {}
    late = sec.get("late") or []
    events = (sec.get("events") or []) + late
    run = sec.get("days_running") or 1
    if not events or (run > REPEAT_DAYS and not sec.get("new_keys")):
        return []
    limit = f"the {_mb(sec['ceiling'])} upload budget for services outside its everyday ones"
    keys = list(dict.fromkeys(e["key"] for e in events))
    hours = len({e["hour"] for e in events})
    if len(events) == 1:
        e = events[0]
        said = f"In one hour the TV sent {e['key']} {_mb(e['net_up'])}"
        said += " more than came back on the same connections"
    else:
        when = "one hour" if hours == 1 else f"{hours} hours"
        to = keys[0] if len(keys) == 1 else f"{len(keys)} services ({_names(keys)})"
        said = f"In {when} the TV sent {to} more than came back on the same connections"
    said += f", over {limit}. Nothing was stopped."
    if late:
        said += " Part of it is from an earlier day: connections that ended only now."
    if (sec.get("fixed") or {}).get("at_cap"):
        said += " The TV's own uploads reached this size in the two weeks the budget was set from,"
        said += " so such hours are listed."
    return [f"  Uploads: {said}{_repeats(run)}"]


def _names_note(o: dict) -> list[str]:
    """(namebound) The TV's connections to a server under a name the filter never answered with that
    server's address, when there were any (the brief's `shared` class, design decision 70): how many and
    to which services. Left out after REPEAT_DAYS days running with no new service; count-only, never an
    action."""
    sec = o.get("names") or {}
    n = (sec.get("counts") or {}).get("shared", 0)
    run = sec.get("days_running") or 1
    if not n or (run > REPEAT_DAYS and not sec.get("new_names")):
        return []
    seen = list(dict.fromkeys(registrable_domain(e["name"]) for e in sec.get("shared") or []))
    shown = f" ({_names([named(d) for d in seen])})" if seen else ""
    if n == 1:
        did = "The TV reached a server once under a name the gateway had not given out for that server"
    else:
        did = f"The TV reached servers {_n(n)} times under names the gateway had not given out for them"
    did += " in the day before"
    return [
        f"  Names: {did}{shown}. A server shared by many sites can explain it, or an app that finds its"
        f" servers on its own. Nothing was stopped.{_repeats(run)}"
    ]


def _threat_note(o: dict) -> list[str]:
    """(threats) The names behind the known-bad red line, which the Action line leaves out: what the TV
    looked up, how often the gateway let it through, and the list (design decision 80)."""
    hits = threats.red_hits(o.get("threats"))
    if not hits:
        return []
    lists = ", ".join(dict.fromkeys(f"{h['source']}, copy of {h['copy']}" for h in hits))
    on = f"a list of known malware and botnet servers ({lists})"
    if len(hits) == 1:
        h = hits[0]
        let = "every one" if h["answered"] == h["lookups"] else _n(h["answered"])
        said = f"The TV looked up {h['name']} {_plural(h['lookups'], 'time')}, and the gateway let {let}"
        return [f"  Known-bad: {said} through. It is on {on}."]
    each = [f"{h['name']} {_plural(h['answered'], 'time')}" for h in hits]
    return [
        f"  Known-bad: The TV looked up {_n(len(hits))} names on {on}. The gateway let them through:"
        f" {_names(each)}."
    ]


def _is_address(name: str) -> bool:
    """(tripwire) A connection no hello named is listed by its server's address, which has no domain."""
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", name))


def _starts_note(o: dict) -> list[str]:
    """(did it work) The app starts that may have failed (design decision 72), in one line: in the
    interactive brief the first one with its app, its time and the name refused in its minutes; in a
    persisted brief their count alone and the receipt command for the rest (design decision 67). Never an
    action: a refusal in the same minutes is a match in time, which `sudo tvgw check NAME` explains."""
    starts = o.get("failed_starts") or {}
    if not starts.get("starts"):
        return []
    from tvgw import didit  # here: didit imports the receipt, which imports this module

    lines = starts.get("lines")
    if not lines:
        return [f"  Apps: {didit.summary_line(starts, didit.day_arg(o))}"]
    more = len(lines) - 1
    tail = f" {more} more: sudo tvgw receipt --since {didit.day_arg(o)}" if more else ""
    return [f"  Apps: {lines[0][0].upper()}{lines[0][1:]}.{tail}"]


def _counting_note(o: dict) -> list[str]:
    """(counting) One line for each count-only mechanism whose two weeks ended by the window's end (design
    decision 72): what the two weeks hold, and what the owner may now decide. On the REPEAT_DAYS-th day
    it says so once, and after that the full brief keeps it. Never an action: nothing changes on its own."""
    from tvgw import counting  # here: counting's mechanisms import the queries module this one imports

    now = o.get("generated")
    out = []
    for r in o.get("counting") or []:
        if r["state"] != counting.REACHED or r.get("days_past_end") is None or now is None:
            continue
        run = max(r["days_past_end"], 0) + 1
        if run <= REPEAT_DAYS:
            out.append(f"  Counting: {counting.plain_line(r, now)}{_repeats(run)}")
    return out


def _receipt_line(o: dict) -> list[str]:
    """(app in front) One line pointing at the receipt, only on a gateway whose store holds a live record
    of the TV (the report's `has_live_record`, a flag with no times; the sessions themselves are computed
    for an interactive run only, design decision 67): every other brief is as it was."""
    if not o.get("has_live_record"):
        return []
    return ["  Which app was in front, and what the TV reached meanwhile: sudo tvgw receipt"]


def _tv_notes(o: dict) -> list[str]:
    """(W12) After the Not checked lines, in plain words: the gateway can no longer read the TV (the TV
    refused its key, and `sudo tvgw tv pair` is the way back), the standby switches that keep the TV's
    network up while the screen is off, the agreements the TV asks for again, and a country whose names
    the gateway does not yet let through. None is an action for action.txt: each is read, not done."""
    out = []
    pairing = o.get("pairing") or {}
    if pairing.get("state") == "refused":
        when = datetime.fromtimestamp(pairing["t"]).strftime("%Y-%m-%d")
        out.append(
            f"  Pairing: The gateway can no longer read the TV since {when}. With the TV on, run:"
            " sudo tvgw tv pair"
        )
    if on := o.get("standby_features"):
        names = [x["label"] for x in on]
        joined = ", ".join(names[:-1]) + (" and " if len(names) > 1 else "") + names[-1]
        verb = "is" if len(names) == 1 else "are"
        out.append(f"  Standby: {joined} {verb} on, so the TV keeps its network up while the screen is off.")
    for x in o.get("agreements_pending") or []:
        out.append(f"  Agreements: The TV asks you to accept {x['name']} again. It is not accepted.")
    country = o.get("tv_country")
    if country:
        out.append(
            f"  Country: The TV says its country is {country['code'].upper()}, and one of its service"
            f" names is not yet let through. Run: {country['allow']}"
        )
    return out


def _not_checked(o: dict) -> list[str]:
    """A `Not checked:` line after the Action for each sentence in the report's `not_checked` list, when
    it carries one: what the brief cannot vouch for (design section 2.5: the TV's Wi-Fi, when nothing
    reads it and the owner has not confirmed it off). It is not an action, so action.txt never holds it."""
    return [f"  Not checked: {s if s.endswith('.') else s + '.'}" for s in o.get("not_checked") or []]
