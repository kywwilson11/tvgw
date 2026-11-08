"""(refused) `tvgw refused`: the names the filter refused the TV in the last minutes, the likeliest cause of a
broken app first, from AdGuard Home's own query log, never the store's late copy.

AdGuard is two stand-ins: a query-log file written the way v0.107.79 appends it (`querylog.json`, one
JSON object a line, `T` with nanoseconds and the zone's offset), and a loopback HTTP server that answers
`GET /control/querylog` as that version's handler does (newest first, `oldest` for the next page, a
quoted `search` matched whole against the client's address), with 401 for a request without the user
and password it was given. The store is a real one, written beforehand and opened read-only by the
report. Nothing here reaches a real AdGuard Home. All times are on 2026-10-26, America/Chicago, before
`NOW` (10:00), as conftest pins them."""

from __future__ import annotations

import base64
import json
import os
import sys
import threading
import urllib.parse
from dataclasses import dataclass, field, replace
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from conftest import NOW, ROOT

from tvgw import adguard, adguardcfg, aghinstall, cli, db, ingest, namecheck, profile, refused
from tvgw.config import Settings

TV = "10.10.10.17"
OTHER = "192.0.2.33"  # another device AdGuard answers: never in the report
BCRYPT = "$2a$10$" + "x" * 53
LG_LIST = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_72.txt"  # HaGeZi LG webOS
PRO = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_48.txt"  # HaGeZi Pro
DAY = 86400
WINDOW_START = NOW - refused.WINDOW  # 09:50


def iso(t: float) -> str:
    """A time as AdGuard writes it: nanoseconds and the local offset."""
    d = datetime.fromtimestamp(t).astimezone()
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond:06d}123" + d.strftime("%z")[:3] + ":00"


# ---- the stand-ins -------------------------------------------------------------------------------------


@dataclass
class Lookup:
    """One lookup the TV made, as both of AdGuard's records of it say it."""

    t: float
    name: str
    qtype: str = "A"
    reason: int = 0  # the file's number: 0 not filtered, 3 a list or a rule blocked it, 9-11 rewrites
    rule: str | None = None
    fid: int | None = None
    client: str = TV

    def file_line(self) -> str:
        result: dict = {"Reason": self.reason}
        if self.rule is not None:  # AdGuard's file leaves a zero list id out, as the namespace CI saw
            result["Rules"] = [{"Text": self.rule, **({"FilterListID": self.fid} if self.fid else {})}]
        if 3 <= self.reason <= 8:
            result["IsFiltered"] = True
        record = {
            "T": iso(self.t),
            "QH": self.name,
            "QT": self.qtype,
            "QC": "IN",
            "CP": "",
            "IP": self.client,
        }
        return json.dumps({**record, "Result": result, "Elapsed": 120000}) + "\n"

    def api_entry(self) -> dict:
        api = {0: "NotFilteredNotFound", 1: "NotFilteredWhiteList", 3: "FilteredBlackList", 11: "RewriteRule"}
        rules = [] if self.rule is None else [{"filter_list_id": self.fid or 0, "text": self.rule}]
        return {
            "time": iso(self.t),
            "client": self.client,
            "client_info": {"name": "lgcx", "ids": [self.client, "b4:b2:91:aa:bb:cc"], "whois": {}},
            "client_proto": "",
            "question": {"class": "IN", "name": self.name, "type": self.qtype},
            "reason": api.get(self.reason, "FilteredBlackList"),
            "rules": rules,
            "status": "NOERROR",
            "elapsedMs": "0.12",
            "cached": False,
            "upstream": "",
        }


class FakeAdGuard(BaseHTTPRequestHandler):
    """/control/querylog as v0.107.79 answers it: newest first, `limit` entries older than `older_than`,
    `oldest` the time of the last one returned, a quoted `search` matched whole against the client."""

    entries: list = []
    asked: list = []
    token: str | None = None

    def log_message(self, *a):
        pass

    def _send(self, code: int, text: str) -> None:
        raw = text.encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        query = dict(urllib.parse.parse_qsl(url.query))
        FakeAdGuard.asked.append((url.path, query, self.headers.get("Authorization")))
        if self.headers.get("Authorization") != FakeAdGuard.token:
            return self._send(401, "")
        if url.path != aghinstall.QUERYLOG:
            return self._send(404, "")
        entries = sorted(FakeAdGuard.entries, key=lambda e: e["time"], reverse=True)
        older = adguard.parse_time(query["older_than"]) if query.get("older_than") else None
        if older is not None:
            entries = [e for e in entries if adguard.parse_time(e["time"]) < older]
        search = query.get("search", "")
        if search.startswith('"') and search.endswith('"'):
            entries = [e for e in entries if search[1:-1] in (e["client"], e["question"]["name"])]
        page = entries[: int(query.get("limit", "500"))]
        oldest = page[-1]["time"] if page else ""
        return self._send(200, json.dumps({"data": page, "oldest": oldest}))


def basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


@dataclass
class Site:
    s: Settings
    admin: Path
    cfg: dict
    log: Path
    lookups: list[Lookup] = field(default_factory=list)

    def list_id(self, url: str) -> int:
        return next(f["id"] for f in self.cfg["filters"] if f["url"] == url)

    def write(self, file_lag: int = 0) -> None:
        """The log file and AdGuard's page from `lookups`: the file without the newest `file_lag`, which
        AdGuard still holds in memory (querylog.size_memory), the page with every one."""
        ordered = sorted(self.lookups, key=lambda x: x.t)
        on_file = ordered[: len(ordered) - file_lag] if file_lag else ordered
        self.log.write_text("".join(x.file_line() for x in on_file), encoding="utf-8")
        FakeAdGuard.entries = [x.api_entry() for x in ordered]

    def write_yaml(self) -> None:
        Path(self.s.adguard_yaml).write_text(adguardcfg.dump_yaml(self.cfg), encoding="utf-8")


@pytest.fixture
def site(tmp_path, lg):
    FakeAdGuard.entries, FakeAdGuard.asked = [], []
    FakeAdGuard.token = basic("admin", "secret")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeAdGuard)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    (tmp_path / "data").mkdir()
    s = Settings(
        tv_ip=TV,
        tv_mac="b4:b2:91:aa:bb:cc",
        tv_name="lgcx",
        adguard_yaml=str(tmp_path / "AdGuardHome.yaml"),
        adguard_querylog=str(tmp_path / "data" / "querylog.json"),
        local_rules=str(tmp_path / "local.rules"),
        auto_rules=str(tmp_path / "auto.rules"),
        db_path=str(tmp_path / "tvgw.db"),
        state_dir=str(tmp_path / "state"),
    )
    users = {"users": [{"name": "admin", "password": BCRYPT}], "schema_version": 34}
    cfg = adguardcfg.plan(users, adguardcfg.desired(lg, s))
    cfg["http"]["address"] = f"127.0.0.1:{srv.server_port}"
    here = Site(s, tmp_path / "adguard-admin", cfg, Path(s.adguard_querylog))
    here.write_yaml()
    aghinstall.write_admin(str(here.admin), "admin", "secret")
    yield here
    srv.shutdown()
    srv.server_close()


def store(site: Site, rows: list[Lookup]) -> None:
    """The store as the hourly ingest leaves it: the TV's lookups before the window, and `hosts`, the
    one row per name the ingest's own refresh_hosts() keeps, which a domain's history is read through."""
    conn = db.connect(site.s.db_path)
    conn.executemany(
        "INSERT INTO dns(t, qname, qtype, blocked, reason, rule, filter_id) VALUES (?,?,?,?,?,?,?)",
        [
            (x.t, x.name, x.qtype, int(3 <= x.reason <= 8), adguard.REASONS[x.reason], x.rule, x.fid)
            for x in rows
        ],
    )
    ingest.refresh_hosts(conn, profile.load("lg-webos"))
    conn.commit()
    conn.close()


def report(site: Site, lg, prof=None, since: float = WINDOW_START, **kw) -> refused.Outcome:
    return refused.run(site.s, prof or lg, since, NOW, admin=str(site.admin), **kw)


def text(site: Site, lg, **kw) -> list[str]:
    done = report(site, lg, **kw)
    assert done.report is not None, done.lines
    return refused.render(done.report)


def every(t0: float, n: int, step: float, **kw) -> list[Lookup]:
    return [Lookup(t0 + i * step, **kw) for i in range(n)]


def steady_ads(site: Site, days: int = 30) -> tuple[list[Lookup], list[Lookup]]:
    """(the store's month, the window's minutes) of three names refused every day, retried more than
    any new refusal in the window: LG's ad host by the profile's rule, a shared list's ad host, and the
    ACR host by the profile's rule."""
    pro = site.list_id(PRO)
    names = (
        ("lgsmartad.com", "||lgsmartad.com^", 0, 40),
        ("ad.doubleclick.net", "||doubleclick.net^", pro, 30),
        ("alphonso.tv", "||alphonso.tv^", 0, 25),
    )
    before, window = [], []
    for name, rule, fid, n in names:
        for d in range(days, 0, -1):
            before += every(NOW - d * DAY, 3, 600, name=name, reason=3, rule=rule, fid=fid)
        window += every(WINDOW_START + 5, n, 14, name=name, reason=3, rule=rule, fid=fid)
    return before, window


# ---- the backwards test: the 2026-09-11 list push ---------------------------------------------------------


def push_of_2026_09_11(site: Site) -> None:
    """A list update of the shape of 2026-09-11 (docs/research/deep-dive-2026-11/04-blocklists-and-
    verification.md, F5): HaGeZi's LG list began blocking the whole `nextlgsdp.com` zone, and webOS 6+
    sets lost their clock. Here a Spanish set, behind a gateway whose TV_COUNTRY was never set, so the
    profile's must-allow names are the US ones: `es.nextlgsdp.com` had been answered every morning for a
    month and is refused 14 times since 09:52, while three ad names are refused as every day, each
    retried more often than the clock host. HTTPS lookups the profile withholds, another device's
    lookups and a local name are refused too, and none of them is the cause."""
    lg_list = site.list_id(LG_LIST)
    history, ads = steady_ads(site)
    clock = []
    for d in range(30, 0, -1):
        clock += every(NOW - d * DAY + 1200, 2, 60, name="es.nextlgsdp.com")  # answered, no rule
    clock += every(NOW - 2400, 2, 60, name="es.nextlgsdp.com")  # 09:20 today, the last answer
    store(site, history + clock)
    took = {"reason": 3, "rule": "||nextlgsdp.com^", "fid": lg_list}
    withheld = {"qtype": "HTTPS", "reason": 3, "rule": f"||*^$dnstype=HTTPS|SVCB,client={TV}"}
    site.lookups = [
        *ads,
        *every(WINDOW_START + 120, 14, 30, name="es.nextlgsdp.com", **took),
        *every(WINDOW_START + 60, 6, 60, name="www.netflix.com", **withheld),
        Lookup(WINDOW_START + 30, "es.nextlgsdp.com", reason=3, rule="||nextlgsdp.com^", client=OTHER),
        Lookup(WINDOW_START + 40, "printer.lan", reason=3, rule="||lan^"),
        *every(WINDOW_START + 10, 20, 25, name="api.netflix.com"),  # answered
    ]
    site.write()


def test_the_clock_host_a_list_push_took_is_named_on_the_first_line(site, lg):
    push_of_2026_09_11(site)
    done = report(site, lg)
    assert done.code == refused.LIKELY == 1
    lines = refused.render(done.report)
    assert lines[:5] == [
        "Most likely cause: es.nextlgsdp.com, refused 14 times since 09:52.",
        "  Why it is first: the TV sets its clock from names like it; the filter let it through until 09:21,"
        " and its rule refused no name under nextlgsdp.com in the record since 26 September.",
        "  Fix: sudo tvgw allow es.nextlgsdp.com",
        "  Rule: ||nextlgsdp.com^, from the shared list HaGeZi LG webOS",
        "  Kind: LG's own services",
    ]
    assert lines[5] == f"  {refused.AFTER_FIX}"
    # the names refused every day follow as such, the most retried first; withheld record types,
    # another device and the local name are none of them
    assert lines[6:9] == [
        "",
        "Also refused, and probably not the cause:",
        "  lgsmartad.com, refused 40 times; first refused 26 September. Refused on purpose, unlikely to break an"
        " app: LG advertising. Company: LG Group.",
    ]
    # a name refused on purpose, before too, carries no fix: the way to one is tvgw check's, said once
    assert lines[9].startswith(
        "  ad.doubleclick.net, refused 30 times; first refused 26 September. Refused on purpose, unlikely"
    )
    assert lines[11] == refused.WHY_CHECK
    assert sum(line.lstrip().startswith(("Fix:", "Rule:")) for line in lines) == 2  # the cause's alone
    shown = "\n".join(lines)
    for absent in ("www.netflix.com", "printer.lan", OTHER, "api.netflix.com", "b4:b2:91"):
        assert absent not in shown
    assert lines[-1] == f"tvgw refused read AdGuard Home's query log from 09:50 to 10:00; {refused.SAID}"


def test_with_the_tvs_country_set_the_same_push_contradicts_the_plan(site, lg):
    """With TV_COUNTRY=es the clock host is on the must-allow list, whose exception no list outranks:
    a refusal of it is the plan broken, and the fix is the doctor's, never an allow."""
    push_of_2026_09_11(site)
    spanish = lg.for_country("es")
    lines = text(site, lg, prof=spanish)
    assert lines[0] == "Most likely cause: es.nextlgsdp.com, refused 14 times since 09:52."
    assert lines[1] == (
        "  Why it is first: the profile says the TV needs it; the filter let it through until 09:21, and its rule"
        " refused no name under nextlgsdp.com in the record since 26 September."
    )
    assert lines[2].startswith("  Needed for: clock + login + store on webOS 6/22+")
    assert lines[3] == f"  Fix: {namecheck.DOCTOR_FIX}"
    assert refused.AFTER_FIX not in "\n".join(lines)  # the doctor's fix is no allow to wait for


# ---- the ranking ----------------------------------------------------------------------------------------


def test_first_sight_outranks_retries_and_a_name_let_through_before_comes_first(site, lg):
    """A name refused for the first time ranks above every name refused before, however often those were
    retried; of two first sights, the one the filter used to let through (something changed) comes
    before the one the TV never asked for (a new feature), and retries order the rest."""
    history, ads = steady_ads(site)
    used = every(NOW - 3 * DAY, 5, 600, name="cdn.app.example")  # answered three days ago
    store(site, history + used)
    pro = site.list_id(PRO)
    site.lookups = [
        *ads,
        *every(WINDOW_START + 300, 3, 20, name="cdn.app.example", reason=3, rule="||app.example^", fid=pro),
        *every(
            WINDOW_START + 100,
            9,
            20,
            name="x.brandnew.example",
            reason=3,
            rule="||brandnew.example^",
            fid=pro,
        ),
    ]
    site.write()
    done = report(site, lg)
    names = [n.name for n in done.report.names]
    assert names == [
        "cdn.app.example",
        "x.brandnew.example",
        "lgsmartad.com",
        "ad.doubleclick.net",
        "alphonso.tv",
    ]
    lines = refused.render(done.report)
    assert lines[0] == "Most likely cause: cdn.app.example, refused 3 times since 09:55."
    assert lines[1] == (
        "  Why it is first: the filter let it through until 23 October 10:40, and its rule refused no name under"
        " app.example in the record since 26 September."
    )
    i = lines.index("Also new, or needed by the TV, in the last 10 minutes:")
    assert lines[i + 1] == (
        "  x.brandnew.example, refused 9 times since 09:51: it is not in the record since 26 September."
    )
    assert lines[i + 2] == "    Fix: sudo tvgw allow x.brandnew.example"
    assert lines[i + 3] == "    Rule: ||brandnew.example^, from the shared list HaGeZi Pro"


def test_a_name_the_tv_needs_comes_first_even_when_it_was_refused_before(site, lg):
    """A must-allow name refused at all contradicts the plan, so it outranks a first sight retried far
    more often; among the names the TV needs, first sight orders them again. The URL filter's names
    count as needed too, each with its own words."""
    history, ads = steady_ads(site)
    lg_list = site.list_id(LG_LIST)
    stale = every(NOW - 2 * DAY, 4, 60, name="us.lgtvsdp.com", reason=3, rule="||lgtvsdp.com^", fid=lg_list)
    store(site, history + stale)
    site.lookups = [
        *ads,
        *every(WINDOW_START + 10, 50, 10, name="x.brandnew.example", reason=3, rule="||brandnew.example^"),
        Lookup(WINDOW_START + 500, "us.lgtvsdp.com", reason=3, rule="||lgtvsdp.com^", fid=lg_list),
    ]
    site.write()
    done = report(site, lg)
    first, second = done.report.names[:2]
    assert (first.name, first.first_sight) == ("us.lgtvsdp.com", False)  # needed, though refused two days ago
    assert (second.name, second.first_sight) == ("x.brandnew.example", True)
    lines = refused.render(done.report)
    assert lines[:5] == [
        "Most likely cause: us.lgtvsdp.com, refused 1 time since 09:58.",
        "  Why it is first: the profile says the TV needs it.",
        "  Needed for: clock sync at boot; if blocked the clock resets to 2019 and TLS fails everywhere",
        f"  Fix: {namecheck.DOCTOR_FIX}",
        "  Rule: ||lgtvsdp.com^, from the shared list HaGeZi LG webOS",
    ]
    assert lines[6] == "  Company: LG Group"  # lgtvsdp.com's, from the snapshot
    site.lookups.append(Lookup(WINDOW_START + 510, "ngfts.lge.com", reason=3, rule="||lge.com^", fid=lg_list))
    site.write()
    done = report(site, lg)
    assert [n.name for n in done.report.names[:3]] == [
        "ngfts.lge.com",
        "us.lgtvsdp.com",
        "x.brandnew.example",
    ]
    lines = refused.render(done.report)
    assert lines[1] == (
        "  Why it is first: the gateway's URL filter answers it, so it should never be refused; it is not in the"
        " record since 26 September."
    )
    assert lines[2] == f"  Fix: {namecheck.FILTER_FIX}"
    i = lines.index("  us.lgtvsdp.com, refused 1 time since 09:58: the profile says the TV needs it.")
    assert lines[i + 1].startswith("    Needed for: clock sync at boot;")


def test_a_window_of_names_refused_every_day_is_nothing_new_and_says_where_to_look(site, lg):
    history, ads = steady_ads(site)
    store(site, history)
    site.lookups = ads
    site.write()
    done = report(site, lg)
    assert done.code == refused.NOTHING_NEW == 0
    lines = refused.render(done.report)
    assert lines[:2] == [
        "Nothing new was refused for the TV in the last 10 minutes: the 3 names below were refused before too,"
        " so they are probably not why an app stopped.",
        refused.DOCTOR_NEXT,
    ]
    assert lines[3] == "What was refused:"


@pytest.mark.parametrize(
    ("lookups", "first"),
    [
        ([], "The TV looked up nothing in the last 10 minutes, so nothing was refused: it may be off, or its"
             " traffic may not be reaching the gateway."),
        ([Lookup(WINDOW_START + 5, "api.netflix.com"), Lookup(WINDOW_START + 7, "printer.lan")],
         "Nothing was refused for the TV in the last 10 minutes."),
        # only what the TV goes without: a withheld record type is no refusal
        ([Lookup(WINDOW_START + 5, "www.netflix.com", qtype="HTTPS", reason=3, rule="||*^$dnstype=HTTPS")],
         "Nothing was refused for the TV in the last 10 minutes."),
    ],
)  # fmt: skip
def test_an_empty_window_says_so_and_points_at_the_doctor(site, lg, lookups, first):
    site.lookups = [
        *lookups,
        *every(WINDOW_START - 900, 5, 60, name="old.example", reason=3, rule="||old.example^"),
    ]
    site.write()
    done = report(site, lg)
    assert done.code == 0 and done.report.names == []
    lines = refused.render(done.report)
    assert lines[:2] == [first, refused.DOCTOR_NEXT]
    assert lines[-1].endswith(refused.SAID)


def test_the_window_is_the_one_asked_for(site, lg):
    site.lookups = [
        *every(NOW - 7000, 3, 60, name="earlier.example", reason=3, rule="||earlier.example^"),
        *every(WINDOW_START + 5, 2, 60, name="now.example", reason=3, rule="||now.example^"),
    ]
    site.write()
    assert [n.name for n in report(site, lg).report.names] == ["now.example"]
    two_hours = report(site, lg, since=NOW - 7200).report
    assert [n.name for n in two_hours.names] == ["earlier.example", "now.example"]
    assert refused.render(two_hours)[-1].startswith(
        "tvgw refused read AdGuard Home's query log from 08:00 to 10:00"
    )


# ---- the newest lookups, and an AdGuard that cannot be asked -----------------------------------------------


def test_the_lookups_adguard_has_not_written_yet_come_from_its_page_once_each(site, lg):
    """AdGuard writes its log in batches (querylog.size_memory): the newest refusals are on its page
    before they are in the file, and a lookup in both counts once."""
    site.lookups = every(WINDOW_START + 30, 6, 60, name="late.example", reason=3, rule="||late.example^")
    site.write(file_lag=4)
    assert len(site.log.read_text(encoding="utf-8").splitlines()) == 2
    done = report(site, lg)
    assert done.report.asked and [(n.name, n.lookups) for n in done.report.names] == [("late.example", 6)]
    assert all(q == {"limit": "500", "search": f'"{TV}"'} for _, q, _ in FakeAdGuard.asked[:1])


def test_the_pages_are_followed_back_to_the_window_and_no_further(site, lg, monkeypatch):
    site.lookups = every(WINDOW_START - 300, 30, 20, name="busy.example", reason=3, rule="||busy.example^")
    site.write()
    pages = []

    def page(base, user, password, client="", older_than="", limit=500, timeout=10.0):
        pages.append((older_than, limit))
        return aghinstall.querylog(base, user, password, client, older_than, limit=limit)

    monkeypatch.setattr(refused, "API_LIMIT", 10)
    done = report(site, lg, page=page)
    assert done.report.complete and done.report.names[0].lookups == 15
    assert pages == [("", 10), (pages[1][0], 10)] and pages[1][0]  # until a page reaches past 09:50


def test_while_adguard_restarts_the_file_answers_and_the_report_says_adguard_was_not_asked(site, lg):
    site.lookups = every(WINDOW_START + 30, 3, 60, name="x.example", reason=3, rule="||x.example^")
    site.write()
    site.cfg["http"]["address"] = f"127.0.0.1:{free_port()}"  # nothing listens: AdGuard is restarting
    site.write_yaml()
    done = report(site, lg)
    assert done.code == 1 and not done.report.asked
    lines = refused.render(done.report)
    assert lines[0] == "Most likely cause: x.example, refused 3 times since 09:50."
    note = next(line for line in lines if line.startswith("Note: Run this again in a minute"))
    assert "AdGuard Home did not answer" in note and "is it running?" in note


def test_no_password_kept_and_no_terminal_is_the_file_alone(site, lg):
    site.admin.unlink()
    site.lookups = every(WINDOW_START + 30, 3, 60, name="x.example", reason=3, rule="||x.example^")
    site.write()
    done = report(site, lg)  # ask=None: no terminal, so no password is asked for
    assert done.code == 1 and not done.report.asked and FakeAdGuard.asked == []
    note = next(n for n in done.report.notes if "adguard-admin" in n)
    assert note.startswith("To let tvgw ask AdGuard Home for its newest lookups, run this at a terminal,")
    assert "sudoedit" in note and "two lines, user=<name> and password=<password>" in note
    assert "echo" not in note and "--password" not in note and "secret" not in note
    asked = []
    done = report(site, lg, ask=lambda prompt, secret: asked.append(prompt) or "secret")
    assert done.report.asked and asked == ["AdGuard Home's password for admin: "]
    assert not site.admin.exists()  # kept nowhere


@pytest.mark.parametrize("how", ["a folder", "missing"])
def test_a_log_that_cannot_be_read_and_an_adguard_that_cannot_be_asked_is_one_plain_line(site, lg, how):
    if how == "a folder":
        site.log.mkdir()  # IsADirectoryError, as root too, where a mode-0 file would still be read
    site.cfg["http"]["address"] = f"127.0.0.1:{free_port()}"
    site.write_yaml()
    done = report(site, lg)
    assert done.code == refused.UNREAD == 2 and done.report is None and len(done.lines) == 1
    assert done.lines[0].startswith(f"tvgw refused: AdGuard Home's query log {site.log}: ")
    assert ("cannot read it" if how == "a folder" else "it is not there") in done.lines[0]
    assert done.lines[0].endswith("is it running? systemctl status AdGuardHome")


def test_a_log_that_cannot_be_read_with_adguard_up_is_its_page_with_a_note(site, lg):
    site.lookups = every(WINDOW_START + 30, 3, 60, name="x.example", reason=3, rule="||x.example^")
    site.write()
    site.log.unlink()
    site.log.mkdir()
    done = report(site, lg)
    assert done.code == 1 and done.report.asked and not done.report.read_log
    lines = refused.render(done.report)
    assert any(line.startswith("Note: AdGuard Home's query log file could not be read") for line in lines)
    assert lines[-1].startswith("tvgw refused read AdGuard Home's page from 09:50")


@pytest.mark.parametrize(
    ("change", "says"),
    [
        (lambda cfg: cfg["querylog"].update(enabled=False), "keeps no query log (querylog.enabled is false)"),
        (None, "AdGuard Home is not set up on this computer yet: sudo tvgw adguard install"),
    ],
)
def test_no_query_log_at_all_is_could_not_read(site, lg, change, says):
    if change is None:
        Path(site.s.adguard_yaml).unlink()
    else:
        change(site.cfg)
        site.write_yaml()
    done = report(site, lg)
    assert done.code == 2 and says in done.lines[0]


def test_a_store_that_cannot_be_read_leaves_the_query_log_as_the_only_before(site, lg):
    Path(site.s.db_path).write_bytes(b"not a database, " * 64)
    site.lookups = [
        *every(NOW - 3000, 2, 60, name="seen.example", reason=3, rule="||seen.example^"),
        *every(WINDOW_START + 30, 2, 60, name="seen.example", reason=3, rule="||seen.example^"),
    ]
    site.write()
    done = report(site, lg)
    assert done.report.names[0].first_sight is False  # the log's 09:10 refusal is "before"
    lines = refused.render(done.report)
    # under the first line, before anything that rests on "before"
    assert lines[1].startswith(
        '  Note: "Before" goes back only to 09:10, the oldest lookup in the query log,'
    )
    assert "the gateway's record could not be read" in lines[1]


def test_without_a_store_every_name_in_a_log_without_history_is_new_and_the_note_says_why(site, lg):
    """A new gateway, or a store a failing disk will not give back: "first time" is the log's alone,
    and the report says so at its top and claims no more than that in its reason."""
    site.lookups = every(WINDOW_START + 30, 2, 60, name="x.example", reason=3, rule="||x.example^")
    site.write()
    lines = text(site, lg)
    assert lines[0].startswith("Most likely cause: x.example")
    assert lines[1] == (
        "  Note: Nothing before this window could be read, since the gateway has no record yet: every name counts"
        " as refused for the first time."
    )
    assert lines[2] == "  Why it is first: nothing before this window could be read to compare it with."


def test_the_store_and_the_log_between_it_and_the_window_are_both_before(site, lg):
    """The store ends at the last hourly ingest; the log fills the gap up to the window, so a name first
    refused after the ingest, before the window, is no first sight."""
    store(site, every(NOW - 2 * DAY, 3, 60, name="steady.example", reason=3, rule="||steady.example^"))
    site.lookups = [
        *every(NOW - 1800, 2, 60, name="gap.example", reason=3, rule="||gap.example^"),  # after the ingest
        *every(WINDOW_START + 30, 2, 60, name="gap.example", reason=3, rule="||gap.example^"),
        *every(WINDOW_START + 30, 2, 60, name="steady.example", reason=3, rule="||steady.example^"),
    ]
    site.write()
    done = report(site, lg)
    assert {n.name: n.first_sight for n in done.report.names} == {
        "gap.example": False,
        "steady.example": False,
    }
    assert done.report.history_from == pytest.approx(NOW - 2 * DAY)


# ---- what is never shown, and what is never written ------------------------------------------------------


def test_odd_names_are_counted_never_shown_and_text_from_a_list_is_made_safe(site, lg, capsys, monkeypatch):
    """A name with a control character, a bidi override or a zero-width space is no internet name: it is
    counted in a note and never printed, and a rule's text from a list passes through cli.clean()."""
    odd = [
        "evil\x1b[31m.example",
        "a‮b.example",
        "zero​width.example",
        "printer.lan",
        "33.2.0.192.in-addr.arpa",
        "10.10.10.99",
    ]
    site.lookups = [Lookup(WINDOW_START + 10 + i, name, reason=3, rule="||x^") for i, name in enumerate(odd)]
    site.lookups += [
        Lookup(WINDOW_START + 30, "UPPER.Example.", reason=3, rule="||upper.example^\x1b]0;x\x07"),
        Lookup(WINDOW_START + 40, "_svc.under-score.example", reason=3, rule="||under-score.example^"),
    ]
    site.write()
    done = report(site, lg)
    assert {n.name for n in done.report.names} == {"upper.example", "_svc.under-score.example"}
    assert done.report.hidden == len(odd)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(refused, "run", lambda *a, **kw: done)
    assert cli.main(["--conf", "/nonexistent", "refused"]) == 1
    out = capsys.readouterr().out
    assert "\x1b" not in out and "‮" not in out and "\\x1b]0;x\\x07" in out
    for name in odd:
        assert name not in out
    assert "6 lookups of names that are not internet names" in out


def test_nothing_from_the_home_network_reaches_the_report_or_its_json(site, lg):
    """Another device's lookups, the TV's MAC and name in AdGuard's client record, its address, and the
    home's local names stay out of the text and the JSON alike."""
    push_of_2026_09_11(site)
    site.lookups += [
        Lookup(WINDOW_START + 50, "nas.home", reason=3, rule="||home^"),
        Lookup(WINDOW_START + 55, "tracker.example", reason=3, rule="||tracker.example^", client=OTHER),
    ]
    site.write()
    done = report(site, lg)
    shown = "\n".join(refused.render(done.report, show_all=True)) + json.dumps(refused.as_json(done.report))
    for home in (OTHER, TV, "b4:b2:91:aa:bb:cc", "lgcx", "nas.home", "printer.lan", "tracker.example"):
        assert home not in shown


AUDIT: list = []
AUDITING = False


def _audit(event: str, args: tuple) -> None:
    if not AUDITING:
        return
    if event == "open":
        path, mode, flags = args
        writes = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
            isinstance(flags, int)
            and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC)
        )
        if writes:
            AUDIT.append(("open", path, mode, flags))
    elif event in ("os.remove", "os.rename", "os.mkdir", "os.chmod", "shutil.rmtree", "os.truncate"):
        AUDIT.append((event, *args))
    elif event == "sqlite3.connect":
        AUDIT.append(("sqlite3.connect", str(args[0])))


sys.addaudithook(_audit)


def test_nothing_is_written_anywhere(site, lg, tmp_path, capsys, monkeypatch):
    """Every file open the report makes is a read, the store is opened `mode=ro`, and the tree is
    byte for byte as it was: no key, no cache, no state, and AdGuard only asked."""
    global AUDITING
    push_of_2026_09_11(site)
    site.lookups.append(Lookup(WINDOW_START + 70, "<title>.amagi.tv", reason=3, rule="||amagi.tv^"))
    site.write()
    s = replace(site.s, name_hmac="on")  # the hasher's keys are the one thing a reader could make
    before = {p: (p.stat().st_mtime_ns, p.stat().st_size) for p in tmp_path.rglob("*")}
    AUDIT.clear()
    AUDITING = True
    try:
        done = refused.run(s, lg, WINDOW_START, NOW, admin=str(site.admin))
        refused.render(done.report)
        refused.as_json(done.report)
    finally:
        AUDITING = False
    assert done.code == 1
    connects = [a for a in AUDIT if a[0] == "sqlite3.connect"]
    assert connects and all(a[1].startswith("file:") and a[1].endswith("?mode=ro") for a in connects)
    assert [a for a in AUDIT if a[0] != "sqlite3.connect"] == []
    assert {p: (p.stat().st_mtime_ns, p.stat().st_size) for p in tmp_path.rglob("*")} == before
    assert all(path in (aghinstall.QUERYLOG,) for path, _, _ in FakeAdGuard.asked)  # GETs, never a change


def test_a_title_bearing_name_is_shown_by_its_zone_under_name_hmac(site, lg):
    """With NAME_HMAC=on the store keeps a FAST channel's show slug only as a keyed tag; the report shows
    the zone alone, one row for every title under it, with the fix for the zone."""
    pro = site.list_id(PRO)
    site.lookups = [
        *every(WINDOW_START + 30, 2, 60, name="the-show-one.amagi.tv", reason=3, rule="||amagi.tv^", fid=pro),
        *every(WINDOW_START + 40, 3, 60, name="other-show.amagi.tv", reason=3, rule="||amagi.tv^", fid=pro),
    ]
    site.write()
    on = replace(site.s, name_hmac="on")
    done = refused.run(on, lg, WINDOW_START, NOW, admin=str(site.admin))
    lines = refused.render(done.report)
    assert lines[0] == "Most likely cause: <title>.amagi.tv, refused 5 times since 09:50."
    assert "  Fix: sudo tvgw allow amagi.tv" in lines
    assert not any("the-show-one" in line or "other-show" in line for line in lines)
    assert any("shown by its zone alone" in line for line in lines)
    off = [n.name for n in report(site, lg).report.names]
    assert sorted(off) == ["other-show.amagi.tv", "the-show-one.amagi.tv"]


# ---- the command --------------------------------------------------------------------------------------


def free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def conf(site: Site, tmp_path: Path) -> str:
    path = tmp_path / "tvgw.conf"
    path.write_text(
        "\n".join(
            f"{k}={v}"
            for k, v in {
                "TV_IP": TV,
                "DB_PATH": site.s.db_path,
                "LOCAL_RULES": site.s.local_rules,
                "AUTO_RULES": site.s.auto_rules,
            }.items()
        )
        + "\n",
        encoding="utf-8",
    )
    return str(path)


def test_it_asks_for_sudo_first(capsys, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert cli.main(["--conf", "/nonexistent", "refused"]) == 2
    assert capsys.readouterr().out.startswith("tvgw refused: it reads AdGuard Home's query log")


@pytest.mark.parametrize("since", ["2d", "25h", "2026-10-24T10:00"])
def test_a_window_past_a_day_is_a_usage_error(capsys, monkeypatch, since):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert cli.main(["--conf", "/nonexistent", "refused", "--since", since]) == 2
    assert "--since must be in the last day" in capsys.readouterr().err


def test_the_command_prints_the_report_or_its_json_and_exits_as_check_does(
    site, lg, capsys, monkeypatch, tmp_path
):
    push_of_2026_09_11(site)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(aghinstall, "ADMIN_FILE", str(site.admin))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    real = refused.run

    def with_paths(s, prof, since, now, **kw):  # the settings file names no AdGuard paths
        here = replace(s, adguard_yaml=site.s.adguard_yaml, adguard_querylog=site.s.adguard_querylog)
        return real(here, prof, since, now, **kw)

    monkeypatch.setattr(refused, "run", with_paths)
    assert cli.main(["--conf", conf(site, tmp_path), "refused"]) == 1
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "Most likely cause: es.nextlgsdp.com, refused 14 times since 09:52."
    assert cli.main(["--conf", conf(site, tmp_path), "refused", "--json", "--since", "1h"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["asked_adguard"] and data["read_log"] and data["complete"]
    assert [n["name"] for n in data["names"]][:2] == ["es.nextlgsdp.com", "lgsmartad.com"]
    assert data["names"][0]["fix"] == "sudo tvgw allow es.nextlgsdp.com" and data["names"][0]["likely"]


def test_the_lists_are_cut_short_and_all_shows_every_one(site, lg):
    store(
        site, [Lookup(NOW - DAY + i, f"ad{i}.example", reason=3, rule=f"||ad{i}.example^") for i in range(8)]
    )
    site.lookups = [
        Lookup(WINDOW_START + 10 + i, f"ad{i}.example", reason=3, rule=f"||ad{i}.example^") for i in range(8)
    ]
    site.lookups += [
        Lookup(WINDOW_START + 30 + i, f"new{i}.example", reason=3, rule=f"||new{i}.example^")
        for i in range(12)
    ]
    site.write()
    done = report(site, lg)
    short, full = refused.render(done.report), refused.render(done.report, show_all=True)
    assert "  and 2 more: sudo tvgw refused --all lists every one." in short  # 12 new: 1 + 9 shown
    assert "  and 3 more: sudo tvgw refused --all lists every one." in short  # 8 old: 5 shown
    assert not any(" more: sudo tvgw refused --all" in line for line in full)
    assert sum(line.startswith("  ad") for line in full) == 8


# ---- the parts ------------------------------------------------------------------------------------------


def test_the_file_is_read_backwards_into_its_rotated_copy_and_says_where_it_stopped(tmp_path):
    log = tmp_path / "querylog.json"
    old = [Lookup(NOW - 3000 + i, f"o{i}.example") for i in range(3)]
    new = [Lookup(NOW - 1000 + i, f"n{i}.example") for i in range(3)]
    Path(f"{log}.1").write_text("".join(x.file_line() for x in old), encoding="utf-8")
    log.write_text(
        "".join(x.file_line() for x in new)
        + Lookup(NOW - 999.5, "x.example", client=OTHER).file_line()
        + '{"T":"2026-10',
        encoding="utf-8",
    )
    found, reached = adguard.records_since(str(log), NOW - 2999, TV)
    assert [r.qname for r in found] == ["o1.example", "o2.example", "n0.example", "n1.example", "n2.example"]
    assert reached
    found, reached = adguard.records_since(str(log), 0, TV)
    assert len(found) == 6 and reached  # every byte read: nothing older exists
    cut = log.stat().st_size - len(new[0].file_line().encode()) + 5  # the read starts inside n0's line
    found, reached = adguard.records_since(str(log), 0, TV, max_bytes=cut)
    assert not reached and [r.qname for r in found] == ["n1.example", "n2.example"]
    log.unlink()
    found, reached = adguard.records_since(str(log), NOW - 2999, TV)  # rotated a moment ago
    assert [r.qname for r in found] == ["o1.example", "o2.example"] and reached


@pytest.mark.parametrize(("fid", "expected"), [(None, 0), (0, 0), (7, 7), (-2, -2)])
def test_a_custom_rules_list_id_is_0_from_the_file_and_from_the_page(fid, expected):
    """The namespace CI's real binary wrote a custom rule's line without `FilterListID` and its page
    entry with `filter_list_id: 0`: both read as 0, the custom rules' id, so the two readers of one
    lookup agree, and a list's or a feature's id is kept as it was."""
    x = Lookup(NOW - 100, "ads.example", reason=3, rule="||ads.example^", fid=fid)
    line = x.file_line()
    assert ('"FilterListID"' in line) == bool(fid)  # the file omits a zero id
    from_file = adguard.parse_querylog_line(line, client=TV)
    from_api = adguard.parse_api_entry(x.api_entry(), client=TV)
    assert from_file.filter_id == from_api.filter_id == expected
    assert adguard.list_id({}, "FilterListID", "Text") is None  # no rule, no list
    assert adguard.list_id({"Text": "x", "FilterListID": True}, "FilterListID", "Text") is None


def test_an_api_entry_reads_as_the_files_line_for_the_same_lookup(tmp_path):
    x = Lookup(NOW - 100, "Ads.Example.", reason=3, rule="||ads.example^", fid=7)
    from_file = adguard.parse_querylog_line(x.file_line(), client=TV)
    from_api = adguard.parse_api_entry(x.api_entry(), client=TV)
    assert from_api == replace(from_file, answers=None, elapsed_ms=from_api.elapsed_ms)
    assert (from_api.blocked, from_api.reason, from_api.filter_id) == (True, "FilteredBlockList", 7)
    assert adguard.parse_api_entry(x.api_entry(), client=OTHER) is None
    for bad in ({}, [], {"time": "soon", "question": {"name": "a"}}, {"time": iso(NOW), "question": {}}):
        assert adguard.parse_api_entry(bad) is None
    rewrite = Lookup(NOW, "ngfts.lge.com", reason=11, rule="||ngfts.lge.com^$dnsrewrite=10.10.10.1")
    assert adguard.parse_api_entry(rewrite.api_entry()).blocked is False


def test_the_api_is_asked_for_the_tvs_lookups_with_tvgws_user_and_says_why_not(site):
    base = aghinstall.page_base(site.cfg)
    page = aghinstall.querylog(base, "admin", "secret", client=TV, older_than=iso(NOW))
    assert page == {"data": [], "oldest": ""}
    assert FakeAdGuard.asked[-1] == (
        aghinstall.QUERYLOG,
        {"limit": "500", "search": f'"{TV}"', "older_than": iso(NOW)},
        FakeAdGuard.token,
    )
    with pytest.raises(aghinstall.AskError, match=r"did not take the user and password \(401\)"):
        aghinstall.querylog(base, "admin", "wrong")


def test_api_pages_are_decided_by_their_oldest(site):
    """AdGuard's `oldest` decides (internal/querylog/search.go at the tag): empty once it has nothing
    older; on a page with entries, its oldest entry; on a page with none, where its capped scan of the
    file stopped. So a page whose entries are all newer than the window, as the namespace CI's real
    binary answered, pages on, and the next, empty page with an empty `oldest` ends the log; an empty
    page with an `oldest` is a scan that ran out, followed; one reaching past the window ends it; one
    whose `oldest` cannot be read cannot be followed; pages that run out first leave it unreached."""
    new = Lookup(NOW - 10, "a.example", reason=3, rule="||a.example^").api_entry()
    old = Lookup(WINDOW_START - 60, "a.example", reason=3, rule="||a.example^").api_entry()
    asked = []

    def pages(*answers):
        it = iter(answers)
        asked.clear()
        return lambda older: asked.append(older) or next(it)

    end = {"data": [], "oldest": ""}
    found, reached = refused.api_records(
        pages({"data": [new] * 3, "oldest": new["time"]}, end), WINDOW_START, TV
    )
    assert len(found) == 3 and reached and asked == ["", new["time"]]  # the CI's shape, then the log's end
    assert refused.api_records(pages(end), WINDOW_START, TV) == ([], True)
    capped = {"data": [], "oldest": new["time"]}  # AdGuard scanned 50,000 lines and matched none
    found, reached = refused.api_records(
        pages(capped, {"data": [old], "oldest": old["time"]}), WINDOW_START, TV
    )
    assert reached and found == [] and asked == ["", new["time"]]  # followed, then past the window
    found, reached = refused.api_records(pages({"data": [new], "oldest": "?"}), WINDOW_START, TV)
    assert len(found) == 1 and not reached
    full = {"data": [new], "oldest": new["time"]}
    found, reached = refused.api_records(pages(full, full, full), WINDOW_START, TV, pages=3)
    assert not reached and len(asked) == 3  # the pages ran out before the window's start


def test_the_ranking_key_is_total_and_stable():
    a = refused.Name("a.example", 5, 1.0, 2.0, "FilteredBlackList", None, None, first_refused=0.5)
    b = refused.Name("b.example", 1, 1.0, 2.0, "FilteredBlackList", None, None)
    c = refused.Name("c.example", 1, 1.0, 2.0, "FilteredBlackList", None, None, last_allowed=0.1)
    d = refused.Name("d.example", 9, 1.0, 2.0, "FilteredBlackList", None, None, first_refused=0.5, needed="x")
    assert [n.name for n in sorted([a, b, c, d], key=refused.rank_key)] == [
        "d.example",
        "c.example",
        "b.example",
        "a.example",
    ]


@pytest.mark.parametrize(
    ("seconds", "words"),
    [(30, "1 minute"), (600, "10 minutes"), (7140, "119 minutes"), (7200, "2 hours"), (86400, "24 hours")],
)
def test_the_window_in_words(seconds, words):
    assert refused.span(NOW - seconds, NOW) == words


def test_moments_today_and_on_other_days():
    assert refused.clock(NOW - 60, NOW) == "09:59"
    assert refused.clock(NOW - 3 * DAY, NOW) == "23 October 10:00"
    assert refused.day(NOW - 3 * DAY, NOW) == "23 October"
    assert refused.day(NOW - 400 * DAY, NOW) == "21 September 2025"


def test_the_troubleshooting_pages_sample_is_what_the_report_prints(site, lg):
    """docs/use/troubleshooting.md shows the start of the report for the 2026-09-11 push, and says it
    comes from the tests: it is this test's output, line for line."""
    page = (ROOT / "docs" / "use" / "troubleshooting.md").read_text(encoding="utf-8")
    after = page.split("A report that found the cause starts like this one, from the project's tests:", 1)[1]
    sample = after.split("```text\n", 1)[1].split("```", 1)[0].splitlines()
    push_of_2026_09_11(site)
    assert refused.render(report(site, lg).report)[: len(sample)] == sample


@pytest.mark.parametrize(
    ("sent", "says"),
    [
        (
            b'HTTP/1.1 200 OK\r\nContent-Length: 4000\r\n\r\n{"data": [',
            r"is not JSON \(10 bytes\)$",
        ),  # cut off
        (b"NOT HTTP AT ALL\r\n\r\n", "did not answer"),  # http.client's BadStatusLine, no OSError
    ],
)
def test_an_answer_cut_off_or_garbled_as_adguard_stops_is_could_not_ask(sent, says):
    """A page AdGuard stops in the middle of, or a reply that is not HTTP, is "could not ask", never a
    traceback: http.client raises its own errors, which are not OSErrors."""
    import socket

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def answer() -> None:
        conn, _ = srv.accept()
        conn.recv(65536)
        conn.sendall(sent)
        conn.close()

    threading.Thread(target=answer, daemon=True).start()
    try:
        with pytest.raises(aghinstall.AskError, match=says):
            aghinstall.querylog(f"http://127.0.0.1:{srv.getsockname()[1]}", "", "", client=TV)
    finally:
        srv.close()


def test_a_name_refused_on_purpose_before_carries_no_fix_unless_every_one_is_asked_for(site, lg):
    """A privacy gateway does not hand out an unblock for every tracker it refuses: a name refused before
    too shows its kind, its company and why it is refused, and no fix; one line says where the way to
    let one through is (tvgw check), and --all shows every rule and fix. A refusal by the owner's own rule
    or the gateway's says whose rule it is."""
    Path(site.s.local_rules).write_text("! a dated note\n||mine.example^\n", encoding="utf-8")
    history, ads = steady_ads(site)
    store(site, [*history, Lookup(NOW - DAY, "mine.example", reason=3, rule="||mine.example^")])
    site.lookups = [*ads, Lookup(WINDOW_START + 30, "mine.example", reason=3, rule="||mine.example^")]
    site.write()
    done = report(site, lg)
    lines = refused.render(done.report)
    assert not any("Fix:" in line or "--force" in line for line in lines)
    mine = next(line for line in lines if line.startswith("  mine.example"))
    assert mine.endswith("Refused by your own rule: other services.")
    assert lines.count(refused.WHY_CHECK) == 1
    every = refused.render(done.report, show_all=True)
    assert refused.WHY_CHECK not in every
    i = every.index(mine)
    assert (
        every[i + 1]
        == f"    Rule: ||mine.example^, from your own rules ({site.s.local_rules}). Fix: sudo tvgw unblock mine.example"
    )
    assert sum(" Fix: " in line for line in every) == 4
    assert all(
        n["on_purpose"] == (n["name"] != "mine.example") for n in refused.as_json(done.report)["names"]
    )


def test_a_new_tracker_is_never_the_likely_cause_and_carries_no_fix(site, lg):
    """The reviewer's case: a new app host refused 4 times and a brand-new LG telemetry host retried 30
    times. The app host is the likely cause; the tracker ranks last, says it is refused on purpose and
    unlikely to break an app, and gets no fix; alone, it makes no likely cause and exits 0."""
    pro = site.list_id(PRO)
    app = every(
        WINDOW_START + 30, 4, 60, name="api.newapp.example", reason=3, rule="||newapp.example^", fid=pro
    )
    tracker = every(
        WINDOW_START + 20,
        30,
        15,
        name="rdth.lgtvcommon.com",
        reason=3,
        rule="||rdth.lgtvcommon.com^",
        fid=pro,
    )
    site.lookups = [*app, *tracker]
    site.write()
    done = report(site, lg)
    assert [n.name for n in done.report.names] == ["api.newapp.example", "rdth.lgtvcommon.com"]
    assert done.code == 1 and done.report.names[1].tracking and not done.report.names[1].likely
    lines = refused.render(done.report)
    assert lines[0] == "Most likely cause: api.newapp.example, refused 4 times since 09:50."
    line = next(x for x in lines if x.startswith("  rdth.lgtvcommon.com"))
    assert line == (
        "  rdth.lgtvcommon.com, refused 30 times since 09:50, new. Refused on purpose, unlikely to break an app:"
        " LG usage reporting. Company: LG Group."
    )
    assert sum("Fix:" in x for x in lines) == 1  # the app host's
    data = refused.as_json(done.report)["names"]
    assert [(n["tracking"], n["on_purpose"], bool(n["fix"])) for n in data] == [
        (False, True, True),
        (True, True, True),
    ]
    site.lookups = tracker
    site.write()
    alone = report(site, lg)
    assert alone.code == refused.NOTHING_NEW
    assert refused.render(alone.report)[0] == (
        "Nothing likely to break an app was refused for the TV in the last 10 minutes: the name below is a"
        " tracker refused on purpose, or was refused before too."
    )


def test_a_rotating_name_under_a_rule_that_has_refused_its_domain_for_a_month_is_no_news(site, lg):
    """The reviewer's case: the profile lists `cdpbeacon*.lgtvcommon.com`, and a month of cdpbeacon0 to 4
    refused by one rule makes cdpbeacon9 under the same rule old news, judged by the rule and the
    registrable domain, not the exact name; it is no likely cause and the run exits 0. A second rule
    under the same domain is news."""
    pro = site.list_id(PRO)
    rows = []
    for d in range(30, 0, -1):
        rows += every(
            NOW - d * DAY,
            3,
            600,
            name=f"cdpbeacon{d % 5}.lgtvcommon.com",
            reason=3,
            rule="||lgtvcommon.com^",
            fid=pro,
        )
        rows += every(NOW - d * DAY + 5, 3, 600, name="api.app.example")  # an app's host, always answered
    store(site, rows)
    site.lookups = every(
        WINDOW_START + 30,
        12,
        30,
        name="cdpbeacon9.lgtvcommon.com",
        reason=3,
        rule="||lgtvcommon.com^",
        fid=pro,
    )
    site.lookups += every(WINDOW_START + 60, 3, 60, name="api.app.example")
    site.write()
    done = report(site, lg)
    (n,) = done.report.names
    assert (n.first_sight, n.by_domain, n.likely) == (False, True, False) and done.code == 0
    line = next(x for x in refused.render(done.report) if x.startswith("  cdpbeacon9"))
    assert "; its rule has refused names under lgtvcommon.com since 26 September. Refused on purpose" in line
    site.lookups = every(
        WINDOW_START + 30,
        3,
        30,
        name="aic.service.lgtvcommon.com",
        reason=3,
        rule="||service.lgtvcommon.com^",
        fid=pro,
    )
    site.write()
    assert report(site, lg).report.names[0].first_sight


def test_a_title_zone_with_a_month_of_tagged_rows_is_no_news_under_name_hmac(site, lg):
    """The reviewer's case: under NAME_HMAC=on the store keeps a FAST zone's titles only as tags; the
    zone's history is read through those tagged rows, so a month of refusals under amagi.tv makes
    today's title old news, and the new app host is the likely cause."""
    pro = site.list_id(PRO)
    rows = []
    for d in range(30, 0, -1):
        rows += every(
            NOW - d * DAY, 3, 600, name=f"t-1-abc{d}.amagi.tv", reason=3, rule="||amagi.tv^", fid=pro
        )
    store(site, rows)
    site.lookups = every(
        WINDOW_START + 30, 20, 20, name="the-show.amagi.tv", reason=3, rule="||amagi.tv^", fid=pro
    )
    site.lookups += every(
        WINDOW_START + 60, 3, 60, name="api.newapp.example", reason=3, rule="||newapp.example^", fid=pro
    )
    site.write()
    on = replace(site.s, name_hmac="on")
    done = refused.run(on, lg, WINDOW_START, NOW, admin=str(site.admin))
    zone = next(n for n in done.report.names if n.name == "<title>.amagi.tv")
    assert (zone.first_sight, zone.by_domain) == (False, True)
    assert (
        refused.render(done.report)[0]
        == "Most likely cause: api.newapp.example, refused 3 times since 09:51."
    )


def test_a_log_read_that_stops_short_of_the_store_says_so_on_top_and_in_the_json(site, lg, monkeypatch):
    """The store's newest lookup is three hours old, and the log's read runs out of bytes half an hour
    back: the window is whole, "before" has a gap, and the report says so under its first line."""
    store(site, every(NOW - 3 * 3600, 2, 60, name="old.example", reason=3, rule="||old.example^"))
    site.lookups = [
        *every(NOW - 7000, 60, 60, name="gap.example"),  # answered, every minute from about 08:03
        *every(WINDOW_START + 30, 2, 60, name="x.example", reason=3, rule="||x.example^"),
    ]
    site.write()
    real = adguard.records_since
    line = len(site.lookups[0].file_line().encode())
    monkeypatch.setattr(adguard, "records_since", lambda p, s, c: real(p, s, c, max_bytes=line * 30))
    rep = report(site, lg).report
    assert rep.complete and not rep.history_complete
    lines = refused.render(rep)
    assert lines[1].startswith("  Note: The query log could be read back only to ")
    assert "short of the gateway's record" in lines[1]
    data = refused.as_json(rep)
    assert (
        data["complete"]
        and data["history_complete"] is False
        and data["notes"][0] == lines[1][len("  Note: ") :]
    )


def test_a_cut_off_page_puts_nothing_of_itself_in_the_report(site, lg):
    """AdGuard sorts its JSON keys, so a cut-off page starts with the first entry's `client`, the TV's
    address: the note says how many bytes came, never what they were, in the text and in --json."""
    import socket

    site.lookups = every(WINDOW_START + 30, 2, 60, name="x.example", reason=3, rule="||x.example^")
    site.write()
    cut = b'{"data":[{"answer":[],"cached":false,"client":"10.10.10.17","client_info":{"ids":["b4:b2:91:aa:bb:cc"'
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def answer() -> None:
        conn, _ = srv.accept()
        conn.recv(65536)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4000\r\n\r\n" + cut)
        conn.close()

    threading.Thread(target=answer, daemon=True).start()
    site.cfg["http"]["address"] = f"127.0.0.1:{srv.getsockname()[1]}"
    site.write_yaml()
    try:
        done = report(site, lg)
    finally:
        srv.close()
    shown = "\n".join(refused.render(done.report)) + json.dumps(refused.as_json(done.report))
    assert f"is not JSON ({len(cut)} bytes)" in shown
    assert TV not in shown and "b4:b2:91" not in shown and '"client"' not in shown


def test_with_json_a_report_it_cannot_make_is_a_json_object(capsys, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert cli.main(["--conf", "/nonexistent", "refused", "--json"]) == 2
    data = json.loads(capsys.readouterr().out)
    assert data["code"] == 2 and data["error"].startswith("tvgw refused: it reads AdGuard Home's query log")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        refused, "run", lambda *a, **kw: refused.Outcome(2, ["tvgw refused: no log, no page"])
    )
    assert cli.main(["--conf", "/nonexistent", "refused", "--json"]) == 2
    assert json.loads(capsys.readouterr().out) == {"error": "tvgw refused: no log, no page", "code": 2}


def test_a_name_let_through_after_an_older_refusal_is_first_sight_by_another_rule_or_the_same(site, lg):
    """The reviewer's case, the list re-push: api.streamco.example was refused by `||streamco.example^`
    30 days ago, then let through for 29 days, and is refused now by a new rule. That is a change, a
    likely cause; so is the same rule taken out and put back. Its own history is judged by its rule,
    and a lookup let through after its last refusal makes the next refusal new."""
    pro = site.list_id(PRO)
    old = [Lookup(NOW - 30 * DAY, "api.streamco.example", reason=3, rule="||streamco.example^", fid=pro)]
    let = [Lookup(NOW - d * DAY, "api.streamco.example") for d in range(29, 0, -1)]
    store(site, old + let)
    for rule in ("||api.streamco.example^", "||streamco.example^"):
        site.lookups = every(
            WINDOW_START + 30, 3, 60, name="api.streamco.example", reason=3, rule=rule, fid=pro
        )
        site.write()
        done = report(site, lg)
        (n,) = done.report.names
        assert (n.first_sight, n.likely, done.code) == (True, True, 1), rule
        lines = refused.render(done.report)
        assert lines[0] == "Most likely cause: api.streamco.example, refused 3 times since 09:50."
        assert (
            lines[1]
            == "  Why it is first: it was refused on 26 September, then let through until 25 October 10:00."
        )


def test_an_allowed_lookup_of_a_withheld_type_is_no_let_through_for_the_name_or_its_siblings(site, lg):
    """AAAA, HTTPS and SVCB lookups the TV goes without may be answered empty while the name's A
    lookups are refused: they neither make a long-refused name new nor hide a sibling's refusals, even
    when such a lookup is a sibling's newest row (its `hosts.last_blocked` is then 0)."""
    pro = site.list_id(PRO)
    rows = []
    for d in range(30, 0, -1):
        for name in ("lgsmartad.com", "cdpbeacon1.lgtvcommon.com"):
            rule = "||lgsmartad.com^" if name == "lgsmartad.com" else "||lgtvcommon.com^"
            rows.append(Lookup(NOW - d * DAY, name, reason=3, rule=rule, fid=pro))
            rows.append(Lookup(NOW - d * DAY + 1, name, qtype="AAAA"))  # answered empty, after
    store(site, rows)
    site.lookups = [
        *every(WINDOW_START + 30, 3, 60, name="lgsmartad.com", reason=3, rule="||lgsmartad.com^", fid=pro),
        *every(
            WINDOW_START + 40,
            3,
            60,
            name="cdpbeacon9.lgtvcommon.com",
            reason=3,
            rule="||lgtvcommon.com^",
            fid=pro,
        ),
    ]
    site.write()
    done = report(site, lg)
    assert {n.name: (n.first_sight, n.by_domain) for n in done.report.names} == {
        "lgsmartad.com": (False, False),
        "cdpbeacon9.lgtvcommon.com": (False, True),
    }
    assert done.code == 0


def test_a_window_whose_only_refusals_are_names_that_are_not_internet_names_says_so(site, lg):
    site.lookups = [
        Lookup(WINDOW_START + 30, "printer.lan", reason=3, rule="||lan^"),
        Lookup(WINDOW_START + 40, "api.netflix.com"),
    ]
    site.write()
    lines = text(site, lg)
    assert lines[0] == (
        "No internet name was refused for the TV in the last 10 minutes: only names that are not internet"
        " names, which the note below counts."
    )
    assert any(line.startswith("Note: 1 lookup of names that are not internet names") for line in lines)


def test_a_title_zones_reason_says_what_was_checked(site, lg):
    """Under NAME_HMAC=on the store is asked about a title zone by its rule, never by the title's name,
    so a first-seen zone's reason speaks of the rule and the zone, not of the name."""
    store(site, every(NOW - 3 * DAY, 3, 600, name="api.app.example"))
    site.lookups = every(
        WINDOW_START + 30,
        2,
        60,
        name="the-show.amagi.tv",
        reason=3,
        rule="||amagi.tv^",
        fid=site.list_id(PRO),
    )
    site.write()
    done = refused.run(replace(site.s, name_hmac="on"), lg, WINDOW_START, NOW, admin=str(site.admin))
    lines = refused.render(done.report)
    assert (
        lines[1]
        == "  Why it is first: its rule refused no name under amagi.tv in the record since 23 October."
    )
