"""(threats) Known-bad and newly registered names, counted (design decision 80): the lists' formats and what
each entry covers, exceptions, public suffixes and punycode; the download's size cap, floor and guards that
keep the old copy, an unchanged list left alone, the newly-registered copies in the tmpfs; matching by
parent domain, the memory-light path; the record with answers that reached a server and the doubts; the
red line only for an answered threat-list name with no doubt, the list-may-be-wrong line and what the
doctor says of it; a day matched again when a newer copy comes; the two sections, the New line's tag,
`tvgw check`'s line, `tvgw threats`, and THREAT_LISTS=off doing nothing. Every list here is made up: no
real list content is in the repository (decision 32)."""

from __future__ import annotations

import dataclasses
import io
import json
import os
import random
import sqlite3
import tracemalloc
from pathlib import Path

import pytest
from conftest import NOW

from tvgw import analyst, cli, config, db, doctor, forget, ingest, namecheck, plain, queries, threats

TIF_URL = "https://lists.example/threats/tif.mini.txt"
NRD7_URL = "https://lists.example/nrd/nrd7.txt"
NRD14_URL = "https://lists.example/nrd/nrd14-8.txt"
URLS = f"tif={TIF_URL},nrd={NRD7_URL},nrd={NRD14_URL}"
DAY = "2026-10-25"  # the day before the fixtures' NOW (2026-10-26 10:00 CDT): settled
FILLER = 2000  # made-up names that pad a list over the floor
SERVER = "A:198.51.100.7"  # an answer that reaches a server
SINK = "A:0.0.0.0"


def filler(prefix: str, n: int = FILLER) -> list[str]:
    return [f"||{prefix}{i}.example.net^" for i in range(n)]


def adblock(*names: str, prefix: str = "pad", n: int = FILLER, declared: int | None = None) -> list[bytes]:
    """A made-up list in adblock format, as HaGeZi's header shapes it; a name with `@@` is an exception."""
    head = ["[Adblock Plus]", "! Title: a made-up threat list", "! Last modified: 25 Oct 2026 06:59 UTC"]
    body = [x if x.startswith("@@") else f"||{x}^" for x in names] + filler(prefix, n)
    head.append(f"! Number of entries: {declared if declared is not None else len(body)}")
    return [(line + "\n").encode() for line in [*head, "!", *body]]


def fetcher(lists: dict[str, list[bytes]], calls: list | None = None):
    """A stand-in for curl_lines: the lines each URL serves; a URL it has none for fails."""

    def fetch(url: str):
        if calls is not None:
            calls.append(url)
        if url not in lists:
            raise threats.FetchError("curl exited 22: The requested URL returned error: 404")
        yield from lists[url]

    return fetch


@pytest.fixture(autouse=True)
def run_dir(tmp_path, monkeypatch):
    """The newly-registered copies' tmpfs, under the test's own directory."""
    path = tmp_path / "run"
    monkeypatch.setattr(threats, "RUN_DIR", str(path))
    return path


@pytest.fixture()
def s(tmp_path):
    (tmp_path / "state").mkdir()
    return config.Settings(
        state_dir=str(tmp_path / "state"),
        db_path=str(tmp_path / "state" / "tvgw.db"),
        threat_lists="count",
        threat_list_urls=URLS,
    )


@pytest.fixture()
def conn(s):
    c = db.connect(s.db_path)
    yield c
    c.close()


def lists(**extra) -> dict[str, list[bytes]]:
    base = {
        TIF_URL: adblock("bad.example", "c2.example.org", prefix="tif"),
        NRD7_URL: adblock("new.example", prefix="nrd7"),
        NRD14_URL: adblock("young.example", prefix="nrd14"),
    }
    return {**base, **extra}


def download(s, served=None, now=NOW) -> threats.Outcome:
    return threats.update(s.state_dir, s.threat_lists, s.threat_list_urls, fetcher(served or lists()), now)


def lookup(conn, name: str, t: float, blocked: int = 0, n: int = 1, answers=SERVER, rule=None) -> None:
    for i in range(n):
        conn.execute(
            "INSERT INTO dns(t, qname, blocked, answers, rule) VALUES (?, ?, ?, ?, ?)",
            (t + i, name, blocked, None if blocked else answers, rule),
        )


def at(day: str, hour: int, minute: int = 0) -> float:
    return queries.day_bounds(day)[0] + hour * 3600 + minute * 60


def must_host(lg) -> str:
    return next(h for h in lg.must_allow if "*" not in h and "{" not in h)


# ---- the formats ----------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("line", "kept"),
    [
        ("||bad.example^", ["bad.example"]),
        ("||Bad.Example.^$important", ["bad.example"]),
        ("||bad.example^|", ["bad.example"]),  # the end anchor after the separator
        ("||bad.example^$client=10.10.10.17", []),  # a modifier that narrows the rule: not a list entry
        ("@@||good.example^", ["!good.example"]),  # an exception, kept to take names back out
        ("@@good.example", []),  # an exception in no form the lists use
        ("! Title: a list", []),
        ("# a comment", []),
        ("[Adblock Plus]", []),
        ("", []),
        ("bad.example", ["bad.example"]),
        ("bad.example   # a trailing comment", ["bad.example"]),
        ("*.bad.example", [".bad.example"]),  # the names under it, not itself
        ("||*.bad.example^", [".bad.example"]),
        ("0.0.0.0 bad.example", ["=bad.example"]),  # a hosts-file line: that name alone
        ("127.0.0.1 a.example b.example", ["=a.example", "=b.example"]),
        ("local=/bad.example/", ["bad.example"]),
        ("address=/a.example/b.example/0.0.0.0", ["a.example", "b.example"]),
        ("example.com##.banner", []),  # cosmetic
        ("/ad[0-9]+\\.example/", []),  # a regular expression
        ("|https://bad.example/path", []),
        ("||192.0.2.1^", []),  # an address
        ("||example^", []),  # a whole top-level domain belongs to another kind of list
        ("||co.uk^", []),  # a public suffix names no one tenant
        ("||github.io^", []),
        ("||evil.github.io^", ["evil.github.io"]),
        ("||ads*.example^", []),  # a wildcard inside a label cannot be matched by parent
        ("||bücher.example^", ["xn--bcher-kva.example"]),  # Unicode, in punycode
        ("printer.local", []),
        ("bad.example extra words", []),
    ],
)
def test_each_format_gives_the_entries_it_holds(line, kept):
    assert threats.entries(line) == kept


def test_the_fast_entry_check_agrees_with_is_public_name():
    """Property: the one expression the update reads millions of entries with keeps exactly the names
    `names.is_public_name()` keeps, a public suffix aside, over random strings of the characters names
    are made of."""
    from tvgw import names

    rng = random.Random(32)
    alphabet = "abcxyz019-_."
    for _ in range(20000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 18)))
        n = names.normalize(text)
        want = n if names.is_public_name(n) and n not in names.PUBLIC_SUFFIXES else None
        assert threats._name(text) == want, text
    for local in ("tv.local", "printer.lan", "1.10.10.10.in-addr.arpa"):
        assert threats._name(local) is None


def test_parse_counts_names_and_exceptions_and_reads_the_header():
    out = io.StringIO()
    got = threats.parse(adblock("bad.example", "@@||ok.bad.example^", n=3), out)
    assert out.getvalue().splitlines() == [
        "bad.example",
        "!ok.bad.example",
        *[f"pad{i}.example.net" for i in range(3)],
    ]
    assert (got.entries, got.exceptions, got.declared, got.modified) == (4, 1, 5, "25 Oct 2026 06:59 UTC")
    assert len(got.sha256) == 64


def test_the_urls_setting_takes_kinds_https_and_file_names_once():
    got = threats.parse_urls(f" tif={TIF_URL}  nrd={NRD7_URL},")
    assert [(x.kind, x.file) for x in got] == [("tif", "tif.mini.txt"), ("nrd", "nrd7.txt")]
    # the default is the threat list alone: the newly-registered lists are the owner's to add
    (default,) = threats.parse_urls(config.Settings().threat_list_urls)
    assert default.kind == "tif" and default.url.startswith("https://cdn.jsdelivr.net/gh/hagezi/")
    for bad, why in (
        ("", "names no list"),
        ("ads=https://lists.example/a.txt", "expected tif=URL or nrd=URL"),
        ("tif=http://lists.example/a.txt", "expected an https:// URL"),
        ("tif=https://lists.example/", "must end in a file name"),
        ("tif=https://lists.example/lists.json", "must end in a file name"),
        (f"tif={TIF_URL},nrd=https://other.example/tif.mini.txt", "same file name"),
        (",".join(f"tif=https://lists.example/{i}.txt" for i in range(9)), "more than 8"),
    ):
        with pytest.raises(ValueError, match=why):
            threats.parse_urls(bad)


def test_the_settings_refuse_a_bad_url_and_a_near_miss(tmp_path):
    conf = tmp_path / "tvgw.conf"
    conf.write_text("THREAT_LIST_URLS=tif=http://lists.example/a.txt\n", encoding="utf-8")
    with pytest.raises(ValueError, match="https://"):
        config.load(conf)
    conf.write_text("THREAT_LISTS=on\n", encoding="utf-8")
    with pytest.raises(ValueError, match=r"THREAT_LISTS='on' in tvgw\.conf: expected one of off, count"):
        config.load(conf)
    assert config.load(tmp_path / "missing.conf").threat_lists == "off"  # absent means off


def test_labels_and_bands():
    assert threats.label("tif", config.Settings().threat_list_urls) == "HaGeZi Threat Intelligence Feeds"
    assert threats.label("nrd", "https://cdn.jsdelivr.net/gh/hagezi/nrd@latest/adblock/nrd7.txt", True) == (
        "HaGeZi NRD"
    )
    assert threats.label("tif", TIF_URL) == "tif.mini.txt from lists.example"
    assert (threats.band("nrd7.txt"), threats.band("nrd14-8.txt"), threats.band("young.txt")) == (
        "1-7",
        "8-14",
        None,
    )
    assert threats.band_words("1-7", "2026-10-26") == "registered in the 7 days before 2026-10-26"
    assert threats.band_words("8-14", "2026-10-26") == "registered 8 to 14 days before 2026-10-26"
    assert threats.band_words(None, "2026-10-26") == "on a list of newly registered names of 2026-10-26"


# ---- the download ---------------------------------------------------------------------------------------
def test_an_update_writes_the_threat_list_to_the_card_and_the_new_domains_to_the_tmpfs(s, run_dir):
    out = download(s)
    assert out.code == 0
    assert out.lines[0] == "tvgw threats: tif.mini.txt: 2,002 names (tif.mini.txt from lists.example)"
    d = threats.threat_dir(s.state_dir)
    assert sorted(os.listdir(d)) == [".update.lock", "lists.json", "tif.mini.txt"]
    assert sorted(os.listdir(run_dir)) == ["nrd14-8.txt", "nrd7.txt"]
    with open(os.path.join(d, "tif.mini.txt"), encoding="utf-8") as fh:
        assert fh.readline() == "bad.example\n"
    assert oct(os.stat(os.path.join(d, "tif.mini.txt")).st_mode & 0o777) == "0o640"
    m = threats.load_manifest(d)["tif.mini.txt"]
    assert (m["kind"], m["url"], m["entries"], m["fetched"], m["declared"]) == (
        "tif",
        TIF_URL,
        2002,
        NOW,
        2002,
    )
    assert [c.file for c in threats.copies(s.state_dir, threats.parse_urls(URLS))] == [
        "tif.mini.txt",
        "nrd7.txt",
        "nrd14-8.txt",
    ]


def test_an_unchanged_list_leaves_its_copy_alone(s):
    assert download(s).code == 0
    copy = Path(threats.threat_dir(s.state_dir)) / "tif.mini.txt"
    inode = copy.stat().st_ino
    out = download(s, now=NOW + 86400)
    assert out.code == 0 and out.lines[0].endswith("(tif.mini.txt from lists.example, unchanged)")
    assert copy.stat().st_ino == inode  # no rename: the card is not written a second copy
    assert threats.load_manifest(str(copy.parent))["tif.mini.txt"]["fetched"] == NOW + 86400
    out = download(
        s, lists(**{TIF_URL: adblock("bad.example", "worse.example", prefix="tif")}), NOW + 2 * 86400
    )
    assert "unchanged" not in out.lines[0] and copy.stat().st_ino != inode


@pytest.mark.parametrize(
    ("served", "why"),
    [
        (adblock("bad.example", n=10), "fewer than the floor of 1,000"),
        (adblock("bad.example", declared=5000), "of the 5,000 it declares: cut off"),
        ([b"<html><body>Bad gateway</body></html>\n"], "fewer than the floor"),
    ],
)
def test_a_list_the_floor_or_the_header_refuses_keeps_the_old_copy(s, served, why):
    assert download(s).code == 0
    d = threats.threat_dir(s.state_dir)
    copy = Path(d) / "tif.mini.txt"
    before = copy.read_text(encoding="utf-8")
    out = download(s, lists(**{TIF_URL: served}), now=NOW + 86400)
    assert out.code == 1
    assert why in out.lines[0] and out.lines[0].endswith("kept the copy of 2026-10-26")
    assert copy.read_text(encoding="utf-8") == before
    m = threats.load_manifest(d)["tif.mini.txt"]
    assert m["fetched"] == NOW and m["entries"] == 2002 and why in m["error"]
    assert not [f for f in os.listdir(d) if f.startswith(".tif")]  # no staged file left behind


def test_a_list_that_shrinks_by_more_than_half_keeps_the_old_copy(s):
    assert download(s, lists(**{TIF_URL: adblock("bad.example", n=5000)})).code == 0
    out = download(s, lists(**{TIF_URL: adblock("bad.example", n=2400)}), now=NOW + 86400)
    assert out.code == 1 and "under half the 5,001 of the copy it would replace" in out.lines[0]
    # half exactly is no shrink past the guard
    assert download(s, lists(**{TIF_URL: adblock("bad.example", n=2500)}), now=NOW + 86400).code == 0


def test_a_download_that_fails_midway_keeps_the_old_copy_and_one_with_none_says_so(s, tmp_path):
    def broken(url):
        yield from adblock("bad.example", n=3000)[:500]
        raise threats.FetchError("curl exited 28: Operation timed out")

    assert download(s).code == 0
    out = threats.update(s.state_dir, "count", URLS, broken, NOW + 86400)
    assert out.code == 1 and all("Operation timed out; kept the copy of 2026-10-26" in x for x in out.lines)
    fresh = str(tmp_path / "fresh")
    os.makedirs(fresh)
    out = threats.update(fresh, "count", URLS, broken, NOW)
    assert out.lines[0].endswith("Operation timed out; no copy yet")
    assert threats.copies(fresh, threats.parse_urls(URLS)) == []


def test_a_list_no_longer_named_is_removed_and_off_downloads_nothing_and_removes_the_copies(s, run_dir):
    assert download(s).code == 0
    out = threats.update(s.state_dir, "count", f"tif={TIF_URL}", fetcher(lists()), NOW)
    assert "tvgw threats: nrd7.txt: removed, since THREAT_LIST_URLS no longer names it" in out.lines
    assert os.listdir(run_dir) == []
    d = threats.threat_dir(s.state_dir)
    assert sorted(f for f in os.listdir(d) if not f.startswith(".")) == ["lists.json", "tif.mini.txt"]
    calls: list = []
    out = threats.update(s.state_dir, "off", URLS, fetcher(lists(), calls), NOW)
    assert calls == [] and out.code == 0
    assert out.lines == ["tvgw threats: THREAT_LISTS is off, so nothing was downloaded; removed 1 old copy"]
    assert [f for f in os.listdir(d) if not f.startswith(".")] == []


def test_a_reboot_empties_the_tmpfs_and_nothing_breaks(s, conn, lg, run_dir):
    """After a reboot the newly-registered copies are gone until the timer's run at boot: the threat
    list still matches, nothing warns, and the day is matched again once they are back."""
    download(s)
    lookup(conn, "bad.example", at(DAY, 9))
    lookup(conn, "new.example", at(DAY, 10))
    for f in os.listdir(run_dir):
        os.unlink(run_dir / f)
    assert threats.step(conn, s, lg, NOW) == []
    assert conn.execute("SELECT name, list FROM threat_hits").fetchall() == [("bad.example", "tif")]
    download(s, now=NOW + 600)
    threats.step(conn, s, lg, NOW + 600)
    assert sorted(conn.execute("SELECT name, list FROM threat_hits")) == [
        ("bad.example", "tif"),
        ("new.example", "nrd"),
    ]


class FakeCurl:
    """subprocess.Popen as curl_lines uses it: the argv, its lines, its stderr and exit status."""

    def __init__(self, lines: list[bytes], rc: int = 0, err: bytes = b""):
        self.lines, self.rc, self.err, self.argv, self.killed = lines, rc, err, None, False

    def __call__(self, argv, stdout, stderr):
        self.argv = argv
        self.stdout = iter(self.lines)
        self.stderr = io.BytesIO(self.err)
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def kill(self):
        self.killed = True

    def wait(self):
        return self.rc


def test_curl_is_https_only_capped_and_a_failure_is_an_error():
    ok = FakeCurl([b"||bad.example^\n"])
    assert list(threats.curl_lines(TIF_URL, popen=ok)) == [b"||bad.example^\n"]
    assert ok.argv[:6] == ["curl", "-fsSL", "--proto", "=https", "--proto-redir", "=https"]
    assert ok.argv[-2:] == ["--", TIF_URL] and "--max-filesize" in ok.argv and "--max-time" in ok.argv
    big = FakeCurl([b"x" * 600 + b"\n"] * 3)
    with pytest.raises(threats.FetchError, match="larger than 1,000 bytes"):
        list(threats.curl_lines(TIF_URL, max_bytes=1000, popen=big))
    assert big.killed
    failed = FakeCurl([], rc=22, err=b"curl: (22) The requested URL returned error: 404\n")
    with pytest.raises(threats.FetchError, match="curl exited 22: curl: \\(22\\) The requested URL"):
        list(threats.curl_lines(TIF_URL, popen=failed))


# ---- matching -------------------------------------------------------------------------------------------
def copy_of(tmp_path, *entries_: str, kind: str = "tif") -> threats.Copy:
    path = tmp_path / f"{kind}-copy.txt"
    path.write_text("".join(f"{e}\n" for e in entries_), encoding="utf-8")
    return threats.Copy(kind, path.name, str(path), TIF_URL, len(entries_), NOW)


def test_a_name_matches_by_itself_or_a_parent_never_by_a_suffix_of_a_label(tmp_path):
    c = copy_of(tmp_path, "bad.example", "c2.example.org")
    names = ["a.b.bad.example", "bad.example", "notbad.example", "bad.example.org", "c2.example.org"]
    found = threats.match(names, [c])
    assert sorted(found) == [("a.b.bad.example", "tif"), ("bad.example", "tif"), ("c2.example.org", "tif")]
    assert found[("a.b.bad.example", "tif")].entry == "bad.example"


def test_what_each_kind_of_entry_covers_and_an_exception_takes_back(tmp_path):
    c = copy_of(tmp_path, "=exact.example", ".under.example", "both.example", "!ok.both.example")
    names = ["exact.example", "a.exact.example", "under.example", "a.under.example", "both.example"]
    names += ["a.both.example", "ok.both.example", "x.ok.both.example"]
    found = threats.match(names, [c])
    assert sorted(n for n, _ in found) == [
        "a.both.example",
        "a.under.example",
        "both.example",
        "exact.example",
    ]
    assert found[("a.under.example", "tif")].entry == "under.example"


def test_the_most_specific_entry_is_the_one_kept(tmp_path):
    found = threats.match(["a.b.bad.example"], [copy_of(tmp_path, "bad.example", "b.bad.example")])
    assert found[("a.b.bad.example", "tif")].entry == "b.bad.example"


def test_a_public_suffix_never_carries_a_match(tmp_path):
    """A copy written before the parse skipped public suffixes, or by hand, still covers no tenant."""
    found = threats.match(["evil.github.io", "a.example.co.uk"], [copy_of(tmp_path, "github.io", "co.uk")])
    assert found == {}


def test_matching_memory_grows_with_the_names_never_with_the_list(tmp_path):
    """The memory-light path: a list a hundred times longer costs the matcher no more memory."""
    names = [f"host{i}.svc{i % 97}.example.com" for i in range(3000)]
    peaks = []
    for n in (2_000, 200_000):
        path = tmp_path / f"list{n}.txt"
        with open(path, "w", encoding="utf-8") as fh:
            fh.writelines(f"d{i}.example.net\n" for i in range(n))
        copy = threats.Copy("nrd", path.name, str(path), NRD7_URL, n, NOW)
        tracemalloc.start()
        threats.match(names, [copy])
        peaks.append(tracemalloc.get_traced_memory()[1])
        tracemalloc.stop()
    assert peaks[1] < 1.2 * peaks[0] + 256 * 1024 and peaks[1] < 8 * 1024**2, peaks


def test_a_random_name_matches_exactly_as_the_entries_define(tmp_path):
    """Property: against the definition of each mark, over random names and lists of a small alphabet."""
    rng = random.Random(80)
    labels = ["a", "b", "ab", "c"]

    def covered(n: str, e: str) -> bool:
        mark, d = (e[0], e[1:]) if e[0] in "=.!" else ("", e)
        return (
            n == d if mark == "=" else n.endswith("." + d) if mark == "." else n == d or n.endswith("." + d)
        )

    for _ in range(80):
        listed = {
            rng.choice(["", "=", ".", "!"]) + ".".join(rng.choice(labels) for _ in range(rng.randint(2, 3)))
            for _ in range(8)
        }
        names = {".".join(rng.choice(labels) for _ in range(rng.randint(2, 4))) for _ in range(12)}
        found = threats.match(names, [copy_of(tmp_path, *sorted(listed))])
        blocks = [e for e in listed if e[0] != "!"]
        out = [e for e in listed if e[0] == "!"]
        expect = {
            n for n in names if any(covered(n, e) for e in blocks) and not any(covered(n, e) for e in out)
        }
        assert {n for n, _ in found} == expect


# ---- the record -----------------------------------------------------------------------------------------
def test_a_day_is_matched_into_its_rows_counting_only_answers_that_reached_a_server(s, conn, lg):
    download(s, lists(**{TIF_URL: adblock("bad.example", "dead.example", "sunk.example", prefix="tif")}))
    lookup(conn, "a.bad.example", at(DAY, 19), n=3)
    lookup(conn, "A.Bad.Example.", at(DAY, 20), blocked=1, n=2)  # the same name, as a log may spell it
    lookup(conn, "dead.example", at(DAY, 9), n=4, answers=None)  # NXDOMAIN or SERVFAIL: no address
    lookup(conn, "sunk.example", at(DAY, 9), n=2, answers=SINK)  # a sinkhole's answer
    lookup(conn, "new.example", at(DAY, 21))
    lookup(conn, "harmless.example", at(DAY, 22))
    lookup(conn, "bad.example", at("2026-10-24", 23))  # another day
    cps = threats.copies(s.state_dir, threats.parse_urls(URLS))
    assert threats.match_day(conn, DAY, lg, cps, NOW) == 4
    got = conn.execute(
        "SELECT name, list, entry, source, copy, band, lookups, answered, first, last, doubt FROM threat_hits"
        " ORDER BY list, name"
    ).fetchall()
    src = "tif.mini.txt from lists.example"
    assert got == [
        ("new.example", "nrd", "new.example", "nrd7.txt from lists.example", "2026-10-26", "1-7", 1, 1,
         at(DAY, 21), at(DAY, 21), None),
        ("a.bad.example", "tif", "bad.example", src, "2026-10-26", None, 5, 3, at(DAY, 19), at(DAY, 20) + 1,
         None),
        ("dead.example", "tif", "dead.example", src, "2026-10-26", None, 4, 0, at(DAY, 9), at(DAY, 9) + 3, None),
        ("sunk.example", "tif", "sunk.example", src, "2026-10-26", None, 2, 0, at(DAY, 9), at(DAY, 9) + 1, None),
    ]  # fmt: skip
    meta = threats.load_meta(conn)[DAY]
    assert meta["copies"][0] == ["tif", "tif.mini.txt", "2026-10-26", 2003, src, NOW]
    # matched again, the day's rows are replaced, never added to
    assert threats.match_day(conn, DAY, lg, cps, NOW) == 4
    assert conn.execute("SELECT COUNT(*) FROM threat_hits").fetchone() == (4,)


def test_each_reason_to_doubt_the_list_is_recorded(s, conn, lg):
    """A must-allow host, an expected category, a zone never blocked at its apex, an answer under an allow
    rule, and a name the TV looked up on most of the 14 days before; the first that holds."""
    names = [must_host(lg), "rr3.googlevideo.com", "x.apex.example", "allowed.example", "routine.example"]
    download(s, lists(**{TIF_URL: adblock(*names, "fresh.example", prefix="tif")}))
    prof = dataclasses.replace(lg, never_block_apex=(*lg.never_block_apex, "apex.example"))
    for name in names[:3]:
        lookup(conn, name, at(DAY, 9))
    lookup(conn, "allowed.example", at(DAY, 9), rule="@@||allowed.example^")
    for back in range(1, 9):  # 8 of the 14 days before
        lookup(conn, "routine.example", at(DAY, 9) - back * 86400)
    for back in (1, 2, 15, 16, 17, 18, 19, 20):  # 8 days, but 6 of them too far back
        lookup(conn, "fresh.example", at(DAY, 9) - back * 86400)
    lookup(conn, "routine.example", at(DAY, 9))
    lookup(conn, "fresh.example", at(DAY, 9))
    threats.match_day(conn, DAY, prof, threats.copies(s.state_dir, threats.parse_urls(URLS)), NOW)
    got = dict(conn.execute("SELECT name, doubt FROM threat_hits WHERE day = ?", (DAY,)).fetchall())
    assert got == {
        names[0]: "must-allow",
        "rr3.googlevideo.com": "expected:Streaming",
        "x.apex.example": "apex:apex.example",
        "allowed.example": "allow-rule",
        "routine.example": "familiar:8",
        "fresh.example": None,  # looked up on 2 of the 14 days before: a name the TV took up lately
    }


def test_the_step_matches_settled_days_once_and_never_the_day_in_progress(s, conn, lg):
    download(s)
    for day in ("2026-10-18", "2026-10-19", "2026-10-25"):
        lookup(conn, "bad.example", at(day, 12))
    lookup(conn, "bad.example", at("2026-10-26", 9))  # today, not settled
    assert threats.step(conn, s, lg, NOW) == []
    days = [r[0] for r in conn.execute("SELECT day FROM threat_hits ORDER BY day")]
    assert days == ["2026-10-19", "2026-10-25"]  # BACKFILL_DAYS back; 10-18 is too old to start with
    assert sorted(threats.load_meta(conn)) == [f"2026-10-{d}" for d in range(19, 26)]
    conn.execute("DELETE FROM threat_hits")
    assert threats.step(conn, s, lg, NOW + 3600) == []  # every settled day is matched: nothing again
    assert conn.execute("SELECT COUNT(*) FROM threat_hits").fetchone() == (0,)
    # the day ends at midnight and is matched SETTLE after it, as tvgw-analyze writes the daily file
    end = queries.day_bounds("2026-10-26")[1]
    threats.step(conn, s, lg, end + threats.SETTLE - 60)
    assert "2026-10-26" not in threats.load_meta(conn)
    threats.step(conn, s, lg, end + threats.SETTLE)
    assert conn.execute("SELECT day FROM threat_hits").fetchall() == [("2026-10-26",)]


def test_a_day_matched_against_a_copy_older_than_its_end_is_matched_again_when_a_newer_comes(s, conn, lg):
    """The night's download failed, so the day was matched against the day before's list: the next copy
    matches it again. A day matched against a copy fetched after it ended is not matched again."""
    end = queries.day_bounds(DAY)[1]
    download(s, now=end - 3600)  # fetched before the day ended
    lookup(conn, "late.example", at(DAY, 9))
    threats.step(conn, s, lg, NOW)
    assert conn.execute("SELECT COUNT(*) FROM threat_hits").fetchone() == (0,)
    newer = lists(**{TIF_URL: adblock("late.example", prefix="tif")})
    download(s, newer, now=NOW + 3600)
    threats.step(conn, s, lg, NOW + 3600)
    assert conn.execute("SELECT name FROM threat_hits WHERE day = ?", (DAY,)).fetchall() == [
        ("late.example",)
    ]
    later = lists(**{TIF_URL: adblock("late.example", "later.example", prefix="tif")})
    lookup(conn, "later.example", at(DAY, 10))
    download(s, later, now=NOW + 7200)
    threats.step(conn, s, lg, NOW + 7200)  # the day's copy now came after its end: it stays as matched
    assert conn.execute("SELECT name FROM threat_hits WHERE day = ?", (DAY,)).fetchall() == [
        ("late.example",)
    ]


def test_off_matches_nothing_and_forgets_which_days_were_matched(s, conn, lg):
    download(s)
    lookup(conn, "bad.example", at(DAY, 12))
    threats.step(conn, s, lg, NOW)
    assert threats.load_meta(conn)
    conn.execute("DELETE FROM threat_hits")
    off = dataclasses.replace(s, threat_lists="off")
    assert threats.step(conn, off, lg, NOW) == []
    assert threats.load_meta(conn) == {} and conn.execute("SELECT COUNT(*) FROM threat_hits").fetchone() == (
        0,
    )


def test_no_copy_warns_only_once_an_update_has_failed(s, conn, lg):
    assert threats.step(conn, s, lg, NOW) == []  # the timer has not run yet
    threats.update(s.state_dir, "count", URLS, fetcher({}), NOW)
    (w,) = threats.step(conn, s, lg, NOW)
    assert w.startswith("no list copy to match against: curl exited 22")


def test_the_hourly_ingest_runs_the_step_and_prunes_the_rows(gateway, lg):
    s = dataclasses.replace(gateway, threat_lists="count", threat_list_urls=URLS)
    download(s)
    stats = ingest.run(s, lg, lock=False, oddport_lines=lambda _: [], gate_lines=lambda _: [])
    assert not [w for w in stats.warnings if w.startswith("threats")]
    c = db.connect(s.db_path)
    assert "2026-10-25" in threats.load_meta(c)
    c.execute(
        "INSERT INTO threat_hits(day, name, list, entry, lookups, answered, first, last) VALUES"
        " ('2025-01-01', 'bad.example', 'tif', 'bad.example', 1, 1, 1.0, 2.0)"
    )
    assert ingest.prune(c, 365, NOW) >= 1
    assert c.execute("SELECT COUNT(*) FROM threat_hits").fetchone() == (0,)
    c.close()


def test_forget_empties_the_rows_and_the_days_matched():
    assert forget.TABLES["threat_hits"][0] == forget.FORGET and threats.META_KEY in forget.META_FORGET
    assert forget.classify("threat", forget.STATE_ENTRIES)[0] == forget.KEEP  # public lists, no viewing


# ---- the brief ------------------------------------------------------------------------------------------
@pytest.fixture()
def matched(s, conn, lg):
    """A settled day with an answered threat-list name, a refused one, a must-allow one and a new one."""
    must = must_host(lg)
    download(s, lists(**{TIF_URL: adblock("bad.example", "worse.example", must, prefix="tif")}))
    lookup(conn, "bad.example", at(DAY, 19), n=14)
    lookup(conn, "worse.example", at(DAY, 20), blocked=1, n=4)
    lookup(conn, must, at(DAY, 9), n=2, rule=f"@@||{must}^$important")
    lookup(conn, "api.new.example", at(DAY, 21), n=3)
    threats.step(conn, s, lg, NOW)
    return must


def test_the_report_sums_a_window_and_tells_matched_days_apart(conn, matched):
    a, b = queries.day_bounds(DAY)
    sec = threats.report(conn, a, b, NOW)
    assert [(h["name"], h["list"], h["lookups"], h["answered"], h["doubt"]) for h in sec["hits"]] == [
        ("bad.example", "tif", 14, 14, None),
        ("worse.example", "tif", 4, 0, None),
        (matched, "tif", 2, 2, "must-allow"),
        ("api.new.example", "nrd", 3, 3, None),
    ]
    assert sec["matched"] == [DAY] and not sec["stale"]
    assert [c["file"] for c in sec["copies"]] == ["tif.mini.txt", "nrd7.txt", "nrd14-8.txt"]
    week = threats.report(conn, a - 6 * 86400, b + 86400, NOW)
    assert week["days"][-1] == "2026-10-26" and "2026-10-26" not in week["matched"]
    assert threats.report(conn, a, b, NOW + 9 * 86400)["stale"]


def test_a_gateway_that_never_matched_has_no_section_and_no_change(conn):
    a, b = queries.day_bounds(DAY)
    assert threats.report(conn, a, b, NOW) is None
    out = io.StringIO()
    cli.render_threats(None, out)
    assert out.getvalue() == ""


def test_the_red_line_is_an_answered_threat_list_name_with_no_doubt_and_its_tier_is_act(conn, lg, matched):
    o = queries.brief(conn, DAY, lg, now=NOW)
    reds = [x for x in o["red_lines"] if x.startswith(threats.RED_LINE)]
    assert reds == [
        "known-bad name answered: bad.example x14 of 14 lookups, on tif.mini.txt from lists.example"
        " (copy of 2026-10-26): see Known-bad names"
    ]
    assert plain.tier(reds[0])[0] == "act"
    t, sentence, act = plain.items(o, lg)[0]
    assert t == "act" and sentence.startswith("The TV looked up a name on a list of known malware")
    assert "bad.example" not in sentence + act  # the action and the login message never carry the name
    assert act.startswith("If you installed an app recently, remove it.")


def test_a_must_allow_host_on_the_list_is_the_lists_error_of_the_doctor_tier(conn, lg, matched):
    o = queries.brief(conn, DAY, lg, now=NOW)
    (doubt,) = [x for x in o["red_lines"] if x.startswith(threats.DOUBT_LINE)]
    assert doubt == (
        "threat list may be wrong: tif.mini.txt from lists.example (copy of 2026-10-26) names 1 name the"
        f" filter answered that the TV uses on purpose or that came too many at once: {matched} (kept"
        " reachable on purpose); see Known-bad names"
    )
    assert plain.tier(doubt)[0] == "doctor"
    assert (
        "doctor",
        "A list of malware servers names services the TV uses on purpose, or many at once, so the list is"
        " probably wrong. Nothing was blocked.",
        plain.doctor_action(),
    ) in plain.items(o, lg)


def test_a_poisoned_list_that_names_a_streaming_host_never_sends_the_household_to_the_tv(s, conn, lg):
    download(s, lists(**{TIF_URL: adblock("googlevideo.com", prefix="tif")}))
    lookup(conn, "rr1.sn-a.googlevideo.com", at(DAY, 20), n=300)
    threats.step(conn, s, lg, NOW)
    o = queries.brief(conn, DAY, lg, now=NOW)
    assert not [x for x in o["red_lines"] if x.startswith(threats.RED_LINE)]
    assert [plain.tier(x)[0] for x in o["red_lines"] if x.startswith(threats.DOUBT_LINE)] == ["doctor"]
    assert all(t != "act" for t, _, _ in plain.items(o, lg))
    assert not plain._threat_note(o)


def test_more_than_three_names_at_once_are_one_line_that_the_list_may_be_wrong(s, conn, lg):
    names = [f"c2-{i}.example" for i in range(threats.MAX_NAMED + 1)]
    download(s, lists(**{TIF_URL: adblock(*names, prefix="tif")}))
    for name in names:
        lookup(conn, name, at(DAY, 12))
    threats.step(conn, s, lg, NOW)
    o = queries.brief(conn, DAY, lg, now=NOW)
    assert not [x for x in o["red_lines"] if x.startswith(threats.RED_LINE)]
    (line,) = [x for x in o["red_lines"] if x.startswith(threats.DOUBT_LINE)]
    assert "names 4 names" in line and "c2-0.example (one of 4 at once)" in line and "and 1 more" in line
    # three at once are three names
    conn.execute("DELETE FROM threat_hits WHERE name = ?", (names[-1],))
    o = queries.brief(conn, DAY, lg, now=NOW)
    assert len([x for x in o["red_lines"] if x.startswith(threats.RED_LINE)]) == 3
    assert not [x for x in o["red_lines"] if x.startswith(threats.DOUBT_LINE)]


def test_a_name_answered_with_no_address_or_refused_makes_no_red_line(conn, lg, matched):
    conn.execute("UPDATE threat_hits SET answered = 0 WHERE name = 'bad.example'")
    o = queries.brief(conn, DAY, lg, now=NOW)
    assert not [x for x in o["red_lines"] if x.startswith(threats.RED_LINE)]
    assert not plain._threat_note(o)


def test_the_doctor_explains_the_lists_error_and_a_stale_copy(s, conn, lg, matched):
    conn.commit()
    notes = threats.doctor_notes(s, NOW)
    assert notes == [
        "Threat lists (counting only):",
        f"  tif.mini.txt from lists.example names {matched}, which the gateway let through: kept reachable on"
        " purpose. The list is probably wrong about it.",
        "  Nothing was blocked. The gateway goes on counting them; to stop, point THREAT_LIST_URLS at another"
        " list, or set THREAT_LISTS=off, in /etc/tvgw/tvgw.conf.",
    ]
    later = threats.doctor_notes(s, NOW + 9 * 86400)
    assert later[-1].startswith("  The copy of nrd14-8.txt is 9 days old. Run sudo tvgw threats --update;")
    assert threats.doctor_notes(dataclasses.replace(s, threat_lists="off"), NOW) == []
    said: list[str] = []
    env = doctor.Env(
        check=lambda: doctor.verify.Result(checks=[]),
        run=lambda argv: (0, ""),
        read=lambda p: "",
        resolve=lambda n: None,
        say=said.append,
        ask=lambda q: False,
        interactive=lambda: False,
        is_root=lambda: True,
        lock=lambda: None,
        trim_backups=lambda: [],
        notes=lambda: notes,
    )
    assert doctor.main(s, lg, env) == 0
    assert said[1:-1] == notes and said[-1] == doctor.BYPASS
    # after a check that wants a look, the notes come at the end too, before the way back
    said.clear()
    warn = doctor.verify.Check("tv_paths", True, "a radio may be on", warn=True)
    assert (
        doctor.main(s, lg, dataclasses.replace(env, check=lambda: doctor.verify.Result(checks=[warn]))) == 0
    )
    assert said[-len(notes) - 1 : -1] == notes and said[-1] == doctor.BYPASS


def test_the_plain_brief_names_the_name_and_tags_a_newly_registered_service_by_its_copy(conn, lg, matched):
    o = queries.brief(conn, DAY, lg, now=NOW)
    o["new_hosts"] = [
        {"name": "api.new.example", "new_domain": True},
        {"name": "other.example", "new_domain": True},
    ]
    lines = plain.plain_brief(o, profile=lg)
    assert (
        "  New: the TV used 2 new services (new.example, registered in the 7 days before 26 October;"
        " other.example)."
    ) in lines
    assert (
        "  Known-bad: The TV looked up bad.example 14 times, and the gateway let every one through. It is on"
        " a list of known malware and botnet servers (tif.mini.txt from lists.example, copy of 2026-10-26)."
    ) in lines
    assert lines[5].startswith("  Action: The TV looked up a name on a list of known malware")
    # with no newly registered name the line reads as before
    o["threats"]["hits"] = [h for h in o["threats"]["hits"] if h["list"] == "tif"]
    assert "  New: the TV used 2 new services (new.example, other.example)." in plain.plain_brief(
        o, profile=lg
    )


def test_several_known_bad_names_are_one_line(conn, lg, matched):
    conn.execute("UPDATE threat_hits SET answered = 1 WHERE name = 'worse.example'")
    o = queries.brief(conn, DAY, lg, now=NOW)
    assert plain._threat_note(o) == [
        "  Known-bad: The TV looked up 2 names on a list of known malware and botnet servers (tif.mini.txt"
        " from lists.example, copy of 2026-10-26). The gateway let them through: bad.example 14 times,"
        " worse.example 1 time."
    ]


def test_the_engineering_brief_keeps_threat_and_newly_registered_names_apart(conn, lg, matched):
    o = queries.brief(conn, DAY, lg, now=NOW)
    out = io.StringIO()
    cli.render_threats(o["threats"], out)
    text = out.getvalue().splitlines()
    assert text[1] == (
        "Known-bad names (count-only; matched on the gateway against downloaded lists): 3 on a threat list"
    )
    assert text[2].startswith("  lists: tif.mini.txt from lists.example (copy of 2026-10-26, 2,003 names);")
    assert text[3].split() == ["name", "lookups", "answered", "first", "last", "note"]
    assert text[4].split()[:3] == ["bad.example", "14", "14"]
    assert text[6].endswith("kept reachable on purpose")
    assert text[8] == (
        "Newly registered names (count-only; a new domain is not a known-bad one): 1 on a list of newly"
        " registered domains"
    )
    assert text[10].endswith("under new.example, registered in the 7 days before 2026-10-26")
    out = io.StringIO()
    cli.render_threats(queries.brief(conn, "2026-10-26", lg, now=NOW)["threats"], out)
    assert (
        out.getvalue()
        .splitlines()[1]
        .endswith("not matched yet; each day is matched once, 3 h after it ends")
    )
    full = io.StringIO()
    cli.render_brief(o, full)
    assert "\nKnown-bad names (count-only;" in full.getvalue()
    assert "RED LINE: known-bad name answered: bad.example x14" in full.getvalue()


def test_a_broken_section_costs_the_brief_one_line(conn, lg, matched):
    o = queries.brief(conn, DAY, lg, now=NOW)
    o["threats"] = {"hits": [{"list": "tif"}], "matched": [DAY]}
    out = io.StringIO()
    cli.render_brief(o, out)
    assert "Known-bad names: could not be shown (KeyError" in out.getvalue()


def test_a_report_failure_is_a_warning_and_no_red_line(conn, lg, matched, monkeypatch):
    def broken(*a):
        raise sqlite3.OperationalError("boom")

    monkeypatch.setattr(threats, "report", broken)
    o = queries.brief(conn, DAY, lg, now=NOW)
    assert o["threats"] is None and "known-bad names: OperationalError: boom" in o["warnings"]
    assert not [x for x in o["red_lines"] if x.startswith((threats.RED_LINE, threats.DOUBT_LINE))]


def test_the_analysts_pack_leaves_both_lines_out(conn, lg, matched, s):
    a, b = queries.day_bounds(DAY)
    o = queries.brief(conn, DAY, lg, now=NOW)
    assert [x for x in o["red_lines"] if x.startswith(threats.RED_LINE)]
    assert [x for x in o["red_lines"] if x.startswith(threats.DOUBT_LINE)]
    p = analyst.pack(conn, a, b, DAY, lg, s)
    assert not [x for x in p["red_lines"] if x.startswith((threats.RED_LINE, threats.DOUBT_LINE))]


# ---- tvgw check and tvgw threats ------------------------------------------------------------------------
def test_check_says_when_a_name_is_on_a_list_and_nothing_otherwise(s):
    download(s)
    assert namecheck.threat_lines("a.bad.example", s) == [  # a list that is not HaGeZi's: by file and host
        "  On a threat list: yes (tif.mini.txt from lists.example, copy of 2026-10-26)"
    ]
    hz = dataclasses.replace(
        s,
        threat_list_urls=(
            "tif=https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt,"
            "nrd=https://cdn.jsdelivr.net/gh/hagezi/nrd@latest/adblock/nrd14-8.txt"
        ),
    )
    served = {
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt": adblock(
            "bad.example", prefix="t"
        ),
        "https://cdn.jsdelivr.net/gh/hagezi/nrd@latest/adblock/nrd14-8.txt": adblock(
            "bad.example", prefix="n"
        ),
    }
    assert threats.update(hz.state_dir, "count", hz.threat_list_urls, fetcher(served), NOW).code == 0
    assert namecheck.threat_lines("a.bad.example", hz) == [
        "  On a threat list: yes (HaGeZi TIF, copy of 2026-10-26)",
        "  Newly registered: yes, registered 8 to 14 days before 2026-10-26 (HaGeZi NRD)",
    ]
    assert namecheck.threat_lines("notbad.example", hz) == []
    assert namecheck.threat_lines("a.bad.example", dataclasses.replace(hz, threat_lists="off")) == []


def test_check_puts_the_line_after_the_company(s, lg):
    answer = {"reason": "NotFilteredNotFound", "rules": []}
    listed = ["  On a threat list: yes (HaGeZi TIF, copy of 2026-10-26)"]
    out = namecheck.explain("bad.example", answer, lg, s, {}, {}, listed)
    assert out.lines[2:4] == ["  Kind: other services", listed[0]]


def test_threats_lists_the_rows_and_says_when_it_is_off(s, conn, lg, matched, capsys, monkeypatch):
    conn.commit()
    monkeypatch.setattr(config, "load", lambda *a, **kw: s)
    assert cli.main(["threats", "2026-10-20"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0].split() == ["day", "name", "list", "lookups", "answered", "first", "last", "note"]
    assert any(line.startswith("2026-10-25  bad.example") for line in out)
    assert out[-1].startswith("lists: tif.mini.txt from lists.example (copy of 2026-10-26, 2,003 names);")
    assert out[-1].endswith("matched up to 2026-10-25")
    assert cli.main(["threats", "2026-10-20", "--json"]) == 0
    got = json.loads(capsys.readouterr().out)
    assert {r["name"] for r in got["rows"]} >= {"bad.example", "api.new.example"} and got["matched"]
    empty = dataclasses.replace(s, threat_lists="off", db_path=s.db_path + "-empty")
    db.connect(empty.db_path).close()
    monkeypatch.setattr(config, "load", lambda *a, **kw: empty)
    assert cli.main(["threats"]) == 0
    assert capsys.readouterr().out.startswith("tvgw threats: THREAT_LISTS is off, so no name is matched")


def test_update_and_match_need_root(s, capsys, monkeypatch):
    monkeypatch.setattr(config, "load", lambda *a, **kw: s)
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert cli.main(["threats", "--update"]) == 2
    assert capsys.readouterr().out == "tvgw threats: --update writes the list copies; run it with sudo\n"
    assert cli.main(["threats", "--match", DAY]) == 2


def test_match_on_demand_marks_only_a_settled_day(s, conn, lg, capsys, monkeypatch):
    download(s)
    lookup(conn, "bad.example", at("2026-10-26", 9))
    lookup(conn, "bad.example", at(DAY, 9))
    conn.commit()
    monkeypatch.setattr(config, "load", lambda *a, **kw: s)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert cli.main(["threats", "--match", "2026-10-26"]) == 0
    assert capsys.readouterr().out == (
        "tvgw threats: 2026-10-26: 1 name on the lists; the day is not over, so the hourly ingest matches"
        " it again once it is\n"
    )
    assert cli.main(["threats", "--match", DAY]) == 0
    c = db.connect(s.db_path, readonly=True)
    assert sorted(threats.load_meta(c)) == [DAY]
    assert c.execute("SELECT day FROM threat_hits ORDER BY day").fetchall() == [(DAY,), ("2026-10-26",)]
    c.close()


def test_the_cli_parses_the_command():
    a = cli.build_parser().parse_args(["threats"])
    assert a.fn is cli.cmd_threats and not a.update and a.match is None
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["threats", "--update", "--match", DAY])
