"""(requests) `tvgw requests`, design decision 75: the companies the TV reached against the ones it only
tried to reach, and the drafts. A company is reached only through a named connection or a plain-HTTP
request; a draft warns first, fills in no identifier, and is never sent; the files are private and never
written over; nothing opens a connection."""

import json
import os
import socket
import stat
import time

import pytest
from appfront_store import DAY, H0, YT, Store, evening

from tvgw import cli, drafts, forget

NOW = H0 + 30 * DAY


@pytest.fixture()
def store(tmp_path):
    s = Store(tmp_path / "tvgw.db")
    yield s
    s.conn.close()


def http(store: Store, t: float, host: str, status: int) -> None:
    store.conn.execute(
        "INSERT INTO http(t, host, method, uri, status, src) VALUES (?, ?, 'GET', '/', ?, 'gfts')",
        (t, host, status),
    )
    store.conn.commit()


def record(store: Store) -> None:
    for day in range(3):
        t = evening(day, 20)
        store.reading(t, "Active", YT)
        store.lookup(t, "us.lgtvsdp.com")
        store.talk(t + 1, "us.lgtvsdp.com")
        store.lookup(t + 2, "tkacr601.alphonso.tv", blocked=1)  # LG Group's, refused
        store.lookup(t + 3, "www.youtube.com")
        store.talk(t + 4, "www.youtube.com")
        store.lookup(t + 5, "ads.doubleclick.net", blocked=1)  # Google's too: Google is reached anyway
        store.lookup(t + 6, "secure.adnxs.com", blocked=1)  # only ever refused
        store.lookup(t + 7, "api.mixpanel.com")  # answered, no named connection
        store.talk(t + 8, "edge.unknownco.example")  # reached, no company known
        store.lookup(t + 9, "printer.lan")  # not an internet name
        store.lookup(t + 10, "mrm.fwmrm.net")
        store.talk(t + 11, "mrm.fwmrm.net", up_=400, down_=0)  # no data came back: refused, never reached
    http(store, evening(1, 21), "ngfts.lge.com", 200)  # the URL filter passed it to LG
    http(store, evening(2, 21), "ngfts.lge.com", 403)  # the URL filter refused it


def read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def found(store, lg) -> dict:
    return drafts.observed(store.conn, lg, NOW - 30 * DAY, NOW)


def test_reached_attempted_and_answered_are_kept_apart(store, lg):
    record(store)
    r = found(store, lg)
    reached = {e["company"]: e for e in r[drafts.REACHED]}
    assert set(reached) == {"LG Group", "Google"}
    lg_group = reached["LG Group"]
    assert lg_group["domains"] == {
        "lge.com": ["2026-10-27"],
        "lgtvsdp.com": ["2026-10-26", "2026-10-27", "2026-10-28"],
    }
    assert lg_group["connections"] == 4 and lg_group["refused_domains"] == ["alphonso.tv"]
    assert reached["Google"]["refused_domains"] == ["doubleclick.net"]
    assert [e["company"] for e in r[drafts.ATTEMPTED]] == ["Microsoft Corporation"]
    assert all(e["connections"] == 0 and e["answered"] == 0 for e in r[drafts.ATTEMPTED])
    assert [e["company"] for e in r[drafts.ANSWERED]] == ["Comcast", "Mixpanel"]
    assert [e["company"] for e in r["unknown"]] == ["unknownco.example"]
    assert "printer.lan" not in json.dumps(r) and "lan" not in {e["company"] for e in r["unknown"]}
    text = "\n".join(drafts.render(r))
    assert "Only attempted" in text and "the TV sent these nothing through it" in text
    assert "The TV also reached 1 site whose company" in text


def test_a_draft_warns_first_names_what_identifies_the_household_and_fills_in_nothing(store, lg):
    record(store)
    store.conn.execute("INSERT INTO tvsettings(t, key, value) VALUES (?, 'model', 'OLED55CX5LB')", (H0,))
    store.conn.commit()
    r = found(store, lg)
    e = next(x for x in r[drafts.REACHED] if x["company"] == "LG Group")
    text = drafts.draft(e, "2026-10-09", "2026-11-08")
    assert text.startswith("DRAFT: a request to LG Group")
    assert text.index("Before you send it") < text.index("To: <the privacy contact of LG Group>")
    for words in ("tvgw never sends a draft", "tells LG Group who you are", "tvgw\n  filled in none",
                  "Delete it if you would rather not say that", "tvgw does not know it", "not legal advice"):  # fmt: skip
        assert words in text, words
    assert "- lgtvsdp.com (3 days)" in text and "- lge.com (1 day)" in text
    assert "which my gateway refused: alphonso.tv" in text
    assert "<your name>" in text and "<the TV's model and\nserial number>" in text
    assert "OLED55CX" not in text and "10.10.10." not in text


def test_a_long_list_is_cut_and_the_slug_is_safe():
    e = {"company": "A/B Co., Ltd.", "domains": {f"d{i:02d}.example": ["2026-11-01"] for i in range(15)},
         "refused_domains": []}  # fmt: skip
    text = drafts.draft(e, "2026-10-09", "2026-11-08")
    assert "- and 3 more" in text and "- d11.example (1 day)" in text and "d12.example" not in text
    assert drafts.slug("A/B Co., Ltd.") == "a-b-co-ltd" and drafts.slug("***") == "company"


def test_drafts_are_private_files_in_a_new_directory_and_never_overwrite(store, lg, tmp_path):
    record(store)
    r = found(store, lg)
    out = str(tmp_path / "drafts")
    paths = drafts.write(r, out)
    names = sorted(os.listdir(out))
    assert names == ["01-lg-group.txt", "02-google.txt", "README.txt"] and len(paths) == 2
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o700
    assert all(stat.S_IMODE(os.stat(os.path.join(out, n)).st_mode) == 0o600 for n in names)
    notice = read(os.path.join(out, drafts.NOTICE))
    assert "tvgw never sends a draft" in notice
    assert all(e["company"] in notice for e in r[drafts.ATTEMPTED])
    before = {n: read(os.path.join(out, n)) for n in names}
    with pytest.raises(drafts.NotEmpty):
        drafts.write(r, out)
    assert {n: read(os.path.join(out, n)) for n in os.listdir(out)} == before


def test_the_default_directory_is_dated_and_a_second_run_gets_its_own(tmp_path):
    first = drafts.default_dir(str(tmp_path), NOW)
    assert first == os.path.join(str(tmp_path), "requests", "2026-11-24")
    os.makedirs(first)
    assert drafts.default_dir(str(tmp_path), NOW) == first + "-2"


def test_forget_deletes_the_drafts():
    assert forget.classify(drafts.DIR, forget.STATE_ENTRIES)[0] == forget.FORGET


def test_the_command_opens_no_connection_and_writes_only_with_draft(store, tmp_path, monkeypatch, capsys):
    record(store)
    monkeypatch.setattr(time, "time", lambda: NOW)

    def no_socket(*a, **k):
        raise AssertionError("tvgw requests opened a socket")

    monkeypatch.setattr(socket, "socket", no_socket)
    monkeypatch.setattr(socket, "create_connection", no_socket)
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f"STATE_DIR={tmp_path / 'state'}\nPROFILE=lg-webos\n", encoding="utf-8")
    run = ["--conf", str(conf), "--db", store.path, "requests"]
    assert cli.main(run) == 0
    assert "Reached (2)" in capsys.readouterr().out and not (tmp_path / "state").exists()
    assert cli.main([*run, "--out", str(tmp_path / "x")]) == 2
    assert "--out goes with --draft" in capsys.readouterr().err
    out = tmp_path / "mine"
    assert cli.main([*run, "--draft", "--out", str(out)]) == 0
    said = capsys.readouterr().out
    assert (
        f"wrote 2 drafts to {out}" in said
        and "Nothing was sent" in said
        and "identifies your household" in said
    )
    assert cli.main([*run, "--draft", "--out", str(out)]) == 1
    assert "is not empty" in capsys.readouterr().err
    (tmp_path / "state").mkdir()
    assert cli.main([*run, "--draft"]) == 0
    assert len(os.listdir(tmp_path / "state" / "requests")) == 1
    assert stat.S_IMODE(os.stat(tmp_path / "state" / "requests").st_mode) == 0o700
    capsys.readouterr()
    assert cli.main([*run, "--json"]) == 0
    assert {e["company"] for e in json.loads(capsys.readouterr().out)["reached"]} == {"LG Group", "Google"}
    assert cli.main([*run, "--days", "0"]) == 2
