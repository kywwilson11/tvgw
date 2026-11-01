"""(record) Minimization at ingest: kernel lines without host name and MAC header, query values as their
lengths, title-bearing names as keyed tags; each applied to new rows and, once, to the rows stored."""

import dataclasses
import json
import os
import stat

import pytest
from conftest import DNS_ALLOWED, NOW, ODDPORT_LINE, fake_extract, fake_oddport

from tvgw import config, db, ingest, minimize, queries

# ---- kernel lines -----------------------------------------------------------------------------------


def test_a_kernel_line_loses_the_host_name_and_the_mac_header_and_keeps_every_parsed_field():
    clean = minimize.scrub_kernel_line(ODDPORT_LINE)
    assert "gateway" not in clean and "00:11" not in clean
    assert clean.startswith("1793020200.123456 kernel: tvgw-oddport: IN=eth0 OUT=wlan0 MAC= SRC=10.10.10.17")
    assert ingest._ODD_RE.search(clean).groups() == ingest._ODD_RE.search(ODDPORT_LINE).groups()
    assert minimize.scrub_kernel_line(clean) == clean  # idempotent: a second pass changes nothing


def test_a_full_mac_header_goes_whole():
    line = "1.5 host-name kernel: tvgw-gate: IN=eth0 MAC=aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:08:00 SRC=10.10.10.17"
    assert minimize.scrub_kernel_line(line) == "1.5 kernel: tvgw-gate: IN=eth0 MAC= SRC=10.10.10.17"


def test_a_line_that_is_not_journalctl_s_shape_keeps_its_words_but_loses_the_mac():
    assert minimize.scrub_kernel_line("no stamp here MAC=aa:bb x") == "no stamp here MAC= x"


# ---- query values -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("uri", "short"),
    [
        ("/a", "/a"),
        ("/a?", "/a?"),
        ("/search?q=the+show+name&page=2", "/search?q=<13>&page=<1>"),
        ("/x?token", "/x?<5>"),
        ("/x?a=&b=1", "/x?a=<0>&b=<1>"),
        ("/fts/x?biz_code=MAS&file_path=/p/a.xml", "/fts/x?biz_code=MAS&file_path=<8>"),
        ("/x?BIZ_CODE=PREMIUM", "/x?BIZ_CODE=PREMIUM"),
        ("/x?id=7#frag", "/x?id=<1>#<4>"),
        ("/x?id=<12>&t=<3>", "/x?id=<12>&t=<3>"),
        ("/x?a=1;biz_code=MAS;b=xyz", "/x?a=<1>;biz_code=MAS;b=<3>"),
        ("/x?a=1&b=2;biz_code=MAS", "/x?a=<1>&b=<1>;biz_code=MAS"),
    ],
)
def test_query_values_become_their_lengths(uri, short):
    assert minimize.uri_lengths(uri) == short
    assert minimize.uri_lengths(short) == short  # idempotent


def test_keep_mode_keeps_the_uri_whole():
    assert minimize.minimize_uri("/a?q=x", "keep") == "/a?q=x"
    assert minimize.minimize_uri("/a?q=x", "lengths") == "/a?q=<1>"


# ---- title-bearing names ----------------------------------------------------------------------------


@pytest.fixture()
def fast(lg):
    """The LG profile with a FAST category, as the acr workstream adds it: one plain zone, one wildcard."""
    return dataclasses.replace(lg, rules=(*lg.rules, ("amagi.tv", "FAST"), ("*.wurl.example", "FAST")))


def test_the_title_zones_are_the_plain_patterns_of_the_fast_category(lg, fast):
    assert minimize.title_zones(lg) == ()
    assert minimize.title_zones(fast) == ("amagi.tv",)


def hasher(tmp_path, now=NOW, protected=lambda n: False):
    return minimize.NameHasher(("amagi.tv",), str(tmp_path / "keys"), protected, now=lambda: now)


def test_a_title_name_becomes_a_keyed_tag_that_keeps_equality_and_the_zone(tmp_path):
    h = hasher(tmp_path)
    a = h.name("cooking-show-lgus.amagi.tv", NOW)
    assert a.endswith(".amagi.tv") and a.startswith(f"t-{int(NOW // minimize.EPOCH)}-")
    assert "cooking" not in a
    assert h.name("Cooking-Show-LGUS.amagi.tv.", NOW - 3600) == a  # same epoch, any case: the same tag
    assert h.name("other-show-lgus.amagi.tv", NOW) != a
    assert h.name(a, NOW) == a  # a tag is never tagged again
    assert h.name("amagi.tv", NOW) == "amagi.tv"  # the zone itself carries no title
    assert h.name("www.example.com", NOW) == "www.example.com"
    assert h.name(None, NOW) is None


def test_the_key_is_root_only_32_bytes_and_survives_a_new_hasher(tmp_path):
    a = hasher(tmp_path).name("x-lgus.amagi.tv", NOW)
    keys = tmp_path / "keys"
    (key,) = keys.iterdir()
    assert stat.S_IMODE(keys.stat().st_mode) == 0o700 and stat.S_IMODE(key.stat().st_mode) == 0o600
    assert len(key.read_bytes()) == minimize.KEY_BYTES
    assert hasher(tmp_path).name("x-lgus.amagi.tv", NOW) == a  # the key is read, not made again


def test_another_key_gives_another_tag_so_a_lost_key_unlinks_its_tags(tmp_path):
    a = hasher(tmp_path).name("x-lgus.amagi.tv", NOW)
    b = hasher(tmp_path / "elsewhere").name("x-lgus.amagi.tv", NOW)
    assert a != b and a.split(".")[0][:-10] == b.split(".")[0][:-10]  # same epoch number, other tag


def test_a_corrupt_key_stops_the_ingest_instead_of_splitting_names(tmp_path):
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / f"{int(NOW // minimize.EPOCH)}.key").write_bytes(b"short")
    with pytest.raises(ValueError, match="expected 32 bytes"):
        hasher(tmp_path).name("x.amagi.tv", NOW)


def test_rows_of_the_previous_epoch_use_its_key_until_it_is_retired(tmp_path):
    epoch = minimize.EPOCH
    start = (int(NOW // epoch) + 1) * epoch  # the first second of the next epoch
    early = hasher(tmp_path, now=start + 86400)
    old = early.name("x.amagi.tv", start - 3600)  # a late row from the epoch before
    assert old.startswith(f"t-{int(start // epoch) - 1}-")
    assert early.retire() == []  # inside the overlap both keys stay
    late = hasher(tmp_path, now=start + minimize.OVERLAP + 1)
    assert late.retire() == [f"{int(start // epoch) - 1}.key"]
    again = late.name("x.amagi.tv", start - 3600)  # the old key is gone and is never made again
    assert again.startswith(f"t-{int(start // epoch)}-") and again != old
    assert sorted(os.listdir(tmp_path / "keys")) == [f"{int(start // epoch)}.key"]


def test_protected_names_and_cname_answers(tmp_path, lg):
    protected = minimize.protected_names(lg)
    assert protected("us.lgtvsdp.com") and protected("gb.lgtvsdp.com") and not protected("x.amagi.tv")
    h = hasher(tmp_path, protected=lambda n: n == "keep.amagi.tv")
    assert h.name("keep.amagi.tv", NOW) == "keep.amagi.tv"
    out = h.answers("CNAME:show-a.amagi.tv,A:203.0.113.5,CNAME:cdn.example", NOW)
    kind, tagged = out.split(",")[0].split(":")
    assert kind == "CNAME" and tagged == h.name("show-a.amagi.tv", NOW)
    assert out.endswith(",A:203.0.113.5,CNAME:cdn.example")


def test_the_hasher_is_a_no_op_unless_asked_and_the_profile_has_title_zones(gateway, lg, fast):
    assert not minimize.hasher(gateway, fast).active  # NAME_HMAC=off
    on = dataclasses.replace(gateway, name_hmac="on")
    assert not minimize.hasher(on, lg).active  # no FAST category
    h = minimize.hasher(on, fast)
    assert h.active and h.key_dir == os.path.join(gateway.state_dir, "name-keys")


# ---- through the ingest ------------------------------------------------------------------------------


def run(s, prof):
    return ingest.run(
        s, prof, extract=fake_extract, oddport_lines=fake_oddport, gate_lines=lambda _: [], lock=False
    )


def test_by_default_the_ingest_keeps_names_and_queries_and_scrubs_kernel_lines(gateway, lg):
    assert run(gateway, lg).warnings == []
    conn = db.connect(gateway.db_path, readonly=True)
    assert conn.execute("SELECT uri FROM http WHERE src='pcap' AND method='GET'").fetchone() == (
        "/fts/x?biz_code=MAS",
    )
    (raw,) = conn.execute("SELECT raw FROM oddport").fetchone()
    assert raw == minimize.scrub_kernel_line(ODDPORT_LINE)
    assert db.get_meta(conn, "minimized_raw") == "1"


def test_lengths_mode_cuts_query_values_and_keeps_the_gfts_table(gateway, lg):
    s = dataclasses.replace(gateway, uri_values="lengths")
    run(s, lg)
    conn = db.connect(s.db_path, readonly=True)
    uris = {r[0] for r in conn.execute("SELECT uri FROM http WHERE src='gfts'")}
    assert uris == {
        "/fts/gftsDownload.lge?biz_code=PREMIUM&func_code=<3>&file_path=<18>",
        "/fts/gftsDownload.lge?biz_code=APP_STORE&func_code=<8>&file_path=<6>",
    }
    by_code = {r[1] for r in queries.gfts_summary(conn, 0, None)}
    assert by_code == {"PREMIUM", "APP_STORE"}  # the brief's GFTS table still reads its codes


def test_switching_to_lengths_rewrites_the_rows_stored_before_once(gateway, lg):
    run(gateway, lg)
    s = dataclasses.replace(gateway, uri_values="lengths")
    conn = db.connect(s.db_path)
    names = minimize.NameHasher((), "")
    done = minimize.rewrite_stored(conn, s, names)
    conn.commit()
    assert done == {"uri": 2}  # the two gfts rows with a file_path; the pcap row holds only biz_code
    assert minimize.rewrite_stored(conn, s, names) == {}
    assert db.get_meta(conn, "minimized_uri") == "lengths"


def test_name_hmac_tags_new_rows_and_the_stored_ones(gateway, fast):
    title = DNS_ALLOWED.replace('"QH":"us.lgtvsdp.com"', '"QH":"cooking-show-lgus.amagi.tv"')
    with open(gateway.adguard_querylog, "a", encoding="utf-8") as fh:
        fh.write("\n" + title)
    run(gateway, fast)  # NAME_HMAC=off: stored in clear, and counted in hosts
    conn = db.connect(gateway.db_path)
    conn.execute("INSERT INTO judgments(name, kind, t) VALUES ('other-show.amagi.tv', 'allow', ?)", (NOW,))
    conn.commit()
    assert conn.execute("SELECT COUNT(*) FROM hosts WHERE name LIKE '%amagi%'").fetchone()[0] == 1
    conn.close()
    on = dataclasses.replace(gateway, name_hmac="on")
    run(on, fast)
    conn = db.connect(on.db_path, readonly=True)
    names = [r[0] for r in conn.execute("SELECT qname FROM dns WHERE qname LIKE '%amagi%'")]
    assert len(names) == 1 and names[0].startswith("t-") and "cooking" not in names[0]
    assert conn.execute("SELECT qname FROM dns WHERE qname='us.lgtvsdp.com'").fetchone()  # the clock stays
    assert conn.execute("SELECT COUNT(*) FROM hosts WHERE name LIKE '%show%'").fetchone()[0] == 0
    (judged,) = conn.execute("SELECT name FROM judgments").fetchone()
    assert judged.startswith("t-") and judged.endswith(".amagi.tv")
    assert json.loads(db.get_meta(conn, "minimized_names")) == ["amagi.tv"]
    # a new lookup of the same title gets the same tag, so the detectors' equality holds
    with open(on.adguard_querylog, "a", encoding="utf-8") as fh:
        fh.write(title.replace("09:14:37", "09:20:00"))
    run(on, fast)
    conn = db.connect(on.db_path, readonly=True)
    assert {r[0] for r in conn.execute("SELECT qname FROM dns WHERE qname LIKE '%amagi%'")} == {names[0]}


def test_the_stored_rewrite_finds_cname_targets_anywhere_and_names_with_a_trailing_dot(gateway, fast):
    run(gateway, fast)  # NAME_HMAC=off: the store exists, nothing tagged
    conn = db.connect(gateway.db_path)
    rows = [
        ("cdn.example", "CNAME:show-one.amagi.tv,A:203.0.113.5"),  # the usual order: CNAME first
        ("cdn2.example", "CNAME:show-two.amagi.tv.,A:203.0.113.6"),  # a target with a trailing dot
        ("show-three.amagi.tv.", "A:203.0.113.7"),  # a qname with a trailing dot
        ("notamagi.tv", "A:203.0.113.8"),  # the zone as a substring of another name: stays
    ]
    for qname, answers in rows:
        conn.execute(
            "INSERT INTO dns(t, qname, qtype, answers, blocked) VALUES (?, ?, 'A', ?, 0)",
            (NOW, qname, answers),
        )
    conn.execute("INSERT INTO tls(t, sni) VALUES (?, 'show-four.amagi.tv.')", (NOW,))
    conn.execute("INSERT INTO http(t, host, src) VALUES (?, 'show-five.amagi.tv.', 'pcap')", (NOW,))
    on = dataclasses.replace(gateway, name_hmac="on")
    names = minimize.hasher(on, fast, now=lambda: NOW)
    done = minimize.rewrite_stored(conn, on, names)
    conn.commit()
    assert done["names"] >= 5
    text = " ".join(
        str(v)
        for q in ("SELECT qname, answers FROM dns", "SELECT sni FROM tls", "SELECT host FROM http")
        for row in conn.execute(q)
        for v in row
    )
    assert "show-" not in text  # no clear title anywhere, CNAME-first or trailing-dot
    (answers,) = conn.execute("SELECT answers FROM dns WHERE qname='cdn.example'").fetchone()
    assert answers == f"CNAME:{names.name('show-one.amagi.tv', NOW)},A:203.0.113.5"
    (tagged,) = conn.execute("SELECT qname FROM dns WHERE answers='A:203.0.113.7'").fetchone()
    assert tagged == names.name("show-three.amagi.tv", NOW)  # the same tag as without the dot
    assert conn.execute("SELECT 1 FROM dns WHERE qname='notamagi.tv'").fetchone()


# ---- settings ----------------------------------------------------------------------------------------


def test_the_settings_default_to_today_s_behaviour():
    s = config.Settings()
    assert (s.uri_values, s.name_hmac, s.journal_days) == ("keep", "off", "14")


@pytest.mark.parametrize(
    ("line", "error"),
    [
        ("URI_VALUES=drop", "URI_VALUES"),
        ("NAME_HMAC=yes", "NAME_HMAC"),
        ("JOURNAL_DAYS=0", "JOURNAL_DAYS"),
        ("JOURNAL_DAYS=3651", "JOURNAL_DAYS"),
        ("JOURNAL_DAYS=2w", "JOURNAL_DAYS"),
    ],
)
def test_a_near_miss_is_refused(tmp_path, line, error):
    conf = tmp_path / "tvgw.conf"
    conf.write_text(line + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match=error):
        config.load(conf)


def test_the_accepted_values_load(tmp_path):
    conf = tmp_path / "tvgw.conf"
    conf.write_text("URI_VALUES=lengths\nNAME_HMAC=on\nJOURNAL_DAYS=off\n", encoding="utf-8")
    s = config.load(conf)
    assert (s.uri_values, s.name_hmac, s.journal_days) == ("lengths", "on", "off")
    conf.write_text("JOURNAL_DAYS=92\n", encoding="utf-8")
    assert config.load(conf).journal_days == "92"
