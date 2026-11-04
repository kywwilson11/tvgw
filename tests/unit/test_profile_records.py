"""Profile format v2: [[lan_api]] and [[privacy_setting]] records, their provenance, the citation check
for `.rules` files, and what `tvgw profile` prints (design decision 31)."""

import re

import pytest

from tvgw import cli, lgwebos, profile

SRC = "https://example.org/source"


def api(**over) -> dict:
    rec = {"name": "Remote API", "port": 8001, "protocol": "ws", "provenance": "unverified", "sources": [SRC]}
    rec.update(over)
    return rec


def setting(**over) -> dict:
    rec = {
        "name": "Viewing Data",
        "controls": "ACR",
        "recommended": "off",
        "menu": {"2024+": "Settings > Privacy > Viewing Data"},
        "sources": [SRC],
    }
    rec.update(over)
    return rec


def test_records_load_with_their_fields_and_provenance():
    p = profile.from_dict(
        {
            "lan_api": [
                api(tls="self-signed", reads=["power"], write="ok", gate="Network access", grade="spec"),
                {
                    "name": "Seen",
                    "port": 3000,
                    "protocol": "ws",
                    "provenance": "verified",
                    "evidence": "lan-api",
                },
            ],
            "privacy_setting": [
                setting(key="option.x", opt_out_effective="no", notes=["n"], grade="peer-reviewed")
            ],
        }
    )
    first, seen = p.lan_apis
    assert (first.port, first.protocol, first.tls, first.write, first.reads) == (
        8001,
        "ws",
        "self-signed",
        "ok",
        ("power",),
    )
    assert first.provenance == profile.Provenance("unverified", "spec", "", (SRC,))
    assert first.provenance.label() == "unverified, spec"
    assert seen.provenance.verified and seen.provenance.grade == "observed" and seen.write == "unknown"
    assert seen.provenance.label() == "verified here (lan-api)"
    (ps,) = p.privacy_settings
    assert ps.menu == (("2024+", "Settings > Privacy > Viewing Data"),) and ps.key == "option.x"
    assert ps.provenance.grade == "peer-reviewed" and ps.notes == ("n",)


def test_an_unverified_record_defaults_to_the_lowest_grade():
    p = profile.from_dict({"privacy_setting": [setting()]})
    assert p.privacy_settings[0].provenance == profile.Provenance("unverified", "low", "", (SRC,))


def test_menu_paths_keep_file_order():
    menu = {"newer": "a > b", "older": "c > d", "oldest": "e"}
    (ps,) = profile.from_dict({"privacy_setting": [setting(menu=menu)]}).privacy_settings
    assert [k for k, _ in ps.menu] == ["newer", "older", "oldest"]


@pytest.mark.parametrize(
    ("data", "key"),
    [
        # provenance: no fact without a capture or a citation
        ({"lan_api": [api(sources=[])]}, "lan_api[0].sources: an unverified record needs"),
        ({"lan_api": [api(sources=None)]}, "lan_api[0].sources: an unverified record needs"),
        ({"privacy_setting": [setting(sources="https://example.org")]}, "privacy_setting[0].sources"),
        ({"lan_api": [api(sources=["see the forum"])]}, "is not an http(s) URL"),
        ({"lan_api": [api(provenance="checked")]}, "lan_api[0].provenance"),
        ({"lan_api": [api(provenance="verified")]}, "lan_api[0].evidence"),  # verified names its evidence
        ({"lan_api": [api(provenance="verified", evidence="hunch")]}, "lan_api[0].evidence"),
        (
            {"lan_api": [api(provenance="verified", evidence="capture", grade="community")]},
            "lan_api[0].grade",
        ),
        ({"lan_api": [api(grade="observed")]}, "lan_api[0].grade"),  # observed is what verified means
        ({"lan_api": [api(grade="excellent")]}, "lan_api[0].grade"),
        ({"lan_api": [api(evidence="capture")]}, "lan_api[0].evidence: only a verified record"),
        # the record itself
        ({"lan_api": [api(port=70000)]}, "lan_api[0].port"),
        ({"lan_api": [api(port="8001")]}, "lan_api[0].port"),
        ({"lan_api": [api(port=True)]}, "lan_api[0].port"),
        ({"lan_api": [api(protocol="carrier-pigeon")]}, "lan_api[0].protocol"),
        ({"lan_api": [api(write="sometimes")]}, "lan_api[0].write"),
        ({"lan_api": [api(name="")]}, "lan_api[0].name"),
        ({"lan_api": [api(reads="power")]}, "lan_api[0].reads"),  # a bare string is not a list
        ({"lan_api": [api(pairing=3)]}, "lan_api[0].pairing"),
        ({"lan_api": [api(source=SRC)]}, "lan_api[0].source: unknown key"),  # the misspelt citation
        ({"lan_api": {"name": "x"}}, "lan_api: expected [[lan_api]] records"),
        ({"privacy_setting": [setting(menu={})]}, "privacy_setting[0].menu"),
        ({"privacy_setting": [setting(menu="Settings > Privacy")]}, "privacy_setting[0].menu"),
        ({"privacy_setting": [setting(menu={"2024": ""})]}, "privacy_setting[0].menu"),
        ({"privacy_setting": [setting(recommended="")]}, "privacy_setting[0].recommended"),
        ({"privacy_setting": [setting(controls=None)]}, "privacy_setting[0].controls"),
        (
            {"privacy_setting": [setting(), setting(evidance="capture")]},
            "privacy_setting[1].evidance: unknown key",
        ),
        ({"privacy_settings": [setting()]}, "privacy_settings: unknown table"),
    ],
)
def test_a_record_that_could_mislead_fails_at_load_naming_the_key(data, key):
    with pytest.raises(ValueError, match=re.escape(key)):
        profile.from_dict(data)


def test_records_change_nothing_that_is_blocked(lg):
    """The records are reference: stripping them leaves the rules AdGuard receives and the lint as they were."""
    import dataclasses

    bare = dataclasses.replace(lg, lan_apis=(), privacy_settings=())
    assert bare.adguard_rules("10.10.10.1", "10.10.10.17") == lg.adguard_rules("10.10.10.1", "10.10.10.17")
    assert bare.lint() == lg.lint() == []


def test_lg_records_are_verified_exactly_where_the_cx_showed_them(lg):
    """Only the webOS 5 SSAP reader (wss on 3001, the port the reader has always used; the record said
    3000 until 2026-11-04), Live Plus (read hourly over it) and the Voice Information agreement (seen on
    the wire) were observed on the CX; the generation table agrees on which line that is."""
    verified = {
        (type(r).__name__, r.name) for r in (*lg.lan_apis, *lg.privacy_settings) if r.provenance.verified
    }
    assert verified == {
        ("LanApi", "SSAP over TLS (webOS second screen)"),
        ("PrivacySetting", "Live Plus"),
        ("PrivacySetting", "Voice Information (user agreement)"),
    }
    (ssap,) = [a for a in lg.lan_apis if a.provenance.verified]
    assert (ssap.port, ssap.protocol) == (lgwebos.SSAP_PORT, "wss") and ssap.write == "refused"
    assert ssap.generations == ("5",)
    # port 3000 is on record as what the CX refuses and newer sets hang on: unverified, never tried
    (plain,) = [a for a in lg.lan_apis if a.port == 3000]
    assert not plain.provenance.verified and plain.reads == ()
    assert lg.generation_for(ssap.generations[0]).verified
    # the key the profile names is the one the reader turns into the hourly ACR warning
    live_plus = [s for s in lg.privacy_settings if s.name == "Live Plus"]
    assert {s.key for s in live_plus} == {lgwebos.ACR_KEY}
    assert any(s.provenance.verified and s.menu[0][0] == "webOS 5" for s in live_plus)


def test_every_bundled_record_is_cited_or_observed():
    for name in profile.bundled_names():
        p = profile.load(name)
        for rec in (*p.lan_apis, *p.privacy_settings):
            prov = rec.provenance
            assert prov.verified or prov.sources, (name, rec.name)
            assert prov.grade in profile.GRADES, (name, rec.name)
        # generations and hardware rows predate the provenance block; their grades must still be known ones
        for row in (*p.generations, *p.hardware):
            assert row.confidence in profile.GRADES, (name, row)


def test_only_the_lg_profile_claims_anything_verified():
    """No other vendor's set has been behind a gateway: a 'verified' record there would be a false claim."""
    for name in profile.bundled_names():
        if name == "lg-webos":
            continue
        p = profile.load(name)
        assert not any(r.provenance.verified for r in (*p.lan_apis, *p.privacy_settings)), name
        assert not any(g.verified for g in p.generations), name


# ---- citations in the .rules file ----------------------------------------------------------------------
def test_uncited_rules_reads_a_citation_as_the_comment_block_over_its_group():
    text = "\n".join(
        [
            "! header without a URL",
            "",
            "! group one, source: https://example.org/a",
            "||a.example^",
            "||b.example^",
            "! a second block inside the group, no URL",
            "||c.example^",
            "",
            "||d.example^",  # a blank line closes the group: nothing stands over this one
            "",
            "! group three",
            "! https://example.org/c on its second line",
            "/^e\\.example$/",
            "! http://example.org/old-style",
            "0.0.0.0 f.example",
            "||c.example^",  # a repeat is reported once
        ]
    )
    assert profile.uncited_rules(text) == ["||c.example^", "||d.example^"]


def test_uncited_rules_needs_a_url_not_the_word_source():
    assert profile.uncited_rules("! Sources: HaGeZi\n||a.example^\n") == ["||a.example^"]
    assert profile.uncited_rules("") == [] and profile.uncited_rules("! only comments\n") == []


def test_bundled_names_lists_every_shipped_profile():
    names = profile.bundled_names()
    assert names == tuple(sorted(names))
    assert {"lg-webos", "samsung-tizen", "roku", "vizio-smartcast"} <= set(names)
    for name in names:
        assert profile.load(name).name == name  # [profile].name agrees with the file it lives in


# ---- tvgw profile --------------------------------------------------------------------------------------
def test_cli_profile_prints_records_with_their_provenance(tmp_path, capsys):
    conf = tmp_path / "none.conf"
    assert cli.main(["--conf", str(conf), "profile"]) == 0
    out = capsys.readouterr().out
    assert "\nLAN APIs:\n" in out and "\nPrivacy settings:\n" in out
    assert (
        "  SSAP over TLS (webOS second screen): wss/3001, TLS self-signed (verified here (lan-api); generations 5)"
        in out
    )
    assert "  SSAP without TLS: ws/3000 (unverified, community; generations 5, 6, 22, 23, 24, 25, 26)" in out
    assert "  Live Plus: off (verified here (lan-api); key option.livePlus)" in out
    assert "    webOS 5: Settings > General > Additional Settings > Live Plus" in out
    assert "    source: https://github.com/home-assistant-libs/aiowebostv/issues/744" in out
    assert out.index("Generations:") < out.index("LAN APIs:") < out.index("Privacy settings:")


def test_cli_profile_escapes_record_text_from_a_profile_file(tmp_path, capsys):
    toml = tmp_path / "x.toml"
    toml.write_text(
        '[profile]\nname = "x"\n[[privacy_setting]]\nname = "Bad\\u001b[2Jname"\ncontrols = "c"\n'
        'recommended = "off"\nmenu = { "a" = "b" }\nsources = ["https://example.org"]\n',
        encoding="utf-8",
    )
    (tmp_path / "x.rules").write_text("", encoding="utf-8")
    assert cli.main(["--conf", str(tmp_path / "none.conf"), "profile", "--profile", str(toml)]) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out and "LAN APIs:" not in out and "  Bad" in out


def test_cli_profile_says_nothing_about_records_a_profile_does_not_have(tmp_path, capsys):
    toml = tmp_path / "bare.toml"
    toml.write_text('[profile]\nname = "bare"\n', encoding="utf-8")
    (tmp_path / "bare.rules").write_text("", encoding="utf-8")
    assert cli.main(["--conf", str(tmp_path / "none.conf"), "profile", "--profile", str(toml)]) == 0
    out = capsys.readouterr().out
    assert "LAN APIs" not in out and "Privacy settings" not in out
