"""(companies) The company behind a name: tvgw's pinned, trimmed snapshot of AdGuard's companies database
(src/tvgw/data/companies.txt), its header's provenance, licence and hash, the lookup that never
guesses, and tools/companies_snapshot.py, which writes the file, on a small input of the database's
own shape (no network here)."""

from __future__ import annotations

import hashlib
import json
import re

import pytest
from conftest import ROOT, load_tool

from tvgw import companies

snap = load_tool("companies_snapshot")

COMMIT = "c" * 40
TRACKERS = {
    "timeUpdated": "2026-11-02T10:07:05.262Z",
    "categories": {"4": "advertising", "8": "misc", "9": "cdn", "10": "hosting"},
    "trackers": {
        "lgads": {"name": "LG Ad Solutions", "categoryId": 4, "companyId": "lgcorp"},
        "lgtv": {"name": "LG TV", "categoryId": 8, "companyId": "lgcorp"},
        "akamai": {"name": "Akamai", "categoryId": 9, "companyId": "akamai"},
        "cloudfront": {"name": "Amazon CloudFront", "categoryId": 10, "companyId": "amazon"},
        "tenant": {"name": "A tenant", "categoryId": 4, "companyId": "tenant"},
        "nobody": {"name": "No company", "categoryId": 4},
        "rcs": {"name": "RCS", "categoryId": 4, "companyId": "rcs"},
    },
    "trackerDomains": {
        "alphonso.tv": "lgads",
        "lgtvsdp.com": "lgtv",
        "akamaized.net": "akamai",
        "cloudfront.net": "cloudfront",
        "d1tenant.cloudfront.net": "tenant",
        "orphan.example": "nobody",
        "corriere.it": "rcs",
        "printer.lan": "lgtv",
        "missing.example": "no-such-tracker",
    },
}
COMPANIES = {
    "companies": {
        "lgcorp": {"name": "LG Group"},
        "akamai": {"name": "Akamai Technologies"},
        "amazon": {"name": "Amazon"},
        "tenant": {"name": "Tenant\tCorp"},
        "rcs": {"name": "RCS MediaGroup S.p.A. \x03"},
    }
}


# ---- the shipped snapshot ------------------------------------------------------------------------------


def test_the_shipped_snapshot_is_whole_and_names_its_source_licence_and_attribution():
    """The header is the provenance the licence asks for: the database and its commit, the hash and the
    git blob of each file read, checked at the fetch, the suffix list's commit, CC BY-SA 4.0 by name and
    link, the copyright holders, the attribution to AdGuard and to WhoTracks.Me, what tvgw changed; and
    the lines are the ones the header's hash was taken of (companies.parse refuses anything else)."""
    header, table = companies.snapshot()
    assert re.fullmatch(
        r"AdGuard Companies DB, https://github\.com/AdguardTeam/companiesdb, commit [0-9a-f]{40}",
        header["Source"],
    )
    assert re.fullmatch(
        r"dist/trackers\.json sha256 [0-9a-f]{64} git blob [0-9a-f]{40}, dist/companies\.json sha256 [0-9a-f]{64}"
        r" git blob [0-9a-f]{40}; timeUpdated \S+; fetched at the commit, blobs checked",
        header["Read from"],
    )
    assert re.match(
        r"the Public Suffix List, https://github\.com/publicsuffix/list, commit [0-9a-f]{40},",
        header["Suffixes"],
    )
    assert header["Copyright"].startswith("the source gives no copyright notice; the database is AdGuard's")
    assert header["Licence"].startswith(
        "Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)"
    )
    text = (ROOT / "src" / "tvgw" / "data" / "companies.txt").read_text(encoding="utf-8")
    assert (
        "https://creativecommons.org/licenses/by-sa/4.0/" in text
        and "not under\n#   tvgw's MIT licence" in text
    )
    assert header["Attribution"].startswith(
        "AdGuard Companies DB by AdGuard; it builds on WhoTracks.Me by Ghostery"
    )
    assert "CC BY 4.0" in text and header["Changes"].startswith("tvgw kept only each domain")
    assert len(table) > 1000 and all("\t" not in v and v.isprintable() for v in table.values())


def test_the_snapshot_is_shipped_with_the_package_and_reaches_the_gateway():
    """pyproject.toml ships it, git keeps it, and both deploy paths copy it: neither .gitignore, which
    leaves out the gateway's own `*.tsv` state files, nor deploy/rsync.exclude, which follows it,
    names the file, or a checkout or a deploy without it would name no company."""
    import fnmatch
    import shutil
    import subprocess

    path = "src/tvgw/data/companies.txt"
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert '"data/*.txt"' in pyproject
    parts = path.split("/")
    for line in (ROOT / "deploy" / "rsync.exclude").read_text(encoding="utf-8").split():
        pattern = line.rstrip("/")
        if "/" in pattern:  # rsync matches a pattern with a slash against the path from the root
            assert not (fnmatch.fnmatchcase(path, pattern) or path.startswith(pattern + "/")), line
        else:  # and one without against each name in it
            assert not any(fnmatch.fnmatchcase(part, pattern) for part in parts), line
    if not shutil.which("git") or not (ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    ignored = subprocess.run(["git", "-C", str(ROOT), "check-ignore", "--no-index", "-q", path], check=False)
    assert ignored.returncode == 1, f".gitignore hides {path}"  # --no-index: a tracked file too


@pytest.mark.parametrize(
    ("name", "company"),
    [
        ("us.lgtvsdp.com", "LG Group"),  # the clock host: lgtvsdp.com's entry
        ("LGTVSDP.COM.", "LG Group"),
        ("x.alphonso.tv", "LG Group"),  # LG Ad Solutions, of LG Group
        ("samsungacr.com", "Samsung"),
        ("rr3---sn-x.googlevideo.com", "Google"),
        ("nflxvideo.net", "Netflix, Inc."),
    ],
)
def test_a_name_takes_the_nearest_domain_the_snapshot_lists(name, company):
    assert companies.company(name) == company


@pytest.mark.parametrize(
    "name",
    [
        "notlgtvsdp.com",  # a label boundary, not a suffix of letters
        "lg.example",  # a company's word in a name says nothing
        "samsung-tv.example",
        "d1.cloudfront.net",  # a carrier's domain names no tenant (the cdn and hosting rows are left out)
        "a.akamaized.net",
        "es.nextlgsdp.com",  # LG's, but the database does not list it: nothing is guessed
        "com",
        "",
        "printer.lan",
    ],
)
def test_a_name_no_entry_covers_says_nothing(name):
    assert companies.company(name) is None


def test_a_hand_edited_or_cut_snapshot_is_refused():
    text = (ROOT / "src" / "tvgw" / "data" / "companies.txt").read_text(encoding="utf-8")
    _, table = companies.parse(text)
    assert table
    edited = text.replace("\tLG Group\n", "\tSomeone Else\n", 1)
    with pytest.raises(companies.SnapshotError, match="do not match the hash"):
        companies.parse(edited)
    with pytest.raises(companies.SnapshotError, match="not a domain and a company"):
        companies.parse(text + "no tab here\n")
    with pytest.raises(companies.SnapshotError, match="do not match the hash"):
        companies.parse(text.rsplit("\n", 40)[0] + "\n")


# ---- the tool that writes it ------------------------------------------------------------------------------


PSL_TEXT = """// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// ===BEGIN ICANN DOMAINS===
com
net
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
// a provider whose customers each get a name under its suffix
azurewebsites.net
*.blob.core.windows.net
!www.blob.core.windows.net
// ===END PRIVATE DOMAINS===
"""


@pytest.fixture
def small(monkeypatch):
    """The tool's floors, lowered for an input of a handful of rows."""
    monkeypatch.setattr(snap, "MIN_ROWS", 1)
    monkeypatch.setattr(snap, "MIN_ADFIRMS", 1)
    monkeypatch.setattr(snap, "MIN_SUFFIXES", 1)


def raw() -> dict[str, bytes]:
    trackers = json.loads(json.dumps(TRACKERS))
    trackers["trackers"]["msft"] = {"name": "Azure Sites", "categoryId": 8, "companyId": "msft"}
    trackers["trackerDomains"].update(
        {
            "azurewebsites.net": "msft",
            "windows.net": "msft",
            "firebaseio.com": "msft",
            "UPPER.Example.": "lgtv",
        }
    )
    found = {"companies": {**COMPANIES["companies"], "msft": {"name": "Microsoft Corporation"}}}
    return {
        "trackers.json": json.dumps(trackers).encode(),
        "companies.json": json.dumps(found).encode(),
        "public_suffix_list.dat": PSL_TEXT.encode(),
    }


def test_the_tool_keeps_a_domain_and_its_company_and_leaves_out_carriers_and_guesses(small):
    """Kept: a tracker's domain with a company. Left out, each counted by reason: no company, the cdn
    and hosting categories, a carrier's domain by hand, a private-section public suffix and a domain
    above one (windows.net, above blob.core.windows.net), and a name no internet name. A tenant's own
    row under a carrier stays; a company's name is cleaned to one line."""
    files = raw()
    trackers, found = json.loads(files["trackers.json"]), json.loads(files["companies.json"])
    suffixes = snap.private_suffixes(PSL_TEXT)
    assert suffixes == {"azurewebsites.net", "blob.core.windows.net"}  # the wildcard's base; no exception
    kept, dropped = snap.rows(trackers, found, suffixes)
    assert kept == [
        ("alphonso.tv", "LG Group"),
        ("corriere.it", "RCS MediaGroup S.p.A."),  # the \x03 an entry ends in, cleaned
        ("d1tenant.cloudfront.net", "Tenant Corp"),  # a tenant's own row is no carrier's
        ("lgtvsdp.com", "LG Group"),
        ("upper.example", "LG Group"),
    ]
    assert dropped == {
        "cdn or hosting category": 2,
        "no company": 1,
        "no tracker": 1,
        "not an internet name": 1,
        "a carrier's domain, by hand": 1,
        "a public suffix, or above one": 2,
        "(kept, name cleaned)": 2,
    }


@pytest.mark.parametrize(
    ("change", "says"),
    [
        (lambda t, c: t.update(trackers=[]), "expected trackers.json with trackers"),
        (lambda t, c: t.update(categories={"4": "advertising"}), "categories no longer name"),
        (lambda t, c: t.update(categories={"9": "cdn", "10": "hosting"}), "categories no longer name"),
        (
            lambda t, c: [e.pop("companyId", None) for e in t["trackers"].values()],
            "trackers name a companyId",
        ),
        (lambda t, c: c.update(companies=[]), "expected trackers.json with trackers"),
        # a renamed categoryId would turn the carriers' filter off: cloudfront.net would name Amazon again
        (
            lambda t, c: [e.update(category=e.pop("categoryId")) for e in t["trackers"].values()],
            "carry a categoryId the categories name",
        ),
    ],
)
def test_the_tool_fails_on_an_input_whose_shape_changed(small, change, says):
    """A renamed field or a reshaped category table would otherwise pass with an almost empty file, or
    with the carriers' filter turned off: each is a DriftError, and the tool exits 2."""
    files = raw()
    trackers, found = json.loads(files["trackers.json"]), json.loads(files["companies.json"])
    change(trackers, found)
    with pytest.raises(snap.DriftError, match=says):
        snap.rows(trackers, found)
    with pytest.raises(snap.DriftError, match="no private section"):
        snap.private_suffixes("com\nnet\n")


def test_too_few_rows_or_suffixes_are_refused():
    with pytest.raises(snap.DriftError, match="fewer than 1000"):
        snap.render(
            COMMIT,
            COMMIT,
            {
                **raw(),
                "public_suffix_list.dat": (
                    "// ===BEGIN PRIVATE DOMAINS===\n"
                    + "\n".join(f"s{i}.example" for i in range(1000))
                    + "\n// ===END PRIVATE DOMAINS===\n"
                ).encode(),
            },
            fetched=False,
        )
    with pytest.raises(snap.DriftError, match="holds 2 suffixes"):
        snap.private_suffixes(PSL_TEXT)


def test_too_few_advertising_rows_are_refused(monkeypatch):
    monkeypatch.setattr(snap, "MIN_ROWS", 1)
    monkeypatch.setattr(snap, "MIN_SUFFIXES", 1)
    with pytest.raises(snap.DriftError, match="advertising domains kept, fewer than 500"):
        snap.render(COMMIT, COMMIT, raw(), fetched=False)


def test_the_file_it_writes_records_its_inputs_and_reads_back_whole(small):
    files = raw()
    text, adfirms, _ = snap.render(COMMIT, COMMIT, files, fetched=False)
    header, table = companies.parse(text)
    # the second file: the rows the database files under advertising, under the same provenance
    ad_header, ad_table = companies.parse(adfirms, companies.ADFIRMS)
    filed = snap.filed_under(json.loads(files["trackers.json"]), snap.ADVERTISING)
    assert ad_table == {domain: name for domain, name in table.items() if domain in filed}
    assert 0 < len(ad_table) < len(table)
    assert {key: ad_header[key] for key in header if key != "Body sha256"} == {
        key: value for key, value in header.items() if key not in ("Body sha256", "Changes")
    } | {"Changes": ad_header["Changes"]}
    assert ad_header["Changes"].startswith("as companies.txt's header lists them, and then only")
    assert header["Source"].endswith(f"commit {COMMIT}")
    for name in ("trackers.json", "companies.json"):
        data = files[name]
        assert (
            f"dist/{name} sha256 {hashlib.sha256(data).hexdigest()} git blob {snap.blob(data)}"
            in header["Read from"]
        )
    assert header["Read from"].endswith(
        "timeUpdated 2026-11-02T10:07:05.262Z; read from a folder, blobs not checked"
    )
    assert f"commit {COMMIT}, public_suffix_list.dat sha256" in header["Suffixes"]
    assert header["Suffixes"].endswith(
        "MPL 2.0; used only to leave rows out, and no part of it is in this file"
    )
    assert header["Copyright"].startswith("the source gives no copyright notice")
    assert "azurewebsites.net" not in text.split(snap.BODY_HASH)[1]  # nothing of the list is in the file
    assert table == dict(
        snap.rows(
            json.loads(files["trackers.json"]),
            json.loads(files["companies.json"]),
            snap.private_suffixes(PSL_TEXT),
        )[0]
    )
    long_ok = ("# Source", "# Read from", "# Suffixes")
    assert all(
        len(line) <= 110 or line.startswith(long_ok) for line in text.splitlines() if line.startswith("#")
    )


def test_a_fetch_is_checked_against_each_files_git_blob_at_its_commit():
    """The tool asks GitHub's contents API for each file's blob id at the commit and refuses a file
    whose bytes are not that blob: a first fetch is checked, not taken on trust."""
    files = raw()
    paths = {
        "dist/trackers.json": "trackers.json",
        "dist/companies.json": "companies.json",
        "public_suffix_list.dat": "public_suffix_list.dat",
    }
    served = []

    def get(url, tamper=None):
        served.append(url)
        path = next(p for p in paths if f"/{p}" in url)
        data = files[paths[path]]
        if "api.github.com" in url:
            return json.dumps({"sha": snap.blob(data)}).encode()
        return data + (b" " if tamper == path else b"")

    assert snap.fetch(COMMIT, "d" * 40, get) == files
    assert any("/AdguardTeam/companiesdb/" + COMMIT + "/dist/trackers.json" in u for u in served)
    assert any("publicsuffix/list/contents/public_suffix_list.dat?ref=" + "d" * 40 in u for u in served)
    with pytest.raises(snap.DriftError, match="is not the blob GitHub names"):
        snap.fetch(COMMIT, "d" * 40, lambda url: get(url, tamper="dist/companies.json"))


def test_the_tool_writes_from_a_folder_checks_without_writing_and_refuses_a_swing(tmp_path, capsys, small):
    for name, data in raw().items():
        (tmp_path / name).write_bytes(data)
    out = tmp_path / "companies.txt"
    args = ["--commit", COMMIT, "--psl-commit", COMMIT, "--from", str(tmp_path), "--out", str(out)]
    assert snap.main(args) == 0
    printed = capsys.readouterr().out
    assert "5 domains" in printed and "companies_snapshot: 2 a public suffix, or above one" in printed
    written = out.read_text(encoding="utf-8")
    adfirms = tmp_path / companies.ADFIRMS  # written beside it in the same run
    assert (
        f"wrote {adfirms}, {len(companies.parse(adfirms.read_text(encoding='utf-8'))[1])} domains" in printed
    )
    assert snap.main([*args, "--check"]) == 0
    adfirms.write_text(adfirms.read_text(encoding="utf-8") + "extra.example\tSomeone\n", encoding="utf-8")
    assert snap.main([*args, "--check"]) == 1  # either file differing fails the check
    assert f"{adfirms} differs from commit" in capsys.readouterr().out
    assert snap.main(args) == 0 and snap.main([*args, "--check"]) == 0
    changed = json.loads((tmp_path / "companies.json").read_text(encoding="utf-8"))
    changed["companies"]["lgcorp"] = {"name": "LG Electronics"}
    (tmp_path / "companies.json").write_text(json.dumps(changed), encoding="utf-8")
    assert snap.main([*args, "--check"]) == 1
    assert out.read_text(encoding="utf-8") == written  # --check writes nothing
    trackers = json.loads((tmp_path / "trackers.json").read_text(encoding="utf-8"))
    for i in range(10):  # twice the rows: more than SWING away from the file's five
        trackers["trackerDomains"][f"more{i}.example"] = "lgads"
    (tmp_path / "trackers.json").write_text(json.dumps(trackers), encoding="utf-8")
    assert snap.main(args) == 2 and out.read_text(encoding="utf-8") == written
    assert "more than 20% apart" in capsys.readouterr().err
    assert snap.main([*args, "--accept-swing"]) == 0 and out.read_text(encoding="utf-8") != written
    with pytest.raises(SystemExit):
        snap.main(["--commit", "main", "--psl-commit", COMMIT, "--from", str(tmp_path), "--out", str(out)])
    (tmp_path / "trackers.json").write_text("[]", encoding="utf-8")
    assert snap.main([*args, "--accept-swing"]) == 2


@pytest.mark.parametrize(
    "name",
    [
        "mytvapp.azurewebsites.net",  # a customer's site under a provider's suffix
        "acct.blob.core.windows.net",
        "x.firebaseio.com",
        "api.someapp.elasticbeanstalk.com",
        "raw.githubusercontent.com",
        "foo.cloudapp.net",
        "myshop.myshopify.com",
        "x.herokuapp.com",  # in tvgw's own names.PUBLIC_SUFFIXES
    ],
)
def test_a_hosting_providers_customer_is_credited_to_nobody(name):
    """The reviewer's case: the walk up never reaches a public suffix (tvgw's own list), and the
    snapshot holds no row that is, or sits above, a private-section suffix of the Public Suffix List, so
    no customer's name is credited to the company that hosts it."""
    assert companies.company(name) is None


def test_the_walk_stops_at_tvgws_own_public_suffixes_whatever_the_table_holds():
    table = {
        "azurewebsites.net": "Microsoft Corporation",
        "mine.azurewebsites.net": "Mine Ltd",
        "lgtvsdp.com": "LG Group",
    }
    assert companies.company("app.azurewebsites.net", table) is None
    assert companies.company("mine.azurewebsites.net", table) == "Mine Ltd"  # the customer's own row
    assert companies.company("x.mine.azurewebsites.net", table) == "Mine Ltd"
    assert companies.company("us.lgtvsdp.com", table) == "LG Group"


@pytest.mark.parametrize("damage", ["missing", "edited"])
def test_a_snapshot_that_cannot_be_read_names_no_company_and_breaks_nothing(
    monkeypatch, tmp_path, lg, damage
):
    """A package whose snapshot is missing or does not match its hash names no company: `company()` is
    None for every name and `trouble()` says why, so the brief and `tvgw check` print what they printed
    before the snapshot existed, and nothing that names companies raises."""
    from tvgw import plain

    if damage == "missing":
        monkeypatch.setattr(companies, "DATA", "no-such-file.txt")
    else:
        bad = tmp_path / "data"
        bad.mkdir()
        text = (ROOT / "src" / "tvgw" / "data" / "companies.txt").read_text(encoding="utf-8")
        (bad / "companies.txt").write_text(text.replace("\tLG Group\n", "\tSomeone\n", 1), encoding="utf-8")
        monkeypatch.setattr(companies.resources, "files", lambda package: tmp_path)
    companies._load.cache_clear()
    try:
        assert companies.company("us.lgtvsdp.com") is None and companies.snapshot() == ({}, {})
        assert companies.trouble()
        o = {"day": "2026-11-04", "new_hosts": [{"name": "x.alphonso.tv", "new_domain": 1}]}
        assert plain._new(o, None) == "New: the TV used 1 new service (alphonso.tv)."
    finally:
        companies._load.cache_clear()  # the next reader loads the shipped file, once the patch is undone
