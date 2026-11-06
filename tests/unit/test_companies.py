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


def raw() -> dict[str, bytes]:
    return {"trackers.json": json.dumps(TRACKERS).encode(), "companies.json": json.dumps(COMPANIES).encode()}


# ---- the shipped snapshot ------------------------------------------------------------------------------


def test_the_shipped_snapshot_is_whole_and_names_its_source_licence_and_attribution():
    """The header is the provenance the licence asks for: the database and its commit, the hash of each
    file read, CC BY-SA 4.0 by name and link, the attribution to AdGuard and to WhoTracks.Me, what tvgw
    changed; and the lines are the ones the header's hash was taken of (companies.parse refuses
    anything else)."""
    header, table = companies.snapshot()
    assert re.fullmatch(
        r"AdGuard Companies DB, https://github\.com/AdguardTeam/companiesdb, commit [0-9a-f]{40}",
        header["Source"],
    )
    assert re.search(
        r"dist/trackers\.json sha256 [0-9a-f]{64}, dist/companies\.json sha256 [0-9a-f]{64}",
        header["Read from"],
    )
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


def test_the_tool_keeps_a_domain_and_its_company_and_leaves_out_carriers_and_guesses():
    assert snap.rows(TRACKERS, COMPANIES) == [
        ("alphonso.tv", "LG Group"),
        ("corriere.it", "RCS MediaGroup S.p.A."),  # the \x03 an entry ends in, cleaned
        ("d1tenant.cloudfront.net", "Tenant Corp"),  # a tenant's own row is no carrier's
        ("lgtvsdp.com", "LG Group"),
    ]
    with pytest.raises(ValueError, match=r"expected trackers\.json"):
        snap.rows({"trackers": []}, COMPANIES)


def test_the_file_it_writes_records_its_inputs_and_reads_back_whole():
    files = raw()
    text = snap.render(COMMIT, files)
    header, table = companies.parse(text)
    assert header["Source"].endswith(f"commit {COMMIT}")
    for name, data in files.items():
        assert f"dist/{name} sha256 {hashlib.sha256(data).hexdigest()}" in header["Read from"]
    assert header["Read from"].endswith("timeUpdated 2026-11-02T10:07:05.262Z")
    assert table == dict(snap.rows(TRACKERS, COMPANIES))
    assert all(
        len(line) <= 110 or line.startswith(("# Source", "# Read from")) for line in text.splitlines()[:16]
    )


def test_the_tool_writes_from_a_folder_and_checks_without_writing(tmp_path, capsys):
    for name, data in raw().items():
        (tmp_path / name).write_bytes(data)
    out = tmp_path / "companies.txt"
    assert snap.main(["--commit", COMMIT, "--from", str(tmp_path), "--out", str(out)]) == 0
    assert "4 domains" in capsys.readouterr().out
    written = out.read_text(encoding="utf-8")
    assert snap.main(["--commit", COMMIT, "--from", str(tmp_path), "--out", str(out), "--check"]) == 0
    COMPANIES_CHANGED = {"companies": {**COMPANIES["companies"], "lgcorp": {"name": "LG Electronics"}}}
    (tmp_path / "companies.json").write_text(json.dumps(COMPANIES_CHANGED), encoding="utf-8")
    assert snap.main(["--commit", COMMIT, "--from", str(tmp_path), "--out", str(out), "--check"]) == 1
    assert out.read_text(encoding="utf-8") == written  # --check writes nothing
    with pytest.raises(SystemExit):
        snap.main(["--commit", "main", "--from", str(tmp_path), "--out", str(out)])
    (tmp_path / "trackers.json").write_text("[]", encoding="utf-8")
    assert snap.main(["--commit", COMMIT, "--from", str(tmp_path), "--out", str(out)]) == 2


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
