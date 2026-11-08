"""(adguard) `tvgw check NAME`: AdGuard Home's own check_host answer, asked with tvgw's credentials, said
in plain words with where the rule comes from and the fix.

AdGuard is a stand-in: a loopback HTTP server that answers `GET /control/filtering/check_host` the way
v0.107.79's openapi.yaml and handler describe it, and answers 401 to a request without the user and
password it was given, as AdGuard's page does. Nothing here reaches a real AdGuard Home."""

from __future__ import annotations

import base64
import json
import threading
import urllib.parse
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from conftest import ROOT

from tvgw import adguardcfg, aghinstall, cli, namecheck
from tvgw.config import Settings

TV = "10.10.10.17"
BCRYPT = "$2a$10$" + "x" * 53
PRO = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_48.txt"  # HaGeZi Pro in lg-webos
CLOCK = "clock sync at boot; if blocked the clock resets to 2019 and TLS fails everywhere"


def basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


class FakeAdGuard(BaseHTTPRequestHandler):
    """check_host as v0.107.79 answers it; a name it was given no answer for has no rule."""

    answers: dict = {}
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
        if url.path != aghinstall.CHECK_HOST or not query.get("name"):
            return self._send(400, 'query parameter "name" is required\n')
        answer = FakeAdGuard.answers.get(query["name"], {"reason": "NotFilteredNotFound", "rules": []})
        return self._send(200, answer if isinstance(answer, str) else json.dumps(answer))


@dataclass
class Site:
    s: Settings
    admin: Path
    cfg: dict
    port: int


def write_yaml(site: Site) -> None:
    Path(site.s.adguard_yaml).write_text(adguardcfg.dump_yaml(site.cfg), encoding="utf-8")


@pytest.fixture
def site(tmp_path, lg):
    FakeAdGuard.answers, FakeAdGuard.asked = {}, []
    FakeAdGuard.token = basic("admin", "secret")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeAdGuard)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    s = Settings(
        tv_ip=TV,
        tv_mac="b4:b2:91:aa:bb:cc",
        tv_name="lgcx",
        adguard_yaml=str(tmp_path / "AdGuardHome.yaml"),
        local_rules=str(tmp_path / "local.rules"),
        auto_rules=str(tmp_path / "auto.rules"),
    )
    users = {"users": [{"name": "admin", "password": BCRYPT}], "schema_version": 34}
    cfg = adguardcfg.plan(users, adguardcfg.desired(lg, s))
    cfg["http"]["address"] = f"127.0.0.1:{srv.server_port}"  # the stand-in's port, not 3000
    here = Site(s, tmp_path / "adguard-admin", cfg, srv.server_port)
    write_yaml(here)
    aghinstall.write_admin(str(here.admin), "admin", "secret")
    yield here
    srv.shutdown()
    srv.server_close()


def pro_id(site: Site) -> int:
    return next(f["id"] for f in site.cfg["filters"] if f["url"] == PRO)


def check(site: Site, lg, name: str, **kw) -> namecheck.Outcome:
    return namecheck.run(site.s, lg, name, admin=str(site.admin), **kw)


def rule(text: str, fid: int = 0) -> list[dict]:
    return [{"text": text, "filter_list_id": fid}]


# ---- the verdicts -------------------------------------------------------------------------------------


def test_a_name_a_shared_list_blocks(site, lg):
    FakeAdGuard.answers["ads.example"] = {
        "reason": "FilteredBlackList",
        "rules": rule("||ads.example^", pro_id(site)),
        "rule": "||ads.example^",  # the deprecated single fields AdGuard still sends
        "filter_id": pro_id(site),
    }
    out = check(site, lg, "Ads.Example.")
    assert out.code == namecheck.BLOCKED == 1
    assert out.lines == [
        "ads.example is blocked for the TV.",
        "  Rule: ||ads.example^, from the shared list HaGeZi Pro",
        "  Kind: other services",
        "  Kept reachable on purpose: no",
        "  Through the URL filter: no",
        "  Fix: sudo tvgw allow ads.example",
    ]
    # asked once, for the TV, with tvgw's user and password
    assert FakeAdGuard.asked == [
        (aghinstall.CHECK_HOST, {"name": "ads.example", "client": TV}, FakeAdGuard.token)
    ]


def test_the_company_line_comes_only_where_the_snapshot_knows_one(site, lg, monkeypatch):
    """(companies) A name the snapshot has no entry for says nothing about whose it is, and the line is
    the snapshot's company, never a guess from the name: here a stand-in table names only one domain."""
    from tvgw import companies

    table = {"tracker.example": "Example Tracking Ltd"}
    monkeypatch.setattr(companies, "snapshot", lambda: ({}, table))
    assert "  Company: Example Tracking Ltd" in check(site, lg, "a.b.tracker.example").lines
    assert not any(line.startswith("  Company") for line in check(site, lg, "tracker.example.org").lines)
    assert not any(line.startswith("  Company") for line in check(site, lg, "us.lgtvsdp.com").lines)


def test_a_name_no_rule_blocks_is_allowed(site, lg):
    out = check(site, lg, "cdn.example")
    assert out.code == namecheck.ALLOWED == 0
    assert out.lines[:2] == ["cdn.example is allowed for the TV.", "  Rule: none, so it is allowed"]
    assert not any(line.startswith(("  Fix", "  Note")) for line in out.lines)


def test_the_older_single_fields_are_read_when_rules_is_absent(site, lg):
    FakeAdGuard.answers["ads.example"] = {
        "reason": "FilteredBlackList",
        "rule": "||ads.example^",
        "filter_id": pro_id(site),
    }
    assert "  Rule: ||ads.example^, from the shared list HaGeZi Pro" in check(site, lg, "ads.example").lines


def test_a_must_allow_name_is_allowed_by_the_profiles_exception(site, lg):
    FakeAdGuard.answers["us.lgtvsdp.com"] = {
        "reason": "NotFilteredWhiteList",
        "rules": rule("@@||us.lgtvsdp.com^$important"),
    }
    out = check(site, lg, "us.lgtvsdp.com")
    assert out.code == 0
    assert out.lines == [
        "us.lgtvsdp.com is allowed for the TV.",
        "  Rule: @@||us.lgtvsdp.com^$important, from the profile (lg-webos)",
        "  Kind: LG's own services",
        "  Company: LG Group",  # (companies) lgtvsdp.com's, from the shipped snapshot
        f"  Kept reachable on purpose: yes, on the profile's must-allow list: {CLOCK}",
        "  Through the URL filter: no",
    ]


def test_a_must_allow_name_without_its_exception_is_allowed_with_a_note(site, lg):
    """No rule matched: nothing blocks it today, but the exception that keeps a list from it is gone."""
    out = check(site, lg, "us.lgtvsdp.com")
    assert out.code == 0 and out.lines[1] == "  Rule: none, so it is allowed"
    assert out.lines[-1] == (
        "  Note: AdGuard Home did not answer with the profile's @@||us.lgtvsdp.com^$important;"
        " run sudo tvgw adguard diff"
    )


def test_a_blocked_must_allow_name_contradicts_the_plan(site, lg):
    FakeAdGuard.answers["us.lgtvsdp.com"] = {
        "reason": "FilteredBlackList",
        "rules": rule("||lgtvsdp.com^", pro_id(site)),
    }
    out = check(site, lg, "us.lgtvsdp.com")
    assert out.code == 1
    assert out.lines[1] == "  Rule: ||lgtvsdp.com^, from the shared list HaGeZi Pro"
    assert out.lines[-1] == "  Fix: a must-allow name cannot be blocked; run sudo tvgw doctor"


def test_the_url_filter_answers_its_names(site, lg):
    FakeAdGuard.answers["ngfts.lge.com"] = {
        "reason": "RewriteRule",
        "rules": rule("||ngfts.lge.com^$dnsrewrite=10.10.10.1"),
        "ip_addrs": [],  # a $dnsrewrite answer is not in ip_addrs, which only the legacy rewrites fill
    }
    out = check(site, lg, "ngfts.lge.com")
    assert out.code == 0
    assert out.lines[0] == "ngfts.lge.com is allowed for the TV, through the URL filter."
    assert out.lines[1] == "  Rule: ||ngfts.lge.com^$dnsrewrite=10.10.10.1, from the profile (lg-webos)"
    assert out.lines[3] == "  Company: LG Group"  # (companies) lge.com's
    assert out.lines[5].startswith(
        "  Through the URL filter: yes: AdGuard Home answers it with the gateway's"
    )
    FakeAdGuard.answers["ngfts.lge.com"] = {"reason": "FilteredBlackList", "rules": rule("||lge.com^", 7)}
    out = check(site, lg, "ngfts.lge.com")
    assert (
        out.code == 1
        and out.lines[-1] == "  Fix: the URL filter's names are never blocked; run sudo tvgw doctor"
    )
    assert out.lines[1] == "  Rule: ||lge.com^, from the shared list number 7"  # an id the YAML lacks


@pytest.mark.parametrize(
    ("name", "file", "line", "reason", "where", "fix"),
    [
        (
            "mine.example",
            "local",
            "||mine.example^",
            "FilteredBlackList",
            "your own rules",
            "unblock mine.example",
        ),
        (
            "a.mine.example",
            "local",
            "||mine.example^",
            "FilteredBlackList",
            "your own rules",
            "allow a.mine.example",
        ),
        (
            "m.example",
            "auto",
            "||m.example^",
            "FilteredBlackList",
            "the rules the gateway added on its own",
            "allow m.example",
        ),
        ("ok.example", "local", "@@||ok.example^$important", "NotFilteredWhiteList", "your own rules", None),
    ],
)
def test_the_owners_and_the_gateways_own_rules_are_named_with_their_fix(
    site, lg, name, file, line, reason, where, fix
):
    path = site.s.local_rules if file == "local" else site.s.auto_rules
    Path(path).write_text(f"! a dated note\n{line}\n", encoding="utf-8")
    FakeAdGuard.answers[name] = {"reason": reason, "rules": rule(line)}
    out = check(site, lg, name)
    assert out.lines[1] == f"  Rule: {line}, from {where} ({path})"
    if fix is None:
        assert out.code == 0 and not out.lines[-1].startswith("  Fix")
    else:
        assert out.code == 1 and out.lines[-1] == f"  Fix: sudo tvgw {fix}"


def test_a_block_of_the_profiles_own_names_the_allow_that_takes_it(site, lg):
    """An allow of a whole site the profile files under tracking needs --force, and the fix says so with
    what it would unblock, as `tvgw allow` does; one host under it does not."""
    # (listguard) the profile's ACR block carries $important, and AdGuard names it so (design decision 68)
    held = "||alphonso.tv^$important"
    FakeAdGuard.answers["alphonso.tv"] = {"reason": "FilteredBlackList", "rules": rule(held)}
    out = check(site, lg, "alphonso.tv")
    assert out.code == 1 and out.lines[1] == f"  Rule: {held}, from the profile (lg-webos)"
    assert out.lines[2] == "  Kind: viewing trackers (ACR)"
    assert out.lines[3] == "  Company: LG Group"  # (companies) alphonso.tv is LG Ad Solutions, of LG Group
    assert out.lines[-1] == (
        "  Fix: sudo tvgw allow alphonso.tv --force, only if you mean it: it lets alphonso.tv and every name"
        " under it through, which the profile files under viewing trackers (ACR)"
    )
    FakeAdGuard.answers["x.alphonso.tv"] = FakeAdGuard.answers["alphonso.tv"]
    assert check(site, lg, "x.alphonso.tv").lines[-1] == "  Fix: sudo tvgw allow x.alphonso.tv"


def test_a_rule_none_of_tvgws_files_holds_is_drift(site, lg):
    FakeAdGuard.answers["stray.example"] = {"reason": "FilteredBlackList", "rules": rule("||stray.example^")}
    out = check(site, lg, "stray.example")
    assert out.code == 1
    assert out.lines[1] == "  Rule: ||stray.example^, in AdGuard Home but in none of tvgw's rules"
    assert out.lines[-1] == f"  Fix: {namecheck.DRIFT_FIX}"
    FakeAdGuard.answers["stray.example"] = {
        "reason": "NotFilteredWhiteList",
        "rules": rule("@@||stray.example^"),
    }
    out = check(site, lg, "stray.example")
    assert out.code == 0 and out.lines[-1] == f"  Note: {namecheck.DRIFT_FIX}"


def test_adguards_own_features_are_named_and_switched_off_on_its_page(site, lg):
    FakeAdGuard.answers["www.youtube.com"] = {
        "reason": "FilteredBlockedService",
        "rules": rule("||youtube.com^", -2),
        "service_name": "youtube",
    }
    out = check(site, lg, "www.youtube.com")
    assert out.code == 1 and out.lines[1] == "  Rule: AdGuard Home's blocked services (youtube)"
    assert out.lines[-1] == f"  Fix: {namecheck.FEATURE_FIX}"
    FakeAdGuard.answers["bad.example"] = {"reason": "FilteredSafeBrowsing", "rules": []}
    assert check(site, lg, "bad.example").lines[1] == "  Rule: AdGuard Home's safe browsing"
    FakeAdGuard.answers["odd.example"] = {"reason": "FilteredBlackList", "rules": []}  # no rule named
    out = check(site, lg, "odd.example")
    assert out.code == 1 and out.lines[1] == "  Rule: one AdGuard Home did not name"
    assert out.lines[-1] == "  Fix: sudo tvgw allow odd.example"
    FakeAdGuard.answers["old.example"] = {"reason": "Rewrite", "rules": [], "ip_addrs": ["192.0.2.8"]}
    out = check(site, lg, "old.example")
    assert out.code == 0 and "DNS rewrites, which tvgw keeps empty" in out.lines[1]
    assert out.lines[-1] == f"  Note: {namecheck.DRIFT_FIX}"
    FakeAdGuard.answers["host.example"] = {
        "reason": "RewriteEtcHosts",
        "rules": [],
        "ip_addrs": ["192.0.2.9"],
    }
    out = check(site, lg, "host.example")
    assert out.code == 0 and out.lines[1] == "  Rule: the gateway's /etc/hosts file"


# ---- when it cannot ask ------------------------------------------------------------------------------


def test_without_a_kept_password_it_asks_at_a_terminal_and_keeps_it_nowhere(site, lg):
    site.admin.unlink()
    prompts: list = []
    out = check(
        site, lg, "ads.example", ask=lambda prompt, secret: prompts.append((prompt, secret)) or "secret"
    )
    assert out.code == 0 and prompts == [("AdGuard Home's password for admin: ", True)]  # the YAML's user
    assert FakeAdGuard.asked[-1][2] == basic("admin", "secret")
    assert not site.admin.exists()
    out = check(site, lg, "ads.example")  # no terminal: nothing to ask with, so nothing is asked
    assert out.code == namecheck.UNASKED == 2
    assert out.lines == [f"tvgw check: {aghinstall.NO_PASSWORD.format(admin=site.admin)}"]
    assert len(FakeAdGuard.asked) == 1


def test_a_refused_password_or_none_typed_is_not_an_answer(site, lg):
    site.admin.unlink()
    out = check(site, lg, "ads.example", ask=lambda prompt, secret: "wrong")
    assert out.code == 2 and "did not take the user and password (401)" in out.lines[0]

    def interrupted(prompt, secret):
        raise KeyboardInterrupt

    out = check(site, lg, "ads.example", ask=interrupted)
    assert out.code == 2 and out.lines == ["tvgw check: no password was given; nothing was asked"]


def test_an_adguard_with_no_user_is_asked_without_one(site, lg):
    site.cfg["users"] = []
    write_yaml(site)
    site.admin.unlink()
    FakeAdGuard.token = None  # AdGuard asks for no password when it has no user
    assert check(site, lg, "ads.example").code == 0
    assert FakeAdGuard.asked[-1][2] is None


@pytest.mark.parametrize("name", ["10.10.10.1", "printer.lan", "*.example", "ads"])
def test_a_name_a_rule_cannot_hold_is_refused_before_anything_is_asked(site, lg, name):
    out = check(site, lg, name)
    assert out.code == 2 and out.lines[0].startswith("tvgw check: ") and FakeAdGuard.asked == []


@pytest.mark.parametrize(
    ("answer", "says"),
    [
        ({"reason": "NotFilteredError"}, "could not check ads.example (NotFilteredError)"),
        ({"reason": "SomethingNew"}, "a reason tvgw does not know: 'SomethingNew'"),
        ({"rules": []}, "answer names no reason"),
        ("not json", "answer names no reason"),
    ],
)
def test_an_answer_tvgw_cannot_read_is_not_a_verdict(site, lg, answer, says):
    FakeAdGuard.answers["ads.example"] = answer
    out = check(site, lg, "ads.example")
    assert out.code == 2 and says in out.lines[0]


def test_no_adguard_or_no_page_is_could_not_ask(site, lg, tmp_path):
    site.cfg["http"]["address"] = f"127.0.0.1:{free_port()}"
    write_yaml(site)
    out = check(site, lg, "ads.example")
    assert (
        out.code == 2 and "did not answer" in out.lines[0] and "systemctl status AdGuardHome" in out.lines[0]
    )
    Path(site.s.adguard_yaml).unlink()
    out = check(site, lg, "ads.example")
    assert out.lines == [
        "tvgw check: AdGuard Home is not set up on this computer yet: sudo tvgw adguard install"
    ]


def free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.parametrize(
    ("address", "base"),
    [
        ("127.0.0.1:3000", "http://127.0.0.1:3000"),
        ("0.0.0.0:8080", "http://127.0.0.1:8080"),  # every address: asked on loopback
        ("[::1]:3000", "http://127.0.0.1:3000"),
        ("192.0.2.5:8080", "http://192.0.2.5:8080"),
        ("", "http://127.0.0.1:3000"),  # none written: AdGuard's own default, as the wizard leaves it
    ],
)
def test_the_page_is_asked_where_the_yaml_puts_it(address, base):
    assert aghinstall.page_base({"http": {"address": address}}) == base


# ---- the command line --------------------------------------------------------------------------------


def test_the_cli_needs_root_and_exits_by_the_verdict(site, lg, monkeypatch, capsys):
    monkeypatch.setattr(cli.config, "load", lambda path, **kw: site.s)
    monkeypatch.setattr(aghinstall, "ADMIN_FILE", str(site.admin))
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    assert cli.main(["check", "ads.example"]) == 2
    assert capsys.readouterr().out == (
        "tvgw check: it asks AdGuard Home with its password; run it with sudo: sudo tvgw check ads.example\n"
    )
    assert FakeAdGuard.asked == []
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    FakeAdGuard.answers["ads.example"] = {
        "reason": "FilteredBlackList",
        "rules": rule("||ads.example^\x1b[2J", pro_id(site)),  # a list's text never steers the terminal
    }
    assert cli.main(["check", "ads.example"]) == 1
    out = capsys.readouterr().out
    assert "  Rule: ||ads.example^\\x1b[2J, from the shared list HaGeZi Pro\n" in out
    assert out.endswith("  Fix: sudo tvgw allow ads.example\n")
    assert cli.main(["check", "cdn.example"]) == 0


def test_the_password_stays_with_aghinstall():
    """namecheck asks through aghinstall.credentials() and check_host(); it never reads the file."""
    text = Path(namecheck.__file__).read_text(encoding="utf-8")
    assert "read_admin(" not in text and "adguard-admin" not in text


def test_the_blocking_page_shows_what_the_command_prints(site, lg):
    """docs/use/blocking.md's example is the command's own output for a name a shared list blocks."""
    text = (ROOT / "docs" / "use" / "blocking.md").read_text(encoding="utf-8")
    block = text.split("A blocked name looks like this:\n\n```text\n", 1)[1].split("\n```", 1)[0]
    FakeAdGuard.answers["ads.example"] = {
        "reason": "FilteredBlackList",
        "rules": rule("||ads.example^", pro_id(site)),
    }
    assert block.split("\n") == check(site, lg, "ads.example").lines
