"""(web) The page on the home network (design decision 76): its server, its pages against a store built from
the fake gateway, its headers, its limits, and its refusals. The server runs for real on 127.0.0.1 in a
thread, without TLS for the handler's own tests and with a certificate `openssl` makes for the TLS ones.
The sign-in's pure parts are in test_webauth.py."""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import http.client
import os
import random
import re
import socket
import sqlite3
import ssl
import subprocess
import threading
import time
import warnings
from contextlib import contextmanager
from pathlib import Path

import pytest
from conftest import NOW, ROOT, fake_extract, fake_oddport

from tvgw import cli, config, db, ingest, plain, web, webauth, webpages
from tvgw.config import Settings

PASSWORD = "correct horse battery"
DAY = "2026-10-26"  # every fixture row falls on it
AFTER = NOW + 86400 + 60  # the next morning: the fixture day is yesterday, settled, and the store a day old
CSP = "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'"


def no_kernel_lines(since):
    return []


@pytest.fixture()
def store(gateway, lg):
    ingest.run(
        gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, gate_lines=no_kernel_lines, lock=False
    )
    return gateway


@pytest.fixture()
def site(store, tmp_path) -> Settings:
    """The fake gateway's settings with the page on, on loopback, and its password stored."""
    pw = tmp_path / "web-password"
    pw.write_text(webauth.hash_password(PASSWORD) + "\n", encoding="utf-8")
    rules = tmp_path / "local.rules"
    rules.write_text(
        "! 2026-10-20 allow: the sports app needs it\n@@||cdn.example.com^$important\n"
        "! 2026-10-21 block\n||ads.example.net^\n",
        encoding="utf-8",
    )
    return dataclasses.replace(
        store,
        web="on",
        web_bind="loopback",
        web_password=str(pw),
        web_cert=str(tmp_path / "web-cert.pem"),
        web_key=str(tmp_path / "web-key.pem"),
        local_rules=str(rules),
    )


class Clock:
    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


@contextmanager
def running(s: Settings, prof, wall: float = AFTER, clock: Clock | None = None, ctx=None, hostname="gw"):
    app = web.App(s, prof, web.LOOPBACK, hostname=hostname, clock=clock or Clock(), wall=lambda: wall)
    httpd = web.Server(("127.0.0.1", 0), app, ctx)
    t = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    t.start()
    try:
        yield httpd
    finally:
        httpd.shutdown()
        httpd.server_close()
        t.join(5)


def request(httpd, method: str, path: str, body: str | None = None, headers: dict | None = None):
    """(status, headers as a dict of lists, body text) of one request."""
    conn = http.client.HTTPConnection("127.0.0.1", httpd.server_address[1], timeout=10)
    h = dict(headers or {})
    if body is not None:
        h.setdefault("Content-Type", "application/x-www-form-urlencoded")
    conn.request(method, path, body=body, headers=h)
    r = conn.getresponse()
    data = r.read().decode("utf-8", errors="replace")
    got: dict[str, list[str]] = {}
    for k, v in r.getheaders():
        got.setdefault(k.lower(), []).append(v)
    conn.close()
    return r.status, got, data


def raw(httpd, data: bytes) -> bytes:
    """What the server sends back to `data`, until it closes (a reset, for a connection closed unread)."""
    out = b""
    with socket.create_connection(("127.0.0.1", httpd.server_address[1]), timeout=10) as sock:
        try:
            sock.sendall(data)
            while chunk := sock.recv(65536):
                out += chunk
        except ConnectionResetError:
            pass
    return out


def cookie_of(headers: dict, name: str) -> str | None:
    for line in headers.get("set-cookie", []):
        if line.startswith(f"{name}="):
            return line.split(";")[0].split("=", 1)[1] or None
    return None


def sign_in(httpd, password: str = PASSWORD, extra: dict | None = None, device: str | None = None):
    """GET the form, then POST it: (status, headers, body, the session cookie or None). The page's clock
    moves on by the spacing of unknown devices first, so a test's sign-ins one after another are not refused
    for coming too soon after each other; `device` is a known-device cookie to send."""
    clock = httpd.app.clock
    if isinstance(clock, Clock):
        clock.t += webauth.UNKNOWN_SPACING
    status, h, body = request(httpd, "GET", "/login")
    assert status == 200, body
    form = cookie_of(h, web.FORM_COOKIE)
    token = re.search(r'name="csrf" value="([0-9a-f]{64})"', body).group(1)
    import urllib.parse

    status, h, body = request(
        httpd,
        "POST",
        "/login",
        urllib.parse.urlencode({"csrf": token, "password": password}),
        {
            "Cookie": f"{web.FORM_COOKIE}={form}" + (f"; {web.DEVICE_COOKIE}={device}" if device else ""),
            **(extra or {}),
        },
    )
    return status, h, body, cookie_of(h, web.SESSION_COOKIE)


def get(httpd, path: str, session: str, method: str = "GET"):
    return request(httpd, method, path, headers={"Cookie": f"{web.SESSION_COOKIE}={session}"})


def assert_headers(h: dict) -> None:
    csp = h.get("content-security-policy", [""])[0]
    assert csp.startswith(CSP), csp
    assert h.get("x-content-type-options") == ["nosniff"]
    assert h.get("referrer-policy") == ["no-referrer"]
    assert h.get("cache-control") == ["no-store"]
    assert h.get("server") == ["tvgw"]  # no Python version


# ---- signing in ----------------------------------------------------------------------------------------
def test_every_page_but_the_sign_in_redirects_to_it_without_a_session(site, lg):
    with running(site, lg) as httpd:
        for path in ("/", f"/day/{DAY}", f"/day/{DAY}/full", "/name/us.lgtvsdp.com", "/rules", "/about"):
            status, h, _ = request(httpd, "GET", path)
            assert (status, h.get("location")) == (303, ["/login"]), path
            assert_headers(h)
        bogus = "A" * 43
        status, h, _ = request(httpd, "GET", "/", headers={"Cookie": f"{web.SESSION_COOKIE}={bogus}"})
        assert (status, h.get("location")) == (303, ["/login"])


def test_signing_in_sets_a_secure_cookie_and_signing_out_ends_the_session(site, lg):
    with running(site, lg) as httpd:
        status, h, _, session = sign_in(httpd)
        assert status == 303 and h["location"] == ["/"] and session and webauth.TOKEN.fullmatch(session)
        line = next(x for x in h["set-cookie"] if x.startswith(web.SESSION_COOKIE))
        for flag in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/", f"Max-Age={30 * 86400}"):
            assert flag in line, flag
        assert web.SESSION_COOKIE.startswith("__Host-") and "Domain" not in line
        status, _, body = get(httpd, "/", session)
        assert status == 200 and "Sign out" in body
        csrf = re.search(r'name="csrf" value="([A-Za-z0-9_-]{43})"', body).group(1)
        # the sign-out needs the session's own form token
        status, _, _ = request(
            httpd, "POST", "/logout", "csrf=" + "B" * 43, {"Cookie": f"{web.SESSION_COOKIE}={session}"}
        )
        assert status == 403
        assert get(httpd, "/", session)[0] == 200
        status, h, _ = request(
            httpd, "POST", "/logout", f"csrf={csrf}", {"Cookie": f"{web.SESSION_COOKIE}={session}"}
        )
        assert status == 303 and h["location"] == ["/login"]
        assert any(x.startswith(f"{web.SESSION_COOKIE}=;") and "Max-Age=0" in x for x in h["set-cookie"])
        assert get(httpd, "/", session)[0] == 303  # the session is gone from memory


def test_a_wrong_password_is_refused_and_counted(site, lg, capsys):
    with running(site, lg) as httpd:
        status, _, body, session = sign_in(httpd, "not the password at all")
        assert status == 403 and session is None and "not right" in body
        assert "tvgw web: a sign-in failed" in capsys.readouterr().out
        for bad in ("", "short"):
            assert sign_in(httpd, bad)[0] == 403


def test_after_five_failures_an_address_waits_without_its_password_being_checked(site, lg, capsys):
    clock = Clock()
    with running(site, lg, clock=clock) as httpd:
        for _ in range(webauth.FREE_TRIES):
            assert sign_in(httpd, "wrong wrong wrong")[0] == 403
        assert "sign-ins from that address wait 60 seconds" in capsys.readouterr().out
        status, h, body, session = sign_in(httpd)  # the right password, refused all the same
        assert status == 429 and session is None and "Wait 57 seconds" in body
        assert h["retry-after"] == ["57"]
        assert_headers(h)
        clock.t += 60  # and back after the wait
        status, h, _, session = sign_in(httpd)
        assert status == 303 and session and cookie_of(h, web.DEVICE_COOKIE)


def test_a_known_device_is_not_held_to_the_limit_for_unknown_devices(site, lg):
    with running(site, lg) as httpd:
        _, h, _, _ = sign_in(httpd)
        device = cookie_of(h, web.DEVICE_COOKIE)
        line = next(x for x in h["set-cookie"] if x.startswith(web.DEVICE_COOKIE))
        for flag in ("Secure", "HttpOnly", "SameSite=Strict", "Path=/", f"Max-Age={400 * 86400}"):
            assert flag in line, flag
        clock = httpd.app.clock
        clock.t += webauth.UNKNOWN_SPACING  # the spacing after the sign-in above has run out
        stranger = []
        for _ in range(2):  # two wrong passwords at once, without moving the clock
            clock.t -= webauth.UNKNOWN_SPACING
            stranger.append(sign_in(httpd, "wrong wrong wrong")[0])
        assert stranger == [403, 429]  # an unknown device: one check every few seconds
        known = []
        for _ in range(2):
            clock.t -= webauth.UNKNOWN_SPACING
            known.append(sign_in(httpd, "wrong wrong wrong", device=device)[0])
        assert known == [403, 403]
        _, h, _, session = sign_in(httpd, device=device)
        assert session and cookie_of(h, web.DEVICE_COOKIE) is None  # it is known already: no new one


def test_guesses_sent_together_are_checked_one_at_a_time_under_the_limit(site, lg, monkeypatch):
    """Reproduced by the security review: 16 wrong passwords at once from one address were all checked."""
    import urllib.parse

    monkeypatch.setattr(web, "MAX_PER_ADDRESS", 64)
    with running(site, lg) as httpd:
        device = cookie_of(sign_in(httpd)[1], web.DEVICE_COOKIE)
        for cookie, checked in (("", 1), (f"; {web.DEVICE_COOKIE}={device}", webauth.FREE_TRIES)):
            httpd.app.clock.t += webauth.UNKNOWN_SPACING
            forms = []
            for _ in range(16):
                _, h, body = request(httpd, "GET", "/login")
                token = re.search(r'name="csrf" value="([0-9a-f]{64})"', body).group(1)
                forms.append((cookie_of(h, web.FORM_COOKIE), token))
            start = threading.Barrier(16)
            got: list[int] = []

            def go(form, token, start=start, got=got, cookie=cookie):
                start.wait()
                body = urllib.parse.urlencode({"csrf": token, "password": "wrong wrong wrong"})
                got.append(
                    request(httpd, "POST", "/login", body, {"Cookie": f"{web.FORM_COOKIE}={form}{cookie}"})[0]
                )

            threads = [threading.Thread(target=go, args=f) for f in forms]
            for th in threads:
                th.start()
            for th in threads:
                th.join()
            assert sorted(got) == [403] * checked + [429] * (16 - checked)
            httpd.app.limiter = webauth.Limiter()  # a fresh start for the known device's turn


def test_the_sign_in_form_needs_its_own_token_and_cookie(site, lg):
    with running(site, lg) as httpd:
        import urllib.parse

        # no form cookie
        status, _, _ = request(
            httpd, "POST", "/login", urllib.parse.urlencode({"csrf": "0" * 64, "password": PASSWORD})
        )
        assert status == 403
        # a cookie and a token that do not belong together
        status, h, _body = request(httpd, "GET", "/login")
        form = cookie_of(h, web.FORM_COOKIE)
        status, h, _ = request(
            httpd,
            "POST",
            "/login",
            urllib.parse.urlencode({"csrf": "a" * 64, "password": PASSWORD}),
            {"Cookie": f"{web.FORM_COOKIE}={form}"},
        )
        assert status == 403 and cookie_of(h, web.SESSION_COOKIE) is None
        # another site's post
        assert sign_in(httpd, extra={"Origin": "https://evil.example"})[0] == 403
        assert sign_in(httpd, extra={"Sec-Fetch-Site": "cross-site"})[0] == 403
        assert sign_in(httpd, extra={"Origin": "null"})[0] == 403
        assert sign_in(httpd, extra={"Origin": "https://gw.local:8443"})[0] == 303


def test_a_new_password_ends_every_session(site, lg):
    with running(site, lg) as httpd:
        session = sign_in(httpd)[3]
        assert get(httpd, "/about", session)[0] == 200
        Path(site.web_password).write_text(
            webauth.hash_password("a brand new password") + "\n", encoding="utf-8"
        )
        assert get(httpd, "/about", session)[0] == 303
        assert sign_in(httpd)[0] == 403 and sign_in(httpd, "a brand new password")[0] == 303


def test_sessions_expire_while_the_server_runs(site, lg):
    clock = Clock()
    with running(site, lg, clock=clock) as httpd:
        session = sign_in(httpd)[3]
        clock.t += webauth.SESSION_IDLE - 1
        assert get(httpd, "/about", session)[0] == 200
        clock.t += webauth.SESSION_IDLE + 1
        assert get(httpd, "/about", session)[0] == 303


# ---- the headers, the methods and the limits -----------------------------------------------------------
def test_the_security_headers_are_on_every_response_errors_included(site, lg):
    with running(site, lg) as httpd:
        session = sign_in(httpd)[3]
        seen = set()
        for method, path, body in (
            ("GET", "/login", None),
            ("GET", "/style.css", None),
            ("GET", "/", None),
            ("GET", "/nothing-here", None),
            ("GET", "/day/2026-02-30", None),
            ("POST", "/about", "x=1"),
            ("DELETE", "/", None),
            ("PUT", "/login", "x=1"),
            ("OPTIONS", "/", None),
            ("POST", "/logout", "x" * (web.MAX_BODY + 1)),
        ):
            status, h, _ = request(httpd, method, path, body, {"Cookie": f"{web.SESSION_COOKIE}={session}"})
            assert_headers(h)
            seen.add(status)
        assert {200, 404, 405, 413} <= seen
        # a request line the base class refuses, and one in HTTP/0.9, which would carry no headers at all
        for line in (b"GARBAGE\r\n\r\n", b"GET /\r\n\r\n", b"GET / HTTP/9.9\r\n\r\n"):
            reply = raw(httpd, line).decode("latin-1")
            assert re.match(r"HTTP/1\.0 (4\d\d|505) ", reply), (line, reply[:60])
            assert "Content-Security-Policy: default-src 'none'" in reply


def test_other_methods_are_405_with_allow_and_head_has_no_body(site, lg):
    with running(site, lg) as httpd:
        status, h, body = request(httpd, "DELETE", "/")
        assert status == 405 and h["allow"] == ["GET, HEAD, POST"]
        status, h, body = request(httpd, "HEAD", "/login")
        assert status == 200 and body == "" and int(h["content-length"][0]) > 0
        status, h, _ = request(httpd, "POST", "/style.css", "a=1")
        assert status == 405 and h["allow"] == ["GET, HEAD"]


def test_post_bodies_are_bounded_and_must_be_a_form(site, lg):
    with running(site, lg) as httpd:
        assert request(httpd, "POST", "/login", "p=" + "x" * web.MAX_BODY)[0] == 413
        assert request(httpd, "POST", "/login", "a=1", {"Content-Type": "application/json"})[0] == 415
        reply = raw(httpd, b"POST /login HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n")
        assert reply.startswith(b"HTTP/1.0 411")
        reply = raw(
            httpd,
            b"POST /login HTTP/1.0\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\na=1",
        )
        assert reply.startswith(b"HTTP/1.0 411")
        assert request(httpd, "POST", "/login", "%ff=%fe")[0] == 400  # not UTF-8


def test_paths_that_climb_or_smuggle_are_404(site, lg):
    with running(site, lg) as httpd:
        session = sign_in(httpd)[3]
        for path in (
            "/day/../",
            "/day/../../etc/passwd",
            "/day/2026-10-26/../../x",
            "/name/%2e%2e",
            "/name/..%2f..%2fetc",
            "/name/a%2fb",
            "/name/%00",
            "/name/a..b",
            "/name/%3Cscript%3E",
            "//etc/passwd",
            "/name/" + "a" * 300,
            "/name?q=../x",
            "/name?q=%3Cscript%3E",
        ):
            status, h, body = get(httpd, path, session)
            assert status == 404, path
            assert "<script" not in body.lower() and "passwd" not in body, path
            assert_headers(h)
        assert get(httpd, "/name?q=US.lgtvsdp.com.", session)[1]["location"] == ["/name/us.lgtvsdp.com"]
        reply = raw(httpd, b"GET http://evil.example/ HTTP/1.0\r\n\r\n")
        assert reply.startswith(b"HTTP/1.0 404")


def test_a_host_header_naming_another_site_is_refused(site, lg):
    with running(site, lg) as httpd:
        for host, want in (("evil.example", 421), ("gw.local:8443", 303), ("GW", 303), ("localhost", 303)):
            status, h, _ = request(httpd, "GET", "/", headers={"Host": host})
            assert status == want, host
            assert_headers(h)


def test_beyond_the_request_limit_the_answer_is_503(site, lg, monkeypatch):
    with running(site, lg) as httpd:
        app = httpd.app
        for _ in range(web.MAX_REQUESTS):
            assert app.requests.acquire(blocking=False)
        try:
            status, h, _ = request(httpd, "GET", "/login")
            assert status == 503 and h["retry-after"] == ["30"]
            assert_headers(h)
        finally:
            for _ in range(web.MAX_REQUESTS):
                app.requests.release()
        assert request(httpd, "GET", "/login")[0] == 200


def test_beyond_the_connection_limit_a_connection_is_closed_unread(site, lg):
    with running(site, lg) as httpd:
        for _ in range(web.MAX_CONNECTIONS):
            assert httpd.slots.acquire(blocking=False)
        try:
            assert raw(httpd, b"GET /login HTTP/1.0\r\n\r\n") == b""
        finally:
            for _ in range(web.MAX_CONNECTIONS):
                httpd.slots.release()


def test_a_silent_client_is_dropped_after_the_socket_timeout(site, lg, monkeypatch):
    monkeypatch.setattr(web, "SOCKET_TIMEOUT", 0.3)
    monkeypatch.setattr(web.Handler, "timeout", 0.3)
    with running(site, lg) as httpd, socket.create_connection(("127.0.0.1", httpd.server_address[1])) as sock:
        sock.settimeout(5)
        sock.sendall(b"GET /login HTTP/1.0\r\n")  # and never the blank line
        start = time.monotonic()
        assert sock.recv(100) == b""
        assert time.monotonic() - start < 4


def test_nothing_from_a_request_reaches_the_journal(site, lg, capsys):
    with running(site, lg) as httpd:
        request(httpd, "GET", "/name/secret-show-name.example?q=x")
        sign_in(httpd)
    out = capsys.readouterr()
    assert "secret-show-name" not in out.out + out.err and "127.0.0.1" not in out.out + out.err
    assert "tvgw web: signed in" in out.out


# ---- the pages -----------------------------------------------------------------------------------------
def test_today_shows_the_status_and_yesterdays_brief_with_the_action_first(site, lg, status_file):
    status_file.write_text(f"ok {int(AFTER - 300)} 40\n", encoding="utf-8")
    with running(site, lg) as httpd:
        session = sign_in(httpd)[3]
        status, h, body = get(httpd, "/", session)
    assert status == 200 and h["content-type"] == ["text/html; charset=utf-8"]
    assert "the protection held at" in body and "(40 checks passed)" in body
    assert '<meta name="viewport" content="width=device-width, initial-scale=1">' in body
    assert "<script" not in body.lower() and "style=" not in body and "onclick" not in body
    action = body.index('class="card action')
    assert action < body.index("<b>Protection:</b>") < body.index("<b>The TV:</b>")
    assert f'href="/day/{DAY}/full"' in body
    with sqlite3.connect(site.db_path) as conn:
        o = cli.queries.brief(conn, DAY, lg, now=AFTER)
        want = cli.plain_lines(conn, o, lg, now=AFTER)
    shown = next(x for x in want if x.strip().startswith("Action: ")).strip().removeprefix("Action: ")
    assert webpages.esc(shown) in body[action : action + 600]


def test_on_its_first_day_today_says_the_first_brief_is_tomorrow(site, lg):
    with running(site, lg, wall=NOW + 3600) as httpd:
        session = sign_in(httpd)[3]
        status, _, body = get(httpd, "/", session)
    assert status == 200 and plain.FIRST_DAY in body


def test_a_day_has_its_brief_neighbours_the_table_and_its_new_names(site, lg):
    with running(site, lg) as httpd:
        session = sign_in(httpd)[3]
        status, _, body = get(httpd, f"/day/{DAY}", session)
        assert status == 200
        assert (
            '<a href="/day/2026-10-27">Later day</a>' in body and "Earlier day" not in body
        )  # the record starts
        assert "<th class=n>Tracker lookups refused</th>" in body
        row = re.search(rf'<a href="/day/{DAY}">{DAY}</a></td>(.*?)</tr>', body).group(1)
        cells = re.findall(r"<td class=n>(.*?)</td>", row)
        # the table and the brief agree: the TV line's refusals and the New line's services
        assert "every one was refused" in body and "asked for known tracking services 1 time;" in body
        assert re.search(r"the TV used 3 new services", body)
        assert cells[1:] == ["1", "3"]
        assert '<a href="/name/aic.recommend.lgtvcommon.com">' in body
        status, _, full = get(httpd, f"/day/{DAY}/full", session)
        assert status == 200 and "<pre>" in full and "aic.recommend.lgtvcommon.com" in full
        assert get(httpd, "/day/2099-01-01", session)[0] == 404
        status, _, before = get(httpd, "/day/2026-10-01", session)
        assert (
            status == 200
            and "keeps no record of this day" in before
            and "Its record starts on 2026-10-26" in before
        )
        assert get(httpd, "/day/2026-10-01/full", session)[0] == 404


def test_a_day_with_a_gap_says_part_of_the_record_is_missing(site, lg):
    with running(site, lg, wall=AFTER + 86400) as httpd:
        session = sign_in(httpd)[3]
        status, _, body = get(httpd, "/day/2026-10-27", session)
    assert status == 200 and "Part of the day" in body
    rows = re.findall(r'<a href="/day/(\d{4}-\d{2}-\d{2})">', body)
    assert "2026-10-26" in rows


def test_finished_days_are_built_once_and_forgotten_with_the_record(site, lg, monkeypatch):
    calls = []
    real = cli.queries.brief
    monkeypatch.setattr(cli.queries, "brief", lambda *a, **k: calls.append(a[1]) or real(*a, **k))
    with running(site, lg) as httpd:
        session = sign_in(httpd)[3]
        for _ in range(3):
            assert get(httpd, f"/day/{DAY}", session)[0] == 200
            assert get(httpd, "/", session)[0] == 200
        assert calls == [DAY]
        assert len(httpd.app.record.briefs) == 1
        # tvgw forget empties ingest_runs: the record starts again, and nothing is shown from memory
        conn = db.connect(site.db_path)
        conn.execute("UPDATE ingest_runs SET t = t + 1")
        conn.commit()
        conn.close()
        assert get(httpd, f"/day/{DAY}", session)[0] == 200
        assert calls == [DAY, DAY]


def test_the_cache_keeps_at_most_fourteen_days():
    c = web.Cache(web.CACHE_DAYS)
    for i in range(30):
        c.put(1, f"d{i}", i)
    assert len(c) == 14 and c.get(1, "d15") is None and c.get(1, "d29") == 29
    assert c.get(2, "d29") is None and len(c) == 0


def test_a_name_page_says_what_the_store_knows_and_the_command_to_change_it(site, lg):
    with running(site, lg) as httpd:
        session = sign_in(httpd)[3]
        status, _, body = get(httpd, "/name/aic.recommend.lgtvcommon.com", session)
        assert status == 200 and "blocked" in body and "<th>Decided by</th>" in body
        assert "sudo tvgw allow aic.recommend.lgtvcommon.com" in body
        assert "sudo tvgw check aic.recommend.lgtvcommon.com" in body
        assert f"<td>{DAY}</td>" in body
        status, _, body = get(httpd, "/name/us.lgtvsdp.com", session)
        assert status == 200 and "sudo tvgw block us.lgtvsdp.com" in body
        status, _, body = get(httpd, "/name/lgtvcommon.com", session)  # a domain: the names under it
        assert status == 200 and '<a href="/name/aic.recommend.lgtvcommon.com">' in body
        status, _, body = get(httpd, "/name/never-seen.example", session)
        assert status == 404 and "no record of this name" in body


def test_decided_by_names_the_kind_of_rule_from_the_store():
    groups = {"profile": ["||a.example^"], "local": ["@@||b.example^"], "machine": ["||c.example^"]}
    assert web.decided_by((1, "||a.example^", None), groups) == "Blocked by the TV's profile."
    assert web.decided_by((0, "@@||b.example^", 0), groups) == "Allowed by your own rules."
    assert (
        web.decided_by((1, "||c.example^", None), groups) == "Blocked by a rule the gateway added on its own."
    )
    assert (
        web.decided_by((1, "||d.example^", 3), groups)
        == "Blocked by a shared list the gateway subscribes to."
    )
    assert web.decided_by((1, None, -2), groups) == "Blocked by one of the filter's own features."
    assert web.decided_by((0, None, None), groups) == "Allowed: no rule matched it."
    assert web.decided_by((1, "||e.example^", None), None) == "Blocked by one of the gateway's rules."
    assert web.decided_by(None, groups) == "No lookup of it is kept."


def test_the_rules_and_about_pages(site, lg):
    with running(site, lg) as httpd:
        session = sign_in(httpd)[3]
        status, _, body = get(httpd, "/rules", session)
        assert status == 200 and "cdn.example.com" in body and "the sports app needs it" in body
        status, _, body = get(httpd, "/about", session)
        assert status == 200 and "Who can see it" in body and "How to turn it off" in body
        status, h, css = get(httpd, "/style.css", session)
        assert status == 200 and h["content-type"] == ["text/css; charset=utf-8"]
        assert "prefers-color-scheme:dark" in css


# ---- escaping ------------------------------------------------------------------------------------------
HOSTILE = (
    "<script>alert(1)</script>.example",
    'a"onmouseover="x.example',
    "a'b.example",
    "‮gnp.exe.example",
    "\x1b[31mred.example",
    "café.example",
    "\ud800.example",
    "&lt;.example",
)


def test_a_hostile_name_in_the_record_is_shown_escaped_and_never_linked(site, lg):
    conn = db.connect(site.db_path)
    t = NOW - 600
    for i, name in enumerate(HOSTILE):
        safe = name.encode("utf-8", "surrogatepass").decode("utf-8", "replace")
        conn.execute("INSERT INTO dns(t, qname, qtype, blocked) VALUES (?,?,?,?)", (t + i, safe, "A", 0))
        conn.execute(
            "INSERT INTO hosts(name, first_seen, last_seen, category, dns_n, last_blocked) VALUES (?,?,?,?,?,?)",
            (safe, t + i, t + i, "Other", 1, 0),
        )
    conn.commit()
    conn.close()
    with running(site, lg) as httpd:
        session = sign_in(httpd)[3]
        for path in (f"/day/{DAY}", f"/day/{DAY}/full"):
            status, _, body = get(httpd, path, session)
            assert status == 200
            assert "<script>alert" not in body and 'onmouseover="x' not in body and "‮" not in body
            assert "\x1b" not in body
            assert "&lt;script&gt;alert(1)&lt;/script&gt;.example" in body
    assert "\\u202egnp" in webpages.esc("‮gnp") and webpages.esc("café") == "café"


def test_any_generated_name_is_escaped_and_only_a_plain_host_name_is_ever_a_link():
    rng = random.Random(76)
    alphabet = "abc.-_<>\"'&/\\%:;= \t\n\r\x00\x1b‮​é﻿.XYZ019"
    for _ in range(3000):
        name = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
        text = webpages.esc(name)
        assert not set(text) & set("<>\"'\x00\x1b‮​﻿\n\r\t")
        assert re.fullmatch(r"(?:[^&]|&(?:lt|gt|amp|quot|#x27);)*", text), (name, text)
        link = webpages.name_link(name)
        if link.startswith("<a "):
            assert webpages.NAME.fullmatch(name) and link == f'<a href="/name/{name}">{name}</a>'
        else:
            assert link == text
        page = webpages.day(
            None,
            DAY,
            None,
            None,
            [webpages.DayRow(DAY, name, name, name)],
            [webpages.NewName(name, name, name, True)],
            "c" * 43,
        )
        assert "<script" not in page.replace("&lt;script", "")


# ---- read-only by construction -------------------------------------------------------------------------
def test_the_store_is_opened_so_that_a_write_fails(site):
    conn = web.open_store(site.db_path)
    assert conn.execute("PRAGMA query_only").fetchone() == (1,)
    for sql in ("INSERT INTO meta(key, value) VALUES ('x', 'y')", "DELETE FROM dns", "CREATE TABLE t(x)"):
        with pytest.raises(sqlite3.OperationalError, match=r"readonly|read-only|attempt to write"):
            conn.execute(sql)
    conn.close()
    # and with query_only switched off again, the file itself is still opened read-only
    conn = web.open_store(site.db_path)
    conn.execute("PRAGMA query_only=0")
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        conn.execute("DELETE FROM dns")
    conn.close()


def test_serving_every_page_changes_no_file(site, lg, tmp_path):
    def snapshot() -> dict[str, str]:
        out = {}
        for root, _, files in os.walk(tmp_path):
            for f in files:
                p = os.path.join(root, f)
                with open(p, "rb") as fh:
                    out[p] = hashlib.sha256(fh.read()).hexdigest()
        return out

    with running(site, lg) as httpd:
        session = sign_in(httpd)[3]
        before = snapshot()
        for path in ("/", f"/day/{DAY}", f"/day/{DAY}/full", "/name/us.lgtvsdp.com", "/rules", "/about"):
            assert get(httpd, path, session)[0] == 200
        assert snapshot() == before


# ---- where it listens ----------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("address", "bind", "why"),
    [
        ("10.10.10.1", "uplink", "TV's side"),  # GW_IP
        ("10.10.10.77", "uplink", "TV's side"),  # in TV_NET
        ("0.0.0.0", "uplink", "every address"),
        ("0.0.0.0", "loopback", "every address"),
        ("203.0.113.9", "uplink", "private"),  # a public address: the internet could reach it
        ("100.64.1.2", "uplink", "private"),  # a carrier's shared range: so could the carrier's customers
        ("127.0.0.1", "uplink", "private"),
        ("192.0.2.5", "loopback", "127.0.0.1 only"),
        ("::1", "loopback", "not an IPv4"),
    ],
)
def test_the_server_refuses_to_listen_where_the_tv_or_the_internet_could_reach_it(address, bind, why):
    s = Settings(web="on", web_bind=bind)
    with pytest.raises(web.WebError, match=why):
        web.check_bind(address, s)


def test_it_listens_on_the_uplinks_private_address_or_loopback():
    web.check_bind("172.20.7.20", Settings(web_bind="uplink"))
    web.check_bind("10.20.30.40", Settings(web_bind="uplink"))
    web.check_bind("127.0.0.1", Settings(web_bind="loopback"))
    s = Settings(web_bind="uplink", wan_if="wlan0")
    assert web.bind_address(s, lambda dev: "172.16.4.4" if dev == "wlan0" else None) == "172.16.4.4"
    with pytest.raises(web.WebError, match="wlan0 has no IPv4 address"):
        web.bind_address(s, lambda dev: None)
    assert web.bind_address(Settings(web_bind="loopback"), lambda dev: "172.16.4.4") == "127.0.0.1"


def test_serve_refuses_root_an_unsafe_address_and_a_missing_password(site, lg, capsys):
    assert web.serve(Settings(), lg) == 0  # WEB=off: nothing
    assert "nothing is served" in capsys.readouterr().out
    assert web.serve(site, lg, euid=lambda: 0) == 2
    assert "refuses to serve as root" in capsys.readouterr().out
    up = dataclasses.replace(site, web_bind="uplink")
    assert web.serve(up, lg, euid=lambda: 1000, find=lambda dev: None) == 1  # no address yet: retried
    assert web.serve(up, lg, euid=lambda: 1000, find=lambda dev: "10.10.10.1") == 2  # never retried
    gone = dataclasses.replace(site, web_password=str(Path(site.web_password).with_name("none")))
    assert web.serve(gone, lg, euid=lambda: 1000) == 2
    assert "no password is set" in capsys.readouterr().out
    assert web.serve(site, lg, euid=lambda: 1000) == 2  # no certificate yet
    assert "sudo tvgw web cert" in capsys.readouterr().out


def test_the_units_address_filter_admits_the_home_and_never_the_tv_subnet():
    import ipaddress

    allowed = web.allowed_sources("10.10.10.0/24")
    nets = [ipaddress.ip_network(n) for n in allowed]
    tv = ipaddress.ip_network("10.10.10.0/24")
    assert not any(n.overlaps(tv) for n in nets)
    for inside in ("10.0.0.5", "10.10.11.1", "10.10.9.255", "172.16.0.1", "172.31.1.20", "127.0.0.1"):
        assert any(ipaddress.ip_address(inside) in n for n in nets), inside
    for outside in ("10.10.10.1", "10.10.10.17", "8.8.8.8", "100.64.0.1", "203.0.113.5"):
        assert not any(ipaddress.ip_address(outside) in n for n in nets), outside
    text = web.dropin(Settings(wan_if="wlan0", web_port=8443))
    assert "[Service]\nIPAddressDeny=any\nIPAddressAllow=127.0.0.0/8 " in text
    assert "\nRestrictNetworkInterfaces=lo wlan0\n" in text and "\nSocketBindAllow=ipv4:tcp:8443\n" in text
    loop = web.dropin(Settings(wan_if="wlan0", web_bind="loopback", web_port=9443, tv_if="eth0"))
    assert "\nRestrictNetworkInterfaces=lo\n" in loop and "eth0" not in loop and "tcp:9443" in loop
    from tvgw import guard

    allow = re.search(r"IPAddressAllow=(.*)", text).group(1)
    assert guard.denies("any", "10.10.10.0/24") and not guard.opens(allow, "10.10.10.0/24", "10.10.10.1")
    assert guard.opens("10.0.0.0/8", "10.10.10.0/24", "10.10.10.1")
    assert not guard.opens("10.10.10.1/32 192.168.0.0/16", "10.10.10.0/24", "10.10.10.1")
    other = web.allowed_sources("172.20.50.0/24")  # a TV subnet in another private range
    assert other[1] == "10.0.0.0/8" and other[-1] == "192.168.0.0/16" and "172.20.50.0/24" not in other


# ---- the certificate, the password and the status ------------------------------------------------------
class Done:
    def __init__(self, returncode=0, stderr=""):
        self.returncode, self.stderr = returncode, stderr


def test_the_certificate_command_is_built_as_browsers_need_it():
    cmd = web.openssl_command("/k", "/c", ["gw.local", "gw", "localhost"], ["192.0.2.5", "127.0.0.1"])
    text = " ".join(cmd)
    assert cmd[:4] == ["openssl", "req", "-x509", "-newkey"] and "ec_paramgen_curve:prime256v1" in cmd
    assert cmd[cmd.index("-days") + 1] == "730" and "-nodes" in cmd and "-sha256" in cmd
    assert "subjectAltName=DNS:gw.local,DNS:gw,DNS:localhost,IP:192.0.2.5,IP:127.0.0.1" in cmd
    assert "basicConstraints=critical,CA:FALSE" in cmd and "extendedKeyUsage=serverAuth" in cmd
    assert (
        cmd[cmd.index("-keyout") + 1] == "/k"
        and cmd[cmd.index("-out") + 1] == "/c"
        and "/CN=gw.local" in text
    )
    assert web.cert_names("Kylebox", "192.0.2.5") == (
        ["kylebox.local", "kylebox", "localhost"],
        ["192.0.2.5", "127.0.0.1"],
    )
    assert web.cert_names("bad name!", None) == (["localhost"], ["127.0.0.1"])


def test_make_cert_writes_the_key_for_the_page_alone_and_prints_the_fingerprint(tmp_path, monkeypatch):
    s = Settings(web_cert=str(tmp_path / "web-cert.pem"), web_key=str(tmp_path / "web-key.pem"))
    pem = ssl.DER_cert_to_PEM_cert(b"0" * 64)
    seen, owners, restarted, out = [], [], [], []

    def fake(cmd):
        seen.append(cmd)
        Path(cmd[cmd.index("-keyout") + 1]).write_text("KEY", encoding="ascii")
        Path(cmd[cmd.index("-out") + 1]).write_text(pem, encoding="ascii")
        return Done()

    monkeypatch.setattr(os, "chown", lambda p, u, g: owners.append((os.path.basename(p), u, g)))
    assert web.make_cert(s, euid=lambda: 1000, out=out.append) == 1 and "sudo" in out[-1]
    rc = web.make_cert(
        s, euid=lambda: 0, run=fake, find=lambda d: "192.0.2.5", hostname=lambda: "gw", gid=lambda: 4242,
        restart=lambda c: restarted.append(c) or "", out=out.append,
    )  # fmt: skip
    assert rc == 0 and len(seen) == 1
    assert oct(os.stat(s.web_key).st_mode & 0o777) == "0o640" and Path(s.web_key).read_text() == "KEY"
    assert oct(os.stat(s.web_cert).st_mode & 0o777) == "0o644"
    assert (".web-key.pem.new", 0, 4242) in owners and (".web-cert.pem.new", 0, 0) in owners
    fp = web.fingerprint(pem)
    assert fp and f"  {fp}" in out and re.fullmatch(r"(?:[0-9A-F]{2}:){31}[0-9A-F]{2}", fp)
    assert restarted == [["systemctl", "try-restart", "tvgw-web.service"]]
    assert not [p for p in os.listdir(tmp_path) if p.startswith(".")]  # no temporary file left
    out.clear()
    assert (
        web.make_cert(s, euid=lambda: 0, run=lambda c: Done(1, "bad\nreason"), gid=lambda: 1, out=out.append)
        == 1
    )
    assert out == ["tvgw web cert: openssl failed: reason"]


def test_set_password_asks_twice_and_stores_only_a_hash(tmp_path, monkeypatch):
    s = Settings(web_password=str(tmp_path / "web-password"))
    monkeypatch.setattr(os, "chown", lambda p, u, g: None)
    out, restarted = [], []

    def asks(*answers):
        it = iter(answers)
        return lambda prompt: next(it)

    kw = {
        "euid": lambda: 0,
        "gid": lambda: 7,
        "restart": lambda c: restarted.append(c) or "",
        "out": out.append,
    }
    assert web.set_password(s, ask=asks("short", "short"), **kw) == 1 and "at least 12" in out[-1]
    assert web.set_password(s, ask=asks("long enough pass", "long enough pasS"), **kw) == 1
    assert "differ" in out[-1] and not os.path.exists(s.web_password)
    assert web.set_password(s, ask=asks("long enough pass", "long enough pass"), **kw) == 0
    stored = Path(s.web_password).read_text(encoding="utf-8")
    assert "long enough pass" not in stored and webauth.check_password("long enough pass", stored)
    assert oct(os.stat(s.web_password).st_mode & 0o777) == "0o640"
    assert restarted == [["systemctl", "try-restart", "tvgw-web.service"]]
    assert web.set_password(s, euid=lambda: 1000, out=out.append) == 1
    assert (
        web.set_password(s, euid=lambda: 0, tty=lambda: False, out=out.append) == 1 and "terminal" in out[-1]
    )


def test_status_says_where_it_listens_its_fingerprint_and_whether_a_password_is_set(site, tmp_path):
    tcp = verify_tcp(("127.0.0.1", 8443))
    pem = ssl.DER_cert_to_PEM_cert(b"1" * 64)
    Path(site.web_cert).write_text(pem, encoding="ascii")
    files = {"/proc/net/tcp": tcp, "/proc/net/tcp6": ""}
    ends = AFTER + 400 * 86400
    stamp = time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(ends))

    def run(cmd):
        if cmd[:2] == ["systemctl", "is-active"]:
            return "active\n"
        if cmd[:2] == ["openssl", "x509"]:
            return f"notAfter={stamp}\n"
        return ""

    lines = web.status_lines(site, run, files.get, hostname=lambda: "gw", now=AFTER)
    text = "\n".join(lines)
    assert "The page is on (WEB=on), and it runs." in text and "Port 8443 is open on: 127.0.0.1." in text
    assert web.fingerprint(pem) in text and "(400 days)" in text and "A password is set." in text
    off = web.status_lines(
        Settings(web_cert=str(tmp_path / "x"), web_password=str(tmp_path / "y")), lambda c: "", {}.get
    )
    assert off[0].startswith("The page is off") and "Nothing listens on port 8443." in off
    assert "There is no certificate yet: sudo tvgw web cert makes one." in off and off[-1].startswith(
        "No password"
    )


def verify_tcp(*listening: tuple[str, int]) -> str:
    """/proc/net/tcp as the kernel writes it, on this machine's byte order, for listening sockets."""
    import struct

    head = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    )
    rows = []
    for i, (addr, port) in enumerate(listening):
        word = struct.unpack("=I", socket.inet_aton(addr))[0]
        rows.append(
            f"   {i}: {word:08X}:{port:04X} 00000000:0000 0A 00000000:00000000 00:00000000 00000000  999 0 1 1"
        )
    return head + "\n".join(rows) + "\n"


# ---- TLS, for real -------------------------------------------------------------------------------------
@pytest.fixture()
def tls_site(site, tmp_path):
    if not shutil_which("openssl"):
        pytest.skip("needs the openssl command to make a certificate")
    cmd = web.openssl_command(site.web_key, site.web_cert, ["gw.local", "gw", "localhost"], ["127.0.0.1"])
    done = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stderr
    return site


def shutil_which(name):
    import shutil

    return shutil.which(name)


def test_the_page_speaks_tls_12_or_newer_only_with_its_own_certificate(tls_site, lg):
    ctx = web.tls_context(tls_site.web_cert, tls_site.web_key)
    with running(tls_site, lg, ctx=ctx) as httpd:
        port = httpd.server_address[1]
        client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client.load_verify_locations(tls_site.web_cert)
        client.check_hostname = True
        with (
            socket.create_connection(("127.0.0.1", port)) as raw_sock,
            client.wrap_socket(raw_sock, server_hostname="gw.local") as tls,
        ):
            assert tls.version() in ("TLSv1.2", "TLSv1.3")
            tls.sendall(b"GET /login HTTP/1.0\r\nHost: gw.local\r\n\r\n")
            reply = b""
            while chunk := tls.recv(65536):
                reply += chunk
        assert reply.startswith(b"HTTP/1.0 200") and b"Content-Security-Policy:" in reply
        old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        old.check_hostname, old.verify_mode = False, ssl.CERT_NONE
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                old.minimum_version = old.maximum_version = ssl.TLSVersion.TLSv1_1
        except (ValueError, ssl.SSLError):
            pytest.skip("this Python's OpenSSL cannot even offer TLS 1.1")
        with (
            socket.create_connection(("127.0.0.1", port)) as raw_sock,
            pytest.raises((ssl.SSLError, OSError)),
        ):
            old.wrap_socket(raw_sock).do_handshake()
        # plain HTTP to the TLS port gets nothing back but a closed connection
        assert raw(httpd, b"GET /login HTTP/1.0\r\n\r\n")[:4] != b"HTTP"


def test_the_settings_take_exactly_their_values(tmp_path):
    conf = tmp_path / "tvgw.conf"
    assert config.load(conf).web == "off" and config.load(conf).web_port == 8443
    for good in ("WEB=on", "WEB=off", "WEB_BIND=loopback", "WEB_PORT=1024", "WEB_PORT=65535"):
        conf.write_text(good + "\n")
        config.load(conf)
    for bad, why in (
        ("WEB=yes", "WEB='yes'"),
        ("WEB=On", "WEB='On'"),
        ("WEB_BIND=0.0.0.0", "WEB_BIND='0.0.0.0'"),
        ("WEB_BIND=all", "WEB_BIND='all'"),
        ("WEB_PORT=443", "WEB_PORT=443 in tvgw.conf: expected 1024 to 65535"),
        ("WEB_PORT=70000", "expected 1024 to 65535"),
        ("WEB_PORT=84a3", "whole number"),
    ):
        conf.write_text(bad + "\n")
        with pytest.raises(ValueError, match=re.escape(why) if "'" in why else why):
            config.load(conf)
    assert {"WEB", "WEB_PORT", "WEB_BIND"} <= config.writable_keys()


def test_the_unit_runs_it_unprivileged_sandboxed_and_closed_to_the_tv():
    unit = (ROOT / "deploy" / "systemd" / "tvgw-web.service").read_text(encoding="utf-8").splitlines()
    for line in (
        "ExecStart=/usr/local/bin/tvgw web serve",
        "User=tvgw-web",
        "Group=tvgw-web",
        "SupplementaryGroups=adm",
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "PrivateTmp=yes",
        "PrivateDevices=yes",
        "RestrictAddressFamilies=AF_INET AF_UNIX",
        "SystemCallFilter=@system-service",
        "MemoryDenyWriteExecute=yes",
        "IPAddressDeny=any",
        "SocketBindDeny=any",
        "RestartPreventExitStatus=2",
        "UMask=0077",
    ):
        assert line in unit, line
    assert any(x.startswith("MemoryMax=") for x in unit)
    hidden = " ".join(
        x.removeprefix("InaccessiblePaths=") for x in unit if x.startswith("InaccessiblePaths=")
    )
    for path in ("-/var/log", "-/run/log/journal", "-/var/lib/tvgw/pcap", "-/etc/tvgw/claude.key"):
        assert path in hidden.split(), path
    assert not [x for x in unit if x.startswith(("ReadWritePaths=", "IPAddressAllow=", "User=root"))]
    install = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
    assert "tvgw web dropin >/etc/systemd/system/tvgw-web.service.d/not-from-tv.conf.new" in install
    assert "useradd --system --no-create-home --shell /usr/sbin/nologin --user-group tvgw-web" in install
    prerm = (ROOT / "packaging" / "scripts" / "prerm").read_text(encoding="utf-8")
    assert "tvgw-web.service" in prerm
    postrm = (ROOT / "packaging" / "scripts" / "postrm").read_text(encoding="utf-8")
    assert "/etc/systemd/system/tvgw-web.service.d" in postrm


def test_install_enables_the_page_only_when_it_is_on_with_a_password_and_a_certificate():
    install = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
    block = install[install.index("# ---- (web) begin") : install.index("# ---- (web) end")]
    assert (
        '"${WEB:-off}" = on' in block
        and "-s /etc/tvgw/web-password" in block
        and "-s /etc/tvgw/web-cert.pem" in block
    )
    assert (
        "systemctl enable --now tvgw-web.service" in block
        and "systemctl disable --now tvgw-web.service" in block
    )


def test_a_new_uplink_address_restarts_the_page_without_holding_up_the_apply(tmp_path):
    """The dispatcher restarts tvgw-web, which read the uplink's address at start, when that address is new
    or changed, without waiting for it (--no-block), before it hands over to tvgw-apply."""
    dispatcher = (ROOT / "deploy" / "networkmanager" / "90-tvgw-dispatcher").read_text(encoding="utf-8")
    line = next(x for x in dispatcher.splitlines() if "tvgw-web" in x and not x.startswith("#"))
    assert line.startswith('case "$moved" in *addr=changed* | *addr=new*)')
    assert "systemctl --no-block try-restart tvgw-web.service" in line and line.endswith("esac")
    assert dispatcher.index("try-restart tvgw-web") < dispatcher.index("exec /usr/local/sbin/tvgw-apply")
    sh = shutil_which("sh")
    if sh is None:
        pytest.skip("no sh here")
    # run the dispatcher with a stub systemctl and tvgw-apply: a changed address restarts, a same one not
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    log = tmp_path / "calls"
    for name in ("systemctl",):
        stub = bin_ / name
        stub.write_text(f'#!/bin/sh\necho "{name} $*" >>"{log}"\n', encoding="utf-8")
        stub.chmod(0o755)
    script = dispatcher.replace("/run/tvgw", str(tmp_path / "run")).replace(
        "exec /usr/local/sbin/tvgw-apply", f'echo apply >>"{log}"; exit 0'
    )
    script = script.replace("/var/lib/tvgw/changes.spool", str(tmp_path / "spool"))
    script = script.replace("[ -r /etc/tvgw/tvgw.conf ] && . /etc/tvgw/tvgw.conf", ":")
    path = tmp_path / "dispatch"
    path.write_text(script, encoding="utf-8")
    (tmp_path / "run").mkdir()
    env = {
        "PATH": f"{bin_}:/usr/bin:/bin",
        "IP4_ADDRESS_0": "198.51.100.2/24 198.51.100.1",
        "IP4_GATEWAY": "198.51.100.1",
    }

    def event() -> list[str]:
        subprocess.run([sh, str(path), "wlan0", "dhcp4-change"], env=env, check=True)
        calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
        log.unlink(missing_ok=True)
        return calls

    assert event() == ["systemctl --no-block try-restart tvgw-web.service", "apply"]  # new since boot
    assert event() == ["apply"]  # the same address: left alone
    env["IP4_ADDRESS_0"] = "198.51.100.3/24 198.51.100.1"
    assert event() == ["systemctl --no-block try-restart tvgw-web.service", "apply"]


# ---- the review's availability findings ----------------------------------------------------------------
def test_a_request_head_over_its_limit_is_431_having_read_no_more(site, lg):
    with running(site, lg) as httpd:
        line = b"X-Pad: " + b"a" * 1000 + b"\r\n"
        reply = raw(httpd, b"GET /login HTTP/1.0\r\n" + line * 20 + b"\r\n")
        assert reply.startswith(b"HTTP/1.0 431") and b"Content-Security-Policy: default-src 'none'" in reply
        reply = raw(httpd, b"GET /" + b"a" * (web.MAX_HEAD + 10) + b" HTTP/1.0\r\n\r\n")
        assert reply.startswith(b"HTTP/1.0 431")
        reply = raw(httpd, b"GET /login HTTP/1.0\r\n" + line * 8 + b"\r\n")  # 8 KB of headers is fine
        assert reply.startswith(b"HTTP/1.0 200")


def test_the_head_limit_keeps_memory_flat_under_huge_headers(site, lg):
    """Reproduced: 8 requests of 99 header lines of 64 KB at once took 326 MiB, past the unit's MemoryMax."""
    import tracemalloc

    with running(site, lg) as httpd:
        port = httpd.server_address[1]
        tracemalloc.start()
        socks = []
        try:
            for _ in range(web.MAX_PER_ADDRESS):
                s = socket.create_connection(("127.0.0.1", port))
                with contextlib.suppress(OSError):
                    s.sendall(b"GET /login HTTP/1.0\r\n" + (b"X-" + b"a" * 65000 + b": b\r\n") * 30)
                socks.append(s)
            time.sleep(0.5)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
            for s in socks:
                s.close()
    assert peak < 16 * 2**20, peak


def test_a_client_trickling_its_headers_is_cut_off_at_the_requests_deadline(site, lg, monkeypatch):
    """Reproduced: a header line every 0.3 s held a connection 6.1 s against a 0.5 s socket timeout."""
    monkeypatch.setattr(web, "SOCKET_TIMEOUT", 0.5)
    monkeypatch.setattr(web.Handler, "timeout", 0.5)
    monkeypatch.setattr(web, "REQUEST_DEADLINE", 1.0)
    with running(site, lg) as httpd, socket.create_connection(("127.0.0.1", httpd.server_address[1])) as sock:
        start = time.monotonic()
        sock.sendall(b"GET /login HTTP/1.0\r\n")
        cut = None
        for _ in range(30):
            time.sleep(0.3)
            try:
                sock.sendall(b"X-a: b\r\n")
            except OSError:
                cut = time.monotonic() - start
                break
        assert cut is not None and cut < 3.0, cut


def test_a_page_slow_to_build_is_not_cut_off_once_its_request_is_read(site, lg, monkeypatch):
    monkeypatch.setattr(web, "REQUEST_DEADLINE", 0.5)
    real = web.Record.brief

    def slow(self, conn, day):
        time.sleep(1.2)
        return real(self, conn, day)

    monkeypatch.setattr(web.Record, "brief", slow)
    with running(site, lg) as httpd:
        session = sign_in(httpd)[3]
        assert get(httpd, f"/day/{DAY}/full", session)[0] == 200


def test_one_address_holds_at_most_four_connections(site, lg):
    with running(site, lg) as httpd:
        port = httpd.server_address[1]
        idle = [socket.create_connection(("127.0.0.1", port)) for _ in range(web.MAX_PER_ADDRESS)]
        try:
            time.sleep(0.3)
            assert raw(httpd, b"GET /login HTTP/1.0\r\n\r\n") == b""  # the fifth is closed unread
        finally:
            for s in idle:
                s.close()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not raw(httpd, b"GET /login HTTP/1.0\r\n\r\n"):
            time.sleep(0.1)
        assert raw(httpd, b"GET /login HTTP/1.0\r\n\r\n").startswith(b"HTTP/1.0 200")


def test_a_length_that_is_no_ascii_number_and_a_name_that_is_no_utf8_are_refused_cleanly(site, lg, capsys):
    with running(site, lg) as httpd:
        head = b"POST /login HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        assert raw(httpd, head + b"Content-Length: \xb2\r\n\r\nab").startswith(b"HTTP/1.0 411")
        assert raw(httpd, head + b"Content-Length: 000000003\r\n\r\na=1").startswith(b"HTTP/1.0 411")
        session = sign_in(httpd)[3]
        assert get(httpd, "/name/%ff%fe", session)[0] == 404
    assert "a page failed" not in capsys.readouterr().out


def test_the_about_page_shows_no_fingerprint_and_sends_the_owner_to_the_gateways(site, lg):
    Path(site.web_cert).write_text(ssl.DER_cert_to_PEM_cert(b"2" * 64), encoding="ascii")
    with running(site, lg) as httpd:
        session = sign_in(httpd)[3]
        _, _, body = get(httpd, "/about", session)
    assert web.fingerprint(Path(site.web_cert).read_text(encoding="ascii")) not in body
    assert "sudo tvgw web cert" in body and ".local" in body


def test_a_tls_handshake_sent_a_byte_at_a_time_is_cut_off_at_the_deadline(tls_site, lg, monkeypatch):
    monkeypatch.setattr(web, "REQUEST_DEADLINE", 1.0)
    ctx = web.tls_context(tls_site.web_cert, tls_site.web_key)
    with (
        running(tls_site, lg, ctx=ctx) as httpd,
        socket.create_connection(("127.0.0.1", httpd.server_address[1])) as sock,
    ):
        start = time.monotonic()
        hello = b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" + b"\x00" * 600  # a ClientHello's start
        cut = None
        for b in hello:
            time.sleep(0.3)
            try:
                sock.sendall(bytes([b]))
            except OSError:
                cut = time.monotonic() - start
                break
        assert cut is not None and cut < 3.0, cut
