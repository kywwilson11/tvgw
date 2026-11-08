"""(web) The page's sign-in, without a server (design decision 76): the password's hash, the sessions in
memory, the limit on failed sign-ins and the sign-in form's token."""

from __future__ import annotations

import random

import pytest

from tvgw import webauth

PASSWORD = "correct horse battery"


@pytest.fixture(scope="module")
def stored() -> str:
    return webauth.hash_password(PASSWORD)


# ---- the password --------------------------------------------------------------------------------------
def test_the_hash_checks_the_right_password_and_no_other(stored):
    assert stored.startswith("scrypt$15$8$1$") and PASSWORD not in stored
    assert webauth.check_password(PASSWORD, stored)
    for wrong in ("", " ", "correct horse batterY", PASSWORD + " ", PASSWORD[:-1], "x" * 5000):
        assert not webauth.check_password(wrong, stored), wrong
    assert webauth.hash_password(PASSWORD) != stored  # a random salt each time


def test_a_new_password_shorter_than_twelve_or_only_spaces_is_refused():
    for bad in ("", "short", "elevenchars", " " * 20, "x" * (webauth.MAX_PASSWORD + 1)):
        assert webauth.password_problem(bad), bad
        with pytest.raises(ValueError):
            webauth.hash_password(bad)
    assert webauth.password_problem("twelve chars") is None


def test_an_accent_typed_either_way_is_the_same_password():
    composed, decomposed = "café au lait 12", "café au lait 12"
    assert webauth.check_password(decomposed, webauth.hash_password(composed))


def test_a_hash_file_that_is_not_one_or_asks_too_much_checks_nothing(stored):
    log_n, r, p, salt, key = stored.split("$")[1:]
    for bad in (
        "",
        None,
        "plain text password",
        stored.replace("scrypt$", "bcrypt$"),
        f"scrypt$30${r}${p}${salt}${key}",  # 2**30 rounds: a check would take the machine down
        f"scrypt${log_n}$64${p}${salt}${key}",
        f"scrypt${log_n}${r}${p}$${key}",
        f"scrypt${log_n}${r}${p}${salt}$short",
        f"scrypt${log_n}${r}${p}${salt}$!!!",
        stored + "$extra",
    ):
        assert webauth.parse_hash(bad) is None, bad
        assert not webauth.check_password(PASSWORD, bad)


def test_read_hash_reads_only_a_hash(tmp_path, stored):
    p = tmp_path / "web-password"
    assert webauth.read_hash(str(p)) is None
    p.write_text("hunter2\n", encoding="utf-8")
    assert webauth.read_hash(str(p)) is None
    p.write_text(stored + "\n", encoding="utf-8")
    assert webauth.read_hash(str(p)) == stored
    assert webauth.mark(stored) != webauth.mark(webauth.hash_password(PASSWORD))


# ---- sessions ------------------------------------------------------------------------------------------
def test_a_session_lives_until_idle_or_absolute_expiry():
    s = webauth.Sessions()
    token, sess = s.open(0.0, "m")
    assert webauth.TOKEN.fullmatch(token) and webauth.TOKEN.fullmatch(sess.csrf) and token != sess.csrf
    t = 0.0
    while t + webauth.SESSION_IDLE - 1 < webauth.SESSION_ABSOLUTE:  # used every day: idle never ends it
        t += webauth.SESSION_IDLE - 1
        assert s.get(token, t, "m") is sess
    assert s.get(token, webauth.SESSION_ABSOLUTE, "m") is None  # 30 days after it opened, however used
    token, _ = s.open(100.0, "m")
    assert s.get(token, 100.0 + webauth.SESSION_IDLE - 1, "m")
    assert s.get(token, 100.0 + 2 * webauth.SESSION_IDLE - 2, "m")  # its last use moved the idle clock
    token, _ = s.open(100.0, "m")
    assert s.get(token, 100.0 + webauth.SESSION_IDLE, "m") is None and len(s) <= 1


def test_a_session_ends_with_the_password_it_was_opened_under_and_at_sign_out():
    s = webauth.Sessions()
    token, _ = s.open(0.0, "old")
    assert s.get(token, 1.0, "new") is None and s.get(token, 1.0, "old") is None  # gone for good
    token, _ = s.open(0.0, "old")
    s.close(token)
    assert s.get(token, 1.0, "old") is None


def test_at_most_twenty_sessions_and_the_one_unused_longest_goes():
    s = webauth.Sessions()
    tokens = [s.open(float(i), "m")[0] for i in range(webauth.SESSION_CAP)]
    assert s.get(tokens[0], 100.0, "m")  # the first is used again, so the second is now the oldest
    extra, _ = s.open(101.0, "m")
    assert len(s) == webauth.SESSION_CAP
    assert s.get(tokens[1], 102.0, "m") is None
    assert s.get(tokens[0], 102.0, "m") and s.get(extra, 102.0, "m")


def test_a_malformed_or_unknown_cookie_is_no_session():
    s = webauth.Sessions()
    s.open(0.0, "m")
    for bad in (None, "", "short", "A" * 43, "A" * 44, "../../" + "A" * 37, "A" * 42 + "=", "é" * 43):
        assert s.get(bad, 1.0, "m") is None
        s.close(bad)
    assert len(s) == 1


def test_a_backward_clock_is_no_reason_to_keep_a_session():
    s = webauth.Sessions()
    token, _ = s.open(1000.0, "m")
    assert s.get(token, 999.0, "m") is None


# ---- the limit on failed sign-ins ----------------------------------------------------------------------
def test_five_failures_from_one_address_refuse_it_for_fifteen_minutes():
    lim = webauth.Limiter()
    for i in range(webauth.FAILS_PER_ADDRESS - 1):
        assert not lim.failed("192.0.2.1", float(i))
        assert lim.refused("192.0.2.1", float(i)) == 0
    assert lim.failed("192.0.2.1", 10.0)
    assert lim.refused("192.0.2.1", 10.0) == webauth.REFUSAL
    assert lim.refused("192.0.2.2", 10.0) == 0  # another address is not refused
    assert lim.refused("192.0.2.1", 10.0 + webauth.REFUSAL - 1) == 1
    assert lim.refused("192.0.2.1", 10.0 + webauth.REFUSAL) == 0  # and it recovers


def test_twenty_failures_in_all_refuse_everyone():
    lim = webauth.Limiter()
    for i in range(webauth.FAILS_TOTAL):
        lim.failed(f"192.0.2.{i}", float(i))  # one failure from each of twenty addresses
    assert lim.refused("198.51.100.7", 20.0) > 0
    assert lim.refused("198.51.100.7", 19.0 + webauth.REFUSAL) == 0


def test_failures_outside_the_window_do_not_count_and_a_success_clears_an_address():
    lim = webauth.Limiter()
    for i in range(webauth.FAILS_PER_ADDRESS - 1):
        lim.failed("192.0.2.1", float(i))
    assert not lim.failed("192.0.2.1", webauth.FAIL_WINDOW + 10.0)  # the first four have aged out
    for i in range(webauth.FAILS_PER_ADDRESS - 2):
        lim.failed("192.0.2.3", float(i))
    lim.succeeded("192.0.2.3")
    assert not lim.failed("192.0.2.3", 5.0) and lim.refused("192.0.2.3", 5.0) == 0


def test_the_limiter_remembers_a_bounded_number_of_addresses():
    lim = webauth.Limiter(max_addresses=10, total=10_000)
    for i in range(1000):
        lim.failed(f"10.0.{i // 256}.{i % 256}", float(i % 100))
    assert len(lim._fails) == 10


# ---- the sign-in form's token --------------------------------------------------------------------------
def test_the_form_token_belongs_to_its_cookie_and_its_process():
    forms = webauth.FormTokens()
    cookie = webauth.new_token()
    token = forms.issue(cookie)
    assert forms.check(cookie, token)
    assert not forms.check(webauth.new_token(), token)
    assert not webauth.FormTokens().check(cookie, token)  # a restart makes old forms stale
    for bad in (None, "", token[:-1], token.upper(), "0" * 64):
        assert not forms.check(cookie, bad)
    assert not forms.check(None, token) and not forms.check("bad cookie", token)


def test_tokens_are_never_repeated():
    rng = random.Random(76)
    seen = {webauth.new_token() for _ in range(2000)}
    assert len(seen) == 2000 and all(webauth.TOKEN.fullmatch(t) for t in rng.sample(sorted(seen), 50))
