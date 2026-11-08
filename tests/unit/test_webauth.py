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
        f"scrypt$1\u00b2${r}${p}${salt}${key}",  # a digit to str.isdigit, not to int()
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
def fail(lim, address, now, known=True):
    """One check that failed: admitted, then never taken back. The wait it was refused for, else 0."""
    ticket, wait = lim.admit(address, known, now)
    return wait if ticket is None else 0.0


def test_an_address_has_five_free_tries_then_waits_one_two_four_minutes_up_to_an_hour():
    lim = webauth.Limiter()
    t = 0.0
    for _ in range(webauth.FREE_TRIES - 1):
        assert fail(lim, "192.0.2.1", t) == 0
    assert fail(lim, "192.0.2.1", t) == 0  # the fifth is checked, and starts the first wait
    for minutes in (1, 2, 4, 8, 16, 32, 60, 60):
        assert fail(lim, "192.0.2.1", t + 1) == minutes * 60 - 1  # refused, not counted
        t += minutes * 60
        assert fail(lim, "192.0.2.1", t) == 0  # the wait is over: one more check, and a longer wait
    assert [webauth.backoff(n) for n in range(1, 9)] == [0, 0, 0, 0, 60, 120, 240, 480]
    assert webauth.backoff(40) == webauth.BACKOFF_CAP


def test_a_success_or_a_quiet_day_starts_an_address_again_and_others_are_not_held():
    lim = webauth.Limiter()
    for _ in range(webauth.FREE_TRIES):
        fail(lim, "192.0.2.1", 0.0)
    assert fail(lim, "192.0.2.2", 1.0) == 0  # another address is not held
    ticket, wait = lim.admit("192.0.2.1", True, 61.0)
    assert ticket is not None and wait == 0
    lim.succeeded(ticket)
    for _ in range(webauth.FREE_TRIES - 1):
        assert fail(lim, "192.0.2.1", 62.0) == 0  # its free tries again
    lim2 = webauth.Limiter()
    for _ in range(webauth.FREE_TRIES + 2):
        fail(lim2, "192.0.2.9", 0.0 if _ < webauth.FREE_TRIES else 10_000.0)
    assert fail(lim2, "192.0.2.9", 10_000.0 + webauth.FORGET + webauth.BACKOFF_CAP) == 0


def test_sixteen_guesses_sent_together_are_judged_one_after_another():
    """Reproduced: the check of the limit and the count of a failure were apart, around the slow hash, so 16
    wrong passwords sent at once from one address were all checked. The reservation is under the lock."""
    import threading

    lim = webauth.Limiter()
    start = threading.Barrier(16)
    got: list = []

    def guess():
        start.wait()
        got.append(lim.admit("192.0.2.1", True, 0.0)[0])

    threads = [threading.Thread(target=guess) for _ in range(16)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert sum(t is not None for t in got) == webauth.FREE_TRIES
    unknown = webauth.Limiter()
    got.clear()
    start = threading.Barrier(16)

    def stranger(i):
        start.wait()
        got.append(unknown.admit(f"192.0.2.{i}", False, 0.0)[0])

    threads = [threading.Thread(target=stranger, args=(i,)) for i in range(16)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert sum(t is not None for t in got) == 1  # unknown devices: one check every few seconds, in all


def test_unknown_devices_get_one_check_every_few_seconds_and_a_cap_a_day_and_known_ones_neither():
    lim = webauth.Limiter()
    assert fail(lim, "192.0.2.1", 0.0, known=False) == 0
    assert fail(lim, "192.0.2.2", 1.0, known=False) == webauth.UNKNOWN_SPACING - 1
    assert fail(lim, "192.0.2.3", 1.0, known=True) == 0  # a known device is not spaced
    t = webauth.UNKNOWN_SPACING
    for i in range(webauth.UNKNOWN_DAILY - 1):  # many addresses, so no address waits: only the day's cap
        assert fail(lim, f"10.0.{i // 200}.{i % 200}", t, known=False) == 0
        t += webauth.UNKNOWN_SPACING
    assert lim.unknown_full()
    wait = fail(lim, "198.51.100.7", t, known=False)
    assert wait == webauth.UNKNOWN_DAY - t  # until the first of the day's failures ages out
    assert fail(lim, "198.51.100.8", t, known=True) == 0  # the owner's phone still signs in
    assert fail(lim, "198.51.100.7", webauth.UNKNOWN_DAY + 1, known=False) == 0


def test_a_right_password_takes_its_reserved_failure_back():
    lim = webauth.Limiter(daily=2)
    ticket, _ = lim.admit("192.0.2.1", False, 0.0)
    lim.succeeded(ticket)
    assert fail(lim, "192.0.2.2", 10.0, known=False) == 0
    assert not lim.unknown_full()  # one failure counted, the success's taken back


def test_the_limiter_remembers_a_bounded_number_of_addresses():
    lim = webauth.Limiter(max_addresses=10)
    for i in range(1000):
        lim.admit(f"10.0.{i // 256}.{i % 256}", True, float(i % 100))
    assert len(lim._addresses) == 10


def test_a_known_device_cookie_survives_a_restart_and_ends_with_a_new_password(stored):
    cookie = webauth.Devices().issue(stored)
    assert webauth.DEVICE.fullmatch(cookie)
    assert webauth.Devices().known(cookie, stored)  # another process: the key is the stored hash's
    other = webauth.hash_password(PASSWORD)  # the same password, a new salt: a new key
    assert not webauth.Devices().known(cookie, other)
    device, _, mac = cookie.partition(".")
    for bad in (None, "", f"{device}.{'0' * 64}", f"{'A' * 22}.{mac}", cookie + "x", cookie.upper()):
        assert not webauth.Devices().known(bad, stored), bad
    assert not webauth.Devices().known(cookie, None)


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
