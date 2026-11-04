"""(W12) LG depth across webOS generations: the key store's manifest and refusal records, the handshake
that reads the TV's release and checks the stored key, the refused-key state that stops the hourly
reading, the per-document consent record and the standby switches, the generations table, and the
must-allow hosts named by the TV's country. No TV is contacted: the SSAP side is a loopback server
(test_tvprobe.FakeTv) or a fake of the library (conftest.fake_lgtv)."""

import asyncio
import json
import os
import sqlite3
import subprocess
import time

import pytest
from conftest import ROOT, counting_lgtv, fake_handshake, fake_lgtv, write_lgtv_keys
from test_tvprobe import FakeTv, run

from tvgw import cli, config, db, doctor, ingest, lgkeys, lgwebos, plain, profile, queries, verify
from tvgw.config import Settings
from tvgw.lgwebos import Handshake
from tvgw.verify import Check

TV = "10.10.10.17"
HELLO = {
    "type": "hello",
    "id": "hello",
    "payload": {
        "protocolVersion": 1,
        "deviceType": "tv",
        "deviceOS": "webOS",
        "deviceOSVersion": "4.1.0",
        "deviceOSReleaseVersion": "11.2.0",
        "deviceUUID": "0123456789abcdef0123456789abcdef",
        "pairingTypes": ["PIN", "PROMPT", "COMBINED", "LGSWITCH-PIN"],
    },
}
REGISTERED = {"type": "registered", "id": "register_0", "payload": {"client-key": "the-key"}}
BLACKLISTED = {
    "type": "error",
    "id": "register_0",
    "error": "403 Pairing rejected: blacklisted certificate detected",
    "payload": {},
}
PROMPT = {"type": "response", "id": "register_0", "payload": {"pairingType": "PROMPT", "returnValue": True}}


# ---- the key store's tvgw half -------------------------------------------------------------------------


def test_a_key_file_from_before_the_table_reads_as_signed_and_its_key_is_untouched(tmp_path):
    """The reference CX's key file: the library's table alone. The first open gives its address a `signed`
    row (every tvgw before the table paired with the library's signed manifest) and rewrites nothing."""
    keys = tmp_path / "lgtv-keys.sqlite"
    write_lgtv_keys(keys, {TV: "cx-key", "10.10.10.18": "other"})
    before = sqlite3.connect(keys).execute('SELECT key, value FROM "unnamed" ORDER BY key').fetchall()
    assert lgkeys.migrate(str(keys)) == [TV, "10.10.10.18"]
    assert lgkeys.migrate(str(keys)) == []  # once
    rec = lgkeys.record(str(keys), TV)
    assert rec.manifest == "signed" and not rec.refused and rec.unreadable == ()
    after = sqlite3.connect(keys).execute('SELECT key, value FROM "unnamed" ORDER BY key').fetchall()
    assert after == before
    meta = sqlite3.connect(keys).execute("SELECT value FROM tvgw_meta WHERE key='schema'").fetchone()
    assert meta == (str(lgkeys.SCHEMA_VERSION),)
    assert lgkeys.record(str(keys), "10.10.10.99") is None


def test_the_store_records_a_refusal_once_a_pairing_clears_it_and_a_missing_file_stays_missing(tmp_path):
    keys = tmp_path / "lgtv-keys.sqlite"
    assert lgkeys.record(str(keys), TV) is None and not keys.exists()
    lgkeys.refused(str(keys), TV, "403 blacklisted")  # nothing to write to: no file is made
    assert not keys.exists()
    write_lgtv_keys(keys, {TV: "key"})
    lgkeys.refused(str(keys), TV, "403 Pairing rejected: blacklisted certificate detected", now=1000.0)
    lgkeys.refused(str(keys), TV, "later, something else", now=2000.0)
    rec = lgkeys.record(str(keys), TV)
    assert rec.refused and rec.refused_at == 1000.0 and "blacklisted" in rec.refused_why
    lgkeys.seen(str(keys), TV, "11.2.0", "4.1.0", "26", now=1500.0)
    lgkeys.unreadable(str(keys), TV, "general.alwaysOn")
    lgkeys.unreadable(str(keys), TV, "eulaInfoNetwork")
    rec = lgkeys.record(str(keys), TV)
    assert (rec.release, rec.os_version, rec.generation) == ("11.2.0", "4.1.0", "26")
    assert rec.unreadable == ("eulaInfoNetwork", "general.alwaysOn")
    lgkeys.paired(str(keys), TV, "unsigned", now=3000.0)
    rec = lgkeys.record(str(keys), TV)
    assert not rec.refused and rec.manifest == "unsigned" and rec.paired_at == 3000.0 and rec.unreadable == ()
    with pytest.raises(ValueError):
        lgkeys.paired(str(keys), TV, "library")
    (tmp_path / "text").write_text("not the library's database")
    assert lgkeys.record(str(tmp_path / "text"), TV) is None


# ---- the handshake: hello, then the stored key, on tvgw's own connection ---------------------------------


def loopback(monkeypatch, port: int) -> None:
    """Point the handshake at a loopback server without TLS."""

    async def connect(ip, timeout):
        return await lgwebos._WebSocket.connect("127.0.0.1", port, None, timeout=timeout)

    monkeypatch.setattr(lgwebos, "_connect_ws", connect)


def test_hello_gives_the_release_and_the_registration_says_the_key_is_taken(monkeypatch):
    async def script(conn):
        msg = await conn.recv()
        assert msg == {"id": "hello", "type": "hello", "payload": {}}
        await conn.send(HELLO)
        msg = await conn.recv()
        assert msg["type"] == "register" and msg["payload"]["client-key"] == "the-key"
        assert msg["payload"]["manifest"] == {"permissions": ["READ_SETTINGS"]}
        await conn.send(REGISTERED)
        await conn.drain_until_close()

    tv = FakeTv(script)

    async def go():
        port = await tv.start()
        loopback(monkeypatch, port)
        try:
            return await lgwebos.handshake(TV, "the-key", {"permissions": ["READ_SETTINGS"]}, timeout=2.0)
        finally:
            await tv.stop()

    h = run(go())
    assert (h.release, h.os_version, h.registered, h.error) == ("11.2.0", "4.1.0", True, "")
    assert h.generation == "26"
    assert tv.closes == [1000]  # a clean close, never a 1006 the TV holds against the next connection
    assert "deviceUUID" not in json.dumps(h.__dict__)


def test_a_blacklisted_certificate_and_a_prompt_are_refusals_and_no_hello_is_not(monkeypatch):
    async def blacklisted(conn):
        await conn.recv()
        await conn.send(HELLO)
        await conn.recv()
        await conn.send(BLACKLISTED)
        await conn.drain_until_close()

    async def prompt(conn):  # the TV forgot the key: a prompt on its screen, then silence
        await conn.recv()
        await conn.send({"type": "error", "id": "hello", "error": "404 no such method"})
        await conn.recv()
        await conn.send(PROMPT)
        await conn.drain_until_close()

    async def no_key(conn):  # hello only: nothing registered, nothing on the screen
        await conn.recv()
        await conn.send(HELLO)
        await conn.drain_until_close()

    async def go(script, key):
        tv = FakeTv(script)
        port = await tv.start()
        loopback(monkeypatch, port)
        monkeypatch.setattr(lgwebos, "PROBE_REGISTER_GRACE", 0.2)
        try:
            return await lgwebos.handshake(TV, key, {}, timeout=2.0), tv
        finally:
            await tv.stop()

    h, _ = run(go(blacklisted, "old-key"))
    assert h.registered is False and h.refused_why == BLACKLISTED["error"] and h.release == "11.2.0"
    h, _ = run(go(prompt, "old-key"))
    assert h.registered is False and "new pairing" in h.refused_why and h.release == ""
    h, tv = run(go(no_key, None))
    assert h.registered is None and h.release == "11.2.0" and len(tv.received) == 1


def test_the_handshake_fails_fast_on_a_port_that_accepts_and_says_nothing(monkeypatch):
    """A 2025 set leaves its old port open and silent for minutes after power-on (aiowebostv #744):
    the connect has a timeout, and the reading reports unreachable within it."""

    async def silent(reader, writer):
        await asyncio.sleep(30)

    async def go():
        server = await asyncio.start_server(silent, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        loopback(monkeypatch, port)
        t0 = time.monotonic()
        try:
            return await lgwebos.handshake(TV, "key", {}, timeout=0.3), time.monotonic() - t0
        finally:
            server.close()

    h, took = run(go())
    assert h.error == "TimeoutError" and h.registered is None and took < 3


def test_hello_fields_keep_plain_versions_only():
    assert lgwebos._hello_fields(HELLO["payload"]) == ("11.2.0", "4.1.0")
    assert lgwebos._hello_fields({"deviceOSReleaseVersion": "5.6.2 (beta)"}) == ("", "")
    assert lgwebos._hello_fields({"deviceOSReleaseVersion": 11}) == ("", "")
    assert lgwebos._hello_fields("garbage") == ("", "")
    assert (
        lgwebos.generation_from_release("5.6.2") == "5" and lgwebos.generation_from_release("7.5.7") == "22"
    )
    assert lgwebos.generation_from_release("11.2.0") == "26" and lgwebos.generation_from_release("12.0") == ""
    assert lgwebos.generation_from_release(None) == "" and lgwebos.generation_from_release("x") == ""


def test_the_release_table_is_the_profiles_generations_table(lg):
    """One table for the webOS the TV reports: lgwebos maps the release major to LG's name, and the
    profile's rows, keyed by os_major, agree row for row."""
    rows = {g.os_major: g.webos for g in lg.generations if g.os_major}
    assert rows == lgwebos.OS_GENERATIONS
    for g in lg.generations:
        assert lg.generation_for(release=f"{g.os_major}.2.0") is g


# ---- the unsigned manifest --------------------------------------------------------------------------------


def test_the_shipped_manifest_is_read_only_and_unsigned():
    m = lgwebos.unsigned_manifest()
    assert "signatures" not in m and "signed" not in m
    perms = m["permissions"]
    assert perms and all(p.startswith("READ_") for p in perms)
    assert not any(p.startswith(("CONTROL_", "LAUNCH", "WRITE_", "TEST_")) for p in perms)
    # the readers' needs: settings, software info, the network paths, power, the foreground app
    assert {"READ_SETTINGS", "READ_UPDATE_INFO", "READ_NETWORK_STATE", "READ_POWER_STATE"} <= set(perms)
    assert {"READ_RUNNING_APPS", "READ_APP_STATUS"} <= set(perms)
    assert os.path.isfile(lgwebos.unsigned_manifest_path())
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert '"profiles/*.json"' in pyproject  # shipped with the package, as the profile is


# ---- the hourly reading: the refused state, the manifest per key, the new keys ---------------------------


def keyed(monkeypatch, tmp_path, tv=None, handshake=None):
    tv, counts = tv or counting_lgtv()
    keys = tmp_path / "lgtv-keys.sqlite"
    fake_lgtv(monkeypatch, tv, {TV: "cx-key"}, keys)
    if handshake is not None:
        monkeypatch.setattr(lgwebos, "handshake", handshake)
    return keys, counts


def test_the_cx_reads_as_before_with_its_signed_key_and_gains_its_webos_keys(monkeypatch, tmp_path):
    """A key file from before the key store's table: the row says `signed`, the library gets no manifest
    file (its signed default, which the CX was paired with), nothing pairs, and the reading carries the
    release, OS version and generation from hello beside the keys it always had."""
    keys, counts = keyed(monkeypatch, tmp_path, handshake=fake_handshake("5.6.2", "4.9.3"))
    r = lgwebos.read(TV, str(keys), timeout=0.5)
    assert r.reachable and r.exit_code() == 0 and counts["manifests"] == ["signed"] and counts["prompts"] == 0
    assert (r.values["webos.release"], r.values["webos.os"], r.values["webos.generation"]) == (
        "5.6.2",
        "4.9.3",
        "5",
    )
    asked = [k for k in r.values if "." in k and not k.startswith(("eula.", "agreement.", "webos."))]
    base = [f"{cat}.{k}" for cat, keys_ in lgwebos.READS for k in keys_]
    assert asked[: len(base)] == base  # the CX asks the same keys, in the same order, as before
    assert "general.alwaysOn" not in r.values and "option.quickStartMode" not in r.values
    rec = lgkeys.record(str(keys), TV)
    assert (rec.manifest, rec.release, rec.generation, rec.refused) == ("signed", "5.6.2", "5", False)


def test_a_refused_key_stops_the_hourly_reading_until_the_owner_pairs_again(monkeypatch, tmp_path):
    """The TV answered the stored key with a 403 (or a prompt): the refusal is recorded with its time and
    reason, the reading exits 5 having connected to nothing more, and every later reading connects to
    nothing at all. No code path pairs again on its own; `pair()` does, and clears the record."""
    refusal = fake_handshake("11.2.0", "4.1.0", registered=False)

    async def handshake(ip, key, manifest, timeout=5.0):
        h = await refusal(ip, key, manifest, timeout)
        h.refused_why = "403 Pairing rejected: blacklisted certificate detected" if key else ""
        return h

    keys, counts = keyed(monkeypatch, tmp_path, handshake=handshake)
    r = lgwebos.read(TV, str(keys), timeout=0.5)
    assert not r.reachable and r.error.startswith(lgwebos.KEY_REFUSED) and r.exit_code() == 5
    assert "blacklisted" in r.error and counts["create"] == 0  # the library never connected
    assert r.lines()[0].startswith("TV refused the gateway's key") and "sudo tvgw tv pair" in r.lines()[0]
    rec = lgkeys.record(str(keys), TV)
    assert rec.refused and "blacklisted" in rec.refused_why and abs(rec.refused_at - time.time()) < 60
    # the next reading: nothing is sent, not even the handshake
    calls = []
    monkeypatch.setattr(lgwebos, "handshake", lambda *a, **k: calls.append(a) or refusal(*a, **k))
    r = lgwebos.read(TV, str(keys), timeout=0.5)
    assert r.exit_code() == 5 and "since" in r.error and calls == [] and counts["create"] == 0
    assert lgwebos.has_key(str(keys), TV)  # the key itself is kept: the owner decides
    # the owner pairs again: a new pairing takes tvgw's unsigned manifest, and the refusal is cleared
    monkeypatch.setattr(lgwebos, "handshake", fake_handshake("11.2.0", "4.1.0"))
    r = lgwebos.pair(TV, str(keys), timeout=0.5)
    assert r.reachable and counts["manifests"] == ["unsigned"] and counts["prompts"] == 0
    rec = lgkeys.record(str(keys), TV)
    assert not rec.refused and rec.manifest == "unsigned"
    r = lgwebos.read(TV, str(keys), timeout=0.5)
    assert r.reachable and counts["manifests"] == ["unsigned", "unsigned"]


def test_pair_keeps_the_manifest_of_a_key_the_tv_still_takes_and_the_owner_may_name_one(
    monkeypatch, tmp_path
):
    keys, counts = keyed(monkeypatch, tmp_path)
    assert lgwebos.pair(TV, str(keys), timeout=0.5).reachable
    assert counts["manifests"] == ["signed"]  # the CX's key, paired again: still the signed manifest
    assert lgwebos.pair(TV, str(keys), timeout=0.5, manifest="unsigned").reachable
    assert counts["manifests"][-1] == "unsigned" and lgkeys.record(str(keys), TV).manifest == "unsigned"
    assert lgwebos.pair(TV, str(keys), timeout=0.5, manifest="signed").reachable
    assert lgkeys.record(str(keys), TV).manifest == "signed"
    with pytest.raises(ValueError):
        lgwebos.pair(TV, str(keys), timeout=0.5, manifest="library")
    # a new TV, no key: tvgw's unsigned manifest, and the key file is born root-only
    tv, counts = counting_lgtv()
    fake_lgtv(monkeypatch, tv)
    new = tmp_path / "new-keys.sqlite"
    r = lgwebos.pair("10.10.10.18", str(new), timeout=0.5)
    assert r.reachable and counts["manifests"] == ["unsigned"] and counts["prompts"] == 1
    assert lgkeys.record(str(new), "10.10.10.18").manifest == "unsigned" and counts["born"] == 0o600


def test_an_unreachable_tv_is_unreachable_before_the_library_is_asked(monkeypatch, tmp_path):
    async def down(ip, key, manifest, timeout=5.0):
        return Handshake(error="ConnectionRefusedError")

    keys, counts = keyed(monkeypatch, tmp_path, handshake=down)
    r = lgwebos.read(TV, str(keys), timeout=0.5)
    assert not r.reachable and r.error == "ConnectionRefusedError" and r.exit_code() == 1
    assert counts["create"] == 0 and not lgkeys.record(str(keys), TV).refused


def generation_tv(answers: dict, refuse: set[str] = frozenset()):
    """A library fake whose settings answers come from `answers`; a key in `refuse` answers 401."""
    asked: list[tuple[str, str]] = []

    class Tv:
        @classmethod
        async def create(cls, ip, states, key_file_path, manifest_file_path=None):
            return cls()

        async def connect(self):
            pass

        async def get_system_settings(self, cat, keys):
            asked.append((cat, keys[0]))
            if keys[0] in refuse:
                raise RuntimeError("401 insufficient permissions (not registered)")
            return {"settings": {keys[0]: answers.get(keys[0], "off")}}

        async def request(self, uri):
            return {"wired": {"state": "connected"}}

        async def get_software_info(self):
            raise RuntimeError("401 insufficient permissions")

        async def get_power_state(self):
            return {"state": "Active"}

        async def get_current_app(self):
            return "netflix"

        async def disconnect(self):
            pass

    return Tv, asked


def test_a_webos_26_set_is_asked_its_standby_switches_and_agreements_and_a_401_is_asked_once(
    monkeypatch, tmp_path
):
    docs = [
        {"id": "S_ADG", "version": "3.1", "accepted": False, "updated": True},
        {"id": "S_PRG", "version": "7", "accepted": True, "updated": False},
        {"id": "bad id!", "accepted": True},
    ]
    answers = {
        "alwaysOn": "on",
        "quickStartMode": "off",
        "wolwowlOnOff": "on",
        "eulaStatus": {"acrAllowed": False},
        "eulaInfoNetwork": docs,
    }
    tv, asked = generation_tv(answers)
    keys = tmp_path / "lgtv-keys.sqlite"
    fake_lgtv(monkeypatch, tv, {TV: "key"}, keys)
    lgkeys.paired(str(keys), TV, "unsigned")
    monkeypatch.setattr(lgwebos, "handshake", fake_handshake("11.2.0", "4.1.0"))
    r = lgwebos.read(TV, str(keys), timeout=0.5)
    assert ("general", "alwaysOn") in asked and ("option", "quickStartMode") in asked
    assert asked[-1] == ("", "eulaInfoNetwork")
    assert r.values["general.alwaysOn"] == "on" and r.values["webos.generation"] == "26"
    assert r.values["info"].startswith("ERR")  # no software info with the unsigned manifest on webOS 26
    assert "firmware" not in r.values and r.values["webos.release"] == "11.2.0"
    assert r.values["eula.doc.S_ADG"] == "false" and r.values["agreement.S_ADG.updated"] == "true"
    assert r.values["agreement.S_ADG.version"] == "3.1" and r.values["eula.doc.S_PRG"] == "true"
    assert not any("bad id" in k for k in r.values)
    assert lgwebos.standby_on(r.values) == ["Always Ready", "TV On With Mobile"]
    assert lgwebos.agreements_pending(r.values) == ["S_ADG"]
    lines = r.lines()
    assert (
        "NOTE: Always Ready, TV On With Mobile on: the TV keeps its network up while the screen is off"
        in lines
    )
    assert "NOTE: the TV asks you to accept Viewing Information (S_ADG) again; it is not accepted" in lines
    assert r.exit_code() == 0  # informational, never a warning
    # a TV whose firmware refuses a standby key or the agreements: asked once, then never again
    tv, asked = generation_tv(answers, refuse={"alwaysOn", "eulaInfoNetwork"})
    fake_lgtv(monkeypatch, tv, {TV: "key"}, keys)
    lgkeys.paired(str(keys), TV, "unsigned")
    monkeypatch.setattr(lgwebos, "handshake", fake_handshake("11.2.0", "4.1.0"))
    r = lgwebos.read(TV, str(keys), timeout=0.5)
    assert r.values["general.alwaysOn"].startswith("ERR") and r.values["agreement.status"].startswith("ERR")
    assert lgkeys.record(str(keys), TV).unreadable == ("eulaInfoNetwork", "general.alwaysOn")
    asked.clear()
    lgwebos.read(TV, str(keys), timeout=0.5)
    assert ("general", "alwaysOn") not in asked and ("", "eulaInfoNetwork") not in asked
    assert ("option", "quickStartMode") in asked and ("", "eulaStatus") in asked


def test_a_tv_whose_hello_goes_unanswered_reads_as_before_and_its_release_is_not_stored(
    monkeypatch, tmp_path
):
    async def mute(ip, key, manifest, timeout=5.0):
        return Handshake(registered=True, error="hello: TimeoutError")

    keys, _counts = keyed(monkeypatch, tmp_path, handshake=mute)
    r = lgwebos.read(TV, str(keys), timeout=0.5)
    assert r.reachable and r.values["webos.release"].startswith("ERR hello") and r.exit_code() == 0
    assert "webos.generation" not in r.values and lgkeys.record(str(keys), TV).release == ""
    conn = db.connect(str(tmp_path / "tvgw.db"))
    s = Settings(
        state_dir=str(tmp_path),
        db_path=str(tmp_path / "tvgw.db"),
        tvcheck_txt=str(tmp_path / "tvcheck.txt"),
        tvcheck_history=str(tmp_path / "tvcheck-history.log"),
    )
    (tmp_path / "tvcheck-history.log").write_text("")
    (tmp_path / "tvcheck.txt").write_text("read 2026-11-04T10:20:00-06:00\n" + "\n".join(r.lines()) + "\n")
    ingest.ingest_tvstate(conn, s, lambda m: None)
    stored = dict(conn.execute("SELECT key, value FROM tvsettings").fetchall())
    assert "webos.release" not in stored and "webos.generation" not in stored  # a miss is not a fact
    conn.close()


def test_agreements_read_both_shapes_and_never_guess():
    as_table = {"eulaInfoNetwork": {"S_VNG": {"accepted": "true", "updated": "false", "version": 2}}}
    assert lgwebos.agreements(as_table) == {
        "eula.doc.S_VNG": "true",
        "agreement.S_VNG.updated": "false",
        "agreement.S_VNG.version": "2",
    }
    assert lgwebos.agreements({"eulaInfoNetwork": [{"id": "S_TAG"}]}) == {
        "eula.doc.S_TAG": "unknown",
        "agreement.S_TAG.updated": "unknown",
    }
    assert lgwebos.agreements({"eulaInfoNetwork": "nothing"}) == {} and lgwebos.agreements(None) == {}
    assert (
        lgwebos.agreement_name("S_ADG") == "Viewing Information (S_ADG)"
        and lgwebos.agreement_name("X9") == "X9"
    )


def test_tvcheck_exits_5_on_a_refused_key_and_the_hourly_script_keeps_the_last_reading(
    monkeypatch, tmp_path, capsys
):
    keys, counts = keyed(monkeypatch, tmp_path)
    lgkeys.refused(str(keys), TV, "403 Pairing rejected: blacklisted certificate detected", now=1_700_000_000)
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f"PROFILE=lg-webos\nTV_IP={TV}\n", encoding="utf-8")
    assert cli.main(["--conf", str(conf), "tvcheck", "--key-file", str(keys)]) == 5
    out = capsys.readouterr().out
    assert out.startswith("TV refused the gateway's key") and counts["create"] == 0
    analyze = (ROOT / "deploy" / "bin" / "tvgw-analyze").read_text(encoding="utf-8")
    # (samsung) exit 5 is no reading for an LG; a Samsung's 5 is its own and is kept
    assert (
        '[ "$rc" -ne 1 ] && [ "$rc" -ne 4 ] && { [ "$rc" -ne 5 ] || [ "${PROFILE:-lg-webos}" = samsung-tizen ]; }'
        in (analyze)
    )


def test_tv_pair_clears_a_refusal_and_names_the_manifest(monkeypatch, tmp_path, capsys):
    keys, counts = keyed(monkeypatch, tmp_path)
    lgkeys.refused(str(keys), TV, "403 Pairing rejected: blacklisted certificate detected", now=1_700_000_000)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f"PROFILE=lg-webos\nTV_IP={TV}\n", encoding="utf-8")
    assert cli.main(["--conf", str(conf), "tv", "pair", "--key-file", str(keys)]) == 0
    out = capsys.readouterr().out
    assert "the TV refused the gateway's key on 2023-11-1" in out and "(unsigned manifest)" in out
    assert counts["manifests"] == ["unsigned"] and not lgkeys.record(str(keys), TV).refused
    # the explicit fallback, and its hint when it fails
    tv, counts = counting_lgtv(accept=False)
    fake_lgtv(monkeypatch, tv)
    new = tmp_path / "new.sqlite"
    rc = cli.main(["--conf", str(conf), "tv", "pair", "--key-file", str(new), "--manifest", "signed"])
    assert rc == 1 and "try again without --manifest signed" in capsys.readouterr().err
    assert counts["manifests"] == ["signed"]


def test_only_pair_writes_the_manifest_and_nothing_switches_it_on_its_own():
    """`lgkeys.paired()` is the one writer of a key's manifest, and `pair()` the one caller of it: no
    reading, probe or doctor changes which manifest a stored key is sent with."""
    src = (ROOT / "src" / "tvgw").rglob("*.py")
    callers = sorted(p.name for p in src if "lgkeys.paired(" in p.read_text(encoding="utf-8"))
    assert callers == ["lgwebos.py"]
    text = (ROOT / "src" / "tvgw" / "lgwebos.py").read_text(encoding="utf-8")
    assert text.count("lgkeys.paired(") == 1


# ---- the probe follows the record ------------------------------------------------------------------------


def test_the_probe_does_not_start_on_a_refused_key(monkeypatch, tmp_path, capsys):
    keys, _counts = keyed(monkeypatch, tmp_path)
    lgkeys.refused(str(keys), TV, "403 Pairing rejected", now=1_700_000_000)
    rc = lgwebos.probe_main(TV, str(keys), str(tmp_path / "probe.jsonl"), 1.0, "eth0")
    assert rc == 2 and "refused the key on 2023-11-1" in capsys.readouterr().out
    assert not (tmp_path / "probe.jsonl").exists()


# ---- the country the TV reports, and the must-allow hosts named by it -----------------------------------


def test_country_codes_map_lgs_values_to_host_prefixes():
    assert lgwebos.country_code("USA") == "us" and lgwebos.country_code("DEU") == "de"
    assert lgwebos.country_code("CA") == "ca" and lgwebos.country_code("nl") == "nl"
    assert lgwebos.country_code("Germany") == "" and lgwebos.country_code("") == ""
    assert lgwebos.country_code(None) == "" and lgwebos.country_code("1234") == ""


US_RULES = [
    "@@||us.lgtvsdp.com^$important",
    "@@||snu.lge.com^$important",
    "@@||lgtvonline.lge.com^$important",
    "@@||us.lgrecommends.lgappstv.com^$important",
    "@@||aic.service.lgtvcommon.com^$important",
    "@@||us.tvsdp.lgeapi.com^$important",
    "@@||us.nextlgsdp.com^$important",
    "@@||ngfts.nextlgsdp.com^$important",
    "@@||aic-gfts.nextlgsdp.com^$important",
]


def test_the_profile_without_a_country_plans_the_us_rules_it_always_did(lg):
    """The reference gateway names no country: the nine exceptions, in this order, byte for byte."""
    assert lg.adguard_rules()[: len(US_RULES)] == US_RULES and lg.country == "us"
    assert lg.for_country("") is lg and lg.for_country("us") is lg
    assert lg.must_allow_templates[0][0] == "{cc}.lgtvsdp.com"


def test_a_country_fills_the_hosts_and_its_region_and_the_lint_stays_clean(lg):
    de = lg.for_country("de")
    assert list(de.must_allow) == [
        "de.lgtvsdp.com",
        "snu.lge.com",
        "lgtvonline.lge.com",
        "de.lgrecommends.lgappstv.com",
        "eic.service.lgtvcommon.com",
        "de.tvsdp.lgeapi.com",
        "de.nextlgsdp.com",
        "ngfts.nextlgsdp.com",
        "eic-gfts.nextlgsdp.com",
    ]
    assert de.country == "de" and de.lint() == [] and de.categorize("de.nextlgsdp.com") == "LG core"
    assert (
        lg.for_country("KR").region_for("kr") == "kic"
        and "kic-gfts.nextlgsdp.com" in lg.for_country("kr").must_allow
    )
    assert lg.for_country("mx").region_for("mx") == "aic"  # a country no region lists: the Americas' prefix
    assert lg.rules == de.rules and lg.custom_rules == de.custom_rules  # only the must-allow hosts move
    with pytest.raises(ValueError):
        lg.for_country("deu")
    with pytest.raises(ValueError):
        profile.from_dict({"profile": {"default_country": "USA"}})
    with pytest.raises(ValueError, match=r"regions\.kic: de is also in eic"):
        profile.from_dict({"regions": {"eic": ["de"], "kic": ["de"]}})


def test_tv_country_in_the_settings_fills_the_profile_every_command_loads(tmp_path, capsys):
    conf = tmp_path / "tvgw.conf"
    conf.write_text("PROFILE=lg-webos\nTV_COUNTRY=de\n", encoding="utf-8")
    assert config.load(conf).tv_country == "de"
    assert cli.main(["--conf", str(conf), "profile"]) == 0
    out = capsys.readouterr().out
    allowed = out[out.index("Must stay allowed") : out.index("Generations:")]
    assert "de.nextlgsdp.com" in allowed and "eic-gfts.nextlgsdp.com" in allowed and "us." not in allowed
    conf.write_text("TV_COUNTRY=Germany\n", encoding="utf-8")
    with pytest.raises(ValueError, match="TV_COUNTRY"):
        config.load(conf)


# ---- the brief: the TV line, the pairing line, the standby and agreement lines, the country ----------------


def store(tmp_path) -> sqlite3.Connection:
    return db.connect(str(tmp_path / "tvgw.db"))


def seed(conn, rows):
    conn.executemany("INSERT OR REPLACE INTO tvsettings(t,key,value) VALUES (?,?,?)", rows)
    conn.commit()


def window() -> tuple[tuple[float, float], float]:
    """The day under test, (bounds, an hour into it), computed inside the test: conftest's autouse fixture
    sets the gateway's time zone (America/Chicago) per test, so a day computed at import time would be
    the runner's day (UTC on CI), and an hour into it the evening before in the gateway's."""
    a, b = queries.day_bounds("2026-11-04")
    return (a, b), a + 3600


def test_the_brief_carries_the_tv_card_the_pairing_the_standby_and_the_agreements(tmp_path, lg):
    _day, T0 = window()
    conn = store(tmp_path)
    seed(
        conn,
        [
            (T0, "model", "OLED55CXPUA"),
            (T0, "webos.generation", "5"),
            (T0, "webos.release", "5.6.2"),
            (T0, "firmware", "04.64.00"),
            (T0 + 60, "general.alwaysOn", "on"),
            (T0 + 60, "agreement.S_ADG.updated", "true"),
            (T0 + 60, "eula.doc.S_ADG", "false"),
            (T0 + 60, "agreement.S_PRG.updated", "true"),
            (T0 + 60, "eula.doc.S_PRG", "true"),
            (T0 + 7200, queries.PAIRING_KEY, "refused"),
        ],
    )
    o = queries.brief(conn, "2026-11-04", lg)
    assert o["tv_card"] == {
        "model": "OLED55CXPUA",
        "generation": "5",
        "release": "5.6.2",
        "firmware": "04.64.00",
    }
    assert o["pairing"] == {"state": "refused", "t": T0 + 7200}
    assert [x["label"] for x in o["standby_features"]] == ["Always Ready"]
    assert [x["doc"] for x in o["agreements_pending"]] == ["S_ADG"]
    assert o["tv_country"] is None  # no country reading
    import io

    out = io.StringIO()
    cli.render_brief(o, out)
    text = out.getvalue()
    assert "Pairing: the gateway can no longer read the TV since 2026-11-04: run sudo tvgw tv pair" in text
    assert "Standby: Always Ready on: the TV keeps its network up while the screen is off" in text
    assert (
        "Agreements: the TV asks you to accept Viewing Information (S_ADG) again; it is not accepted" in text
    )
    assert "\nTV (OLED55CXPUA, webOS 5 (5.6.2), firmware 04.64.00): " in text
    lines = plain.plain_brief(o, profile=lg)
    assert (
        "  Pairing: The gateway can no longer read the TV since 2026-11-04. With the TV on, run: sudo tvgw tv pair"
        in lines
    )
    assert "  Standby: Always Ready is on, so the TV keeps its network up while the screen is off." in lines
    assert (
        "  Agreements: The TV asks you to accept Viewing Information (S_ADG) again. It is not accepted."
        in lines
    )
    assert not any(w in s for _, s, _ in plain.items(o, lg) for w in ("Pairing", "Standby", "accept"))
    conn.close()


def test_an_agreement_document_accepted_is_the_agreement_red_line_and_an_update_alone_is_not(tmp_path, lg):
    DAY, T0 = window()
    conn = store(tmp_path)
    seed(
        conn,
        [
            (DAY[0] - 86400, "eula.doc.S_VNG", "false"),
            (T0, "eula.doc.S_VNG", "true"),
            (DAY[0] - 86400, "agreement.S_TAG.updated", "false"),
            (T0, "agreement.S_TAG.updated", "true"),
        ],
    )
    o = queries.brief(conn, "2026-11-04", lg)
    reds = [x for x in o["red_lines"] if x.startswith("TV agreement")]
    assert reds == [
        f"TV agreement Voice Information (S_VNG) accepted (at {queries._fmt(T0)}): an agreement was accepted on the TV"
    ]
    assert not any("S_TAG" in x for x in o["red_lines"])
    assert plain.items(o, lg)[0][0] == "act" and "decline it again" in plain.items(o, lg)[0][2]
    conn.close()


def test_a_release_change_is_a_software_update_where_the_firmware_call_answers_401(tmp_path, lg):
    DAY, T0 = window()
    conn = store(tmp_path)
    seed(
        conn,
        [
            (DAY[0] - 86400, "webos.release", "10.3.2"),
            (T0, "webos.release", "11.2.0"),
            (DAY[0] - 86400, "firmware", "33.31.68"),
        ],
    )
    fc = queries.firmware_changes(conn, *DAY)
    assert [(x["firmware"], x["source"]) for x in fc] == [("webOS 11.2.0", "webos.release")]
    # a reading in which both change is one update, named by the firmware
    seed(conn, [(T0 + 3600, "firmware", "43.21.71"), (T0 + 3600, "webos.release", "11.2.1")])
    fc = queries.firmware_changes(conn, *DAY)
    assert [(x["firmware"], x.get("release")) for x in fc] == [("webOS 11.2.0", None), ("43.21.71", "11.2.1")]
    o = queries.brief(conn, "2026-11-04", lg)
    assert "the TV's software updated to 43.21.71" in plain.plain_brief(o, profile=lg)[4]
    # (depth) the owner's yes from before the release change is asked again
    seed(conn, [(DAY[0] - 3600, queries.WIFI_CONFIRMED, "yes")])
    conn.execute("DELETE FROM tvsettings WHERE key='firmware'")
    conn.commit()
    (line,) = queries.not_checked(conn, DAY[1], {})
    assert "before the TV's software changed on 2026-11-04" in line
    conn.close()


def test_a_tv_outside_the_configured_country_gets_the_allow_line(tmp_path, lg):
    _day, T0 = window()
    conn = store(tmp_path)
    seed(conn, [(T0, "country", "DEU")])
    o = queries.brief(conn, "2026-11-04", lg)
    c = o["tv_country"]
    assert (c["reported"], c["code"], c["allow"]) == ("DEU", "de", "sudo tvgw allow de.lgtvsdp.com")
    assert "de.nextlgsdp.com" in c["missing"] and "snu.lge.com" not in c["missing"]
    import io

    out = io.StringIO()
    cli.render_brief(o, out)
    assert (
        "TV country: the TV reports DEU (de); de.lgtvsdp.com is not on the must-allow list: run sudo tvgw allow de.lgtvsdp.com, or set TV_COUNTRY=de"
        in out.getvalue()
    )
    assert (
        "  Country: The TV says its country is DE, and one of its service names is not yet let through. Run: sudo tvgw allow de.lgtvsdp.com"
        in plain.plain_brief(o, profile=lg)
    )
    # the settings name the country: nothing to say
    assert queries.brief(conn, "2026-11-04", lg.for_country("de"))["tv_country"] is None
    # a US set behind the default: nothing to say; an unreadable country: nothing to say
    seed(conn, [(T0 + 1, "country", "USA")])
    assert queries.brief(conn, "2026-11-04", lg)["tv_country"] is None
    seed(conn, [(T0 + 2, "country", "Narnia")])
    assert queries.brief(conn, "2026-11-04", lg)["tv_country"] is None
    conn.close()


# ---- the ingest copies the pairing's state; verify and the doctor read it --------------------------------


def test_ingest_copies_the_pairing_state_once_per_change(tmp_path):
    s = Settings(state_dir=str(tmp_path), db_path=str(tmp_path / "tvgw.db"), profile="lg-webos", tv_ip=TV)
    conn = store(tmp_path)
    assert ingest.ingest_pairing(conn, s, lambda m: None) == 0  # no key file: nothing to say
    keys = tmp_path / "lgtv-keys.sqlite"
    write_lgtv_keys(keys, {TV: "key"})
    lgkeys.paired(str(keys), TV, "signed", now=1000.0)
    assert ingest.ingest_pairing(conn, s, lambda m: None) == 1
    assert ingest.ingest_pairing(conn, s, lambda m: None) == 0
    lgkeys.refused(str(keys), TV, "403", now=2000.0)
    assert ingest.ingest_pairing(conn, s, lambda m: None) == 1
    rows = conn.execute(
        "SELECT t, value FROM tvsettings WHERE key=? ORDER BY t", (queries.PAIRING_KEY,)
    ).fetchall()
    assert rows == [(1000.0, "ok"), (2000.0, "refused")]
    other = Settings(state_dir=str(tmp_path), db_path=str(tmp_path / "tvgw.db"), profile="generic-tv")
    assert ingest.ingest_pairing(conn, other, lambda m: None) == 0
    conn.close()


def test_verify_warns_not_checked_on_a_refused_key_and_the_doctor_names_the_fix(lg):
    from test_verify import S, gateway, resolver

    stale = "read 2026-10-26T15:20:00-05:00\noption.livePlus = off\nnetwork.wifi.state = connected\n"
    refused = lgkeys.Pairing(TV, "signed", refused_at=1_762_300_000.0, refused_why="403 blacklisted")
    r = verify.check(
        S, lg, **gateway(files={S.tvcheck_txt: stale}), resolve=resolver(), pairing=lambda: refused
    )
    (c,) = [c for c in r.checks if c.name == "tv_paths"]
    assert (
        c.ok
        and c.warn
        and c.detail.startswith("not checked: the TV refuses the gateway's key since 2025-11-0")
    )
    assert "sudo tvgw tv pair" in c.detail
    good = lgkeys.Pairing(TV, "signed")
    r = verify.check(S, lg, **gateway(files={S.tvcheck_txt: stale}), resolve=resolver(), pairing=lambda: good)
    (c,) = [c for c in r.checks if c.name == "tv_paths"]
    assert not c.ok and c.detail.startswith("second path: Wi-Fi connected")
    plan = doctor.plan_for(Check("tv_paths", True, "not checked: ...", warn=True), S, lg, None, {})
    assert plan.fixes == [] and any("sudo tvgw tv pair" in n for n in plan.notes)
    assert verify.PLAIN["tv_paths"][2].endswith("after running sudo tvgw tv pair.")


def test_the_hourly_script_treats_a_refused_key_like_an_unpaired_one(tmp_path):
    """tvgw-analyze: exit 5 writes no tvcheck.txt and records power `unknown`, as 4 does."""
    import shutil

    from test_deploy_files import tv_reading_block

    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed here")
    stub = tmp_path / "bin"
    stub.mkdir()
    (stub / "tvgw").write_text(
        '#!/bin/sh\n[ "$1" = tvcheck ] || exit 9\necho "TV refused the gateway\'s key (key refused since 2026-11-04)"\nexit 5\n'
    )
    (stub / "date").write_text("#!/bin/sh\necho 2026-11-04T10:20:00-06:00\n")
    for f in stub.iterdir():
        f.chmod(0o755)
    (tmp_path / "tvcheck.txt").write_text("read 2026-11-03T22:20:00-06:00\noption.livePlus = off\n")
    script = tv_reading_block().replace("/usr/local/bin/tvgw", str(stub / "tvgw"))
    env = {"PATH": f"{stub}:/usr/bin:/bin", "STATE": str(tmp_path)}
    out = subprocess.run([bash, "-euo", "pipefail", "-c", script], env=env, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert (tmp_path / "tvcheck.txt").read_text() == "read 2026-11-03T22:20:00-06:00\noption.livePlus = off\n"
    assert (tmp_path / "tvcheck-history.log").read_text() == "2026-11-04T10:20:00-06:00\tunknown\t\n"


# ---- the generations table --------------------------------------------------------------------------------


def test_the_generations_table_names_what_the_gateway_needs_per_webos(lg):
    gens = {g.webos: g for g in lg.generations}
    assert list(gens) == ["3", "4", "5", "6", "22", "23", "24", "25", "26"]
    assert gens["5"].support == "tested" and gens["5"].verified and gens["5"].manifest == "signed"
    assert gens["5"].menu_path("agreements") == "Support > Additional Settings > User Agreements"
    assert gens["5"].menu_path("live_plus") == "General > Additional Settings > Live Plus"
    assert gens["26"].manifest == "unsigned" and gens["25"].manifest == "unsigned"
    assert "general.alwaysOn" in gens["24"].readable and "general.alwaysOn" not in gens["5"].readable
    assert "option.livePlus" in gens["26"].readable and "eulaInfoNetwork" in gens["26"].readable
    assert "installerTermsOnAllowed" in gens["26"].consent_flags and len(gens["5"].consent_flags) == 22
    assert gens["22"].readable == () and gens["23"].confidence == "low"  # no dump of a set on 22 or 23
    for g in lg.generations:
        assert g.os_major and g.support in ("tested", "not-yet-tested") and g.sources
        assert g.confidence in ("observed", "community", "spec", "low")
        assert all(topic in profile.MENU_TOPICS for topic, _ in g.menu)
    # the lookups: the release the TV reports first, then LG's name, then a firmware major one row has
    assert lg.generation_for(release="7.5.7").webos == "22" and lg.generation_for(release="12.0.0") is None
    assert (
        lg.generation_for(firmware="43.21.71").webos == "26"
        and lg.generation_for(firmware="03.53.45") is None
    )
    assert "03" in gens["6"].firmware_majors and "03" in gens["22"].firmware_majors  # shared: no lookup key
    # the lan_api records agree: wss 3001 is the verified one
    (seen,) = [a for a in lg.lan_apis if a.provenance.verified]
    assert seen.port == 3001 and seen.protocol == "wss"
    with pytest.raises(ValueError, match=r"os_major: 11 is also webOS 26's"):
        profile.from_dict(
            {"generations": [{"webos": "26", "os_major": "11"}, {"webos": "27", "os_major": "11"}]}
        )
    with pytest.raises(ValueError, match=r"generations\[0\]\.readble: unknown key"):
        profile.from_dict({"generations": [{"webos": "5", "readble": []}]})
    with pytest.raises(ValueError, match="menu"):
        profile.from_dict({"generations": [{"webos": "5", "menu": {"lunch": "x"}}]})


def test_cli_profile_prints_the_generation_the_tv_reports(tmp_path, capsys):
    conf = tmp_path / "none.conf"
    assert cli.main(["--conf", str(conf), "profile", "--release", "11.2.0"]) == 0
    out = capsys.readouterr().out
    assert "Generation for webOS ? / firmware ? / release 11.2.0:" in out
    assert "webOS 26 (2026, queue; community confidence)" in out
    assert "    pairing manifest: unsigned" in out and "    menu agreements: Support > Privacy & Terms" in out
    assert "    reports: release 11.x" in out and "Not yet tested" in out
    assert cli.main(["--conf", str(conf), "profile", "--release", "99.0"]) == 0
    assert "unknown to this profile" in capsys.readouterr().out
