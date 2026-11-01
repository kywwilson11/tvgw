"""`tvgw setup` and the settings-file writer behind it. The flow runs against a fake system (`Env`):
discovery, the TV-side check, the installer, pairing and verify are scripted callables, so every path,
the dry run and the unattended run are exercised with no network, no root and no Pi."""

import contextlib
import dataclasses
import io
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from tvgw import cli, config, setup
from tvgw.discover import Candidate
from tvgw.lgwebos import TvReading
from tvgw.verify import Check, Result

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = (ROOT / "deploy" / "tvgw.conf.example").read_text(encoding="utf-8")
MAC = "02:00:00:00:00:01"  # locally administered: never a real device
OTHER_MAC = "02:00:00:00:00:02"
ROUTER = "192.0.2.1"


# ---- the writer ----------------------------------------------------------------------------------------
def test_writer_round_trips_the_shipped_template_line_for_line():
    """Every line but the changed ones is byte for byte what it was, comments included."""
    new = config.update_conf(EXAMPLE, {"TV_MAC": MAC, "TV_IP": "10.10.10.12", "WAN_GW": ROUTER})
    old_lines, new_lines = EXAMPLE.splitlines(), new.splitlines()
    assert len(old_lines) == len(new_lines)
    changed = [(a, b) for a, b in zip(old_lines, new_lines, strict=True) if a != b]
    assert [b.split("=")[0] for _, b in changed] == ["TV_MAC", "TV_IP", "WAN_GW"]
    for a, b in changed:
        if "#" in a:  # the comment survives, starting in the same column
            assert b.index("#") == a.index("#") and b[b.index("#") :] == a[a.index("#") :]
    c = config.parse_conf(new)
    assert c["TV_MAC"] == MAC and c["TV_IP"] == "10.10.10.12" and c["WAN_GW"] == ROUTER
    assert config.update_conf(new, {"TV_MAC": MAC}) == new  # a value already there changes nothing


def test_writer_keeps_unknown_keys_junk_and_quoting():
    text = (
        "# my notes\nFUTURE_KEY=keep me   # not ours\n".replace("keep me", '"keep me"')
        + "garbage line\n"
        + "ANALYST_WEEKLY_SCHEDULE='Mon 04:10'\n"
        + "UPLINK=direct\n"
    )
    new = config.update_conf(
        text, {"ANALYST_WEEKLY_SCHEDULE": "Tue 05:00", "ANALYST_SCHEDULE": "*-*-* 06,18:00:00"}
    )
    assert '# my notes\nFUTURE_KEY="keep me"   # not ours\ngarbage line\n' in new
    assert "ANALYST_WEEKLY_SCHEDULE='Tue 05:00'\n" in new  # the line's own quotes kept
    assert new.endswith(
        f'\n{config.ADDED_HEADER}\nANALYST_SCHEDULE="*-*-* 06,18:00:00"\n'
    )  # a space forces quotes
    again = config.update_conf(new, {"WAN_GW": ROUTER})
    assert again.count(config.ADDED_HEADER) == 1 and again.endswith(f"WAN_GW={ROUTER}\n")


def test_writer_sets_every_copy_of_a_repeated_key():
    new = config.update_conf("UPLINK=direct\nUPLINK=direct\n", {"UPLINK": "vpn"})
    assert new == "UPLINK=vpn\nUPLINK=vpn\n"


def test_writer_shortens_and_lengthens_values_around_a_comment():
    text = "TV_NAME=tv                 # DHCP hostname\n"
    longer = config.update_conf(text, {"TV_NAME": "a" * 40})
    assert longer == "TV_NAME=" + "a" * 40 + " # DHCP hostname\n"  # at least one space before the comment
    back = config.update_conf(longer, {"TV_NAME": "tv"})
    assert back.index("#") == len("TV_NAME=") + 40 + 1


@pytest.mark.parametrize(
    "key,value",
    [
        ("WAN_IF", "wlan0;reboot"),
        ("WAN_IF", "$(id)"),
        ("WAN_IF", "`id`"),
        ("STATE_DIR", "~/x"),
        ("TV_NAME", "tv\nUPLINK=vpn"),
        ("PROFILE", "a#b"),
        ("PROFILE", 'a"b'),
        ("TV_MAC", "aa:bb:cc"),
        ("TV_NAME", "my tv"),
        ("WAN_GW", "router"),
        ("URL_FILTER_RESOLVER", "2001:db8::1"),
        ("DOH_LIST_URL", "http://example.com/doh.txt"),
        ("NOT_A_KEY", "x"),
        ("BLOCK_QUIC", "Yes"),  # load() refuses it
        ("TV_IP", "10.10.10"),
        ("DB_DAYS", "0"),
        ("ANALYST_EFFORT", "extreme"),
    ],
)
def test_writer_refuses_what_the_shell_or_settings_would_refuse(key, value):
    with pytest.raises(ValueError):
        config.update_conf(EXAMPLE, {key: value})


def test_writer_refuses_a_file_that_would_not_load_even_for_an_unrelated_key():
    """A broken line elsewhere (an unquoted space) makes the whole file unloadable: refused, not
    written around."""
    with pytest.raises(ValueError, match="must be quoted"):
        config.update_conf("ANALYST_WEEKLY_SCHEDULE=Mon 04:10\n", {"UPLINK": "vpn"})


@pytest.mark.parametrize(
    "text",
    [
        'DOH_LIST_URL="https://a.example/b\nc"\n',  # a quoted value over two lines
        'DOH_LIST_URL="https://a.example/b" c\n',  # a quoted value with something after it
    ],
)
def test_writer_refuses_to_rewrite_a_line_it_cannot_read(text):
    """Replacing such a line could leave the rest of the value behind as shell syntax."""
    with pytest.raises(ValueError, match="not a plain KEY=VALUE line; edit it by hand"):
        config.update_conf(text, {"DOH_LIST_URL": "https://x.example/y"})


@pytest.mark.skipif(not Path(config.BASH).exists(), reason="no bash to syntax-check with")
def test_writer_refuses_a_result_bash_cannot_source():
    with pytest.raises(ValueError, match="bash -n"):
        config.update_conf("if then\nUPLINK=direct\n", {"UPLINK": "vpn"})
    assert config.update_conf("UPLINK=direct\n", {"UPLINK": "vpn"}) == "UPLINK=vpn\n"


def test_save_conf_writes_atomically_keeps_mode_and_reports_the_diff(tmp_path):
    p = tmp_path / "tvgw.conf"
    p.write_text(EXAMPLE, encoding="utf-8")
    p.chmod(0o640)
    assert config.save_conf(p, {"WAN_GW": ROUTER}, dry_run=True)
    assert p.read_text(encoding="utf-8") == EXAMPLE  # the dry run wrote nothing
    diff = config.save_conf(p, {"WAN_GW": ROUTER})
    assert f"+WAN_GW={ROUTER}" in diff and "-WAN_GW=192.168.1.1" in diff
    assert stat.S_IMODE(p.stat().st_mode) == 0o640
    assert config.load(p) is not None and config.parse_conf(p.read_text(encoding="utf-8"))["WAN_GW"] == ROUTER
    assert config.save_conf(p, {"WAN_GW": ROUTER}) == []  # idempotent
    assert not [f for f in os.listdir(tmp_path) if f.startswith(".tvgw.conf.")]  # no temp file left


def test_save_conf_creates_a_missing_file_from_the_template(tmp_path):
    p = tmp_path / "etc" / "tvgw.conf"
    diff = config.save_conf(p, {}, template=EXAMPLE)
    assert diff and p.read_text(encoding="utf-8") == EXAMPLE
    q = tmp_path / "other.conf"
    config.save_conf(q, {"WAN_GW": ROUTER})
    assert q.read_text(encoding="utf-8") == f"{config.ADDED_HEADER}\nWAN_GW={ROUTER}\n"
    assert stat.S_IMODE(q.stat().st_mode) == 0o640


def test_writable_keys_follow_conf_keys(monkeypatch):
    monkeypatch.setitem(config.CONF_KEYS, "TV_NET", "tv_if")  # a key another change might add
    assert "TV_NET" in config.writable_keys()
    config.check_value("TV_NET", "10.10.10.0/24")


# ---- answers --------------------------------------------------------------------------------------------
def test_answers_file_is_the_conf_format():
    a = setup.parse_answers(
        f"# unattended\nSETUP_TV={MAC.upper()}\nSETUP_PAIR=no\nSETUP_APPLY=yes\nSETUP_SSDP=no\n"
        f"SETUP_WAIT=30\nWAN_GW={ROUTER}\nUPLINK=vpn\n"
    )
    assert (a.tv, a.pair, a.apply, a.ssdp, a.wait) == (MAC, "no", "yes", False, 30.0)
    assert a.conf == {"WAN_GW": ROUTER, "UPLINK": "vpn"}
    assert setup.parse_answers("").tv == "auto"


@pytest.mark.parametrize(
    "text",
    [
        "SETUP_TVV=auto\n",
        "SETUP_TV=the-big-one\n",
        "SETUP_PAIR=maybe\n",
        "SETUP_APPLY=always\n",
        "SETUP_SSDP=on\n",
        "SETUP_WAIT=-1\n",
        "SETUP_WAIT=99999\n",
        "WANIF=eth1\n",
        "WAN_GW=$(reboot)\n",
        "SETUP_TV=02:00:00:00:00:01\nTV_MAC=02:00:00:00:00:02\n",  # two different devices
    ],
)
def test_answers_file_refuses_typos_before_anything_runs(text):
    with pytest.raises(ValueError):
        setup.parse_answers(text)


def test_answers_tv_mac_names_the_tv_and_the_placeholder_names_none():
    a = setup.parse_answers(f"TV_MAC={OTHER_MAC.upper()}\n")
    assert a.tv == OTHER_MAC and a.conf["TV_MAC"] == OTHER_MAC  # it must match a device found
    a = setup.parse_answers(EXAMPLE)  # a copy of the template names no TV
    assert a.tv == "auto" and "TV_MAC" not in a.conf
    a = setup.parse_answers(f"SETUP_TV=configured\nTV_MAC={MAC}\n")
    assert a.tv == "configured" and a.conf["TV_MAC"] == MAC


# ---- the fake system ----------------------------------------------------------------------------------------
def lg_tv(mac=MAC, ip="10.10.10.12", hostname="LGwebOSTV"):
    return Candidate(
        ip=ip,
        mac=mac,
        hostname=hostname,
        vendor="LG",
        platform="webOS",
        profile="lg-webos",
        evidence=["DHCP lease"],
    )


class Fake:
    """A scripted gateway. `found` is a list of discovery results returned in turn (the last repeats)."""

    def __init__(self, tmp_path, found=None, side_up=True, root=True, can_pair=True, installed=False):
        self.tmp = tmp_path
        self.found = found if found is not None else [[lg_tv()]]
        self.side_up = side_up
        self.root = root
        self.can_pair_now = can_pair
        self.is_installed = installed
        self.calls: list[tuple] = []
        self.installer_rc = 0
        self.reading = TvReading(True, {"option.livePlus": "off"})
        self.result = Result(checks=[Check("ruleset", True), Check("resolver", True)])
        self.lock_held = False
        self.now = 0.0
        self.key = tmp_path / "state" / "lgtv-keys.sqlite"
        self.installs = 0
        self.pair_ready_after = 1  # installer runs after which the LAN-API library is there

    def env(self) -> setup.Env:
        def discover(iface, gw, ssdp):
            self.calls.append(("discover", iface, gw, ssdp))
            return self.found.pop(0) if len(self.found) > 1 else list(self.found[0])

        def run_installer(path, fd):
            assert self.lock_held, "the installer runs under the install lock"
            self.calls.append(("installer", path, fd))
            self.side_up = True
            self.is_installed = True
            self.installs += 1
            self.can_pair_now = self.can_pair_now or self.installs >= self.pair_ready_after
            return self.installer_rc

        def pair(ip, key):
            self.calls.append(("pair", ip, key))
            Path(key).parent.mkdir(parents=True, exist_ok=True)
            Path(key).write_text("key", encoding="utf-8")
            return self.reading

        @contextlib.contextmanager
        def lock():
            self.calls.append(("lock",))
            self.lock_held = True
            try:
                yield 42
            finally:
                self.lock_held = False

        def sleep(sec):
            self.calls.append(("sleep", sec))
            self.now += sec

        return setup.Env(
            discover=discover,
            tv_side_up=lambda iface, gw: self.side_up,
            run_installer=run_installer,
            can_pair=lambda key: self.can_pair_now,
            pair=pair,
            secure_key=lambda key: self.calls.append(("secure", key)),
            key_exists=lambda key: Path(key).exists(),
            verify=lambda s: self.calls.append(("verify", s.tv_ip)) or self.result,
            wan_route=lambda: ("wlan0", ROUTER),
            installed=lambda: self.is_installed,
            lock=lock,
            is_root=lambda: self.root,
            sleep=sleep,
            clock=lambda: self.now,
        )

    def names(self) -> list[str]:
        return [c[0] for c in self.calls]


def make(tmp_path, fake, answers="", replies=None, dry_run=False, unattended=None, conf_text=None):
    conf = tmp_path / "tvgw.conf"
    if conf_text is not None:
        conf.write_text(conf_text, encoding="utf-8")
    installer = tmp_path / "install.sh"
    installer.write_text("#!/bin/bash\n", encoding="utf-8")
    s = config.Settings(state_dir=str(tmp_path / "state"))
    out = io.StringIO()
    script = list(replies or [])

    def ask(prompt):
        out.write(prompt + "\n")
        if not script:
            raise EOFError
        return script.pop(0)

    if unattended is None:
        unattended = replies is None
    ui = setup.Prompter(out, ask=None if unattended else ask, unattended=unattended)
    st = setup.Setup(
        s,
        str(conf),
        fake.env(),
        ui,
        answers=setup.parse_answers(answers),
        dry_run=dry_run,
        installer=str(installer),
        template=EXAMPLE,
    )
    return st, out, conf


S = setup.Step


# ---- the flow -----------------------------------------------------------------------------------------------
def test_first_install_guided_path_runs_every_step_in_order(tmp_path):
    fake = Fake(tmp_path)
    (tmp_path / "state").mkdir()
    st, out, conf = make(tmp_path, fake, replies=["", "", "", "", "", "", ""])
    assert st.run() == 0, out.getvalue()
    assert st.trail == [
        S.PREFLIGHT,
        S.DISCOVER,
        S.PICK,
        S.SETTINGS,
        S.PAIR,
        S.WRITE,
        S.APPLY,
        S.PAIR_LATE,
        S.VERIFY,
        S.DONE,
    ]
    c = config.parse_conf(conf.read_text(encoding="utf-8"))
    assert (c["TV_MAC"], c["TV_IP"], c["TV_NAME"], c["PROFILE"], c["WAN_IF"], c["WAN_GW"]) == (
        MAC,
        "10.10.10.12",
        "lgwebostv",
        "lg-webos",
        "wlan0",
        ROUTER,
    )
    assert "# wired MAC of the TV" in conf.read_text(encoding="utf-8")  # the template's comments came along
    assert fake.names() == ["discover", "pair", "secure", "lock", "installer", "verify"]
    assert fake.calls[0][3] is True  # root and not a dry run: SSDP allowed
    text = out.getvalue()
    assert "not one of the TV's user agreements" in text and "leave" in text
    assert "Live Plus (LG's viewing-data collection) is off" in text
    assert "Result: the gateway holds. All 2 checks passed" in text
    assert "\x1b[" not in text  # no colour codes: a bare SSH terminal reads it as it is


def test_unattended_answers_run_asks_nothing_and_logs_each_decision(tmp_path):
    fake = Fake(tmp_path, found=[[lg_tv(), lg_tv(OTHER_MAC, "10.10.10.13")]])
    (tmp_path / "state").mkdir()
    st, out, conf = make(tmp_path, fake, answers=f"SETUP_TV={OTHER_MAC}\nSETUP_PAIR=no\nUPLINK=vpn\n")
    assert st.run() == 0, out.getvalue()
    c = config.parse_conf(conf.read_text(encoding="utf-8"))
    assert (c["TV_MAC"], c["TV_IP"], c["UPLINK"]) == (OTHER_MAC, "10.10.10.13", "vpn")
    assert "pair" not in fake.names() and "installer" in fake.names()
    assert "Write these changes" in out.getvalue() and "[Y/n]: yes" in out.getvalue()


def test_dry_run_prints_the_plan_and_changes_nothing(tmp_path):
    fake = Fake(tmp_path)
    st, out, conf = make(tmp_path, fake, answers="SETUP_PAIR=yes\n", dry_run=True, conf_text=EXAMPLE)
    assert st.run() == 0, out.getvalue()
    assert conf.read_text(encoding="utf-8") == EXAMPLE
    assert fake.names() == ["discover"]  # no pairing, no lock, no installer, no verify
    assert fake.calls[0][3] is False  # no SSDP: its firewall exemption is a change
    text = out.getvalue()
    assert f"+TV_MAC={MAC}" in text and "(dry run) would run" in text and "would pair with the TV" in text
    assert "Nothing was written" in text


def test_dry_run_works_without_root_and_a_real_run_refuses(tmp_path):
    fake = Fake(tmp_path, root=False)
    st, out, _ = make(tmp_path, fake, dry_run=True)
    assert st.run() == 0 and "not running as root" in out.getvalue()
    st, out, conf = make(tmp_path, Fake(tmp_path, root=False))
    assert st.run() == 1
    assert "needs root: run `sudo tvgw setup`" in out.getvalue() and not conf.exists()


def test_rerun_with_nothing_new_writes_nothing_and_installs_nothing(tmp_path):
    fake = Fake(tmp_path, installed=True)
    (tmp_path / "state").mkdir()
    first, out, conf = make(tmp_path, fake, answers="SETUP_PAIR=yes\n")
    assert first.run() == 0, out.getvalue()
    written = conf.read_bytes()
    fake.calls.clear()
    again, out, _ = make(tmp_path, fake)
    assert again.run() == 0, out.getvalue()
    assert conf.read_bytes() == written
    assert again.plan.changes == {} and "installer" not in fake.names()
    assert "already holds these settings" in out.getvalue()
    assert "already paired" in out.getvalue() and ("pair" in fake.names())  # a read-only check, no prompt
    assert "accept the connection prompt" not in out.getvalue()


def test_the_same_tv_keeps_its_pinned_address_and_name(tmp_path):
    conf_text = config.update_conf(
        EXAMPLE, {"TV_MAC": MAC, "TV_IP": "10.10.10.17", "TV_NAME": "lounge", "WAN_GW": ROUTER}
    )
    fake = Fake(tmp_path, found=[[lg_tv(ip="10.10.10.12")]], installed=True)
    st, out, conf = make(tmp_path, fake, answers="SETUP_PAIR=no\n", conf_text=conf_text)
    assert st.run() == 0, out.getvalue()
    assert st.plan.changes == {}
    assert conf.read_text(encoding="utf-8") == conf_text


def test_a_tv_side_that_is_down_is_brought_up_by_the_installer_first(tmp_path):
    fake = Fake(tmp_path, found=[[], [lg_tv()]], side_up=False, can_pair=False)
    fake.pair_ready_after = 2  # the bring-up run stops before the package step
    st, out, _ = make(tmp_path, fake, answers="SETUP_PAIR=yes\n")
    assert st.run() == 0, out.getvalue()
    assert st.trail[:5] == [S.PREFLIGHT, S.DISCOVER, S.BRING_UP, S.DISCOVER, S.PICK]
    assert fake.names().count("installer") == 2  # bring-up, then the real apply
    assert "TV not identified" in out.getvalue()
    # pairing could not run before the install (no library, no state dir), so it ran after it
    names = fake.names()
    assert names.index("pair") > len(names) - 1 - names[::-1].index("installer")
    assert "pairing follows the install" in out.getvalue()


def test_bring_up_in_a_dry_run_stops_without_running_anything(tmp_path):
    fake = Fake(tmp_path, found=[[]], side_up=False)
    st, out, conf = make(tmp_path, fake, dry_run=True)
    assert st.run() == 0
    text = out.getvalue()
    assert "would run" in text and "installer" not in fake.names() and not conf.exists()
    assert "the plan goes on without it" in text and "no TV identified yet; pairing skipped" in text
    assert f"+WAN_GW={ROUTER}" in text


def test_a_tv_side_still_down_after_bring_up_is_a_stop(tmp_path):
    fake = Fake(tmp_path, found=[[]], side_up=False)
    orig = fake.env

    def env():
        e = orig()
        e.tv_side_up = lambda iface, gw: False
        return e

    fake.env = env
    st, out, _ = make(tmp_path, fake)
    assert st.run() == 1 and "still does not carry" in out.getvalue()


def test_unattended_discovery_retries_until_the_wait_runs_out(tmp_path):
    fake = Fake(tmp_path, found=[[]])
    st, out, conf = make(tmp_path, fake, answers="SETUP_WAIT=30\n")
    assert st.run() == 1
    assert fake.names().count("sleep") == 3 and "no TV found and none configured" in out.getvalue()
    assert not conf.exists()


def test_nothing_found_falls_back_to_the_configured_tv(tmp_path):
    conf_text = config.update_conf(EXAMPLE, {"TV_MAC": MAC, "WAN_GW": ROUTER})
    fake = Fake(tmp_path, found=[[]], installed=True)
    st, out, _ = make(tmp_path, fake, answers="SETUP_WAIT=0\nSETUP_PAIR=no\n", conf_text=conf_text)
    assert st.run() == 0, out.getvalue()
    assert "keeping the TV the settings already name" in out.getvalue()


def test_interactive_nothing_found_asks_to_look_again(tmp_path):
    fake = Fake(tmp_path, found=[[], [lg_tv()]])
    (tmp_path / "state").mkdir()
    st, out, _ = make(tmp_path, fake, replies=["", "", "", "", "", "", "", "", ""])
    assert st.run() == 0, out.getvalue()
    assert st.trail[:3] == [S.PREFLIGHT, S.DISCOVER, S.DISCOVER]


def test_configured_mode_skips_discovery(tmp_path):
    fake = Fake(tmp_path)
    st, out, conf = make(
        tmp_path, fake, answers=f"SETUP_TV=configured\nTV_MAC={MAC}\nTV_IP=10.10.10.12\nSETUP_PAIR=no\n"
    )
    assert st.run() == 0, out.getvalue()
    assert (
        "discover" not in fake.names()
        and config.parse_conf(conf.read_text(encoding="utf-8"))["TV_MAC"] == MAC
    )


def test_configured_mode_needs_a_configured_tv(tmp_path):
    st, out, _ = make(tmp_path, Fake(tmp_path), answers="SETUP_TV=configured\n")
    assert st.run() == 1 and "name a TV" in out.getvalue()


def test_several_candidates_unattended_need_setup_tv(tmp_path):
    phone = Candidate(ip="10.10.10.14", mac=OTHER_MAC, hostname="phone")
    two_tvs = [[lg_tv(), lg_tv(OTHER_MAC, "10.10.10.13")]]
    st, out, conf = make(tmp_path, Fake(tmp_path, found=two_tvs))
    assert st.run() == 1 and "SETUP_TV=" in out.getvalue() and not conf.exists()
    # one TV among other devices is not ambiguous
    (tmp_path / "state").mkdir()
    st, out, conf = make(tmp_path, Fake(tmp_path, found=[[phone, lg_tv()]]), answers="SETUP_PAIR=no\n")
    assert st.run() == 0 and config.parse_conf(conf.read_text(encoding="utf-8"))["TV_MAC"] == MAC


def test_setup_tv_that_is_not_found_retries_then_stops(tmp_path):
    st, out, _ = make(tmp_path, Fake(tmp_path), answers=f"SETUP_TV={OTHER_MAC}\nSETUP_WAIT=10\n")
    assert st.run() == 1 and f"SETUP_TV={OTHER_MAC} is not among the devices found" in out.getvalue()


def test_a_candidate_without_a_mac_is_not_written(tmp_path):
    nomac = lg_tv(mac="")
    st, out, conf = make(tmp_path, Fake(tmp_path, found=[[nomac]]), answers="SETUP_WAIT=0\n")
    assert st.run() == 1 and "no MAC address" in out.getvalue() and not conf.exists()


def test_the_owner_picks_from_a_numbered_list_and_a_bad_number_is_asked_again(tmp_path):
    fake = Fake(tmp_path, found=[[lg_tv(), lg_tv(OTHER_MAC, "10.10.10.13")]])
    (tmp_path / "state").mkdir()
    st, out, conf = make(tmp_path, fake, replies=["7", "2", "", "", "", "", "", ""])
    assert st.run() == 0, out.getvalue()
    assert "a number from 1 to 2" in out.getvalue()
    assert config.parse_conf(conf.read_text(encoding="utf-8"))["TV_MAC"] == OTHER_MAC


def test_a_bad_answer_to_a_settings_question_is_asked_again(tmp_path):
    fake = Fake(tmp_path)
    (tmp_path / "state").mkdir()
    # name, WAN_IF (the TV side is refused), WAN_GW (not an address), then defaults
    st, out, conf = make(
        tmp_path, fake, replies=["", "my tv", "lounge", "eth0", "eth1", "router", "198.51.100.1", "n", "", ""]
    )
    assert st.run() == 0, out.getvalue()
    text = out.getvalue()
    assert "TV_NAME='my tv'" in text and "is the TV side" in text and "not an IPv4 address" in text
    c = config.parse_conf(conf.read_text(encoding="utf-8"))
    assert (c["TV_NAME"], c["WAN_IF"], c["WAN_GW"]) == ("lounge", "eth1", "198.51.100.1")


def test_declining_the_write_writes_nothing(tmp_path):
    fake = Fake(tmp_path)
    (tmp_path / "state").mkdir()
    # pick, name, WAN_IF, WAN_GW, pair, then "n" to the write
    st, out, conf = make(tmp_path, fake, replies=["", "", "", "", "", "n"])
    assert st.run() == 1 and not conf.exists() and "installer" not in fake.names()
    assert "tvgw setup: nothing written" in out.getvalue() and "end of input" not in out.getvalue()


def test_a_refused_answer_stops_before_anything_is_written(tmp_path):
    fake = Fake(tmp_path)
    st, out, conf = make(tmp_path, fake, answers="SETUP_PAIR=no\nBLOCK_QUIC=Yes\n")
    assert st.run() == 1
    assert "refused, nothing written" in out.getvalue() and not conf.exists() and "lock" not in fake.names()


def test_pairing_is_skipped_for_a_tv_without_a_lan_api_reader(tmp_path):
    """The template says PROFILE=lg-webos; a Roku picked under it must not be paired with as an LG."""
    roku = Candidate(ip="10.10.10.12", mac=MAC, hostname="Roku-1", vendor="Roku", platform="Roku OS")
    fake = Fake(tmp_path, found=[[roku]])
    (tmp_path / "state").mkdir()
    st, out, conf = make(tmp_path, fake)
    assert st.run() == 0, out.getvalue()
    assert "no LAN-API reader for this TV (profile none)" in out.getvalue() and "pair" not in fake.names()
    assert "no bundled profile matches this device" in out.getvalue()
    assert config.parse_conf(conf.read_text(encoding="utf-8"))["PROFILE"] == "lg-webos"  # left as it was


def test_setup_pair_no_skips_pairing(tmp_path):
    fake = Fake(tmp_path)
    (tmp_path / "state").mkdir()
    st, out, _ = make(tmp_path, fake, answers="SETUP_PAIR=no\n")
    assert (
        st.run() == 0 and "pairing skipped (SETUP_PAIR=no)" in out.getvalue() and "pair" not in fake.names()
    )


def test_live_plus_on_is_said_plainly_and_never_with_an_agreement(tmp_path):
    fake = Fake(tmp_path)
    fake.reading = TvReading(True, {"option.livePlus": "on"})
    (tmp_path / "state").mkdir()
    st, out, _ = make(tmp_path, fake, answers="SETUP_PAIR=yes\n")
    assert st.run() == 0
    text = out.getvalue()
    assert "Live Plus (LG's viewing-data collection) is ON" in text and "Turn it off" in text
    assert "accept the" not in text.replace("accept the connection prompt", "").replace(
        "accept that one prompt", ""
    )


def test_an_unreachable_tv_does_not_stop_setup(tmp_path):
    fake = Fake(tmp_path)
    fake.reading = TvReading(False, error="TimeoutError")
    (tmp_path / "state").mkdir()
    st, out, _ = make(tmp_path, fake, answers="SETUP_PAIR=yes\n")
    assert st.run() == 0 and "did not answer over its LAN API (TimeoutError)" in out.getvalue()


def test_a_failed_check_is_a_plain_not_done_and_exit_1(tmp_path):
    fake = Fake(tmp_path)
    fake.result = Result(
        checks=[Check("ruleset", True), Check("resolver", False, "no answer from 10.10.10.1")]
    )
    (tmp_path / "state").mkdir()
    st, out, _ = make(tmp_path, fake)
    assert st.run() == 1
    assert (
        "FAIL resolver: no answer" in out.getvalue()
        and "Result: NOT done. 1 of 2 checks failed" in out.getvalue()
    )


def test_a_failed_installer_is_exit_1_even_when_verify_passes(tmp_path):
    fake = Fake(tmp_path)
    fake.installer_rc = 3
    (tmp_path / "state").mkdir()
    st, out, _ = make(tmp_path, fake)
    assert st.run() == 1 and "the installer stopped (exit 3)" in out.getvalue()
    assert "the installer exited 3" in out.getvalue()


def test_the_template_as_answers_file_writes_the_device_picked(tmp_path):
    """A copy of the shipped template names no TV: its placeholder MAC and example TV_IP must not
    replace the device discovery picked."""
    fake = Fake(tmp_path)
    st, out, conf = make(tmp_path, fake, answers=EXAMPLE + "\nSETUP_PAIR=no\n")
    assert st.run() == 0, out.getvalue()
    c = config.parse_conf(conf.read_text(encoding="utf-8"))
    assert (c["TV_MAC"], c["TV_IP"]) == (MAC, "10.10.10.12")
    assert "TV_IP=10.10.10.17 in the answers is not used" in out.getvalue()


def test_an_answers_mac_that_is_not_found_is_never_paired_with_another_devices_address(tmp_path):
    """TV_MAC=X with only device Y found: not a guess of Y, and never X beside Y's lease address."""
    fake = Fake(tmp_path)
    st, out, conf = make(tmp_path, fake, answers=f"TV_MAC={OTHER_MAC}\nSETUP_PAIR=no\nSETUP_WAIT=0\n")
    assert st.run() == 1 and not conf.exists() and "lock" not in fake.names()
    assert f"SETUP_TV={OTHER_MAC} is not among the devices found" in out.getvalue()


def test_an_answers_mac_that_differs_from_the_device_picked_is_refused(tmp_path):
    fake = Fake(tmp_path)
    answers = f"SETUP_TV=10.10.10.12\nTV_MAC={OTHER_MAC}\nSETUP_PAIR=no\n"
    st, out, conf = make(tmp_path, fake, answers=answers)
    assert st.run() == 1 and not conf.exists()
    assert f"the answers say TV_MAC={OTHER_MAC}, but the TV picked is {MAC}" in out.getvalue()


def test_an_answers_mac_and_address_for_the_tv_found_pin_that_address(tmp_path):
    fake = Fake(tmp_path)
    st, out, conf = make(tmp_path, fake, answers=f"TV_MAC={MAC}\nTV_IP=10.10.10.17\nSETUP_PAIR=no\n")
    assert st.run() == 0, out.getvalue()
    c = config.parse_conf(conf.read_text(encoding="utf-8"))
    assert (c["TV_MAC"], c["TV_IP"]) == (MAC, "10.10.10.17")


def test_an_answers_address_without_a_tv_does_not_move_the_configured_tv(tmp_path):
    conf_text = config.update_conf(EXAMPLE, {"TV_MAC": MAC, "TV_IP": "10.10.10.12", "WAN_GW": ROUTER})
    fake = Fake(tmp_path, installed=True)
    answers = "SETUP_TV=configured\nTV_IP=10.10.10.30\nSETUP_PAIR=no\n"
    st, out, conf = make(tmp_path, fake, answers=answers, conf_text=conf_text)
    assert st.run() == 0, out.getvalue()
    assert conf.read_text(encoding="utf-8") == conf_text and "they name no TV" in out.getvalue()


def test_setup_apply_no_never_runs_the_installer_to_bring_the_tv_side_up(tmp_path):
    fake = Fake(tmp_path, found=[[]], side_up=False)
    st, out, conf = make(tmp_path, fake, answers="SETUP_APPLY=no\nSETUP_PAIR=no\n")
    assert st.run() == 1 and "installer" not in fake.names() and "lock" not in fake.names()
    assert "the TV side is not up and SETUP_APPLY=no; nothing was installed" in out.getvalue()
    assert not conf.exists() and "the gateway holds" not in out.getvalue()
    # a TV the answers already name: the settings are written, still with no installer
    fake = Fake(tmp_path, found=[[]], side_up=False)
    answers = f"SETUP_APPLY=no\nSETUP_PAIR=no\nSETUP_TV=configured\nTV_MAC={MAC}\nTV_IP=10.10.10.12\n"
    st, out, conf = make(tmp_path, fake, answers=answers)
    assert st.run() == 0, out.getvalue()
    assert "installer" not in fake.names() and "apply them later" in out.getvalue()


def test_unattended_auto_pairs_only_with_a_key_and_yes_pairs(tmp_path):
    """Unattended, nobody may be at the TV: SETUP_PAIR=auto never puts a prompt on it; yes does."""
    fake = Fake(tmp_path)
    (tmp_path / "state").mkdir()
    st, out, _ = make(tmp_path, fake)
    assert st.run() == 0, out.getvalue()
    assert "pair" not in fake.names() and "SETUP_PAIR=yes pairs unattended" in out.getvalue()
    fake = Fake(tmp_path)
    st, out, _ = make(tmp_path, fake, answers="SETUP_PAIR=yes\n")
    assert st.run() == 0, out.getvalue()
    assert "pair" in fake.names() and "pairing (SETUP_PAIR=yes)" in out.getvalue()
    assert "Pair the TV's LAN API now?" not in out.getvalue()  # yes is not asked


def test_interactive_setup_tv_not_found_falls_back_to_the_list(tmp_path):
    fake = Fake(tmp_path)
    (tmp_path / "state").mkdir()
    st, out, conf = make(tmp_path, fake, answers=f"SETUP_TV={OTHER_MAC}\n", replies=[""] * 8)
    assert st.run() == 0, out.getvalue()
    assert f"SETUP_TV={OTHER_MAC} is not among them" in out.getvalue()
    assert config.parse_conf(conf.read_text(encoding="utf-8"))["TV_MAC"] == MAC


def test_pairing_that_still_cannot_run_after_the_install_says_so(tmp_path):
    fake = Fake(tmp_path, can_pair=False)
    fake.pair_ready_after = 99  # the library never arrives
    st, out, _ = make(tmp_path, fake, replies=[""] * 8)
    assert st.run() == 0, out.getvalue()
    assert "pairing still cannot run" in out.getvalue() and "pair" not in fake.names()


def test_a_rerun_keeps_the_profile_of_the_same_tv(tmp_path):
    """The owner's own profile (a TOML path) is not replaced by the bundled one discovery matched."""
    conf_text = config.update_conf(
        EXAMPLE, {"TV_MAC": MAC, "TV_IP": "10.10.10.12", "PROFILE": "/etc/tvgw/my-tv.toml", "WAN_GW": ROUTER}
    )
    fake = Fake(tmp_path, installed=True)
    st, out, _ = make(tmp_path, fake, answers="SETUP_PAIR=no\n", conf_text=conf_text)
    assert st.run() == 0, out.getvalue()
    assert "PROFILE" not in st.plan.changes and st.plan.changes == {}


def test_an_installed_gateway_keeps_its_uplink_when_the_default_route_moves(tmp_path):
    """On an installed gateway WAN_IF=wlan0 is the owner's even though the template says wlan0 too."""
    conf_text = config.update_conf(EXAMPLE, {"TV_MAC": MAC, "TV_IP": "10.10.10.12", "WAN_GW": ROUTER})
    fake = Fake(tmp_path, installed=True)
    st, out, conf = make(tmp_path, fake, answers="SETUP_PAIR=no\n", conf_text=conf_text)
    st.env.wan_route = lambda: ("eth1", "198.51.100.1")
    assert st.run() == 0, out.getvalue()
    assert st.plan.changes == {} and conf.read_text(encoding="utf-8") == conf_text


def test_a_new_uplink_interface_takes_its_router_from_the_route_too(tmp_path):
    """Not installed yet, the route says eth1: WAN_IF moves, and the old router must not stay beside it."""
    conf_text = config.update_conf(EXAMPLE, {"WAN_GW": ROUTER})
    fake = Fake(tmp_path)
    st, out, _ = make(tmp_path, fake, answers="SETUP_PAIR=no\n", conf_text=conf_text)
    st.env.wan_route = lambda: ("eth1", "198.51.100.1")
    assert st.run() == 0, out.getvalue()
    assert (st.plan.changes["WAN_IF"], st.plan.changes["WAN_GW"]) == ("eth1", "198.51.100.1")


def test_a_new_uplink_typed_by_the_owner_flags_the_old_router(tmp_path):
    conf_text = config.update_conf(EXAMPLE, {"WAN_GW": ROUTER})
    fake = Fake(tmp_path)
    (tmp_path / "state").mkdir()
    st, out, _ = make(tmp_path, fake, replies=["", "", "eth1", "", "n", "", ""], conf_text=conf_text)
    assert st.run() == 0, out.getvalue()
    assert "WAN_GW in the file is the router of wlan0: check it" in out.getvalue()


def test_apply_no_writes_the_settings_and_leaves_the_install(tmp_path):
    fake = Fake(tmp_path)
    (tmp_path / "state").mkdir()
    st, out, conf = make(tmp_path, fake, answers="SETUP_APPLY=no\nSETUP_PAIR=no\n")
    assert st.run() == 0 and conf.exists() and "installer" not in fake.names()
    assert "apply them later" in out.getvalue()


def test_end_of_input_and_interrupt_stop_cleanly(tmp_path):
    st, out, conf = make(tmp_path, Fake(tmp_path), replies=[])
    assert st.run() == 1 and "end of input" in out.getvalue() and not conf.exists()

    def boom(iface, gw, ssdp):
        raise KeyboardInterrupt

    st, out, conf = make(tmp_path, Fake(tmp_path))
    st.env.discover = boom
    assert st.run() == 130 and "nothing was written" in out.getvalue()


def test_missing_installer_stops_before_the_write(tmp_path):
    fake = Fake(tmp_path)
    (tmp_path / "state").mkdir()
    st, out, conf = make(tmp_path, fake, answers="SETUP_PAIR=no\n")
    st.installer = None
    st.answers.installer = str(tmp_path / "nope.sh")
    assert st.run() == 1 and "install.sh not found" in out.getvalue() and not conf.exists()


# ---- the live helpers ----------------------------------------------------------------------------------------
def test_default_route_skips_tunnels_and_the_tv_side():
    routes = (
        '[{"dst":"default","dev":"tun0","gateway":"198.51.100.9"},'
        '{"dst":"default","dev":"eth0","gateway":"10.10.10.1"},'
        f'{{"dst":"default","gateway":"{ROUTER}","dev":"wlan0","protocol":"dhcp"}}]'
    )
    assert setup.default_route(lambda cmd: routes) == ("wlan0", ROUTER)
    assert setup.default_route(lambda cmd: "") == ("", "")
    assert setup.default_route(lambda cmd: "not json") == ("", "")


def test_tv_side_is_up_reads_the_interface_addresses():
    up = '[{"ifname":"eth0","addr_info":[{"family":"inet","local":"10.10.10.1","prefixlen":24}]}]'
    assert setup.tv_side_is_up("eth0", "10.10.10.1", lambda cmd: up)
    assert not setup.tv_side_is_up("eth0", "10.10.10.1", lambda cmd: '[{"ifname":"eth0","addr_info":[]}]')
    assert not setup.tv_side_is_up("eth0", "10.10.10.1", lambda cmd: "")


def test_install_lock_is_exclusive(tmp_path):
    path = str(tmp_path / "run" / "install.lock")
    with setup.install_lock(path) as fd:
        assert fd >= 0
        with (
            pytest.raises(setup.SetupError, match="another install"),
            setup.install_lock(path, wait=0, say=lambda m: None),
        ):
            pass
    with setup.install_lock(path, wait=0):
        pass  # released


def test_run_installer_hands_the_lock_down_as_fd_8_with_no_terminal(tmp_path):
    script = tmp_path / "install.sh"
    marker = tmp_path / "ran"
    script.write_text(
        "#!/bin/bash\n"
        f'[ "$TVGW_INSTALL_LOCKED" = 1 ] && [ "$PYTHONUTF8" = 1 ] && [ ! -t 0 ] && {{ : >&8; }} 2>/dev/null '
        f'&& [ "$PWD" = "{tmp_path}" ] && echo ok > {marker}\n'
        "exit 4\n",
        encoding="utf-8",
    )
    with setup.install_lock(str(tmp_path / "install.lock")) as fd:
        assert setup.run_installer(str(script), fd) == 4
    assert marker.read_text(encoding="utf-8").strip() == "ok"
    assert setup.run_installer(str(script), None) == 4  # unlocked: no fd 8, no marker update needed


def test_find_installer_prefers_the_checkout_this_code_runs_from(tmp_path):
    assert setup.find_installer() == str(ROOT / "deploy" / "install.sh")
    assert setup.find_installer(str(tmp_path / "nope")) is None


def test_pair_without_the_library_says_so(monkeypatch, tmp_path):
    monkeypatch.setattr(setup.importlib.util, "find_spec", lambda name: None)
    monkeypatch.setattr(setup, "VENV_PYTHONS", (str(tmp_path / "none"),))
    r = setup.pair("10.10.10.12", str(tmp_path / "k"))
    assert not r.reachable and "not installed" in r.error
    assert not setup.can_pair(str(tmp_path / "k"))


# ---- the command --------------------------------------------------------------------------------------------
def test_tvgw_setup_dry_run_from_the_command_line(tmp_path, monkeypatch, capsys):
    conf = tmp_path / "tvgw.conf"
    conf.write_text(EXAMPLE, encoding="utf-8")
    fake = Fake(tmp_path)
    monkeypatch.setattr(setup, "live_env", lambda s: fake.env())
    assert cli.main(["--conf", str(conf), "setup", "--dry-run", "--yes"]) == 0
    out = capsys.readouterr().out
    assert f"+TV_MAC={MAC}" in out and conf.read_text(encoding="utf-8") == EXAMPLE


def test_tvgw_setup_without_a_terminal_or_yes_says_how_to_run_unattended(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert cli.main(["--conf", str(tmp_path / "c"), "setup"]) == 1
    assert "--answers FILE --yes" in capsys.readouterr().out


def test_tvgw_setup_refuses_a_bad_answers_file(tmp_path, capsys):
    ans = tmp_path / "answers.conf"
    ans.write_text("SETUP_TV=which\n", encoding="utf-8")
    assert cli.main(["--conf", str(tmp_path / "c"), "setup", "--answers", str(ans), "--yes"]) == 1
    assert "answers file" in capsys.readouterr().out


def test_python_m_tvgw_runs_the_cli():
    p = subprocess.run(
        [sys.executable, "-m", "tvgw", "--version"],
        capture_output=True,
        encoding="utf-8",
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        check=False,
    )
    assert p.returncode == 0 and p.stdout.startswith("tvgw")


def test_live_env_wires_every_field_to_a_callable():
    env = setup.live_env(config.Settings())
    for f in dataclasses.fields(setup.Env):
        assert callable(getattr(env, f.name)), f.name
    assert env.installed() in (True, False) and env.is_root() in (True, False)


def fake_venv(tmp_path, body: str) -> str:
    """A stand-in for the gateway's virtualenv Python: a shell script that checks how it was run."""
    py = tmp_path / "venv-python"
    py.write_text(
        "#!/bin/sh\n"
        # always isolated and run from /; the pairing call (-I -c CODE ip key timeout) also under umask 077
        '[ "$1" = "-I" ] && [ "$(pwd)" = "/" ] && { [ $# -lt 4 ] || [ "$(umask)" = "0077" ]; } || '
        '{ echo \'{"reachable": false, "values": {}, "error": "unsafe"}\'; exit 3; }\n' + body,
        encoding="utf-8",
    )
    py.chmod(0o755)
    return str(py)


def test_pair_through_the_venv_is_isolated_and_creates_the_key_private(monkeypatch, tmp_path):
    """-I and cwd=/ keep a planted json.py out of a root Python; umask 077 makes the key 600 from birth."""
    monkeypatch.setattr(setup.importlib.util, "find_spec", lambda name: None)
    key = tmp_path / "state" / "lgtv-keys.sqlite"
    py = fake_venv(
        tmp_path,
        f': > "{key}"\necho noise\n'
        'echo \'{"reachable": true, "values": {"option.livePlus": "off"}, "error": null}\'\n',
    )
    monkeypatch.setattr(setup, "VENV_PYTHONS", (py,))
    (tmp_path / "state").mkdir()
    before = os.umask(0o022)
    try:
        r = setup.pair("10.10.10.12", str(key))
        assert os.umask(0o022) == 0o022  # restored after the reading
    finally:
        os.umask(before)
    assert r.reachable and r.acr_off is True, r.error
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert setup.can_pair(str(key))  # the probe runs the same way and exits 0


def test_pair_through_the_venv_reports_garbage_as_unreachable(monkeypatch, tmp_path):
    monkeypatch.setattr(setup.importlib.util, "find_spec", lambda name: None)
    monkeypatch.setattr(setup, "VENV_PYTHONS", (fake_venv(tmp_path, "echo not json\n"),))
    r = setup.pair("10.10.10.12", str(tmp_path / "k"))
    assert not r.reachable and r.error == "JSONDecodeError"


def test_python_m_tvgw_names_the_package_a_missing_module_needs(monkeypatch):
    import runpy

    def main():
        raise ModuleNotFoundError("No module named 'yaml'", name="yaml")

    monkeypatch.setattr(cli, "main", main)
    with pytest.raises(SystemExit) as e:
        runpy.run_module("tvgw.__main__", run_name="__main__")
    assert "sudo apt install python3-yaml" in str(e.value.code)


def test_unattended_never_takes_the_templates_example_router(tmp_path):
    """No default route to read (the Pi has no uplink yet): the template's 192.168.1.1 is a guess, and
    an unattended run stops rather than install it."""
    fake = Fake(tmp_path)
    st, out, conf = make(tmp_path, fake, answers="SETUP_PAIR=no\n")
    st.env.wan_route = lambda: ("", "")
    assert st.run() == 1 and "WAN_IF and WAN_GW: no default route" in out.getvalue() and not conf.exists()
    (tmp_path / "state").mkdir()
    st, out, conf = make(tmp_path, Fake(tmp_path), answers=f"SETUP_PAIR=no\nWAN_IF=eth1\nWAN_GW={ROUTER}\n")
    st.env.wan_route = lambda: ("", "")
    assert st.run() == 0, out.getvalue()
