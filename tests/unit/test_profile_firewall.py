"""(ports) A profile's [firewall] table: the clock port its TV gets (design decision 71).

`ntp` is one of any, resolved and none, and any when the table or the key is absent, as every bundled
profile has it today; the LG profile says so outright, where the decision will be taken. tvgw-apply reads
it through `tvgw profile --firewall`, which prints the keys and nothing else."""

from __future__ import annotations

import pytest

from tvgw import cli, profile

BASE = '[profile]\nname = "plain"\n'


def test_the_clock_port_is_any_unless_the_profile_says_otherwise():
    assert profile.from_dict({"profile": {"name": "plain"}}).ntp == "any"
    assert profile.NTP_POLICIES[0] == "any"
    for value in profile.NTP_POLICIES:
        assert profile.from_dict({"firewall": {"ntp": value}}).ntp == value


@pytest.mark.parametrize(
    ("table", "said"),
    [
        ({"ntp": "None"}, "firewall.ntp"),
        ({"ntp": "off"}, "firewall.ntp"),
        ({"ntp": ["none"]}, "firewall.ntp"),
        ({"nntp": "none"}, "firewall.nntp: unknown key"),  # a misspelt key would read as any
        ("none", "firewall: expected a [firewall] table"),
    ],
)
def test_a_value_or_a_key_it_does_not_know_is_refused_at_load(table, said):
    with pytest.raises(ValueError, match=said.replace("[", r"\[").replace("]", r"\]")):
        profile.from_dict({"firewall": table})


def test_every_bundled_profile_keeps_the_port_open_and_the_lg_profile_says_so():
    """This package builds the narrowing and switches it on nowhere: the LG profile's decision waits for
    the NTP count's two weeks on the reference gateway."""
    for name in ("lg-webos", "generic-tv", "samsung-tizen", "roku", "vizio-smartcast"):
        assert profile.load(name).ntp == "any", name
    text = (profile.resources.files("tvgw.profiles") / "lg-webos.toml").read_text(encoding="utf-8")
    assert '\n[firewall]\nntp = "any"\n' in text


def test_tvgw_profile_firewall_prints_the_keys_and_nothing_else(tmp_path, capsys):
    f = tmp_path / "closed.toml"
    f.write_text(BASE + '[firewall]\nntp = "none"\n', encoding="utf-8")
    f.with_suffix(".rules").write_text("", encoding="utf-8")
    conf = str(tmp_path / "none.conf")
    assert cli.main(["--conf", conf, "profile", "--profile", str(f), "--firewall"]) == 0
    assert capsys.readouterr().out == "ntp=none\n"
    assert cli.main(["--conf", conf, "profile", "--profile", "lg-webos", "--firewall"]) == 0
    assert capsys.readouterr().out == "ntp=any\n"
    assert cli.main(["--conf", conf, "profile", "--profile", "lg-webos"]) == 0
    assert "clock port (NTP, [firewall] ntp): any" in capsys.readouterr().out
