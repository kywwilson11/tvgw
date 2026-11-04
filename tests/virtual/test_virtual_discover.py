"""(profile) Design decision 62's acceptance on a kernel: a TV that answers only Roku's LAN-API port is
found by discovery's own probes and is never given the LG profile.

The TV namespace serves TCP 8060, the one port of Roku's discovery row, on its address; its other
listener, 8000, is the unsolicited-inbound row's and in no discovery row. Its lease names no host. The
gateway namespace runs the general profile's scenario of matrix.txt, as a first install from the
template does, and `discover.gather` runs inside it: the real neighbour table and the real TCP probe
across the veth, through the loaded firewall, with no SSDP search (a dry run makes none either). What it
finds is handed to `tvgw setup` in a dry run. Unattended, setup plans the general profile; guided, it
asks the brand question once and plans the answer. No path plans lg-webos, not even over a settings
file that says lg-webos for no TV, as the 0.2.0 template did."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest
import vnet

from tvgw import config, discover, setup

pytestmark = pytest.mark.virtual

ROKU_PORT = 8060  # the one port of Roku's row in discover.PORT_SIGNATURES
GENERIC = next(s for s in vnet.parse_matrix(vnet.MATRIX.read_text(encoding="utf-8")) if s.name == "generic")
EXAMPLE = (vnet.ROOT / "deploy" / "tvgw.conf.example").read_text(encoding="utf-8")
# runs inside the gateway namespace with `python -I`: this checkout's tvgw, the live sources, the leases
# and the gateway's TV port
GATHER = (
    "import dataclasses, json, sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "from tvgw import discover\n"
    "found = discover.gather(sys.argv[4], sys.argv[2], leases_path=sys.argv[3], with_ssdp=False)\n"
    "print(json.dumps([dataclasses.asdict(c) for c in found]))\n"
)


@pytest.fixture(scope="module")
def found(net) -> list[discover.Candidate]:
    """What discovery finds of the TV from inside the gateway, with the general profile's firewall
    loaded. The next module applies what it needs, as this one does."""
    out = net.apply(net.gw, vnet.render_conf(GENERIC.settings))
    net.save("discover/apply.log", out.stdout + out.stderr)
    assert out.returncode == 0, out.stderr
    assert net.reply_dev() == vnet.TV_IF  # the apply put the TV subnet in table 100 (design decision 49)
    net.serve(net.tv, ["--bind", vnet.TV_IP, "--tcp", str(ROKU_PORT)])
    mac = json.loads(net.ns(net.tv, "ip", "-j", "link", "show", vnet.TV_END).stdout)[0]["address"]
    leases = net.sandbox / "dnsmasq.leases"
    leases.write_text(f"0 {mac} {vnet.TV_IP} * *\n", encoding="utf-8")
    got = net.ns(
        net.gw,
        sys.executable,
        "-I",
        "-c",
        GATHER,
        str(vnet.ROOT / "src"),
        vnet.GW_TV,
        str(leases),
        vnet.TV_IF,
    )
    # the neighbour table may also hold the TV's other addresses, from the matrix's alias probes
    return [discover.Candidate(**c) for c in json.loads(got.stdout) if c["ip"] == vnet.TV_IP]


def dry_run(
    tmp_path: Path, found: list[discover.Candidate], brand: str | None = None, conf_text: str | None = None
) -> tuple[setup.Setup, str]:
    """`tvgw setup --dry-run` over what the namespace discovery found: unattended when `brand` is None,
    else guided, answering the brand question with `brand` and every other question with its default."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    out = io.StringIO()

    def ask(prompt: str) -> str:
        out.write(prompt + "\n")
        return brand if "Is it?" in prompt else ""

    def never(*_args):
        raise AssertionError("a dry run only discovers")

    env = setup.Env(
        discover=lambda iface, gw_ip, ssdp: list(found),
        tv_side_up=lambda iface, gw_ip: True,
        run_installer=never,
        can_pair=lambda key: False,
        pair=never,
        secure_key=never,
        key_exists=lambda key: False,
        verify=never,
        wan_route=lambda: (vnet.WAN_IF, vnet.WAN_GW),
        installed=lambda: False,
        lock=never,
        is_root=lambda: True,
    )
    conf = tmp_path / "tvgw.conf"
    if conf_text is not None:
        conf.write_text(conf_text, encoding="utf-8")
    installer = tmp_path / "install.sh"
    installer.write_text("#!/bin/bash\n", encoding="utf-8")
    ui = setup.Prompter(out, ask=None if brand is None else ask, unattended=brand is None)
    st = setup.Setup(
        config.Settings(state_dir=str(tmp_path / "state")),
        str(conf),
        env,
        ui,
        answers=setup.parse_answers(""),
        dry_run=True,
        installer=str(installer),
        template=EXAMPLE,
    )
    assert st.run() == 0, out.getvalue()
    assert (conf.read_text(encoding="utf-8") if conf.exists() else None) == conf_text  # nothing written
    return st, out.getvalue()


def test_the_probes_find_the_roku_port_which_names_a_vendor_and_no_profile(found):
    assert len(found) == 1, found
    tv = found[0]
    assert tv.open_ports == [ROKU_PORT] and (tv.vendor, tv.platform, tv.hostname) == ("Roku", "Roku OS", "")
    assert tv.profile is None and f"tcp {ROKU_PORT} open (Roku OS LAN API)" in tv.evidence
    a = discover.assign(tv, discover.bundled_profiles())
    assert (a.profile, a.vendor) == (None, "Roku")
    assert a.evidence == (f"one signal names Roku (tcp {ROKU_PORT} open): no profile on that alone",)


def test_unattended_setup_plans_the_general_profile(tmp_path, found):
    st, text = dry_run(tmp_path, found)
    assert st.target()["PROFILE"] == "generic-tv" and setup.MSG_GENERIC in text
    assert "(SETUP_PROFILE=roku names it)" in text and "Is it?" not in text


@pytest.mark.parametrize(("brand", "profile"), [("y", "roku"), ("", "roku"), ("n", "generic-tv")])
def test_guided_setup_asks_the_brand_once_and_plans_the_answer(tmp_path, found, brand, profile):
    st, text = dry_run(tmp_path, found, brand=brand)
    assert text.count("This looks like a Roku TV. Is it? [Y/n]") == 1
    assert st.target()["PROFILE"] == profile


@pytest.mark.parametrize("brand", [None, "y", "n"], ids=["unattended", "yes", "no"])
def test_no_path_plans_lg_webos_over_a_file_that_names_it_for_no_tv(tmp_path, found, brand):
    """The 0.2.0 template said PROFILE=lg-webos beside the TV_MAC placeholder: that file names no TV,
    so the TV found gets a profile of its own, and it is never LG's."""
    old = EXAMPLE.replace("PROFILE=generic-tv", "PROFILE=lg-webos", 1)
    assert config.parse_conf(old)["PROFILE"] == "lg-webos"
    st, _ = dry_run(tmp_path, found, brand=brand, conf_text=old)
    assert st.target()["PROFILE"] in ("generic-tv", "roku") and st.plan.changes["PROFILE"] != "lg-webos"
