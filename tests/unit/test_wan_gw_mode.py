"""(uplink) WAN_GW_MODE: how tvgw-apply finds the home router for table 100's default route.

literal, which a settings file without the key means, is WAN_GW as written, as every release before
the key read it; auto is WAN_IF's own default route in the main table, then the address an apply last
took from it, then WAN_GW. The script runs against the stubs of test_apply.py, with an `ip` that
answers the main table's default route the way `ip -4 -o route show default dev wlan0` prints it."""

from pathlib import Path

import pytest
import test_apply
from conftest import ROOT
from test_apply import run_apply

from tvgw import config

ROUTER, NEW_ROUTER, STALE = "203.0.113.1", "203.0.113.254", "198.51.100.77"
pytestmark = test_apply.pytestmark


def ip_stub(default: str | None) -> str:
    """`ip` that logs every call, and prints a main-table default route via `default` on wlan0."""
    route = (
        f"printf 'default via {default} dev wlan0 proto dhcp src 203.0.113.10 metric 600 \\n'"
        if default
        else ":"
    )
    return f"""#!/bin/sh
printf '%s\\n' "$*" >>"$STUB_DIR/ip.calls"
case "$*" in
"-4 -o route show default dev wlan0") {route} ;;
esac
exit 0
"""


def conf(mode: str | None, wan_gw: str | None = ROUTER) -> str:
    text = "UPLINK=direct\nWAN_IF=wlan0\n"
    text += f"WAN_GW={wan_gw}\n" if wan_gw else ""
    return text + (f"WAN_GW_MODE={mode}\n" if mode else "")


def calls(tmp_path) -> list[str]:
    return (tmp_path / "stub" / "ip.calls").read_text(encoding="utf-8").splitlines()


def applied(tmp_path) -> dict[str, str]:
    return config.parse_conf((tmp_path / "run" / "tvgw" / "settings.applied").read_text(encoding="utf-8"))


def last(tmp_path) -> Path:
    return tmp_path / "run" / "tvgw" / "wan_gw.last"


def routed_via(tmp_path) -> list[str]:
    return [c for c in calls(tmp_path) if c.startswith("route replace default via")]


@pytest.mark.parametrize("mode", [None, "literal"])
def test_literal_is_wan_gw_as_written_and_asks_no_route(tmp_path, mode):
    """The reference gateway has no WAN_GW_MODE: the apply asks nothing new and routes by WAN_GW, even
    with a main-table default via another router, and writes no wan_gw.last."""
    out = run_apply(tmp_path, conf=conf(mode), stubs={"ip": ip_stub(NEW_ROUTER)})
    assert out.returncode == 0, out.stderr
    assert routed_via(tmp_path) == [f"route replace default via {ROUTER} dev wlan0 table 100"]
    assert not [c for c in calls(tmp_path) if c.startswith("-4 -o route show default")]
    assert not last(tmp_path).exists()
    got = applied(tmp_path)
    assert (got["WAN_GW"], got["WAN_GW_MODE"], got["WAN_GW_USED"]) == (ROUTER, "literal", ROUTER)


def test_auto_takes_the_uplinks_own_default_route_and_remembers_it(tmp_path):
    out = run_apply(tmp_path, conf=conf("auto"), stubs={"ip": ip_stub(NEW_ROUTER)})
    assert out.returncode == 0, out.stderr
    assert routed_via(tmp_path) == [f"route replace default via {NEW_ROUTER} dev wlan0 table 100"]
    assert last(tmp_path).read_text(encoding="utf-8") == f"{NEW_ROUTER}\n"
    got = applied(tmp_path)
    # the file's literal is what the conf says, for verify's comparison; the address used is beside it
    assert (got["WAN_GW"], got["WAN_GW_MODE"], got["WAN_GW_USED"]) == (ROUTER, "auto", NEW_ROUTER)


def test_auto_without_a_default_route_takes_the_last_one_seen_then_the_literal(tmp_path):
    last(tmp_path).parent.mkdir(parents=True)
    last(tmp_path).write_text(f"{NEW_ROUTER}\n", encoding="utf-8")
    assert run_apply(tmp_path, conf=conf("auto"), stubs={"ip": ip_stub(None)}).returncode == 0
    assert routed_via(tmp_path) == [f"route replace default via {NEW_ROUTER} dev wlan0 table 100"]
    assert last(tmp_path).read_text(encoding="utf-8") == f"{NEW_ROUTER}\n"  # kept, not rewritten
    other = tmp_path / "fresh"  # after a reboot: no .last on the tmpfs
    assert run_apply(other, conf=conf("auto"), stubs={"ip": ip_stub(None)}).returncode == 0
    assert routed_via(other) == [f"route replace default via {ROUTER} dev wlan0 table 100"]
    assert not last(other).exists() and applied(other)["WAN_GW_USED"] == ROUTER


def test_auto_prefers_the_live_route_over_a_stale_last(tmp_path):
    last(tmp_path).parent.mkdir(parents=True)
    last(tmp_path).write_text(f"{STALE}\n", encoding="utf-8")
    assert run_apply(tmp_path, conf=conf("auto"), stubs={"ip": ip_stub(NEW_ROUTER)}).returncode == 0
    assert routed_via(tmp_path) == [f"route replace default via {NEW_ROUTER} dev wlan0 table 100"]
    assert last(tmp_path).read_text(encoding="utf-8") == f"{NEW_ROUTER}\n"
    # a .last that is not an address is no router
    other = tmp_path / "again"
    (other / "run" / "tvgw").mkdir(parents=True)
    (other / "run" / "tvgw" / "wan_gw.last").write_text("not-an-address\n", encoding="utf-8")
    assert run_apply(other, conf=conf("auto"), stubs={"ip": ip_stub(None)}).returncode == 0
    assert routed_via(other) == [f"route replace default via {ROUTER} dev wlan0 table 100"]


def test_auto_with_no_router_anywhere_loads_the_filter_and_leaves_the_route_to_the_dispatcher(tmp_path):
    out = run_apply(tmp_path, conf=conf("auto", wan_gw=None), stubs={"ip": ip_stub(None)})
    assert out.returncode == 0, out.stderr
    assert "no router on wlan0 yet; dispatcher will add the route" in out.stderr
    assert routed_via(tmp_path) == []
    assert (tmp_path / "run" / "tvgw" / "ruleset.applied").exists()
    # literal mode keeps its stop: without WAN_GW nothing is loaded
    other = tmp_path / "literal"
    out = run_apply(other, conf=conf(None, wan_gw=None), stubs={"ip": ip_stub(NEW_ROUTER)})
    assert out.returncode == 1 and "WAN_GW must be set for UPLINK=direct" in out.stderr


def test_a_mode_tvgw_apply_does_not_know_stops_it(tmp_path):
    out = run_apply(tmp_path, conf=conf("Auto"))
    assert out.returncode == 1 and "WAN_GW_MODE must be literal or auto" in out.stderr
    assert not (tmp_path / "stub" / "nft-script.0").exists()


def test_an_older_tvgw_apply_reads_the_same_file_and_uses_the_literal(tmp_path, monkeypatch):
    """decision 53: setup writes WAN_GW_MODE=auto and keeps WAN_GW, so a rollback to a release that
    predates the key (v0.2.0's tvgw-apply, kept verbatim beside this file) sources the file, ignores the
    key and routes by the literal, as it always did."""
    old = (Path(__file__).with_name("tvgw-apply-v0.2.0")).read_text(encoding="utf-8")
    assert "WAN_GW_MODE" not in old
    monkeypatch.setattr(test_apply, "APPLY", old)
    out = run_apply(tmp_path, conf=conf("auto"), stubs={"ip": ip_stub(NEW_ROUTER)})
    assert out.returncode == 0, out.stderr
    assert routed_via(tmp_path) == [f"route replace default via {ROUTER} dev wlan0 table 100"]
    assert applied(tmp_path)["WAN_GW"] == ROUTER


def test_the_resolver_is_in_the_block_install_sh_shares_and_install_sh_refuses_a_bad_mode():
    install = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
    apply = (ROOT / "deploy" / "nftables" / "tvgw-apply").read_text(encoding="utf-8")
    for text in (install, apply):
        block = text[text.index("# ---- tvgw-net:") : text.index("# ---- end tvgw-net ----")]
        assert "wan_router() {" in block
    assert '[[ $WAN_GW_MODE =~ ^(literal|auto)$ ]] || die "WAN_GW_MODE must be literal or auto"' in install
