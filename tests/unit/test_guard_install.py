"""install.sh's guard block (design decision 42) run for real against fakes of systemctl, ss, nft and
nginx, its paths moved under tmp_path: the guard loads only when it changed, and a sandbox that stops
dnsmasq or nginx from serving the TV comes out again on its own, once, and is not tried again."""

import os
import re
import shutil
import subprocess

import pytest
from conftest import ROOT

DEPLOY = ROOT / "deploy"
INSTALL = (DEPLOY / "install.sh").read_text(encoding="utf-8")
BASH = shutil.which("bash")
pytestmark = pytest.mark.skipif(BASH is None or shutil.which("sha256sum") is None, reason="needs bash")

BLOCK = INSTALL[INSTALL.index("# ---- (guard) begin") : INSTALL.index("# ---- (guard) end ----")]

# systemctl: a unit is active while $STATE/active-<unit> exists; a restart fails when FAIL names the
# unit and its drop-in carries a sandbox line, as a sandbox the daemon cannot start under would, and
# always when BROKEN names it, as a daemon with a broken config of its own would
SYSTEMCTL = r"""#!/bin/sh
echo "systemctl $*" >>"$LOG"
[ "$1" = -q ] && shift
case "$1" in
is-active)
	[ "$2" = -q ] && shift
	[ -e "$STATE/active-${2%.service}" ] ;;
restart | reload-or-restart | reload)
	u=${2%.service}
	if [ "$BROKEN" = "$u" ] || { [ "$FAIL" = "$u" ] && grep -qs '^ProtectSystem=' "$ETC/systemd/system/$u.service.d/"*; }; then
		rm -f "$STATE/active-$u"; exit 1
	fi
	touch "$STATE/active-$u" ;;
esac
exit 0
"""
SS = r"""#!/bin/sh
case "$*" in
*-ulnp*) [ -e "$STATE/active-dnsmasq" ] && echo 'UNCONN 0 0 0.0.0.0%eth0:67 0.0.0.0:* users:(("dnsmasq",pid=7,fd=4))' ;;
*:80*) [ -e "$STATE/active-nginx" ] && echo 'LISTEN 0 511 10.10.10.1:80 0.0.0.0:*' ;;
*:443*) [ -e "$STATE/active-nginx" ] && echo 'LISTEN 0 511 10.10.10.1:443 0.0.0.0:*' ;;
esac
exit 0
"""
NFT = r"""#!/bin/sh
echo "nft $*" >>"$LOG"
case "$1" in
-c) [ -z "$NFT_REJECT" ] ;;
list) [ -e "$STATE/active-tvgw-guard" ] ;;
-s) [ -e "$STATE/active-tvgw-guard" ] && cat "$STATE/live" 2>/dev/null ;;
esac
"""
NGINX = '#!/bin/sh\n[ "$1" = -T ] && printf "%s\\n" "$NGINX_T"\nexit 0\n'
# tvgw guard cotenants|avahi: prints $COTENANTS_OUT or $AVAHI_OUT, as the real one prints one line per
# file it changed and nothing when nothing changed
TVGW = r"""#!/bin/sh
echo "tvgw $*" >>"$LOG"
case "$2" in
cotenants) [ -n "$COTENANTS_OUT" ] && printf '%s\n' "$COTENANTS_OUT" ;;
avahi) [ -n "$AVAHI_OUT" ] && printf '%s\n' "$AVAHI_OUT" ;;
esac
exit 0
"""


def run(
    tmp_path,
    call: str,
    fail: str = "",
    nginx_t: str = "http {\n}\n",
    nft_reject: str = "",
    active=(),
    env_extra: dict[str, str] | None = None,
):
    """The block, then `call`, in bash -e as install.sh runs it. Returns (status, stderr, calls)."""
    etc, state, bin_dir = tmp_path / "etc", tmp_path / "state", tmp_path / "bin"
    for d in (etc / "tvgw", etc / "systemd" / "system", state, bin_dir):
        d.mkdir(parents=True, exist_ok=True)
    for name, body in (("systemctl", SYSTEMCTL), ("ss", SS), ("nft", NFT), ("nginx", NGINX), ("tvgw", TVGW)):
        (bin_dir / name).write_text(body, encoding="utf-8")
        (bin_dir / name).chmod(0o755)
    for unit in active:
        (state / f"active-{unit}").touch()
    block = (
        BLOCK.replace("/etc/tvgw/", f"{etc}/tvgw/")
        .replace("/etc/systemd/system/", f"{etc}/systemd/system/")
        .replace("/var/lib/tvgw/", f"{state}/")
        .replace("/run/tvgw/", f"{state}/run-")
    )
    script = "\n".join(
        (
            'die() { echo "tvgw: $*" >&2; exit 1; }',
            "TV_IF=eth0 TV_NET=10.10.10.0/24 GW_IP=10.10.10.1",
            block,
            call,
        )
    )
    log = tmp_path / "calls"
    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "LOG": str(log),
        "STATE": str(state),
        "ETC": str(etc),
        "FAIL": fail,
        "NGINX_T": nginx_t,
        "NFT_REJECT": nft_reject,
        "BROKEN": "",
        "COTENANTS_OUT": "",
        "AVAHI_OUT": "",
        **(env_extra or {}),
    }
    out = subprocess.run(
        [BASH, "-euo", "pipefail", "-c", script],
        cwd=DEPLOY,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    log.write_text("", encoding="utf-8")
    return out.returncode, out.stderr, calls


def dropin(tmp_path, unit, name):
    return tmp_path / "etc" / "systemd" / "system" / f"{unit}.service.d" / name


# ---- dnsmasq ----------------------------------------------------------------------------------------


def test_dnsmasq_keeps_the_hardening_when_it_serves_dhcp_with_it(tmp_path):
    rc, err, calls = run(tmp_path, "restart_dnsmasq")
    assert rc == 0, err
    text = dropin(tmp_path, "dnsmasq", "20-tvgw-hardening.conf").read_text(encoding="utf-8")
    assert "IPAddressAllow=localhost 0.0.0.0/32 255.255.255.255/32 10.10.10.0/24" in text
    assert "CAP_NET_ADMIN" not in text.split("[Service]", 1)[1].split("\n", 2)[1]  # the bounding set line
    assert "systemctl restart dnsmasq.service" in calls and "WARNING" not in err


def test_dnsmasq_that_will_not_serve_hardened_gets_its_drop_in_taken_out_and_not_tried_again(tmp_path):
    """The TV must never lose DHCP to a hardening line: one failed check removes the drop-in, restarts
    dnsmasq plainly and leaves a stamp, so the next deploy does not restart it twice again."""
    rc, err, calls = run(tmp_path, "restart_dnsmasq", fail="dnsmasq")
    assert rc == 0, err
    assert "WARNING: dnsmasq is not serving DHCP with the hardening drop-in" in err
    assert not dropin(tmp_path, "dnsmasq", "20-tvgw-hardening.conf").exists()
    assert calls.count("systemctl restart dnsmasq.service") == 2
    assert (tmp_path / "state" / ".unit-stamps" / "dnsmasq-refused").exists()
    rc, err, calls = run(tmp_path, "restart_dnsmasq", fail="dnsmasq")
    assert rc == 0 and calls.count("systemctl restart dnsmasq.service") == 1
    assert "runs unhardened" in err and not dropin(tmp_path, "dnsmasq", "20-tvgw-hardening.conf").exists()


def test_a_dnsmasq_that_will_not_serve_at_all_stops_the_install(tmp_path):
    (tmp_path / "bin").mkdir(parents=True)
    rc, err, _ = run(tmp_path, "ss() { :; }; restart_dnsmasq")  # nothing ever holds UDP 67
    assert rc == 1 and "dnsmasq is not serving DHCP on UDP 67" in err


# ---- nginx ------------------------------------------------------------------------------------------


def test_nginx_is_restarted_once_for_a_new_sandbox_and_reloaded_after(tmp_path):
    rc, err, calls = run(tmp_path, "nginx_service", active=("nginx",))
    assert rc == 0, err
    text = dropin(tmp_path, "nginx", "tvgw.conf").read_text(encoding="utf-8")
    assert text.startswith("[Unit]\nAfter=network-online.target\n") and "Restart=on-failure" in text
    assert (
        "MemoryDenyWriteExecute=yes" in text and "RestrictAddressFamilies=AF_INET AF_NETLINK AF_UNIX" in text
    )
    assert "systemctl restart nginx.service" in calls
    rc, err, calls = run(tmp_path, "nginx_service", active=("nginx",))
    assert (
        rc == 0
        and "systemctl reload nginx.service" in calls
        and "systemctl restart nginx.service" not in calls
    )


def test_pcre_jit_keeps_writable_code_and_an_ipv6_listener_keeps_inet6(tmp_path):
    conf = "http {\n  pcre_jit on;\n  server { listen [::]:8080; }\n}\n"
    rc, err, _ = run(tmp_path, "nginx_service", nginx_t=conf, active=("nginx",))
    assert rc == 0, err
    text = dropin(tmp_path, "nginx", "tvgw.conf").read_text(encoding="utf-8")
    assert "MemoryDenyWriteExecute" not in text and "AF_INET6" in text
    rc, _, _ = run(tmp_path, "nginx_service", nginx_t="http {\n  # pcre_jit on;\n}\n", active=("nginx",))
    assert "MemoryDenyWriteExecute=yes" in dropin(tmp_path, "nginx", "tvgw.conf").read_text(encoding="utf-8")


def test_nginx_that_will_not_serve_hardened_gets_the_plain_drop_in_back(tmp_path):
    rc, err, calls = run(tmp_path, "nginx_service", fail="nginx", active=("nginx",))
    assert rc == 0, err
    assert "restoring the drop-in without them" in err
    assert dropin(tmp_path, "nginx", "tvgw.conf").read_text(encoding="utf-8") == (
        "[Unit]\nAfter=network-online.target\nWants=network-online.target\n[Service]\nRestart=on-failure\nRestartSec=5\n"
    )
    assert calls.count("systemctl restart nginx.service") == 2
    rc, err, calls = run(tmp_path, "nginx_service", fail="nginx", active=("nginx",))
    assert rc == 0 and "runs unhardened" in err and "systemctl reload nginx.service" in calls


# ---- the guard table ----------------------------------------------------------------------------------


def test_the_guard_loads_when_new_and_is_left_alone_when_unchanged(tmp_path):
    rc, err, calls = run(tmp_path, "guard_load")
    assert rc == 0, err
    assert (tmp_path / "etc" / "tvgw" / "guard.nft").read_text(encoding="utf-8").count('"eth0"') >= 3
    assert any(c.startswith("nft -c -f ") for c in calls)
    assert "systemctl -q enable tvgw-guard.service" in calls
    assert "systemctl reload-or-restart tvgw-guard.service" in calls
    rc, err, calls = run(tmp_path, "guard_load")  # active, table there, file the same: counters kept
    assert rc == 0 and "systemctl reload-or-restart tvgw-guard.service" not in calls
    (tmp_path / "state" / "active-tvgw-guard").unlink()  # the table was deleted by hand
    rc, err, calls = run(tmp_path, "guard_load")
    assert "systemctl reload-or-restart tvgw-guard.service" in calls


def test_a_guard_nft_rejects_stops_the_install_before_anything_is_loaded(tmp_path):
    rc, err, calls = run(tmp_path, "guard_load", nft_reject="1")
    assert rc == 1 and "nft rejected the rendered guard" in err
    assert not (tmp_path / "etc" / "tvgw" / "guard.nft").exists()
    assert not [c for c in calls if c.startswith("systemctl")]


def test_the_guard_steps_run_before_the_tv_side_comes_up():
    """The Pi closed to the TV before tv-lan is brought up and before the first-install discovery."""
    at = INSTALL.index("\nguard_load\n")
    assert INSTALL.index("install -m 644 systemd/*.service") < at < INSTALL.index("\ntv_lan\n")
    assert INSTALL.index("\nguard_cotenants\n") < INSTALL.index('if [ "$have_tv" = no ]; then')
    # its definition and the three restarts: (setup) the bring-up pass's, the first install's before
    # discovery and the full install's, each after the guard
    assert INSTALL.count("restart_dnsmasq") == 4
    restarts = [m.start() for m in re.finditer(r"^\s*restart_dnsmasq # \(guard\)", INSTALL, re.M)]
    assert len(restarts) == 3 and min(restarts) > at
    assert "systemctl restart dnsmasq.service\n" not in INSTALL.replace(
        "\tsystemctl restart dnsmasq.service || true\n", ""
    )


def test_a_hole_left_in_the_live_guard_is_closed_by_the_next_deploy(tmp_path):
    """A `tvgw discover` killed mid-search leaves its `tvgw-discover` accept at the head of the guard's
    input chain; the next deploy reloads, so verify's guard_present does not FAIL on every run after."""
    rc, err, calls = run(tmp_path, "guard_load")
    assert rc == 0, err
    state = tmp_path / "state"
    loaded = "table inet tvgw_guard {\n\tchain input {\n\t}\n}\n"
    (state / "run-guard.applied").write_text(loaded, encoding="utf-8")
    (state / "live").write_text(loaded, encoding="utf-8")
    rc, err, calls = run(tmp_path, "guard_load")  # live equals what the unit loaded: left alone
    assert rc == 0 and "systemctl reload-or-restart tvgw-guard.service" not in calls, err
    hole = '\t\tiifname "eth0" ip daddr 10.10.10.1 udp dport 41234 counter accept comment "tvgw-discover"\n'
    (state / "live").write_text(loaded.replace("input {\n", "input {\n" + hole), encoding="utf-8")
    rc, err, calls = run(tmp_path, "guard_load")
    assert rc == 0 and "systemctl reload-or-restart tvgw-guard.service" in calls, err
    (state / "run-guard.applied").write_text("", encoding="utf-8")  # no baseline is not drift
    rc, err, calls = run(tmp_path, "guard_load")
    assert rc == 0 and "systemctl reload-or-restart tvgw-guard.service" not in calls, err


def test_a_dnsmasq_broken_without_the_hardening_too_leaves_no_stamp(tmp_path):
    """A dnsmasq that fails with and without the drop-in has a fault of its own (a broken dnsmasq.d):
    the install stops, and once that is fixed the drop-in is tried again rather than kept out."""
    rc, err, calls = run(tmp_path, "restart_dnsmasq", env_extra={"BROKEN": "dnsmasq"})
    assert rc == 1 and "dnsmasq is not serving DHCP on UDP 67" in err
    assert calls.count("systemctl restart dnsmasq.service") == 2
    assert not (tmp_path / "state" / ".unit-stamps" / "dnsmasq-refused").exists()
    rc, err, calls = run(tmp_path, "restart_dnsmasq")  # the config fixed: hardened again
    assert rc == 0 and "WARNING" not in err, err
    assert dropin(tmp_path, "dnsmasq", "20-tvgw-hardening.conf").exists()


def test_an_nginx_broken_without_the_hardening_too_leaves_no_stamp(tmp_path):
    rc, err, calls = run(tmp_path, "nginx_service", active=("nginx",), env_extra={"BROKEN": "nginx"})
    assert rc == 1 and "nginx is not listening on 10.10.10.1:80 and :443" in err
    assert calls.count("systemctl restart nginx.service") == 2
    assert not (tmp_path / "state" / ".unit-stamps" / "nginx-refused").exists()
    rc, err, calls = run(tmp_path, "nginx_service")
    assert rc == 0 and "WARNING" not in err, err
    assert "ProtectSystem=" in dropin(tmp_path, "nginx", "tvgw.conf").read_text(encoding="utf-8")


# ---- the co-tenants -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cotenants", "avahi"),
    [
        ("", ""),
        ("wrote /etc/systemd/system/smbd.service.d/10-tvgw-not-from-tv.conf", ""),
        ("", "changed /etc/avahi/avahi-daemon.conf"),
        ("removed /x.conf", "changed /etc/avahi/avahi-daemon.conf"),
    ],
)
def test_systemd_is_reloaded_and_avahi_restarted_only_when_tvgw_changed_something(tmp_path, cotenants, avahi):
    rc, err, calls = run(
        tmp_path, "guard_cotenants", env_extra={"COTENANTS_OUT": cotenants, "AVAHI_OUT": avahi}
    )
    assert rc == 0, err
    assert "tvgw guard cotenants" in calls and "tvgw guard avahi" in calls
    assert calls.count("systemctl daemon-reload") == (1 if cotenants else 0)
    assert calls.count("systemctl try-restart avahi-daemon.service") == (1 if avahi else 0)
    assert not [c for c in calls if c.startswith("systemctl") and "restart" in c and "avahi" not in c]
