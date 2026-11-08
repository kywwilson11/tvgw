"""tvgw-doh-update, run for real with its absolute paths moved under tmp_path: curl copies a fake list,
chgrp and tvgw-apply only record their calls, and nothing touches the network or the firewall."""

import ipaddress
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from conftest import ROOT

SCRIPT = ROOT / "deploy" / "bin" / "tvgw-doh-update"
BASH = shutil.which("bash")
pytestmark = pytest.mark.skipif(BASH is None, reason="bash is not installed here")


def moved(text: str, root: Path) -> str:
    """The script with every absolute path it touches moved under `root` (as test_packaging does)."""
    prefixes = r"/(?:etc|usr/local|usr/lib/tvgw|opt|var|run)/"
    return re.sub(rf"(?<=[\s\"'=>(|:])(?={prefixes})", str(root), text)


def stub(root: Path, bin_dir: Path, name: str, body: str = "") -> None:
    bin_dir.mkdir(parents=True, exist_ok=True)
    log = root / "calls"
    (bin_dir / name).write_text(f'#!/bin/sh\necho "{name}" >>{log}\n{body}\n', encoding="utf-8")
    (bin_dir / name).chmod(0o755)


def run(
    root: Path,
    download: str,
    old_list: str | None = "203.0.113.1\n",
    conf: str = "",
    args: tuple[str, ...] = (),
) -> subprocess.CompletedProcess:
    """One run of the script; `old_list` None keeps the list in force a run before left."""
    (root / "etc" / "tvgw").mkdir(parents=True, exist_ok=True)
    (root / "etc" / "tvgw" / "tvgw.conf").write_text("DOH_LIST_URL=https://example.invalid/doh.txt\n" + conf)
    (root / "etc" / "tvgw" / "doh-exclude.txt").write_text("198.51.100.0/24\n")
    (root / "var" / "lib" / "tvgw").mkdir(parents=True, exist_ok=True)
    if old_list is not None:
        (root / "var" / "lib" / "tvgw" / "doh4.txt").write_text(old_list)
    (root / "download.txt").write_text(download)
    (root / "usr" / "local" / "sbin").mkdir(parents=True, exist_ok=True)
    # curl -o FILE URL: the fake download lands in FILE
    stub(
        root,
        root / "bin",
        "curl",
        'while [ $# -gt 1 ]; do [ "$1" = -o ] && out=$2; shift; done; cp "$FAKE_LIST" "$out"',
    )
    stub(root, root / "bin", "chgrp")
    stub(root, root / "usr" / "local" / "sbin", "tvgw-apply")
    script = root / "tvgw-doh-update"
    script.write_text(moved(SCRIPT.read_text(encoding="utf-8"), root), encoding="utf-8")
    env = {"PATH": f"{root / 'bin'}{os.pathsep}{os.environ['PATH']}", "FAKE_LIST": str(root / "download.txt")}
    return subprocess.run(
        [BASH, str(script), *args], env=env, capture_output=True, text=True, encoding="utf-8"
    )


def calls(root: Path) -> list[str]:
    log = root / "calls"
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


def test_a_resolver_list_is_filtered_written_and_applied(tmp_path):
    download = (
        "# resolvers\n" + "\n".join(f"203.0.113.{i}" for i in range(1, 70)) + "\n198.51.100.7\n1.2.3.0/8\n"
    )
    out = run(tmp_path, download)
    assert out.returncode == 0, out.stderr
    written = (tmp_path / "var" / "lib" / "tvgw" / "doh4.txt").read_text().splitlines()
    assert len(written) == 69 and "198.51.100.7" not in written  # the excluded CDN edge, the /8, the comment
    assert "tvgw: 69 DoH IPs loaded" in out.stdout
    assert calls(tmp_path)[-1] == "tvgw-apply"
    assert not list((tmp_path / "var" / "lib" / "tvgw").glob(".doh4.*")), "no staged file left"


@pytest.mark.parametrize(
    ("download", "says"),
    [
        ("\n".join(f"203.0.113.{i}" for i in range(1, 20)) + "\n", "only 19 DoH IPs fetched"),
        # 70 /16 networks: 4,587,520 addresses, more than any resolver list; a source gone wrong would
        # black out the TV's HTTPS rather than block resolvers
        (
            "\n".join(f"{a}.{b}.0.0/16" for a in (11, 12, 13, 14, 15, 16, 17) for b in range(10)) + "\n",
            "covering 4587520 addresses",
        ),
        (
            "\n".join(f"{a}.{b}.{c}.1" for a in (11, 12, 13) for b in range(130) for c in range(130)) + "\n",
            "names 50700 networks",
        ),
    ],
    ids=["too few", "too many addresses", "too many entries"],
)
def test_a_list_too_small_or_too_large_keeps_the_old_one_and_applies_nothing(tmp_path, download, says):
    out = run(tmp_path, download)
    assert out.returncode == 1, out.stdout
    assert says in out.stderr and "keeping old list" in out.stderr, out.stderr
    assert (tmp_path / "var" / "lib" / "tvgw" / "doh4.txt").read_text() == "203.0.113.1\n"
    assert "tvgw-apply" not in calls(tmp_path)
    assert not list((tmp_path / "var" / "lib" / "tvgw").glob(".doh4.*")), "the staged file is removed"


# ---- (listguard) the bound on how much one refresh may drop (design decision 68) ------------------------------
def listing(*nets: str) -> str:
    return "".join(f"{n}\n" for n in nets)


IN_FORCE = [f"203.0.113.{i}" for i in range(1, 101)]  # 100 entries, the list in force


def state(root: Path) -> Path:
    return root / "var" / "lib" / "tvgw"


def test_a_refresh_that_drops_more_than_a_fifth_of_the_list_in_force_is_held_back(tmp_path):
    """HaGeZi's list dropped about 2% a day; a source that lost a fifth of it overnight is broken, and its
    refresh would unblock every resolver it lost. What it drops stays blocked (here it adds nothing, so the
    list in force is unchanged and nothing is applied), the last refresh taken is kept beside it, and the
    held file says why, and when that refresh was taken, for tvgw verify and the brief."""
    state(tmp_path).mkdir(parents=True)
    written = state(tmp_path) / "doh4.txt"
    written.write_text(listing(*IN_FORCE))
    os.utime(written, (1_700_000_000, 1_700_000_000))
    out = run(tmp_path, listing(*IN_FORCE[:79]), None)
    assert out.returncode == 1, out.stderr
    assert (
        "would drop 21 of the 100 entries of the last refresh taken (21%, over DOH_DROP_MAX=20%)"
        in out.stderr
    )
    assert (state(tmp_path) / "doh4.txt").read_text() == listing(*IN_FORCE)
    assert "tvgw-apply" not in calls(tmp_path)
    held = json.loads((state(tmp_path) / "doh4.held").read_text())
    assert (held["in_force"], held["fetched"], held["dropped"], held["max"]) == (100, 79, 21, 20)
    assert held["since"] == held["t"] and held["accepted"] == 1_700_000_000
    assert (state(tmp_path) / "doh4.base").read_text().splitlines() == [f"{n}/32" for n in IN_FORCE]
    assert not list(state(tmp_path).glob(".doh4.*")) and not list(state(tmp_path).glob("doh4.*.tmp"))


def test_a_hold_that_goes_on_keeps_the_time_it_began_and_the_refresh_last_taken(tmp_path):
    run(tmp_path, listing(*IN_FORCE[:50]), listing(*IN_FORCE))
    first = json.loads((state(tmp_path) / "doh4.held").read_text())
    run(tmp_path, listing(*IN_FORCE[:40]), None)
    again = json.loads((state(tmp_path) / "doh4.held").read_text())
    assert again["since"] == first["since"] and again["accepted"] == first["accepted"]
    assert again["dropped"] == 60 and again["in_force"] == 100


def test_a_held_refresh_adds_its_new_entries_and_drops_nothing(tmp_path):
    """A hold must not freeze the list: a resolver the source added is blocked at once, and nothing it
    dropped is unblocked until a refresh within the bound, or --accept, is taken."""
    new = [f"198.18.0.{i}" for i in range(1, 31)]
    out = run(tmp_path, listing(*IN_FORCE[:50], *new), listing(*IN_FORCE))
    assert out.returncode == 1 and calls(tmp_path)[-1] == "tvgw-apply", out.stderr
    in_force = (state(tmp_path) / "doh4.txt").read_text().splitlines()
    assert len(in_force) == 130 and "198.18.0.7/32" in in_force and "203.0.113.99/32" in in_force
    assert len((state(tmp_path) / "doh4.base").read_text().splitlines()) == 100


def test_a_hold_ends_against_the_refresh_last_taken_not_the_grown_list(tmp_path):
    """The source comes back: judged against the last refresh taken (100 entries), not against the list in
    force, which grew by the held refresh's new entries, it drops 10 and is taken; the hold's files go."""
    run(tmp_path, listing(*IN_FORCE[:50], *(f"198.18.0.{i}" for i in range(1, 31))), listing(*IN_FORCE))
    out = run(tmp_path, listing(*IN_FORCE[:90]), None)
    assert out.returncode == 0, out.stderr
    assert len((state(tmp_path) / "doh4.txt").read_text().splitlines()) == 90
    assert not (state(tmp_path) / "doh4.held").exists() and not (state(tmp_path) / "doh4.base").exists()


def test_a_refresh_within_the_bound_is_taken_and_ends_the_hold(tmp_path):
    (state(tmp_path)).mkdir(parents=True)
    (state(tmp_path) / "doh4.held").write_text('{"since": 1, "t": 1}')
    out = run(tmp_path, listing(*IN_FORCE[:80], "203.0.113.200"), listing(*IN_FORCE))
    assert out.returncode == 0, out.stderr
    assert len((state(tmp_path) / "doh4.txt").read_text().splitlines()) == 81
    assert not (state(tmp_path) / "doh4.held").exists() and calls(tmp_path)[-1] == "tvgw-apply"


def test_accept_takes_a_refresh_the_bound_would_hold(tmp_path):
    run(tmp_path, listing(*IN_FORCE[:60]), listing(*IN_FORCE))
    out = run(tmp_path, listing(*IN_FORCE[:60]), listing(*IN_FORCE), args=("--accept",))
    assert out.returncode == 0, out.stderr
    assert "taking the refresh on request: it drops 40 of 100 entries" in out.stderr
    assert len((state(tmp_path) / "doh4.txt").read_text().splitlines()) == 60
    assert not (state(tmp_path) / "doh4.held").exists() and not (state(tmp_path) / "doh4.base").exists()


def test_the_bound_follows_the_setting(tmp_path):
    out = run(tmp_path, listing(*IN_FORCE[:60]), listing(*IN_FORCE), conf="DOH_DROP_MAX=50\n")
    assert out.returncode == 0, out.stderr
    held = run(tmp_path / "b", listing(*IN_FORCE[:60]), listing(*IN_FORCE), conf="DOH_DROP_MAX=39\n")
    assert held.returncode == 1 and "over DOH_DROP_MAX=39%" in held.stderr


@pytest.mark.parametrize("value", ["0", "101", "a fifth", "-5"])
def test_a_bound_out_of_range_keeps_the_list_in_force(tmp_path, value):
    out = run(tmp_path, listing(*IN_FORCE), listing(*IN_FORCE), conf=f"DOH_DROP_MAX='{value}'\n")
    assert out.returncode == 1 and "expected 1 to 100" in out.stderr
    assert (state(tmp_path) / "doh4.txt").read_text() == listing(*IN_FORCE)


def test_an_exclusion_added_to_free_an_address_never_counts_as_a_drop(tmp_path):
    """198.51.100.0/24 is excluded (the CDN edge an owner freed): entries in force under it left the
    list for that reason, not because the source lost them."""
    in_force = [*IN_FORCE[:70], *(f"198.51.100.{i}" for i in range(1, 31))]
    out = run(tmp_path, listing(*IN_FORCE[:70]), listing(*in_force))
    assert out.returncode == 0, out.stderr


def test_a_held_refresh_still_lets_todays_exclusions_take_their_entries_out(tmp_path):
    """The exclusions keep shared CDN edges reachable for the TV's streaming; a hold must not keep one
    blocked that the exclusions now name."""
    in_force = [*IN_FORCE, "198.51.100.7"]
    out = run(tmp_path, listing(*IN_FORCE[:10]), listing(*sorted(in_force, key=ipaddress.ip_address)))
    assert out.returncode == 1, out.stderr
    kept = (state(tmp_path) / "doh4.txt").read_text().splitlines()
    assert "198.51.100.7" not in kept and len(kept) == 100
    assert calls(tmp_path)[-1] == "tvgw-apply"


def test_a_list_in_force_under_the_floor_is_replaced_whatever_it_drops(tmp_path):
    out = run(tmp_path, listing(*(f"192.0.2.{i}" for i in range(1, 60))), listing(*IN_FORCE[:40]))
    assert out.returncode == 0, out.stderr


def test_a_first_install_has_no_list_in_force_to_bound(tmp_path):
    out = run(tmp_path, listing(*IN_FORCE[:60]), "")
    assert out.returncode == 0, out.stderr


def test_an_unknown_argument_is_a_usage_error_and_changes_nothing(tmp_path):
    out = run(tmp_path, listing(*IN_FORCE), listing(*IN_FORCE), args=("--force",))
    assert out.returncode == 2 and "usage: tvgw-doh-update [--accept]" in out.stderr
    assert calls(tmp_path) == []


def test_the_held_record_is_not_readable_by_others(tmp_path):
    """The hardware suite fails on any file directly in the state directory that others can read."""
    run(tmp_path, listing(*IN_FORCE[:10]), listing(*IN_FORCE))
    assert oct((state(tmp_path) / "doh4.held").stat().st_mode & 0o777) == "0o640"
