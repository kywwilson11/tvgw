"""tvgw-doh-update, run for real with its absolute paths moved under tmp_path: curl copies a fake list,
chgrp and tvgw-apply only record their calls, and nothing touches the network or the firewall."""

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


def run(root: Path, download: str, old_list: str = "203.0.113.1\n") -> subprocess.CompletedProcess:
    (root / "etc" / "tvgw").mkdir(parents=True, exist_ok=True)
    (root / "etc" / "tvgw" / "tvgw.conf").write_text("DOH_LIST_URL=https://example.invalid/doh.txt\n")
    (root / "etc" / "tvgw" / "doh-exclude.txt").write_text("198.51.100.0/24\n")
    (root / "var" / "lib" / "tvgw").mkdir(parents=True, exist_ok=True)
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
    return subprocess.run([BASH, str(script)], env=env, capture_output=True, text=True, encoding="utf-8")


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
