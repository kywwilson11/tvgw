"""A release's own files and its publication (docs/project/packaging.md#releases).

`packaging/release-assets.sh` runs for real on stand-in packages. `packaging/publish-release.sh` runs
against a stub `gh` that answers as GitHub does for a tag with no release, a draft left by an earlier run,
or a published release. `packaging/install-check.sh` needs a container and runs in release.yml; here its
commands are held to install.sh's and its AdGuard Home pin to the floor, and its refusals run with stubs."""

import hashlib
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
from conftest import ROOT

from tvgw import aghinstall

PKG = ROOT / "packaging"
INSTALL = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
CHECK = (PKG / "install-check.sh").read_text(encoding="utf-8")
V = "0.3.0"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stand_ins(folder: Path, version: str = V) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    for arch in ("arm64", "amd64"):
        (folder / f"tvgw_{version}-1_{arch}.deb").write_bytes(f"{arch} package\n".encode() * 100)


def assets(folder: Path, version: str = V, script: Path = PKG / "release-assets.sh"):
    return subprocess.run(
        ["sh", str(script), version, str(folder)], capture_output=True, text=True, encoding="utf-8"
    )


# ---- release-assets.sh ---------------------------------------------------------------------------

needs_sha256sum = pytest.mark.skipif(shutil.which("sha256sum") is None, reason="needs sha256sum")


@needs_sha256sum
def test_the_sums_list_both_packages_then_the_installer_with_their_hashes_written_in(tmp_path):
    stand_ins(tmp_path)
    out = assets(tmp_path)
    assert out.returncode == 0, out.stderr
    arm, amd, getsh = (
        tmp_path / f"tvgw_{V}-1_arm64.deb",
        tmp_path / f"tvgw_{V}-1_amd64.deb",
        tmp_path / "get.sh",
    )
    assert (tmp_path / "SHA256SUMS").read_text(encoding="utf-8") == (
        f"{sha256(arm)}  {arm.name}\n{sha256(amd)}  {amd.name}\n{sha256(getsh)}  get.sh\n"
    )
    text = getsh.read_text(encoding="utf-8")
    assert f"\nTVGW_REL={V} #" in text
    assert f"\nSHA256_ARM64={sha256(arm)}\n" in text and f"\nSHA256_AMD64={sha256(amd)}\n" in text
    assert not re.search(r"@[A-Z][A-Z0-9_]*@", text)
    assert stat.S_IMODE(getsh.stat().st_mode) == 0o755
    assert out.stdout == (tmp_path / "SHA256SUMS").read_text(encoding="utf-8")


@needs_sha256sum
def test_the_render_is_the_template_with_three_fields_filled_and_nothing_else(tmp_path):
    stand_ins(tmp_path)
    assets(tmp_path)
    template = (PKG / "get.sh.in").read_text(encoding="utf-8")
    want = (
        template.replace("@VERSION@", V)
        .replace("@SHA256_ARM64@", sha256(tmp_path / f"tvgw_{V}-1_arm64.deb"))
        .replace("@SHA256_AMD64@", sha256(tmp_path / f"tvgw_{V}-1_amd64.deb"))
    )
    assert (tmp_path / "get.sh").read_text(encoding="utf-8") == want


@needs_sha256sum
def test_a_missing_package_writes_nothing(tmp_path):
    stand_ins(tmp_path)
    (tmp_path / f"tvgw_{V}-1_amd64.deb").unlink()
    out = assets(tmp_path)
    assert out.returncode == 1 and f"no tvgw_{V}-1_amd64.deb" in out.stderr
    assert sorted(p.name for p in tmp_path.iterdir()) == [f"tvgw_{V}-1_arm64.deb"]


@pytest.mark.parametrize("version", ["", "v0.3.0", "0.3.0-rc1", "0.3.0/../x", ".3", "3.", "0..3", "0.3&0"])
def test_a_version_that_is_not_dotted_numbers_is_refused(tmp_path, version):
    out = assets(tmp_path, version)
    assert out.returncode == 1 and "the version must be dotted numbers" in out.stderr


@needs_sha256sum
def test_a_template_field_left_unfilled_fails_and_leaves_no_installer(tmp_path):
    scripts = tmp_path / "packaging"
    scripts.mkdir()
    shutil.copy(PKG / "release-assets.sh", scripts)
    (scripts / "get.sh.in").write_text(
        (PKG / "get.sh.in").read_text(encoding="utf-8") + "MIRROR=@MIRROR@\n", encoding="utf-8"
    )
    stand_ins(tmp_path / "dist")
    out = assets(tmp_path / "dist", script=scripts / "release-assets.sh")
    assert out.returncode == 1
    assert "a field this script does not fill" in out.stderr and "MIRROR=@MIRROR@" in out.stderr
    assert not (tmp_path / "dist" / "get.sh").exists() and not (tmp_path / "dist" / "get.sh.new").exists()


# ---- publish-release.sh --------------------------------------------------------------------------

GH = """#!/bin/sh
echo "gh $*" >>"$CALLS"
case "$1 $2" in
"release view")
	if [ "$3" = --json ]; then # the latest release
		[ "${FAKE_DOWN:-}" != latest ] || { echo "HTTP 502: Bad Gateway" >&2; exit 1; }
		[ -n "${FAKE_LATEST:-}" ] || { echo "release not found" >&2; exit 1; }
		echo "$FAKE_LATEST"
	elif [ "$5" = url ]; then
		echo "https://github.com/kywwilson11/tvgw/releases/tag/$3"
	else
		[ "${FAKE_DOWN:-}" != tag ] || { echo "HTTP 502: Bad Gateway" >&2; exit 1; }
		case ${FAKE_STATE:-none} in
		none) echo "release not found" >&2; exit 1 ;;
		draft) echo true ;;
		published) echo false ;;
		esac
	fi
	;;
"release upload") [ "${FAKE_FAIL:-}" = upload ] && exit 1 ;;
esac
exit 0
"""


@pytest.fixture(scope="module")
def gh_bin(tmp_path_factory) -> Path:
    bin_dir = tmp_path_factory.mktemp("bin")
    (bin_dir / "gh").write_text(GH, encoding="utf-8")
    (bin_dir / "gh").chmod(0o755)
    return bin_dir


def publish(tmp_path, gh_bin, tag=f"v{V}", **fake):
    dist = tmp_path / "dist"
    if not dist.exists():
        stand_ins(dist)
        for name in ("get.sh", "SHA256SUMS", "RELEASE_NOTES.md"):
            (dist / name).write_text(f"{name}\n", encoding="utf-8")
    env = {"PATH": f"{gh_bin}{os.pathsep}{os.environ['PATH']}", "CALLS": str(tmp_path / "calls"), **fake}
    out = subprocess.run(
        ["sh", str(PKG / "publish-release.sh"), tag, str(dist)],
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    log = tmp_path / "calls"
    return out, (log.read_text(encoding="utf-8").splitlines() if log.exists() else [])


def test_a_new_tag_is_drafted_then_given_every_file_then_published_as_latest(tmp_path, gh_bin):
    out, calls = publish(tmp_path, gh_bin)
    assert out.returncode == 0, out.stderr
    dist = tmp_path / "dist"
    assert calls == [
        f"gh release view v{V} --json isDraft --jq .isDraft",
        f"gh release create v{V} --verify-tag --draft --title tvgw {V} --notes-file {dist}/RELEASE_NOTES.md",
        f"gh release upload v{V} {dist}/tvgw_{V}-1_arm64.deb {dist}/tvgw_{V}-1_amd64.deb {dist}/get.sh "
        f"{dist}/SHA256SUMS --clobber",
        "gh release view --json tagName --jq .tagName",
        f"gh release edit v{V} --draft=false --latest",
        f"gh release view v{V} --json url --jq .url",
    ]
    assert out.stdout.strip().endswith(f"releases/tag/v{V}")


def test_a_draft_left_by_a_failed_run_is_refreshed_then_published(tmp_path, gh_bin):
    out, calls = publish(tmp_path, gh_bin, FAKE_STATE="draft", FAKE_LATEST="v0.2.0")
    assert out.returncode == 0, out.stderr
    assert "has a draft from an earlier run" in out.stdout
    assert not [c for c in calls if " create " in c]
    edits = [c for c in calls if c.startswith("gh release edit")]
    assert edits[0] == f"gh release edit v{V} --title tvgw {V} --notes-file {tmp_path}/dist/RELEASE_NOTES.md"
    assert edits[1] == f"gh release edit v{V} --draft=false --latest"


def test_a_published_release_is_never_changed(tmp_path, gh_bin):
    out, calls = publish(tmp_path, gh_bin, FAKE_STATE="published")
    assert out.returncode == 1
    assert "already published, and a published release is never changed" in out.stderr
    assert calls == [f"gh release view v{V} --json isDraft --jq .isDraft"]


def test_github_failing_to_answer_about_the_tag_is_not_read_as_no_release(tmp_path, gh_bin):
    """Only gh's own "release not found" means there is none; a 502 read as none would create a second
    draft beside one an earlier run left."""
    out, calls = publish(tmp_path, gh_bin, FAKE_STATE="draft", FAKE_DOWN="tag")
    assert out.returncode == 1
    assert "HTTP 502: Bad Gateway" in out.stderr
    assert f"could not ask GitHub about v{V}'s release" in out.stderr
    assert calls == [f"gh release view v{V} --json isDraft --jq .isDraft"]


def test_github_failing_to_name_the_latest_release_leaves_the_release_a_draft(tmp_path, gh_bin):
    """A 502 read as "no release yet" would mark a fix for an older line latest."""
    dist = tmp_path / "dist"
    stand_ins(dist, "0.3.1")
    for name in ("get.sh", "SHA256SUMS", "RELEASE_NOTES.md"):
        (dist / name).write_text(f"{name}\n", encoding="utf-8")
    out, calls = publish(tmp_path, gh_bin, tag="v0.3.1", FAKE_LATEST="v0.4.0", FAKE_DOWN="latest")
    assert out.returncode == 1
    assert "could not ask GitHub which release is the latest" in out.stderr
    assert not [c for c in calls if "--draft=false" in c]
    assert any(c.startswith("gh release upload v0.3.1 ") for c in calls)


def test_a_failed_upload_leaves_the_release_a_draft(tmp_path, gh_bin):
    out, calls = publish(tmp_path, gh_bin, FAKE_FAIL="upload")
    assert out.returncode != 0
    assert not [c for c in calls if "--draft=false" in c]


@pytest.mark.parametrize(
    ("tag", "latest", "flag"),
    [
        ("v0.3.1", "v0.4.0", "--latest=false"),  # a fix for an older line
        ("v0.9.0", "v0.10.0", "--latest=false"),  # numbers, not text: 10 is after 9
        ("v0.10.0", "v0.9.0", "--latest"),
        ("v0.3.0", "v0.3.0", "--latest"),
        ("v1.0.0", "", "--latest"),  # the first release
    ],
)
def test_latest_stays_with_the_newest_version(tmp_path, gh_bin, tag, latest, flag):
    dist = tmp_path / "dist"
    stand_ins(dist, tag[1:])
    for name in ("get.sh", "SHA256SUMS", "RELEASE_NOTES.md"):
        (dist / name).write_text(f"{name}\n", encoding="utf-8")
    out, calls = publish(tmp_path, gh_bin, tag=tag, FAKE_LATEST=latest)
    assert out.returncode == 0, out.stderr
    assert f"gh release edit {tag} --draft=false {flag}" in calls


def test_a_missing_file_stops_before_github_is_asked(tmp_path, gh_bin):
    stand_ins(tmp_path / "dist")
    (tmp_path / "dist" / "SHA256SUMS").write_text("x\n", encoding="utf-8")
    (tmp_path / "dist" / "RELEASE_NOTES.md").write_text("x\n", encoding="utf-8")
    out, calls = publish(tmp_path, gh_bin)
    assert out.returncode == 1 and "get.sh: nothing was created or changed" in out.stderr
    assert calls == []


@pytest.mark.parametrize("tag", ["0.3.0", "v", "v0.3.0-rc1", "v.3", "v0..3", "release-0.3.0"])
def test_a_tag_that_is_not_v_and_a_version_is_refused(tmp_path, gh_bin, tag):
    out, calls = publish(tmp_path, gh_bin, tag=tag)
    assert out.returncode == 1 and "a release tag is v and the version" in out.stderr
    assert calls == []


# ---- install-check.sh ----------------------------------------------------------------------------


def lines(text: str) -> set[str]:
    return {line.strip().removesuffix(" ||").replace('"$VENV"', "$VENV") for line in text.splitlines()}


def test_the_install_check_installs_the_wheelhouse_with_install_shs_own_commands():
    branch = INSTALL[INSTALL.index('if [ "$MODE" = package ]; then') : INSTALL.index("\nelse\n")]
    commands = [line for line in lines(branch) if line.startswith(("(cd", "$VENV/bin/pip"))]
    assert len(commands) == 3
    assert set(commands) <= lines(CHECK)
    assert "REPO=/usr/lib/tvgw" in CHECK
    assert 'python3 -m venv "$VENV"' in CHECK


def test_the_install_check_runs_tvgw_and_its_imports_from_the_package():
    assert '[ "$have" = "tvgw $V" ]' in CHECK
    assert "-c 'import bscpylgtv, anthropic, yaml'" in CHECK
    assert (
        "echo 'wireshark-common wireshark-common/install-setuid boolean false' | debconf-set-selections"
        in CHECK
    )
    assert 'apt_get install -y "$DEB"' in CHECK


def test_the_install_check_installs_the_pinned_adguard_while_the_preinst_requires_it():
    """The block goes when the preinst's refusal goes, and not before: a package that needs AdGuard Home
    first is checked the way a user must install it, which is the release the preinst's hint names,
    aghinstall.PIN. Until 2026-11-05 the pin was the floor and the check installed the floor; from
    v0.107.80 the pin is above it, and the check follows the pin, at or above the floor."""
    preinst = PKG / "scripts" / "preinst"
    needs_adguard = preinst.exists() and "adguard_ok" in preinst.read_text(encoding="utf-8")
    has_block = "# ---- AdGuard Home first:" in CHECK
    assert has_block == needs_adguard, "install-check.sh's AdGuard Home block must follow the preinst"
    if has_block:
        (floor,) = re.findall(r"^AGH_MIN=(\S+)$", INSTALL, re.M)
        (version,) = re.findall(r"^AGH_VERSION=(\S+)$", CHECK, re.M)
        # (adguard) the pinned release and its hashes are aghinstall.PIN's, which virtual.yml fetches through
        # and tvgw adguard install installs, and the preinst's floor must accept it
        assert version == aghinstall.PIN["version"]
        assert tuple(int(x) for x in version.split(".")) >= tuple(int(x) for x in floor.split("."))
        for arch, (name, sha256) in aghinstall.PIN["assets"].items():
            assert name == f"AdGuardHome_linux_{arch}.tar.gz"
            assert f"{arch}) AGH_SHA256={sha256} ;;" in CHECK
        for arch in ("arm64", "amd64"):
            assert re.search(rf"^{arch}\) AGH_SHA256=[0-9a-f]{{64}} ;;$", CHECK, re.M)
        assert 'echo "$AGH_SHA256  $AGH_TAR" | sha256sum -c -' in CHECK


@pytest.mark.parametrize(
    ("deb", "says"),
    [
        ("tvgw_0.3.0-1_arm64.deb", "not a tvgw package for this computer's architecture (amd64)"),
        ("something_else.deb", "not a tvgw package for this computer's architecture (amd64)"),
    ],
)
def test_the_install_check_refuses_a_package_for_another_architecture(tmp_path, deb, says):
    (tmp_path / deb).write_text("x", encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "dpkg").write_text("#!/bin/sh\necho amd64\n", encoding="utf-8")
    (bin_dir / "dpkg").chmod(0o755)
    (bin_dir / "apt-get").write_text("#!/bin/sh\necho apt-get ran >&2\nexit 1\n", encoding="utf-8")
    (bin_dir / "apt-get").chmod(0o755)
    out = subprocess.run(
        ["sh", str(PKG / "install-check.sh"), str(tmp_path / deb)],
        env={"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"},
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert out.returncode == 1 and says in out.stderr
    assert "apt-get ran" not in out.stderr
