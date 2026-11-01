"""Build the .deb's offline wheelhouse from the committed, hash-pinned lock.

Every dependency in packaging/requirements.lock is fetched with `pip download --require-hashes`, so a
file PyPI serves that the lock does not list is refused at build time. Most dependencies publish
wheels: one per target interpreter is fetched for the target machine. A few publish only a source
archive (sqlitedict, which bscpylgtv needs): the archive is fetched against the lock's hash and built
into a wheel here, because the gateway installs offline and has no build backend to hand. The build
runs without build isolation, with the backend build-deb.sh installed from build-requirements.lock
into the interpreter running this, so no unpinned setuptools is fetched for it.

The lock the package carries is the committed one with the hash of each wheel built here added to
its requirement, so the gateway's `pip install --require-hashes` checks every file it installs,
built or downloaded. Nothing else in the lock changes. Standard library only: this runs before any
virtualenv exists, in CI and on a workstation.

    python3 packaging/wheelhouse.py --lock packaging/requirements.lock --dest build/deb \
        --machine aarch64 --python 3.11 --python 3.13
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path

# `name==version [; marker] \` then `--hash=sha256:<hex> \` lines, as uv and pip-tools write them
_REQ = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)\s*(?:;\s*([^\\]+?))?\s*\\?\s*$")
_HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})")
PYPI_JSON = "https://pypi.org/pypi/{name}/{version}/json"
# glibc baselines the wheels may target: Debian 12 has 2.36, Debian 13 2.41, Ubuntu 24.04 2.39
MANYLINUX = ("manylinux2014", "manylinux_2_17", "manylinux_2_28", "manylinux_2_34", "manylinux_2_36")


@dataclass(frozen=True)
class Req:
    """One pinned requirement of the lock: what pip is told to fetch, and the files it may accept."""

    name: str
    version: str
    marker: str
    hashes: tuple[str, ...]

    @property
    def pin(self) -> str:
        return f"{self.name}=={self.version}" + (f" ; {self.marker}" if self.marker else "")


def parse_lock(text: str) -> list[Req]:
    """The lock's requirements in order. A requirement that is not pinned with `==`, or has no
    hash, is an error: either would let pip pick a file the lock never named."""
    reqs: list[Req] = []
    name = version = marker = ""
    hashes: list[str] = []

    def close() -> None:
        if name:
            if not hashes:
                raise ValueError(f"{name}=={version} in the lock has no --hash")
            reqs.append(Req(name, version, marker, tuple(hashes)))

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("--hash="):
            m = _HASH.search(line)
            if not m or not name:
                raise ValueError(f"a hash line outside a requirement: {raw!r}")
            hashes.append(m.group(1))
            continue
        m = _REQ.match(line)
        if not m:
            raise ValueError(f"not a pinned requirement: {raw!r}")
        close()
        name, version, marker = m.group(1), m.group(2), (m.group(3) or "").strip()
        hashes = []
    close()
    return reqs


def with_built_hashes(text: str, built: dict[str, list[str]]) -> str:
    """The lock text with each built wheel's hash added to its requirement's hash list, everything
    else byte for byte. `built` maps a normalized name to the sha256 of the wheels made for it."""
    out: list[str] = []
    lines = text.splitlines()
    current = ""
    for i, raw in enumerate(lines):
        m = _REQ.match(raw.strip()) if raw.strip() and not raw.lstrip().startswith(("#", "--")) else None
        if m:
            current = normalize(m.group(1))
        out.append(raw)
        nxt = lines[i + 1].strip() if i + 1 < len(lines) else ""
        if current in built and raw.strip().startswith("--hash=") and not nxt.startswith("--hash="):
            # the last hash of the requirement: continue the line, then the new hashes
            out[-1] = raw.rstrip() + " \\"
            extra = [f"    --hash=sha256:{h}" for h in built[current]]
            out += [h + " \\" for h in extra[:-1]] + extra[-1:]
            current = ""
    return "\n".join(out) + "\n"


def normalize(name: str) -> str:
    """PEP 503: names compare case-insensitively with runs of -, _ and . as one -."""
    return re.sub(r"[-_.]+", "-", name).lower()


def has_wheels(release: dict) -> bool:
    """Does this release (PyPI's JSON for name/version) publish any wheel at all?"""
    return any(f.get("packagetype") == "bdist_wheel" for f in release.get("urls", []))


def pypi_release(name: str, version: str) -> dict:
    with urllib.request.urlopen(PYPI_JSON.format(name=name, version=version), timeout=60) as resp:
        return json.load(resp)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def requirements_file(reqs: list[Req], path: Path) -> Path:
    path.write_text(
        "".join(r.pin + " " + " ".join(f"--hash=sha256:{h}" for h in r.hashes) + "\n" for r in reqs),
        encoding="utf-8",
    )
    return path


def pip(*args: str) -> None:
    subprocess.run([sys.executable, "-m", "pip", "-q", "--disable-pip-version-check", *args], check=True)


def build(
    lock: Path, dest: Path, machine: str, pythons: list[str], release=pypi_release
) -> dict[str, list[str]]:
    """Fill dest/wheels and write dest/requirements.lock; returns the hashes of the wheels built here."""
    text = lock.read_text(encoding="utf-8")
    reqs = parse_lock(text)
    wheels = dest / "wheels"
    wheels.mkdir(parents=True, exist_ok=True)
    binary = [r for r in reqs if has_wheels(release(r.name, r.version))]
    source = [r for r in reqs if r not in binary]
    built: dict[str, list[str]] = {}
    with tempfile.TemporaryDirectory() as tmp:
        if binary:
            req_file = requirements_file(binary, Path(tmp) / "binary.txt")
            platforms = ["--platform", "any"]
            for tag in MANYLINUX:
                platforms += ["--platform", f"{tag}_{machine}"]
            for py in pythons:
                abis = ("--abi", "cp" + py.replace(".", ""), "--abi", "abi3", "--abi", "none")
                fetch = ["download", "--no-deps", "--require-hashes", "--only-binary=:all:"]
                fetch += ["--implementation", "cp", "--python-version", py, *abis, *platforms]
                pip(*fetch, "--dest", str(wheels), "-r", str(req_file))
        for r in source:
            sdists = Path(tmp) / normalize(r.name)
            req_file = requirements_file([r], Path(tmp) / f"{normalize(r.name)}.txt")
            # the archive's metadata is prepared by the pinned backend too, not an isolated one
            fetch = ["download", "--no-deps", "--require-hashes", "--no-binary=:all:", "--no-build-isolation"]
            pip(*fetch, "--dest", str(sdists), "-r", str(req_file))
            before = set(wheels.glob("*.whl"))
            (sdist,) = sdists.iterdir()
            pip("wheel", "--no-deps", "--no-build-isolation", "--wheel-dir", str(wheels), str(sdist))
            made = sorted(set(wheels.glob("*.whl")) - before)
            if not made or not all(w.name.endswith("-none-any.whl") for w in made):
                raise SystemExit(f"wheelhouse: {r.name} built {made}, not one pure-Python wheel")
            built[normalize(r.name)] = [sha256(w) for w in made]
    out = with_built_hashes(text, built)
    carried = {normalize(r.name): set(r.hashes) for r in parse_lock(out)}
    for name, hashes in built.items():  # the gateway's pip would refuse a wheel the lock does not list
        if not set(hashes) <= carried[name]:
            raise SystemExit(f"wheelhouse: could not add the built {name} wheel's hash to the lock")
    (dest / "requirements.lock").write_text(out, encoding="utf-8")
    return built


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--lock", type=Path, required=True)
    ap.add_argument("--dest", type=Path, required=True)
    ap.add_argument("--machine", required=True, choices=("aarch64", "x86_64"))
    ap.add_argument("--python", action="append", required=True, help="a target interpreter, e.g. 3.13")
    a = ap.parse_args(argv)
    built = build(a.lock, a.dest, a.machine, a.python)
    for name, hashes in built.items():
        print(f"wheelhouse: built {name} from its source archive ({len(hashes)} wheel)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
