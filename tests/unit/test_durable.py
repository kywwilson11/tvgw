"""(reliability) durable.replace(): the order a power cut cannot tear (bytes, fsync, mode, rename, the
directory's fsync), the failure paths that leave the old file, and the writers that go through it: the
machine's rules file, its restore after a failed site-rule change, and the live reading's give-up counts
(design decision 73). The cut itself is in tests/virtual/test_virtual_powercut.py."""

import errno
import os
import stat

import pytest

from tvgw import autoblock, durable, localrules, tvlive


class Recorder:
    """The os calls durable.replace makes, by name, each with whether it was about the temporary file,
    the target or the directory; every call goes on to the real function."""

    def __init__(self, monkeypatch, path):
        self.calls: list[tuple[str, str]] = []
        self.path = str(path)
        self.fds: dict[int, str] = {}
        real = {n: getattr(os, n) for n in ("write", "fsync", "chmod", "chown", "replace", "open", "close")}

        def what(x) -> str:
            if isinstance(x, int):
                return self.fds.get(x, "?")
            x = str(x)
            return "target" if x == self.path else "dir" if x == os.path.dirname(self.path) else "tmp"

        def wrap(name):
            def call(*a, **k):
                if name == "open":
                    fd = real["open"](*a, **k)
                    self.fds[fd] = what(a[0])
                    return fd
                if name != "close":
                    self.calls.append((name, what(a[0])))
                if name == "chown":  # not as root here: recorded, not done
                    return None
                return real[name](*a, **k)

            return call

        for name in real:
            monkeypatch.setattr(os, name, wrap(name))
        real_mkstemp = durable.tempfile.mkstemp

        def mkstemp(*a, **k):
            fd, tmp = real_mkstemp(*a, **k)
            self.fds[fd] = "tmp"
            return fd, tmp

        monkeypatch.setattr(durable.tempfile, "mkstemp", mkstemp)

    def order(self) -> list[tuple[str, str]]:
        """The calls with the writes run together into one."""
        out: list[tuple[str, str]] = []
        for c in self.calls:
            if not (out and c == out[-1] and c[0] == "write"):
                out.append(c)
        return out


def test_bytes_then_fsync_then_mode_then_rename_then_the_directory(tmp_path, monkeypatch):
    target = tmp_path / "auto.rules"
    target.write_text("old\n", encoding="utf-8")
    rec = Recorder(monkeypatch, target)
    durable.replace(str(target), "new\n" * 10_000, 0o640, owner=(0, 4))
    assert rec.order() == [
        ("write", "tmp"),
        ("fsync", "tmp"),
        ("chmod", "tmp"),
        ("chown", "tmp"),
        ("replace", "tmp"),
        ("fsync", "dir"),
    ]
    monkeypatch.undo()
    assert target.read_text(encoding="utf-8") == "new\n" * 10_000
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o640
    assert os.listdir(tmp_path) == ["auto.rules"]  # no temporary file left


def test_the_order_is_what_the_module_says_it_is(tmp_path, monkeypatch):
    """STEPS names the order for a reader; a reorder in the code fails here as well as above."""
    rec = Recorder(monkeypatch, tmp_path / "f")
    durable.replace(str(tmp_path / "f"), b"x", 0o600)
    names = [n for n, _ in rec.order()]
    assert names == ["write", "fsync", "chmod", "replace", "fsync"]
    assert durable.STEPS == ("write", "fsync", "chmod", "replace", "fsync_dir")


def test_a_rename_without_the_fsync_before_it_is_caught(tmp_path, monkeypatch):
    """The rule broken on purpose: the old autoblock writer's order, written out, fails the check the
    durable one passes."""

    def old_writer(path, text):
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)

    rec = Recorder(monkeypatch, tmp_path / "auto.rules")
    old_writer(str(tmp_path / "auto.rules"), "rules\n")
    names = [n for n, _ in rec.order()]
    assert "fsync" not in names[: names.index("replace")]  # the tear a cut can make
    assert names[-1] == "replace"  # and no directory fsync after it


@pytest.mark.parametrize("failing", ["write", "fsync", "replace"])
def test_a_failure_at_any_step_leaves_the_old_file_and_no_temporary_one(tmp_path, monkeypatch, failing):
    target = tmp_path / "tvgw.conf"
    target.write_text("KEEP=me\n", encoding="utf-8")

    def boom(*a, **k):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(os, failing, boom)
    with pytest.raises(OSError):
        durable.replace(str(target), "NEW=1\n", 0o640)
    monkeypatch.undo()
    assert target.read_text(encoding="utf-8") == "KEEP=me\n"
    assert os.listdir(tmp_path) == ["tvgw.conf"]


def test_a_new_file_gets_its_mode_and_a_str_is_utf8(tmp_path):
    target = tmp_path / "progress"
    durable.replace(str(target), "café", 0o600)
    assert target.read_bytes() == "café".encode()
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600


def writes_through_durable(monkeypatch) -> list[tuple[str, int]]:
    seen: list[tuple[str, int]] = []
    real = durable.replace

    def spy(path, data, mode=0o640, owner=None):
        seen.append((os.path.basename(path), mode))
        real(path, data, mode, owner)

    monkeypatch.setattr(durable, "replace", spy)
    return seen


def test_the_machines_rules_file_is_written_through_it(tmp_path, monkeypatch):
    seen = writes_through_durable(monkeypatch)
    path = str(tmp_path / "auto.rules")
    autoblock.add_rule(path, "||tracker.example^", "tvgw autoblock 2026-11-08: a tracker")
    assert autoblock.remove_rule(path, "||tracker.example^")
    assert seen == [("auto.rules", 0o640), ("auto.rules", 0o640)]
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o640


def test_the_rules_files_restore_is_written_through_it(tmp_path, monkeypatch):
    seen = writes_through_durable(monkeypatch)
    localrules.write_auto(str(tmp_path / "auto.rules"), "! header\n")
    assert seen == [("auto.rules", 0o640)]


def test_the_live_readings_give_up_counts_are_written_through_it(tmp_path, monkeypatch):
    seen = writes_through_durable(monkeypatch)
    path = str(tmp_path / "tvlive-progress")
    tvlive.write_progress(path, {"refusals": 2})
    assert seen == [("tvlive-progress", 0o600)]
    assert tvlive.read_progress(path) == {"refusals": 2}
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
