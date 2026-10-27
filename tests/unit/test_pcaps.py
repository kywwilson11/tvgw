"""The pcap directory as a store: which file tcpdump is writing, read from a /proc tree, and which are finished."""

import os
from pathlib import Path

# bound at import, before the autouse `fake_live` fixture replaces the module attribute for ingest
from tvgw.pcaps import finished, live_files


def test_finished_excludes_the_live_file_and_sorts_by_name(tmp_path):
    for name in ("tv-b.pcap", "tv-a.pcap", "tv-c.pcap"):
        (tmp_path / name).write_bytes(b"")
    (tmp_path / "notes.txt").write_text("not a capture")
    live = {os.path.realpath(tmp_path / "tv-b.pcap")}
    assert finished(str(tmp_path), live) == [str(tmp_path / "tv-a.pcap"), str(tmp_path / "tv-c.pcap")]
    assert finished(str(tmp_path), set()) == [str(tmp_path / f"tv-{x}.pcap") for x in "abc"]


def fake_proc(root: Path, processes: dict[str, tuple[str, dict[str, str]]]) -> str:
    """A /proc tree: pid -> (comm, {fd: link target}), plus the entries that are not processes."""
    for pid, (comm, fds) in processes.items():
        (root / pid / "fd").mkdir(parents=True)
        (root / pid / "comm").write_text(comm + "\n")
        for fd, target in fds.items():
            os.symlink(target, root / pid / "fd" / fd)
    (root / "self").mkdir(parents=True)
    (root / "meminfo").write_text("")
    return str(root)


def test_live_files_are_the_pcaps_in_the_directory_that_a_tcpdump_holds_open(tmp_path):
    pcap_dir, elsewhere = tmp_path / "pcap", tmp_path / "elsewhere"
    pcap_dir.mkdir()
    elsewhere.mkdir()
    proc = fake_proc(
        tmp_path / "proc",
        {
            "100": (
                "tcpdump",
                {
                    "0": "/dev/null",
                    "3": str(pcap_dir / "tv-live.pcap"),
                    "4": str(elsewhere / "other.pcap"),  # another capture in another directory
                    "5": f"{pcap_dir / 'tv-gone.pcap'} (deleted)",  # pruned under tcpdump: still being written
                    "6": "socket:[12345]",
                    "7": str(pcap_dir / "notes.txt"),
                },
            ),
            "200": ("bash", {"3": str(pcap_dir / "tv-read-by-a-shell.pcap")}),  # a reader, not the writer
            "300": ("tcpdump", {}),  # a second capture with nothing open yet
        },
    )
    (tmp_path / "proc" / "400").mkdir()  # ended between the listing and the read: no comm file
    assert live_files(str(pcap_dir), proc=proc) == {
        os.path.realpath(pcap_dir / "tv-live.pcap"),
        os.path.realpath(pcap_dir / "tv-gone.pcap"),
    }


def test_live_files_is_unknown_when_a_tcpdumps_descriptors_cannot_be_listed(tmp_path, monkeypatch):
    proc = fake_proc(tmp_path / "proc", {"100": ("tcpdump", {})})
    real_listdir = os.listdir

    def denied(path):
        if str(path).endswith(os.path.join("100", "fd")):
            raise PermissionError(13, "Permission denied", str(path))
        return real_listdir(path)

    monkeypatch.setattr(os, "listdir", denied)
    assert live_files(str(tmp_path / "pcap"), proc=proc) is None


def test_live_files_is_unknown_without_proc(tmp_path):
    assert live_files(str(tmp_path), proc=str(tmp_path / "no-proc")) is None
