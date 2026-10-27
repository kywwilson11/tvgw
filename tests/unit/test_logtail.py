"""Incremental log reading across copytruncate and rename rotation."""

import builtins
import os

from tvgw import logtail
from tvgw.logtail import TailState, read_new_lines


def test_reads_only_complete_lines_and_resumes(tmp_path):
    p = tmp_path / "a.log"
    p.write_bytes(b"one\ntwo\nthr")
    lines, st = read_new_lines(str(p), TailState())
    assert lines == ["one", "two"]
    with open(p, "ab") as fh:
        fh.write(b"ee\nfour\n")
    lines, st = read_new_lines(str(p), st)
    assert lines == ["three", "four"]
    assert read_new_lines(str(p), st)[0] == []


def test_missing_file_is_not_an_error(tmp_path):
    lines, st = read_new_lines(str(tmp_path / "nope.log"), TailState(inode=1, offset=5))
    assert lines == [] and st == TailState(inode=1, offset=5)


def test_copytruncate_rotation_recovers_lines_from_dot1(tmp_path):
    p = tmp_path / "a.log"
    p.write_bytes(b"a\nb\n")
    _, st = read_new_lines(str(p), TailState())
    with open(p, "ab") as fh:
        fh.write(b"c\n")  # written after our read, before rotation
    (tmp_path / "a.log.1").write_bytes(p.read_bytes())  # logrotate copies...
    p.write_bytes(b"d\n")  # ...then truncates in place (same inode) and new lines arrive
    lines, st2 = read_new_lines(str(p), st)
    assert lines == ["c", "d"]
    assert st2.inode == os.stat(p).st_ino and st2.offset == 2 and not st2.gap


def test_rename_rotation_recovers_lines_from_dot1(tmp_path):
    p = tmp_path / "q.json"
    p.write_bytes(b"1\n2\n")
    _, st = read_new_lines(str(p), TailState())
    with open(p, "ab") as fh:
        fh.write(b"3\n")
    os.rename(p, tmp_path / "q.json.1")  # daemon renames and opens a fresh file
    p.write_bytes(b"4\n")
    lines, st2 = read_new_lines(str(p), st)
    assert lines == ["3", "4"]
    assert st2.inode == os.stat(p).st_ino and not st2.gap


def test_shrunk_file_without_dot1_restarts_from_zero(tmp_path):
    p = tmp_path / "a.log"
    p.write_bytes(b"aaaa\nbbbb\n")
    _, st = read_new_lines(str(p), TailState())
    p.write_bytes(b"x\n")
    lines, st2 = read_new_lines(str(p), st)
    assert lines == ["x"] and st2.gap  # whatever was written before the truncation is gone, and said so


def test_invalid_utf8_is_replaced_not_fatal(tmp_path):
    p = tmp_path / "a.log"
    p.write_bytes(b"ok\xff\xfe\n")
    lines, _ = read_new_lines(str(p), TailState())
    assert lines == ["ok��"]


def test_copytruncate_that_regrew_past_the_old_offset_is_not_read_mid_line(tmp_path):
    """The reviewer's case: after copytruncate the new file is already longer than our offset, so size
    alone says 'plain growth'. The head fingerprint says otherwise."""
    from tvgw.logtail import TailState, read_new_lines

    log = tmp_path / "x.log"
    log.write_text("one\ntwo\n")
    lines, st = read_new_lines(str(log), TailState())
    assert lines == ["one", "two"] and st.head == b"one\ntwo\n"
    log.write_text("one\ntwo\nthree-written-after-our-read\n")  # grows before the rotation
    (tmp_path / "x.log.1").write_bytes(log.read_bytes())  # copytruncate: copy ...
    log.write_text("")  # ... truncate ...
    log.write_text(
        "a-much-longer-first-line-than-before\nnew-2\nnew-3\n"
    )  # ... and regrow past the old offset
    lines, st2 = read_new_lines(str(log), st)
    assert lines == ["three-written-after-our-read", "a-much-longer-first-line-than-before", "new-2", "new-3"]
    assert st2.offset == len("a-much-longer-first-line-than-before\nnew-2\nnew-3\n")
    lines, _ = read_new_lines(str(log), st2)
    assert lines == []


def test_plain_growth_with_a_short_initial_head_is_not_mistaken_for_truncation(tmp_path):
    from tvgw.logtail import TailState, read_new_lines

    log = tmp_path / "y.log"
    log.write_text("ab\n")  # shorter than the fingerprint window
    lines, st = read_new_lines(str(log), TailState())
    assert lines == ["ab"] and st.head == b"ab\n"
    log.write_text("ab\n" + "c" * 100 + "\n")
    lines, st2 = read_new_lines(str(log), st)
    assert lines == ["c" * 100] and st2.offset == len("ab\n" + "c" * 100 + "\n")


def test_a_rotation_between_our_open_and_read_is_seen_on_the_next_run(tmp_path, monkeypatch):
    """With stat, fingerprint and read done by name, a rename between them saved the old inode with
    the new file's offset, and the next run replayed a torn line and two duplicates. One descriptor
    serves all three, so the saved identity is the file that was read."""
    p = tmp_path / "a.log"
    p.write_bytes(b"one\ntwo\n")
    _, st = read_new_lines(str(p), TailState())
    real_open = builtins.open
    rotated = []

    def rotating_open(file, *args, **kwargs):
        if str(file) == str(p) and not rotated:  # the daemon rotates just as we come to read
            rotated.append(True)
            with real_open(p, "ab") as fh:
                fh.write(b"late\n")
            os.rename(p, tmp_path / "a.log.1")
            with real_open(p, "wb") as fh:
                fh.write(b"three\n")
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", rotating_open)
    lines, st2 = read_new_lines(str(p), st)
    assert lines == ["late", "three"] and not st2.gap
    assert st2.inode == os.stat(p).st_ino and st2.offset == len(b"three\n")
    assert read_new_lines(str(p), st2)[0] == []


def test_a_rotation_between_our_open_and_fstat_is_seen_on_the_next_run(tmp_path, monkeypatch):
    """The other interleaving: we hold the old file open when the daemon rotates it. Its identity,
    fingerprint and lines all come from that descriptor, so what is saved is the file that was read,
    and the new file's lines come exactly once on the next run."""
    p = tmp_path / "a.log"
    p.write_bytes(b"one\ntwo\n")
    _, st = read_new_lines(str(p), TailState())
    real_fstat = os.fstat
    rotated = []

    def rotating_fstat(fd):
        if not rotated:
            rotated.append(True)
            with open(p, "ab") as fh:
                fh.write(b"late\n")
            os.rename(p, tmp_path / "a.log.1")
            p.write_bytes(b"three\n")
        return real_fstat(fd)

    monkeypatch.setattr(logtail.os, "fstat", rotating_fstat)
    lines, st2 = read_new_lines(str(p), st)
    assert lines == ["late"] and not st2.gap and st2.inode == os.stat(tmp_path / "a.log.1").st_ino
    lines, st3 = read_new_lines(str(p), st2)
    assert lines == ["three"] and not st3.gap and st3.inode == os.stat(p).st_ino
    assert read_new_lines(str(p), st3)[0] == []


def test_a_dot1_that_vanishes_before_we_can_open_it_leaves_a_gap_not_an_error(tmp_path, monkeypatch):
    p = tmp_path / "q.json"
    p.write_bytes(b"1\n2\n")
    _, st = read_new_lines(str(p), TailState())
    with open(p, "ab") as fh:
        fh.write(b"3\n")
    os.rename(p, tmp_path / "q.json.1")
    p.write_bytes(b"4\n")
    real_open = builtins.open

    def vanishing_open(file, *args, **kwargs):
        if str(file).endswith("q.json.1"):
            raise FileNotFoundError(file)
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", vanishing_open)
    lines, st2 = read_new_lines(str(p), st)
    assert (lines, st2.gap) == (["4"], True)
