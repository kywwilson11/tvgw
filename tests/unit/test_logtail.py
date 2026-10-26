"""Incremental log reading across copytruncate and rename rotation."""

import os

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
    assert st2.inode == os.stat(p).st_ino and st2.offset == 2


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
    assert st2.inode == os.stat(p).st_ino


def test_shrunk_file_without_dot1_restarts_from_zero(tmp_path):
    p = tmp_path / "a.log"
    p.write_bytes(b"aaaa\nbbbb\n")
    _, st = read_new_lines(str(p), TailState())
    p.write_bytes(b"x\n")
    lines, _ = read_new_lines(str(p), st)
    assert lines == ["x"]


def test_invalid_utf8_is_replaced_not_fatal(tmp_path):
    p = tmp_path / "a.log"
    p.write_bytes(b"ok\xff\xfe\n")
    lines, _ = read_new_lines(str(p), TailState())
    assert lines == ["ok��"]
