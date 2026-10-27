"""Incremental reading of growing log files, surviving both rotation styles.

logrotate `copytruncate` keeps the inode and shrinks the file (the old content is in `path.1`);
AdGuard and most daemons rename the file to `path.1` and start a new inode. Either way the lines
written between our last read and the rotation must not be lost, and a partial trailing line is
left for the next call. A copytruncated file that has already grown past our old offset looks like
plain growth by size alone, so the state also keeps the file's first bytes: a different beginning
means a different file.

Everything about the live file (identity, size, fingerprint, the read) comes from one descriptor,
so a rotation between two of those steps cannot pair the old file's inode with the new file's
offset. When lines are known to be lost (rotated twice, or truncated with no `.1` of ours) the
returned state says so in `gap`, which the caller reports and nobody stores.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, replace

HEAD = 64  # bytes of the file's beginning kept as its fingerprint


@dataclass(frozen=True)
class TailState:
    inode: int | None = None
    offset: int = 0
    head: bytes = b""
    gap: bool = False  # lines before this read could not be recovered; for the caller, never persisted


def _complete_lines(fh) -> list[str]:
    out: list[str] = []
    while True:
        pos = fh.tell()
        raw = fh.readline()
        if not raw:
            return out
        if not raw.endswith(b"\n"):
            fh.seek(pos)
            return out
        out.append(raw.decode("utf-8", "replace").rstrip("\n"))


def _head(path: str) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(HEAD)
    except OSError:
        return b""


def _same_file(head_now: bytes, head_then: bytes) -> bool:
    """Does the file still begin the way it did? A short stored head (the file was tiny) is compared
    on what it has."""
    if not head_then:
        return True
    n = min(len(head_then), len(head_now)) if len(head_then) < HEAD else HEAD
    return head_now[:n] == head_then[:n] if head_now else False


def read_new_lines(path: str, state: TailState) -> tuple[list[str], TailState]:
    """New complete lines since `state`, and the state to store for next time."""
    try:
        with open(path, "rb") as fh:
            return _read(fh, path, state)
    except FileNotFoundError:
        return [], state


def _read(fh, path: str, state: TailState) -> tuple[list[str], TailState]:
    st = os.fstat(fh.fileno())
    head_now = fh.read(HEAD)
    lines: list[str] = []
    offset = state.offset
    gap = False
    if state.inode is not None:
        rotated = path + ".1"
        try:
            rst = os.stat(rotated)
        except FileNotFoundError:
            rst = None
        same_inode = st.st_ino == state.inode
        copytruncated = same_inode and (st.st_size < offset or not _same_file(head_now, state.head))
        renamed = not same_inode
        rotated_is_ours = rst is not None and (
            (renamed and rst.st_ino == state.inode)
            or (copytruncated and _same_file(_head(rotated), state.head))
        )
        if rotated_is_ours and rst.st_size > offset:
            try:
                with open(rotated, "rb") as old:
                    old.seek(offset)
                    lines.extend(_complete_lines(old))
            except FileNotFoundError:  # rotated again between the stat and the read
                gap = True
        if copytruncated or renamed:
            offset = 0
            gap = gap or not rotated_is_ours
    elif st.st_size < offset:
        offset = 0
        gap = True
    fh.seek(offset)
    lines.extend(_complete_lines(fh))
    return lines, replace(state, inode=st.st_ino, offset=fh.tell(), head=head_now, gap=gap)
