"""Incremental reading of growing log files, surviving both rotation styles.

logrotate `copytruncate` keeps the inode and shrinks the file (the old content is in `path.1`);
AdGuard and most daemons rename the file to `path.1` and start a new inode. Either way the lines
written between our last read and the rotation must not be lost, and a partial trailing line is
left for the next call. A copytruncated file that has already grown past our old offset looks like
plain growth by size alone, so the state also keeps the file's first bytes: a different beginning
means a different file.

Everything about a file (identity, size, fingerprint, the read) comes from one descriptor, for the
live file and for its rotated copy alike, so a rotation between two of those steps cannot pair one
file's inode with another file's offset. When lines are known to be lost (rotated twice, or
truncated with no `.1` of ours) the returned state says so in `gap`, which the caller reports and
nobody stores.
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


def _complete_lines(fh, limit: int | None = None) -> list[str]:
    """Complete lines from the current position, at most `limit`; the file is left after the last
    one returned, so a partial last line waits for the next call."""
    out: list[str] = []
    while limit is None or len(out) < limit:
        pos = fh.tell()
        raw = fh.readline()
        if not raw.endswith(b"\n"):  # EOF, or a line still being written
            fh.seek(pos)
            break
        out.append(raw.decode("utf-8", "replace").rstrip("\n"))
    return out


def _same_file(head_now: bytes, head_then: bytes) -> bool:
    """Does the file still begin the way it did? A short stored head (the file was tiny) is compared
    on what it has."""
    if not head_then:
        return True
    n = min(len(head_then), len(head_now)) if len(head_then) < HEAD else HEAD
    return head_now[:n] == head_then[:n] if head_now else False


def read_new_lines(path: str, state: TailState, max_lines: int | None = None) -> tuple[list[str], TailState]:
    """New complete lines since `state`, and the state to store for next time. `max_lines` bounds
    what is read from the live file; the remainder of a rotated `path.1` is always read whole (it is
    at most one rotation period behind). Call again with the returned state until fewer than
    `max_lines` lines come back."""
    try:
        with open(path, "rb") as fh:
            return _read(fh, path, state, max_lines)
    except FileNotFoundError:
        return [], state


def _read(fh, path: str, state: TailState, max_lines: int | None) -> tuple[list[str], TailState]:
    st = os.fstat(fh.fileno())
    head_now = fh.read(HEAD)
    lines: list[str] = []
    offset = state.offset
    gap = False
    if state.inode is not None:
        renamed = st.st_ino != state.inode
        copytruncated = not renamed and (st.st_size < offset or not _same_file(head_now, state.head))
        if renamed or copytruncated:
            lines, gap = _remainder(path + ".1", state, renamed)
            offset = 0
    elif st.st_size < offset:
        offset = 0
        gap = True
    fh.seek(offset)
    lines.extend(_complete_lines(fh, max_lines))
    return lines, replace(state, inode=st.st_ino, offset=fh.tell(), head=head_now, gap=gap)


def _remainder(rotated: str, state: TailState, renamed: bool) -> tuple[list[str], bool]:
    """What our file still owed us when it was rotated to `rotated`: the complete lines past our
    offset, or a gap when the file there is not ours (rotated twice, or truncated with no copy). A
    renamed file keeps its inode; a copytruncate copy keeps only its beginning."""
    try:
        with open(rotated, "rb") as old:
            ours = (
                os.fstat(old.fileno()).st_ino == state.inode
                if renamed
                else _same_file(old.read(HEAD), state.head)
            )
            if not ours:
                return [], True
            old.seek(state.offset)
            return _complete_lines(old), False
    except FileNotFoundError:
        return [], True
