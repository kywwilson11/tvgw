"""Incremental reading of growing log files, surviving both rotation styles.

logrotate `copytruncate` keeps the inode and shrinks the file (the old content is in `path.1`);
AdGuard and most daemons rename the file to `path.1` and start a new inode. Either way the lines
written between our last read and the rotation must not be lost, and a partial trailing line is
left for the next call.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class TailState:
    inode: int | None = None
    offset: int = 0


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


def read_new_lines(path: str, state: TailState) -> tuple[list[str], TailState]:
    """New complete lines since `state`, and the state to store for next time."""
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return [], state
    lines: list[str] = []
    offset = state.offset
    rotated = path + ".1"
    if state.inode is not None:
        rst = None
        if os.path.exists(rotated):
            try:
                rst = os.stat(rotated)
            except FileNotFoundError:
                rst = None
        copytruncated = st.st_ino == state.inode and st.st_size < state.offset
        renamed = st.st_ino != state.inode
        if (
            rst is not None
            and (copytruncated or (renamed and rst.st_ino == state.inode))
            and rst.st_size > offset
        ):
            with open(rotated, "rb") as fh:
                fh.seek(offset)
                lines.extend(_complete_lines(fh))
        if copytruncated or renamed:
            offset = 0
    elif st.st_size < offset:
        offset = 0
    with open(path, "rb") as fh:
        fh.seek(offset)
        lines.extend(_complete_lines(fh))
        new_offset = fh.tell()
    return lines, replace(state, inode=st.st_ino, offset=new_offset)
