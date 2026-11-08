"""(reliability) One file replaced whole, in an order a power cut cannot tear (design decision 73).

A new file beside the old one, its bytes written and fsynced, its mode set, renamed over the old name,
and the directory fsynced. A cut at any instant leaves the old file or the new one, never a short or empty
one, and once `replace()` returns the new one survives a cut too. A file renamed into place without the
first fsync can surface empty after a cut on a filesystem that allocates late, and one without the last
can come back as the old file after the caller acted on the new one. `tests/virtual/test_virtual_powercut.py`
cuts the power under it at the block device; `tests/unit/test_durable.py` holds the order.
"""

from __future__ import annotations

import contextlib
import os
import tempfile

# the steps, as the tests record them: each name is the os function it calls
STEPS = ("write", "fsync", "chmod", "replace", "fsync_dir")


def replace(path: str, data: str | bytes, mode: int = 0o640, owner: tuple[int, int] | None = None) -> None:
    """Put `data` (str is written as UTF-8) at `path` whole, with `mode` and, given, `owner` (uid, gid).
    The temporary file starts with a dot and the target's name, beside it, so the rename never crosses a
    filesystem; on any failure it is removed and the old file is left as it was. Raises OSError."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    blob = data.encode("utf-8") if isinstance(data, str) else data
    fd, tmp = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.", dir=directory)
    try:
        try:
            view = memoryview(blob)
            while view:
                view = view[os.write(fd, view) :]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.chmod(tmp, mode)
        if owner is not None:
            os.chown(tmp, *owner)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    sync_dir(directory)


def sync_dir(directory: str) -> None:
    """fsync a directory, so the names it holds survive a cut as they are now."""
    dfd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
