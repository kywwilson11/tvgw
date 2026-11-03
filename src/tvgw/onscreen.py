"""On-screen confirmations: the owner's dated word on a TV setting the TV does not report.

Some TVs cannot say whether their Wi-Fi is off or a privacy setting is declined: a Samsung read without
pairing, a TV with no LAN API, a menu the TV's reader does not cover. For those the owner looks at the
TV and answers, and the answer is kept with its time. It is never inferred, and `unknown` is an answer
of its own, for a setting the owner could not find, so nobody has to answer yes falsely to finish.

`record()` appends one line per answer to `/var/lib/tvgw/onscreen.log`:

    <local time, ISO 8601 with its UTC offset>\\tonscreen.<setting>\\t<value>

and `latest()` reads the newest answer for each setting back. The file holds the setting, the value and
the time, never an address, a name or anything the TV sent; it is root's, group `adm`, mode 0640, like
the TV's readings beside it, and `tvgw forget` keeps it with the TV's settings history
(forget.STATE_ENTRIES).
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime

LOG = "/var/lib/tvgw/onscreen.log"  # in the state directory; log_path() follows a moved STATE_DIR
MODE = 0o640  # root and adm, as tvcheck.txt: it says when the owner last looked at the TV
PREFIX = "onscreen."  # the key a confirmation is known by: onscreen.<setting>
SWITCH = ("on", "off", "unknown")  # a setting the TV has a switch for
DONE = ("yes", "no", "unknown")  # a step the owner did, or did not, on the TV
# setting -> the answers it takes. A setting nobody named here is refused, so the log never gains a
# key the brief cannot read, and an answer of the wrong kind (`wifi-forgotten off`) never reads as one
SETTINGS: dict[str, tuple[str, ...]] = {
    "viewing-info": SWITCH,  # the TV's viewing information (ACR) service
    "interest-ads": SWITCH,  # interest-based advertising
    "voice": SWITCH,  # the TV's voice information service
    "mic-switch": SWITCH,  # the microphone switch on the TV or its remote
    "wifi-forgotten": DONE,  # Wi-Fi switched off and every saved network forgotten
}
_LINE = re.compile(
    r"(?P<stamp>[^\t]+)\t" + re.escape(PREFIX) + r"(?P<setting>[a-z][a-z-]*)\t(?P<value>[a-z]+)"
)


@dataclass(frozen=True)
class Confirmation:
    setting: str
    value: str
    t: float  # seconds since the epoch, whole: the log keeps the time to the second

    @property
    def key(self) -> str:
        return PREFIX + self.setting


def log_path(state_dir: str) -> str:
    """The log in a given state directory (Settings.state_dir), for a gateway whose STATE_DIR moved."""
    return os.path.join(state_dir, os.path.basename(LOG))


def stamp(t: float) -> str:
    """The local time of `t` with its UTC offset, to the second: readable in the gateway's own time, and
    exact through a daylight-saving change, when one local hour happens twice."""
    return datetime.fromtimestamp(t, UTC).astimezone().isoformat(timespec="seconds")


def record(setting: str, value: str, path: str = LOG) -> Confirmation:
    """Append the owner's answer for one setting, now. Refuses a setting SETTINGS does not name, or an
    answer the setting does not take, with ValueError and nothing written. The file is created 0640 and
    set back to 0640 on every write; a symbolic link in its place is refused, not followed. The line is
    one write to a file opened for appending, then fsynced. A line an earlier write left cut short (a
    full disk, a power cut) is ended first, so this answer starts a line of its own: parse() skips the
    broken line and nothing else."""
    allowed = SETTINGS.get(setting)
    if allowed is None:
        raise ValueError(f"unknown on-screen setting {setting!r}: one of {', '.join(SETTINGS)}")
    if value not in allowed:
        raise ValueError(f"{setting} takes {', '.join(allowed)}, not {value!r}")
    t = float(int(time.time()))
    data = f"{stamp(t)}\t{PREFIX}{setting}\t{value}\n".encode()
    fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, MODE)
    try:
        os.fchmod(fd, MODE)
        size = os.fstat(fd).st_size
        if size and os.pread(fd, 1, size - 1) != b"\n":  # appended to, the cut line would hide this answer
            data = b"\n" + data
        while data:  # a regular file takes the whole line at once; a short write only on a full disk
            data = data[os.write(fd, data) :]
        os.fsync(fd)
    finally:
        os.close(fd)
    return Confirmation(setting, value, t)


def parse(line: str) -> Confirmation | None:
    """One log line, or None when it is not one record() could have written: a line cut short by a full
    disk, a setting or an answer this version does not know, a time without its offset."""
    m = _LINE.fullmatch(line.rstrip("\n"))
    if not m or m["value"] not in SETTINGS.get(m["setting"], ()):
        return None
    try:
        when = datetime.fromisoformat(m["stamp"])
    except ValueError:
        return None
    if when.tzinfo is None:
        return None
    return Confirmation(m["setting"], m["value"], when.timestamp())


def latest(path: str = LOG) -> dict[str, Confirmation]:
    """The newest answer for each setting, by the order the answers were given (the file's order, which a
    clock set back cannot reorder). No file: no answers. A line parse() refuses is skipped, so one bad
    line never hides the others. Any other error reading the file is raised: an answer that cannot be
    read must not look like an answer never given."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except FileNotFoundError:
        return {}
    found: dict[str, Confirmation] = {}
    for line in lines:
        c = parse(line)
        if c is not None:
            found[c.setting] = c
    return found
