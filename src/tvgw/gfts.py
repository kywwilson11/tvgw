"""The vendor file-service URL filter: nginx access-log lines and biz_code extraction.

nginx log format (deploy/nginx/tvgw-gfts.conf):
    $time_iso8601 $remote_addr $status $body_bytes_sent $request_time "$host" "$request_uri" "$ua"
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from tvgw.adguard import parse_time

_LINE = re.compile(r'^(\S+) (\S+) (\d{3}) (\d+) (\S+) "([^"]*)" "([^"]*)" "([^"]*)"')
_BIZ = re.compile(r"biz_code=([A-Za-z_]+)")


@dataclass(frozen=True)
class GftsRequest:
    t: float
    client: str
    status: int
    bytes: int
    host: str
    uri: str
    user_agent: str

    @property
    def biz_code(self) -> str | None:
        return biz_code(self.uri)

    @property
    def blocked(self) -> bool:
        return self.status == 403


def biz_code(uri: str) -> str | None:
    m = _BIZ.search(uri)
    return m.group(1) if m else None


def parse_line(line: str) -> GftsRequest | None:
    m = _LINE.match(line)
    if not m:
        return None
    t = parse_time(m.group(1))
    if t is None:
        return None
    return GftsRequest(
        t=t,
        client=m.group(2),
        status=int(m.group(3)),
        bytes=int(m.group(4)),
        host=m.group(6).lower(),
        uri=m.group(7),
        user_agent=m.group(8),
    )
