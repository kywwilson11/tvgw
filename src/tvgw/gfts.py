"""The vendor file-service URL filter: nginx access-log lines and biz_code extraction.

nginx log format (deploy/nginx/tvgw-gfts.conf):
    $time_iso8601 $remote_addr $status $body_bytes_sent $request_time "$host" "$request_uri"
    "$http_user_agent" $request_method $request_length "$upstream_status"

The last three fields were appended on 2026-10-27; a line without them still parses, with those
fields None. `$upstream_status` is `-` when nginx answered by itself, which is how the filter's own
403 is told from one the real host sent back.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from tvgw.adguard import parse_time

_LINE = re.compile(
    r'^(\S+) (\S+) (\d{3}) (\d+) (\S+) "([^"]*)" "([^"]*)" "([^"]*)"'
    r'(?: (\S+) (\d+) "([^"]*)")?'  # nginx joins several upstream attempts with ', ', hence the quotes
)
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
    method: str | None = None
    request_length: int | None = None
    upstream_status: str | None = None  # None: nginx answered by itself (or the line predates the field)

    @property
    def biz_code(self) -> str | None:
        return biz_code(self.uri)

    @property
    def blocked(self) -> bool:
        """The filter's own 403, not one the real host returned through the proxy."""
        return self.status == 403 and self.upstream_status is None


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
    method, length, upstream = m.group(9), m.group(10), m.group(11)
    return GftsRequest(
        t=t,
        client=m.group(2),
        status=int(m.group(3)),
        bytes=int(m.group(4)),
        host=m.group(6).lower(),
        uri=m.group(7),
        user_agent=m.group(8),
        method=method,
        request_length=int(length) if length else None,
        upstream_status=None if upstream in (None, "-") else upstream,
    )
