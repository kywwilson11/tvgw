"""What the gateway may print where others read it: text with the home's identifiers replaced.

The CI hardware job's log on a public repository, a check's detail, a report a user is asked to
attach: each can carry the router's address, the uplink's addresses, a MAC, a USB adapter's name
(which embeds its MAC), the computer's host name, the name typed for the TV, a Wi-Fi network's name or
a home directory's user name (design decision 63). `scrub()` replaces each with a fixed placeholder:

- every IPv4 and IPv6 address outside `TV_NET` with `<lan address>`, or `<public address>` when it is
  a global one, and the router's with `<router>`. Kept as written: addresses inside `TV_NET`, the
  addresses tvgw ships (`keep`: the DoH upstreams and resolvers of decision 9, the DoH block list,
  the public addresses in the code), and the ones that name no site (unspecified, loopback,
  multicast, the limited broadcast). The gateway's own home-side addresses (`uplink_addrs`) are
  replaced even where one of those rules would keep them;
- every MAC address, a run of six or more two-digit hex groups, with `<mac>`;
- every `enx` or `wlx` interface name with 12 hex digits with `usb-ethernet-<n>` or `usb-wifi-<n>`,
  numbered in the order the scrubber first meets them;
- the host name with `<this computer>`, a `TV_NAME` that is not a vendor's default with `<tv name>`,
  the Wi-Fi network names with `<wifi name>`, and the user in a `/home/<name>` or `/Users/<name>`
  path with `<user>`.

`scrub_for(s)` builds the scrubber for this gateway from the settings and the live system, and
`python3 -m tvgw.scrub --stdin` filters a stream line by line with it, falling back to the default
TV subnet when the settings file cannot be read. Nothing here writes anything.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
from collections.abc import Callable, Iterable

from tvgw import config
from tvgw.config import Settings

LAN, PUBLIC, ROUTER = "<lan address>", "<public address>", "<router>"
MAC, HOST, TV, WIFI, USER = "<mac>", "<this computer>", "<tv name>", "<wifi name>", "<user>"
# the public addresses written into the code: Cloudflare's, Google's and Quad9's resolvers (the DoH
# upstreams and bootstrap of decision 9, and the hardware suite's block-set probes) and LG's firmware
# fallback that tvgw-apply allows by address. Nothing about a home
SHIPPED = ("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "156.147.69.32")
# host names that name no one: the project's, the distributions' defaults, and a word tvgw prints
GENERIC_HOSTS = frozenset({"localhost", "tvgw", "gateway", "raspberrypi", "debian", "ubuntu"})
# what a TV announces by default (discover.HOSTNAME_HINTS), and the template's TV_NAME: a TV_NAME
# that starts with one of these is the vendor's word, not the household's
VENDOR_SLUGS = (
    "lgwebostv",
    "samsung",
    "roku",
    "vizio",
    "bravia",
    "firetv",
    "amazon-",
    "chromecast",
    "googletv",
)
MIN_NAME = 3  # a name shorter than this is replaced nowhere: it would take letters out of words
CONF = "/etc/tvgw/tvgw.conf"
HOSTNAME = "/proc/sys/kernel/hostname"

# four dotted numbers with an optional prefix length. A fifth dotted number still leaves the first four
# an address: tcpdump writes a port that way (192.0.2.1.443), and a five-part version number replaced
# costs less than an address left in. Only a digit, or a digit and a dot, before the first number makes
# it part of something longer
_IPV4 = re.compile(r"(?<!\d)(?<!\d\.)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?!\d)")
# a colon-separated run of hex groups with at least two colons, optionally ending in a dotted IPv4
# and a zone; ipaddress decides whether it is an address (a time such as 12:30:45 is not). A label and
# a colon may come before it (`src:fe80::1`)
_IPV6 = re.compile(
    r"(?<![0-9A-Za-z_.])"
    r"((?:[0-9A-Fa-f]{0,4}:){2,6}\d{1,3}(?:\.\d{1,3}){3}|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})"
    r"(%[0-9A-Za-z_.-]+)?"
    r"(?![0-9A-Za-z_:])"
)
# six or more two-digit hex groups with one separator: a MAC, or a DHCP client id that holds one. The
# separators are a colon, a dash and nmcli's escaped colon (`nmcli -t` writes `00\:00\:5E...`); a label
# and a separator may come before it (`mac:00:00:5e:00:53:01`), a letter or digit may not. IPv6
# addresses go first, whole, so a run of two-digit groups inside one is never half replaced
_MACS = tuple(
    re.compile(rf"(?<![0-9A-Za-z])[0-9A-Fa-f]{{2}}(?:{re.escape(sep)}[0-9A-Fa-f]{{2}}){{5,}}(?![0-9A-Fa-f])")
    for sep in (":", "-", "\\:")
)
_USB_IF = re.compile(r"(?<![0-9A-Za-z_])(en|wl)x[0-9A-Fa-f]{12}(?![0-9A-Za-z_])")
_HOME = re.compile(r"(/home/|/Users/)(?!<user>)([^/\s'\"]+)")
Address = ipaddress.IPv4Address | ipaddress.IPv6Address
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def _addresses(values: Iterable[str]) -> set[Address]:
    out: set[Address] = set()
    for v in values:
        try:
            out.add(ipaddress.ip_address(str(v).strip().split("%")[0]))
        except ValueError:
            continue
    return out


def _word(name: str, flags: int = 0) -> re.Pattern[str]:
    """A literal that matches only as a whole: no letter or digit may touch an end that is one."""
    left = r"(?<![A-Za-z0-9])" if name[:1].isalnum() else ""
    right = r"(?![A-Za-z0-9])" if name[-1:].isalnum() else ""
    return re.compile(left + re.escape(name) + right, flags)


def vendor_slug(name: str) -> bool:
    """Whether a TV_NAME is a vendor's default word, which names no household."""
    low = name.lower()
    return low == "tv" or low.startswith(VENDOR_SLUGS)


class Scrubber:
    """`scrub()` for one gateway, callable on any text. It keeps the numbering of the USB interface
    names it has met, so a stream reads the same adapter as the same `usb-ethernet-<n>` throughout."""

    def __init__(
        self,
        tv_net: str = Settings.tv_net,
        *,
        router: str | Iterable[str] | None = None,
        uplink_addrs: Iterable[str] = (),
        hostname: str | None = None,
        tv_name: str | None = None,
        ssids: Iterable[str] = (),
        keep: Iterable[str] = (),
    ):
        try:
            self.tv_net: Network = ipaddress.ip_network(tv_net, strict=False)
        except ValueError:
            self.tv_net = ipaddress.ip_network(Settings.tv_net)
        routers = [router] if isinstance(router, str) else list(router or ())
        self.routers = _addresses(routers)
        self.uplink = _addresses(uplink_addrs) - self.routers
        self.keep_addrs: set[Address] = set()
        self.keep_nets: list[Network] = []
        for item in keep:
            try:
                net = ipaddress.ip_network(str(item).strip(), strict=False)
            except ValueError:
                continue
            if not net.is_global:  # only an address no home owns is kept by name
                continue
            if net.num_addresses == 1:
                self.keep_addrs.add(net.network_address)
            else:
                self.keep_nets.append(net)
        self.usb: dict[str, str] = {}
        words: list[tuple[str, str, int]] = []
        for name in sorted(
            {x.strip() for x in ssids if x and len(x.strip()) >= MIN_NAME}, key=len, reverse=True
        ):
            words.append((name, WIFI, 0))
        host = (hostname or "").strip()
        for name in dict.fromkeys((host, host.split(".")[0])):
            if len(name) >= MIN_NAME and name.lower() not in GENERIC_HOSTS:
                words.append((name, HOST, re.IGNORECASE))
        tv = (tv_name or "").strip()
        if len(tv) >= MIN_NAME and not vendor_slug(tv):
            words.append((tv, TV, re.IGNORECASE))
        self.words = [(_word(name, flags), label) for name, label, flags in words]

    def __call__(self, text: str) -> str:
        for pattern, label in self.words:
            text = pattern.sub(label, text)
        text = _HOME.sub(lambda m: m.group(1) + USER, text)
        text = _IPV6.sub(self._v6, text)
        for mac in _MACS:
            text = mac.sub(MAC, text)
        text = _USB_IF.sub(self._usb, text)
        return _IPV4.sub(self._v4, text)

    def _usb(self, m: re.Match[str]) -> str:
        name = m.group(0).lower()
        if name not in self.usb:
            kind = "ethernet" if m.group(1).lower() == "en" else "wifi"
            n = 1 + sum(1 for v in self.usb.values() if v.startswith(f"usb-{kind}-"))
            self.usb[name] = f"usb-{kind}-{n}"
        return self.usb[name]

    def _label(self, addr: Address) -> str | None:
        """The placeholder for an address, or None to keep it as written."""
        if addr in self.routers:
            return ROUTER
        if addr not in self.uplink:
            if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
                return self._label(addr.ipv4_mapped)
            if addr.version == self.tv_net.version and addr in self.tv_net:
                return None
            if addr in self.keep_addrs or any(addr in net for net in self.keep_nets):
                return None
            if addr.is_unspecified or addr.is_loopback or addr.is_multicast:
                return None
            if addr == ipaddress.IPv4Address("255.255.255.255"):
                return None
        return PUBLIC if addr.is_global else LAN

    def _v4(self, m: re.Match[str]) -> str:
        octets = [int(x) for x in m.groups()]
        if any(o > 255 for o in octets):
            return m.group(0)
        label = self._label(ipaddress.IPv4Address(".".join(map(str, octets))))
        return m.group(0) if label is None else label

    def _v6(self, m: re.Match[str]) -> str:
        try:
            addr = ipaddress.IPv6Address(m.group(1))
        except ValueError:
            return m.group(0)
        label = self._label(addr)
        return m.group(0) if label is None else label


def scrub(
    text: str,
    tv_net: str,
    *,
    router: str | Iterable[str] | None = None,
    uplink_addrs: Iterable[str] = (),
    hostname: str | None = None,
    tv_name: str | None = None,
    ssids: Iterable[str] = (),
    keep: Iterable[str] = (),
) -> str:
    """`text` with the home's identifiers replaced (the module docstring lists them)."""
    return Scrubber(
        tv_net,
        router=router,
        uplink_addrs=uplink_addrs,
        hostname=hostname,
        tv_name=tv_name,
        ssids=ssids,
        keep=keep,
    )(text)


def run_cmd(cmd: list[str]) -> str:
    """stdout of a command, '' when it fails, is missing or takes over 10 seconds."""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def read_file(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _json_list(text: str) -> list:
    try:
        data = json.loads(text) if text.strip() else []
    except ValueError:
        return []
    return [x for x in data if isinstance(x, dict)] if isinstance(data, list) else []


def _terse(line: str) -> list[str]:
    """One line of `nmcli -t` split into its fields: `\\:` is a colon inside a field."""
    fields, cur, esc = [], [], False
    for ch in line:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ":":
            fields.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    fields.append("".join(cur))
    return fields


def wifi_names(run: Callable[[list[str]], str]) -> list[str]:
    """The saved Wi-Fi connections' names and the SSID each Wi-Fi device is connected to, from
    NetworkManager; none where nmcli is missing."""
    names = []
    for line in run(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"]).splitlines():
        fields = _terse(line)
        if len(fields) == 2 and fields[1] == "802-11-wireless":
            names.append(fields[0])
    wifi = ["nmcli", "-t", "-f", "ACTIVE,SSID", "device", "wifi", "list", "--rescan", "no"]
    for line in run(wifi).splitlines():
        fields = _terse(line)
        if len(fields) == 2 and fields[0] == "yes":
            names.append(fields[1])
    return [n for n in names if n]


def shipped(s: Settings, conf: dict[str, str], read: Callable[[str], str]) -> list[str]:
    """The addresses tvgw itself ships or was told to use for DNS: SHIPPED, the upstreams, the
    bootstrap and fallback resolvers, the URL filter's resolver, and the DoH block list."""
    found = list(SHIPPED)
    for value in (s.dns_upstreams, s.dns_bootstrap, s.dns_fallback, conf.get("URL_FILTER_RESOLVER", "")):
        found += [m.group(0) for m in _IPV4.finditer(value or "")]
    for line in read(os.path.join(s.state_dir, "doh4.txt")).splitlines():
        entry = line.split("#")[0].strip()
        if entry:
            found.append(entry)
    return found


def scrub_for(
    s: Settings,
    *,
    run: Callable[[list[str]], str] = run_cmd,
    read: Callable[[str], str] = read_file,
    hostname: Callable[[], str] = socket.gethostname,
    conf_path: str = CONF,
) -> Scrubber:
    """The scrubber for this gateway: the TV subnet and TV name from the settings, the router from
    `WAN_GW` and the default routes, the gateway's home-side addresses from `ip -j addr`, its host
    name, its Wi-Fi names, and the addresses tvgw ships. Every source is optional."""
    try:
        conf = config.parse_conf(read(conf_path))
    except ValueError:
        conf = {}
    routers = [conf.get("WAN_GW", "")]
    for family in ([], ["-6"]):
        routers += [
            r.get("gateway", "") for r in _json_list(run(["ip", "-j", *family, "route", "show", "default"]))
        ]
    uplink = []
    for link in _json_list(run(["ip", "-j", "addr", "show"])):
        if link.get("ifname") in (s.tv_if, "lo"):
            continue
        uplink += [a.get("local", "") for a in link.get("addr_info", []) if isinstance(a, dict)]
    name = read(HOSTNAME).strip()
    if not name:
        try:
            name = hostname()
        except OSError:
            name = ""
    return Scrubber(
        s.tv_net,
        router=[r for r in routers if r],
        uplink_addrs=[a for a in uplink if a],
        hostname=name,
        tv_name=s.tv_name,
        ssids=wifi_names(run),
        keep=shipped(s, conf, read),
    )


def _settings(path: str) -> Settings:
    """The settings file's values, or the defaults when it cannot be read or is refused: the
    scrubber must run whatever state the gateway is in."""
    try:
        return config.load(path)
    except (OSError, ValueError):
        return Settings()


def filter_stream(scrubber: Callable[[str], str], src, dst) -> None:
    """Every line of the byte stream `src` scrubbed onto `dst`, flushed as it goes, so a CI log
    streams. A line the scrubber fails on is withheld whole, never passed through."""
    for raw in src:
        line = raw.decode("utf-8", errors="replace")
        try:
            out = scrubber(line)
        except Exception as e:  # a scrubber bug must neither stop the stream nor pass a line unscrubbed
            out = f"<line withheld: the scrubber failed on it ({type(e).__name__})>\n"
        dst.write(out.encode("utf-8", errors="replace"))
        dst.flush()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="python3 -m tvgw.scrub",
        description="Copy standard input to standard output with the home's identifiers replaced.",
    )
    p.add_argument("--stdin", action="store_true", required=True, help="filter standard input")
    p.add_argument("--conf", default=CONF, help=f"the settings file (default {CONF})")
    a = p.parse_args(argv)
    s = _settings(a.conf)
    scrubber = scrub_for(s, conf_path=a.conf)
    try:
        filter_stream(scrubber, sys.stdin.buffer, sys.stdout.buffer)
    except BrokenPipeError:  # the reader went away: nothing left to protect
        with open(os.devnull, "wb") as null:
            os.dup2(null.fileno(), sys.stdout.fileno())
    return 0


if __name__ == "__main__":
    sys.exit(main())
