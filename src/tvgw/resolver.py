"""(resolver) Who answers the TV's lookups: a short list of checked operators, and a change that is all
or nothing (design decision 81).

Every name the filter lets through is looked up by one outside operator, which sees the name with the
home's internet address (or the VPN's, on a gateway that has one). `DNS_UPSTREAMS` names that operator
as DoH URLs by address (design decision 9) and `DNS_BOOTSTRAP` its plain addresses. This module holds:

- `CANDIDATES`: operators that need no account and do not filter (tvgw is the only filter, so no
  upstream may block a must-allow host), each with its DoH URLs by address, the bootstrap of the same
  operator, its country and one line of what its published policy says it keeps, with the link and the
  day it was read. `PRESETS` are the candidates whose DoH answered on each address with a certificate
  valid for that address when it was checked (`checked`); one not checked yet is offered nowhere and
  cannot be set, only tried with `tvgw resolver test`.
- `current()`: the preset the settings name, or None for the owner's own.
- `precheck()`: each new address asked directly from the gateway, over DoH with the certificate held to
  the address, for a made-up name under the profile's first must-allow host, before anything changes.
- `change()`: `tvgw resolver set`. The precheck; the settings written through `config.save_conf`;
  AdGuard applied through the restart guard (`adguardcfg.Deferred` while the current upstreams are
  down and the new ones do not answer a direct test either at that moment: exit 3, nothing changed;
  with the new ones answering, the apply goes past the guard to leave a failed operator); then the
  guard's own probe and every must-allow name, asked at
  `GW_IP` where the TV asks. On any failure the settings file goes back byte for byte and AdGuard is
  applied again without the guard: its upstreams are then the new ones that failed, and the restart
  already emptied its cache, so holding the restart back would keep the TV on them. One ledger line
  when the change took.

Everything that touches the network, AdGuard or the locks is a parameter, so the tests drive every path
with fakes.
"""

from __future__ import annotations

import contextlib
import dataclasses
import http.client
import ipaddress
import re
import secrets
import signal
import ssl
import textwrap
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from tvgw import config, dnsmsg, dnsq
from tvgw.config import Settings
from tvgw.profile import Profile


@dataclass(frozen=True)
class Preset:
    """One operator. `upstreams` are DoH URLs by IPv4 address (no host name: design decision 9) and
    `bootstrap` the same operator's plain addresses, so nothing is ever asked of a second party."""

    name: str  # the word `tvgw resolver set` and SETUP_RESOLVER take
    label: str  # the plain name the owner reads
    operator: str  # who runs it
    country: str  # where the operator is based
    upstreams: tuple[str, ...]
    bootstrap: tuple[str, ...]
    keeps: str  # one line from its published privacy policy
    policy: str  # the policy's address
    read: str  # the day the policy was read
    shares: str = ""  # what it passes on of the home's address, by its own documentation, when it does
    filters: bool = False  # True would make it a cloud filter beside tvgw's: none is offered
    checked: str = ""  # the day its DoH by address answered with a certificate valid for each address
    held: str = ""  # why a candidate is not offered yet


# The order is the setup question's: today's default first. Each policy and each check is dated in
# design decision 81. Quad9 is held: its encrypted service closed every connection by address from the
# machine the presets were built on (2026-11-08), so its certificate for the address was never seen
CANDIDATES: tuple[Preset, ...] = (
    Preset(
        name="cloudflare",
        label="Cloudflare",
        operator="Cloudflare, Inc.",
        country="United States",
        upstreams=("https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query"),
        bootstrap=("1.1.1.1", "1.0.0.1"),
        keeps=(
            "deletes its lookup logs within 25 hours, keeping a sample without your address and totals"
            " made from it"
        ),
        policy="https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/",
        read="2026-11-08",
        checked="2026-11-08",
    ),
    Preset(
        name="quad9",
        label="Quad9 (unfiltered)",
        operator="Quad9 Foundation",
        country="Switzerland",
        upstreams=("https://9.9.9.10/dns-query", "https://149.112.112.10/dns-query"),
        bootstrap=("9.9.9.10", "149.112.112.10"),
        keeps="keeps no address of yours; counts lookups by name, network and country",
        policy="https://quad9.net/privacy/policy/",
        read="2026-11-08",
        held="it has not yet been seen to answer encrypted lookups by address",
    ),
    Preset(
        name="adguard",
        label="AdGuard DNS (unfiltered)",
        operator="AdGuard Software Ltd",
        country="Cyprus",
        upstreams=("https://94.140.14.140/dns-query", "https://94.140.14.141/dns-query"),
        bootstrap=("94.140.14.140", "94.140.14.141"),
        keeps="says it keeps no personal data: the names asked in the last 24 hours, not who asked",
        policy="https://adguard-dns.io/en/privacy.html",
        read="2026-11-08",
        checked="2026-11-08",
    ),
    Preset(
        name="google",
        label="Google Public DNS",
        operator="Google LLC",
        country="United States",
        upstreams=("https://8.8.8.8/dns-query", "https://8.8.4.4/dns-query"),
        bootstrap=("8.8.8.8", "8.8.4.4"),
        keeps="keeps your address for 24 to 48 hours, then a sample with your city instead of it",
        policy="https://developers.google.com/speed/public-dns/privacy",
        read="2026-11-08",
        shares=(
            "It passes part of this home's internet address on to the name servers of the services"
            " looked up, where they take it (EDNS Client Subnet:"
            " https://developers.google.com/speed/public-dns/docs/ecs)."
        ),
        checked="2026-11-08",
    ),
)
PRESETS: tuple[Preset, ...] = tuple(p for p in CANDIDATES if p.checked and not p.filters)
DEFAULT = "cloudflare"  # what a settings file without DNS_UPSTREAMS means (config.Settings)
CUSTOM = "custom"  # `set custom URL[,URL]`: the owner's own operator, by address
OWN = "your own resolver"  # its label wherever the URLs must not appear (the brief, the analyst's pack)
WIDTH = 100  # columns the explanation is wrapped to
DOH_TIMEOUT = 8.0  # seconds per address for the precheck: connect, TLS and one answer
LOCK_WAIT = 30.0  # seconds to wait for the hourly check or the analyst to finish a step
INSTALL_LOCK_WAIT = 120.0  # seconds to wait for a deploy or setup to finish
# exit statuses, as `tvgw allow` has them: done (or nothing to do); refused, failed or put back with
# nothing changed; AdGuard held its restart back because the current upstreams are down
OK, REFUSED, DEFERRED = 0, 1, 3
SAY = "tvgw resolver: "  # every line the commands print starts with it
SPOOL_SOURCE = "resolver"  # the change ledger's spool line: `resolver set <name>` (ledger._spool_row)
# a DoH URL by address: https, an IPv4 address, an optional port and a path of plain characters (the
# settings file takes no `?`, decision 29)
_DOH = re.compile(r"https://(?P<ip>[0-9.]+)(?::(?P<port>[0-9]{1,5}))?(?P<path>/[A-Za-z0-9._~/-]*)")


@dataclass
class Outcome:
    """What a command did: the exit status and the lines it prints."""

    code: int
    lines: list[str] = dataclasses.field(default_factory=list)


@dataclass(frozen=True)
class Target:
    """What `set` puts in place: a preset, or the owner's own URLs (bootstrap None: left as it is)."""

    name: str
    label: str
    upstreams: tuple[str, ...]
    bootstrap: tuple[str, ...] | None


# ---- reading the settings ----------------------------------------------------------------------------
def csv(text: str) -> tuple[str, ...]:
    """Comma-separated items, trimmed, empties dropped (as adguardcfg reads the two settings)."""
    return tuple(x for x in (item.strip() for item in text.split(",")) if x)


def by_name(name: str, offered_only: bool = True) -> Preset | None:
    """The preset called `name` (any case), or None; with offered_only False a held candidate too."""
    pool = PRESETS if offered_only else CANDIDATES
    return next((p for p in pool if p.name == name.strip().lower()), None)


def find(upstreams: tuple[str, ...]) -> Preset | None:
    """The offered preset whose addresses hold every one of these upstreams, or None (the owner's own).
    A subset counts: `https://1.1.1.1/dns-query` alone is still Cloudflare answering."""
    want = set(upstreams)
    return next((p for p in PRESETS if want and want <= set(p.upstreams)), None)


def current(s: Settings) -> Preset | None:
    return find(csv(s.dns_upstreams))


def label_for(s: Settings) -> str:
    """Who answers, in a word or two and never with an address: the brief's Coverage line and the
    report's JSON, which the analyst's pack may carry."""
    p = current(s)
    return p.label if p else OWN


def address(url: str) -> str:
    """The IPv4 address a DoH URL by address names, or the URL itself."""
    m = _DOH.fullmatch(url)
    return m.group("ip") if m else url


def custom_target(text: str, gw_ip: str = "") -> Target:
    """`set custom URL[,URL]`: DoH by IPv4 address only, as decision 9 requires. ValueError, in plain
    words, for a host name, another scheme, an address that is not a public or private host (loopback,
    link-local, multicast, reserved), or the gateway's own address, which would ask AdGuard itself."""
    urls = tuple(dict.fromkeys(csv(text)))
    if not urls:
        raise ValueError("give at least one address, such as https://198.51.100.9/dns-query")
    for url in urls:
        m = _DOH.fullmatch(url)
        if not m:
            raise ValueError(
                f"{url!r} is not encrypted DNS by address: write it as https://<address>/dns-query, with"
                " the address in digits (a name would need a plain lookup first)"
            )
        try:
            ip = ipaddress.IPv4Address(m.group("ip"))
        except ValueError:
            raise ValueError(f"{url!r}: {m.group('ip')} is not an IPv4 address") from None
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            raise ValueError(f"{url!r}: {ip} cannot be a resolver for the gateway")
        if gw_ip and str(ip) == gw_ip:
            raise ValueError(f"{url!r}: {ip} is the gateway itself, whose filter would ask itself")
        port = m.group("port")
        if port is not None and not 1 <= int(port) <= 65535:
            raise ValueError(f"{url!r}: {port} is not a port")
    return Target(CUSTOM, OWN, urls, None)


def target_for(name: str, urls: str = "", gw_ip: str = "") -> Target:
    """A preset's target, or the owner's own for `custom`. ValueError naming the choices otherwise."""
    if name.strip().lower() == CUSTOM:
        return custom_target(urls, gw_ip)
    if urls:
        raise ValueError(f"{name} takes no addresses; only custom does")
    p = by_name(name)
    if p is None:
        held = by_name(name, offered_only=False)
        if held is not None:
            raise ValueError(f"{held.label} is not offered yet: {held.held}")
        raise ValueError(f"no choice called {name!r}; the choices are {', '.join(names())}")
    return Target(p.name, p.label, p.upstreams, p.bootstrap)


def names() -> list[str]:
    return [p.name for p in PRESETS] + [CUSTOM]


# ---- what the owner reads -----------------------------------------------------------------------------
SEES = (
    "Every name the filter lets through is looked up by one outside service. That service sees each"
    " name, with this home's internet address, or the VPN's when the gateway uses one. None of the"
    " services below filters anything itself, so the gateway stays the only filter."
)


def list_lines(s: Settings) -> list[str]:
    """`tvgw resolver list`: the choices in plain words, the one answering now marked."""
    now = current(s)
    width = max(len(p.name) for p in PRESETS)
    out = [*textwrap.wrap(SEES, WIDTH), ""]
    for p in PRESETS:
        mark = "*" if p is now else " "
        default = " (the default)" if p.name == DEFAULT else ""
        out.append(f"{mark} {p.name:<{width}}  {p.label}, {p.country}{default}")
        out.append(f"  {'':<{width}}  By its own policy, it {p.keeps}.")
        if p.shares:
            out.append(f"  {'':<{width}}  {p.shares}")
        out.append(f"  {'':<{width}}  Its privacy policy, read {p.read}: {p.policy}")
    out.append("")
    if now is None:
        out.append(f"Now: your own choice, {', '.join(csv(s.dns_upstreams))}, which is none of these.")
    else:
        out.append("* answers the TV's lookups now.")
    out += [
        "To change it: sudo tvgw resolver set NAME",
        "Your own service, by its address: sudo tvgw resolver set custom https://<address>/dns-query",
    ]
    return out


def _and(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def show_lines(s: Settings, adguard_upstreams: list[str] | None = None) -> list[str]:
    """`tvgw resolver show`: who answers now, what it sees and keeps, and the fallback when there is
    one. `adguard_upstreams` is AdGuard Home's own list when it could be read: a line says so when it
    is not the settings' choice."""
    ups = list(csv(s.dns_upstreams))
    p = find(tuple(ups))
    who = p.label if p else "that service"
    if p:
        first = (
            f"The TV's lookups are answered by {p.label} ({p.country}), over an encrypted connection to"
            f" {_and([address(u) for u in ups])}."
        )
    else:
        first = f"The TV's lookups are answered by your own choice: {', '.join(ups)}."
    out = [
        first,
        f"{who[0].upper()}{who[1:]} sees every name the filter lets through, with this home's internet"
        " address, or the VPN's when the gateway uses one.",
    ]
    if p:
        if p.shares:
            out.append(p.shares)
        out.append(f"By its own policy (read {p.read}), it {p.keeps}: {p.policy}")
    fallback = list(csv(s.dns_fallback))
    if fallback:
        out.append(
            f"When those fail, the filter asks {', '.join(fallback)} instead, which then sees those"
            " lookups. A lookup through the filter can come from either, so sudo tvgw resolver set also"
            " asks a new service directly."
        )
    if adguard_upstreams is not None and adguard_upstreams != ups:
        out.append(
            "AdGuard Home asks other services than the settings name right now:"
            " sudo tvgw adguard apply puts the settings' choice in place."
        )
    out.append("To see the choices: tvgw resolver list")
    return out


def show_json(s: Settings, adguard_upstreams: list[str] | None = None) -> dict:
    """`tvgw resolver show --json`, for a page that shows it (the About page G1 plans)."""
    p, ups = current(s), list(csv(s.dns_upstreams))
    return {
        "preset": p.name if p else None,
        "label": p.label if p else OWN,
        "operator": p.operator if p else None,
        "country": p.country if p else None,
        "upstreams": ups,
        "bootstrap": list(csv(s.dns_bootstrap)),
        "fallback": list(csv(s.dns_fallback)),
        "adguard_matches": None if adguard_upstreams is None else adguard_upstreams == ups,
    }


def adguard_upstreams(path: str) -> list[str] | None:
    """`dns.upstream_dns` from AdGuardHome.yaml, or None when this account cannot read it (only root
    can) or it is not there."""
    try:
        from tvgw import adguardcfg

        return adguardcfg.upstreams_of(adguardcfg.load_yaml(path))
    except Exception:  # unreadable, absent, not YAML, or no PyYAML here: the settings say it alone
        return None


# ---- asking an operator directly ----------------------------------------------------------------------
def probe_label(name: str) -> str:
    """A made-up name under `name`, the restart guard's form: no cache holds it, and it carries nothing
    about the household."""
    return f"tvgw-probe-{secrets.token_hex(4)}.{name.strip('.')}"


def ask_doh(url: str, name: str, timeout: float = DOH_TIMEOUT) -> tuple[bool, str]:
    """(answered, why not) for one DoH URL by address: a POST of one question (RFC 8484), over TLS with
    the certificate checked against the address itself, as AdGuard Home checks it. NOERROR or NXDOMAIN
    is an answer; anything else says why, in plain words."""
    m = _DOH.fullmatch(url)
    if not m:
        return False, "not encrypted DNS by address"
    ip, port = m.group("ip"), int(m.group("port") or 443)
    ctx = ssl.create_default_context()  # the system's authorities; the address must be in the certificate
    conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
    try:
        conn.request(
            "POST",
            m.group("path"),
            body=dnsq.question(name, qid=0),
            headers={"content-type": "application/dns-message", "accept": "application/dns-message"},
        )
        reply = conn.getresponse()
        data = reply.read(65536)
    except ssl.SSLCertVerificationError:
        return False, f"its certificate is not valid for {ip}"
    except (OSError, http.client.HTTPException) as e:
        return False, f"no answer ({type(e).__name__})"
    finally:
        conn.close()
    if reply.status != 200:
        return False, f"it answered HTTP {reply.status}, not a lookup"
    kind = (reply.getheader("content-type") or "").split(";")[0].strip().lower()
    if kind != "application/dns-message":
        return False, "it answered with something that is not a DNS message"
    if not answers(data, name):
        return False, "it answered with a DNS message that is not the answer to the question asked"
    code = dnsmsg.rcode(data)
    if code in (0, 3):
        return True, ""
    return False, f"it answered with DNS error {code}"


def answers(data: bytes, name: str) -> bool:
    """`data` is a DNS response to the one question `dnsq.question(name, qid=0)` asked: id 0, the
    response bit set, a standard query, and that name and type A, class IN, in its question section."""
    import struct

    if len(data) < 12 or data[:2] != b"\x00\x00" or not data[2] & 0x80 or (data[2] >> 3) & 0x0F:
        return False
    if struct.unpack_from(">H", data, 4)[0] != 1:
        return False
    try:
        asked, off = dnsmsg.read_name(data, 12)
    except (ValueError, IndexError):
        return False
    return asked.lower() == name.strip(".").lower() and data[off : off + 4] == b"\x00\x01\x00\x01"


def precheck(
    urls: tuple[str, ...] | list[str],
    name: str,
    ask: Callable[[str, str], tuple[bool, str]] | None = None,
    stop_at_first: bool = False,
) -> list[tuple[str, str]]:
    """(url, why) for each address that did not answer a made-up name under `name`; empty when all did.
    `stop_at_first` ends at the first that did not (adguardcfg's test in an outage need not wait for
    every timeout). No address at all is one failure, never a pass."""
    ask = ask or ask_doh
    if not urls:
        return [("", "no upstream to ask")]
    label = probe_label(name)
    out = []
    for url in urls:
        ok, why = ask(url, label)
        if not ok:
            out.append((url, why))
            if stop_at_first:
                break
    return out


def trial(target: Target, name: str, ask: Callable[[str, str], tuple[bool, str]] | None = None) -> Outcome:
    """`tvgw resolver test`: each address of a choice (a held candidate too) asked from this computer,
    nothing changed."""
    failed = dict(precheck(target.upstreams, name, ask))
    lines = []
    for url in target.upstreams:
        why = failed.get(url)
        lines.append(
            f"{address(url)}: {'answered, with a certificate valid for the address' if why is None else why}"
        )
    if failed:
        lines.append(f"{SAY}{target.label} did not answer from this computer at every address")
        return Outcome(REFUSED, lines)
    lines.append(f"{SAY}{target.label} answers from this computer; nothing was changed")
    return Outcome(OK, lines)


# ---- the change ----------------------------------------------------------------------------------------
def _apply_with(
    prof: Profile, ask: Callable[[str, str], tuple[bool, str]] | None = None
) -> Callable[[Settings, bool], object]:
    """AdGuard applied the way `tvgw allow` applies it (lint, take-over refusal, readiness wait); with
    `guarded` False the restart guard is skipped, for the way back. Past a deferral it goes only when
    the new upstreams answer a direct test right then, asked through `ask`, `set`'s own seam."""

    def apply(st: Settings, guarded: bool) -> object:
        from tvgw import analyst

        def direct(d) -> bool:
            return not precheck(d.upstreams, d.probe_name, ask, stop_at_first=True)

        return analyst.adguardcfg_apply(st, prof, guard=None if guarded else (lambda: None), direct=direct)

    return apply


def _state_with(prof: Profile) -> Callable[[Settings], str]:
    """The restart guard's own probe after the apply, asked at GW_IP where the TV asks: 'up' when a
    made-up name under the first must-allow host resolved through the upstreams."""

    def state(st: Settings) -> str:
        from tvgw import adguardcfg

        name, local = adguardcfg.probe_targets(prof, st)
        try:
            wait = adguardcfg.upstream_wait(adguardcfg.load_yaml(st.adguard_yaml))
        except Exception:
            wait = None
        return adguardcfg.upstream_state(name, server=st.gw_ip, wait=wait, local=local)

    return state


@contextlib.contextmanager
def _held(s: Settings) -> Iterator[str | None]:
    """The install lock (a deploy or setup writes the settings and applies under it) and the autonomy's
    lock (the hourly check and the analyst apply AdGuard under it), in that order. Yields None when
    both are held, or the reason they could not be had."""
    from tvgw import autoblock, setup

    with contextlib.ExitStack() as stack:
        try:
            stack.enter_context(
                setup.install_lock(wait=INSTALL_LOCK_WAIT, say=lambda line: print(SAY + line))
            )
        except setup.SetupError:  # it waited INSTALL_LOCK_WAIT seconds
            yield "a deploy or setup is still running"
            return
        except OSError as e:
            yield f"the install lock cannot be taken ({e})"
            return
        deadline = time.monotonic() + LOCK_WAIT
        while True:
            inner = contextlib.ExitStack()
            if inner.enter_context(autoblock.exclusive(s.state_dir)):
                stack.enter_context(inner)
                break
            inner.close()
            if time.monotonic() >= deadline:
                yield "the gateway's hourly check or the analyst is changing rules right now"
                return
            time.sleep(1.0)
        yield None


class Interrupted(BaseException):
    """SIGHUP (a dropped SSH session) or SIGTERM arrived while `set` was changing the resolver. Like
    KeyboardInterrupt it is not an Exception, so only the way back handles it, and then it goes on."""


STOP_SIGNALS = ("SIGHUP", "SIGTERM")  # SIGINT is KeyboardInterrupt already
HELD_SIGNALS = ("SIGINT", "SIGHUP", "SIGTERM")  # held off while the way back runs


def _signal_set(names: tuple[str, ...]) -> set[signal.Signals]:
    return {getattr(signal, n) for n in names if hasattr(signal, n)}


@contextlib.contextmanager
def _signals_raise() -> Iterator[None]:
    """For the duration of a change, SIGHUP and SIGTERM raise `Interrupted`, as Ctrl-C raises
    KeyboardInterrupt, so the settings and AdGuard Home go back before the process ends; the handlers
    in place before are put back after. Outside the main thread no handler can be set, and none is."""

    def stop(signum, frame):
        raise Interrupted(signal.Signals(signum).name)

    before: dict = {}
    try:
        for sig in _signal_set(STOP_SIGNALS):
            before[sig] = signal.signal(sig, stop)
    except ValueError:  # not the main thread
        pass
    try:
        yield
    finally:
        for sig, handler in before.items():
            signal.signal(sig, handler)


@contextlib.contextmanager
def _held_off() -> Iterator[None]:
    """SIGINT, SIGHUP and SIGTERM held while the way back runs: a second Ctrl-C, or the SSH session
    going, arrives once the settings file and AdGuard Home are both back. The handlers are swapped for
    one that only notes the signal, and the first noted is raised once the handlers before are back
    (KeyboardInterrupt for SIGINT, `Interrupted` for the others). A signal mask would hold the calling
    thread alone; Python runs every handler in the main thread, which is where this runs."""
    noted: list[int] = []

    def note(signum, frame):
        noted.append(signum)

    before: dict = {}
    try:
        for sig in _signal_set(HELD_SIGNALS):
            before[sig] = signal.signal(sig, note)
    except ValueError:  # not the main thread: nothing to swap
        pass
    try:
        yield
    finally:
        for sig, handler in before.items():
            signal.signal(sig, handler)
    if noted:
        if noted[0] == signal.SIGINT:
            raise KeyboardInterrupt
        raise Interrupted(signal.Signals(noted[0]).name)


def _reload(conf_path: str, s: Settings) -> tuple[Settings, Profile]:
    """The settings and the profile as they are now, read again under the locks: a setup or another `set`
    that held them may have changed GW_IP, the upstreams or the profile while this one waited. The store
    path the command was given (`--db`) is kept."""
    from tvgw import profile

    fresh = config.load(conf_path, db_path=s.db_path)
    prof = profile.load(fresh.profile)
    return fresh, (prof.for_country(fresh.tv_country) if fresh.tv_country else prof)


def label_of(upstreams: list[str] | tuple[str, ...]) -> str:
    """Who answers, for a list of upstreams: a preset's label, or "your own resolver"."""
    p = find(tuple(upstreams))
    return p.label if p else OWN


def change(
    s: Settings,
    prof: Profile,
    conf_path: str,
    target: Target,
    *,
    apply_fn: Callable[[Settings, bool], object] | None = None,
    ask: Callable[[str, str], tuple[bool, str]] | None = None,
    state: Callable[[Settings], str] | None = None,
    resolve: Callable[[str], list[str] | None] | None = None,
    sleep: Callable[[float], None] | None = None,
    lock: Callable[[Settings], contextlib.AbstractContextManager[str | None]] | None = None,
    reload: Callable[[], tuple[Settings, Profile]] | None = None,
    live: Callable[[Settings], list[str] | None] | None = None,
    now: float | None = None,
) -> Outcome:
    """`tvgw resolver set`: all or nothing. See the module's docstring for the order. `reload` reads the
    settings and the profile again once the locks are held (`_reload`); `live` reads AdGuard Home's own
    upstreams (`adguard_upstreams`), None when it cannot."""
    with _signals_raise(), (lock or _held)(s) as busy:
        if busy:
            return Outcome(REFUSED, [f"{SAY}{busy}; nothing changed; run it again in a few minutes"])
        try:
            s, prof = reload() if reload else _reload(conf_path, s)
        except (OSError, ValueError) as e:
            return Outcome(
                REFUSED, [f"{SAY}the settings or the profile cannot be read now ({e}); nothing changed"]
            )
        return _change(
            s,
            prof,
            conf_path,
            target,
            apply_fn or _apply_with(prof, ask),
            ask,
            state or _state_with(prof),
            resolve or (lambda name: dnsq.a_records(name, s.gw_ip)),
            sleep or _pause(),
            live or (lambda st: adguard_upstreams(st.adguard_yaml)),
            now,
        )


def _pause() -> Callable[[float], None]:
    from tvgw import verify

    return verify.pause


def _change(s, prof, conf_path, target, apply_fn, ask, state, resolve, sleep, live, now) -> Outcome:
    from tvgw import adguardcfg, ledger, verify

    try:
        before = Path(conf_path).read_bytes()  # bytes: a file with CRLF lines goes back as it was
        before.decode("utf-8")
    except FileNotFoundError:
        return Outcome(REFUSED, [f"{SAY}no settings file at {conf_path}; run sudo tvgw setup first"])
    except (OSError, UnicodeDecodeError) as e:
        return Outcome(REFUSED, [f"{SAY}cannot read {conf_path} ({e}); nothing changed"])
    if target.name == CUSTOM:
        try:
            custom_target(",".join(target.upstreams), s.gw_ip)  # GW_IP as it is now
        except ValueError as e:
            return Outcome(REFUSED, [f"{SAY}{e}; nothing changed"])
    bootstrap = target.bootstrap if target.bootstrap is not None else csv(s.dns_bootstrap)
    asks = live(s)  # what AdGuard Home asks now, when this account can read it
    was = label_of(asks) if asks is not None else label_for(s)
    settled = target.upstreams == csv(s.dns_upstreams) and bootstrap == csv(s.dns_bootstrap)
    if settled and (asks is None or asks == list(target.upstreams)):
        return Outcome(OK, [f"{SAY}{target.label} already answers the TV's lookups; nothing changed"])
    # 1. the new operator answers from here, by address, with a certificate for the address
    name = next(iter(prof.must_allow), "example.com")
    failed = precheck(target.upstreams, name, ask)
    if failed:
        return Outcome(
            REFUSED,
            [
                *(f"{SAY}{address(url)} did not answer: {why}" for url, why in failed),
                f"{SAY}nothing changed; the TV's lookups still go to {was}",
            ],
        )
    changes = {"DNS_UPSTREAMS": ",".join(target.upstreams)}
    if target.bootstrap is not None:
        changes["DNS_BOOTSTRAP"] = ",".join(target.bootstrap)
    new = dataclasses.replace(s, dns_upstreams=changes["DNS_UPSTREAMS"], dns_bootstrap=",".join(bootstrap))
    # the way back: the old file, then (once AdGuard may have changed) AdGuard applied from it. When the
    # settings already named the target (AdGuard Home had drifted from them), there is no old file to go
    # back to, and AdGuard's own restore is all the way back there is
    old = None if settled else s
    # what to say when the settings already named it and something failed: there is no older file
    settled_lines = {
        "defer": f"{SAY}nothing changed: the settings name {target.label}, and AdGuard Home still asks {was}",
        "apply": f"{SAY}the settings name {target.label} and stay so; AdGuard Home did not take it and kept"
        " the file it had, as the line above says",
        "test": f"{SAY}the settings already named {target.label}, and AdGuard Home now asks it too, though it"
        " failed the test above. Choose another with sudo tvgw resolver set NAME (tvgw resolver list)",
    }
    stage = "write"
    why = None
    try:
        # 2. the settings, through the one writer that refuses a file the next command could not load
        if not settled:
            config.save_conf(conf_path, changes)
        # 3. AdGuard, behind the restart guard: the current upstreams down defers with nothing changed
        stage = "apply"
        apply_fn(new, True)
        # 4. the new operator through AdGuard: a made-up name, every name the TV needs, then once more
        #    directly, since with DNS_FALLBACK set AdGuard may have answered from the fallback
        stage = "test"
        why = _tested(target, prof, name, new, state, resolve, sleep, ask, verify)
    except adguardcfg.Deferred as e:  # raised before anything was staged: AdGuard is as it was
        return Outcome(
            DEFERRED,
            [
                f"{SAY}lookups through {was} are failing right now, and {target.label} did not answer a"
                f" direct test at that moment either, so AdGuard Home was not restarted ({e})",
                *(_way_back(conf_path, before, None, old) if old else [settled_lines["defer"]]),
            ],
        )
    except Exception as e:
        if stage == "write":
            reason = (
                f"the settings would not load with it ({e})"
                if isinstance(e, ValueError)
                else f"cannot write {conf_path} ({e}); run it with sudo"
            )
            return Outcome(REFUSED, [f"{SAY}{reason}", *_way_back(conf_path, before, None, old)])
        if stage == "apply":
            lines = _way_back(conf_path, before, apply_fn, old) if old else [settled_lines["apply"]]
            return Outcome(REFUSED, [f"{SAY}AdGuard Home did not take the change ({e})", *lines])
        why = f"the new service could not be tested ({e})"
    except BaseException:  # Ctrl-C, SIGHUP, SIGTERM: the way back runs, then the interrupt goes on
        if old:
            _way_back(conf_path, before, None if stage == "write" else apply_fn, old)
        raise
    if why:
        lines = _way_back(conf_path, before, apply_fn, old) if old else [settled_lines["test"]]
        return Outcome(REFUSED, [f"{SAY}{why}", *lines])
    with contextlib.suppress(OSError):  # one spool line; a failed write never undoes the change
        ledger.append_spool(ledger.spool_path(s), [SPOOL_SOURCE, "set", target.name], now)
    prev = find(tuple(asks)) if asks is not None else current(s)
    back = f"set {prev.name}" if prev else f"set custom {','.join(asks or csv(s.dns_upstreams))}"
    return Outcome(
        OK,
        [
            f"{SAY}the TV's lookups are now answered by {target.label}",
            f"{SAY}tested: a new lookup, and the {len(prof.must_allow)} names the TV needs, resolved"
            " through it",
            f"{SAY}to go back: sudo tvgw resolver {back}",
        ],
    )


def _tested(target, prof, name, new, state, resolve, sleep, ask, verify) -> str | None:
    """Why the new operator failed through AdGuard Home, or None when it passed every test."""
    got = state(new)
    if got != "up":
        return f"a new lookup did not resolve through {target.label} ({got})"
    check = verify.must_allow_check(prof, resolve, sleep)
    if not check.ok:
        return f"names the TV needs did not resolve through {target.label}: {check.detail}"
    again = precheck(target.upstreams, name, ask)
    if again:
        url, why = again[0]
        return f"{address(url)} did not answer directly after the change: {why}"
    return None


def _way_back(
    conf_path: str,
    before: bytes,
    apply_fn: Callable[[Settings, bool], object] | None,
    old: Settings,
) -> list[str]:
    """The settings file as it was, byte for byte (only when it differs), then, unless AdGuard was never
    touched, AdGuard applied again from it without the restart guard. Ctrl-C, SIGHUP and SIGTERM wait
    until both are back. Every step that fails is said, with the command that finishes it:
    `sudo tvgw adguard apply` is never held back by the guard while AdGuard asks other upstreams than
    the settings name and those answer from here (adguardcfg.apply), so it brings AdGuard to the
    settings as soon as their operator answers."""
    from tvgw import discover

    with _held_off():
        try:
            try:
                same = Path(conf_path).read_bytes() == before
            except OSError:
                same = False
            if not same:
                discover.write_conf(conf_path, before.decode("utf-8"))
        except OSError as e:
            return [
                f"{SAY}could not put the settings file back ({e}); AdGuard Home keeps what it has.",
                f"{SAY}put DNS_UPSTREAMS and DNS_BOOTSTRAP back by hand, then run sudo tvgw adguard apply",
            ]
        if apply_fn is None:
            return [f"{SAY}nothing changed; the TV's lookups still go to {label_for(old)}"]
        try:
            apply_fn(old, False)
        except Exception as e:
            return [
                f"{SAY}the settings are as they were, but AdGuard Home could not be put back ({e});"
                " run sudo tvgw adguard apply, which brings it to the settings",
            ]
        return [f"{SAY}put back; the TV's lookups go to {label_for(old)} as before"]


def spool_change(fields: list[str]) -> tuple[str, dict] | None:
    """(subject, detail) of a spool line `resolver set <name>`, or None for any other: the ledger's
    `resolver_change` row (ledger._spool_row)."""
    if len(fields) >= 2 and fields[0] == "set" and fields[1] in (*(p.name for p in CANDIDATES), CUSTOM):
        return fields[1], {"action": "set"}
    return None
