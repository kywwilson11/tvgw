"""Gateway settings: `/etc/tvgw/tvgw.conf` (KEY=VALUE, shell-style) plus the paths everything uses.

Every path is a field so tests and other deployments can point the tools elsewhere; the
defaults are the layout `deploy/install.sh` creates on the Pi.
"""

from __future__ import annotations

import ipaddress
import math
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

_LINE = re.compile(r'^\s*([A-Z][A-Z0-9_]*)=("([^"]*)"|\'([^\']*)\'|([^#\n]*?))\s*(#.*)?$')


@dataclass(frozen=True)
class Settings:
    tv_ip: str = "10.10.10.17"
    tv_mac: str = ""
    tv_name: str = "tv"
    # (W12) the TV's country as two lower-case letters (de, ca): fills `{cc}` in the profile's must-allow
    # hosts (LG names its clock and store hosts by country); "" means the profile's default (us)
    tv_country: str = ""
    gw_ip: str = "10.10.10.1"
    tv_if: str = "eth0"
    tv_net: str = "10.10.10.0/24"  # (packaging) the TV subnet; GW_IP and TV_IP sit inside it
    wan_if: str = "wlan0"
    uplink: str = "direct"  # direct | vpn (the tunnel vpn_if names or finds)
    # (events) the VPN client's tunnel: auto (tun0, else wgpia0, whichever exists) | none | a name
    vpn_if: str = "auto"
    block_quic: str = "yes"
    strict_ports: str = "no"
    dnsgate: str = "count"  # off | count: addresses the TV connects to that no lookup returned
    # (inpath) how the gate's set is filled: passive (tvgw-dnsgate alone, from a capture) | inpath (also
    # tvgw-dnsgate-inpath, which holds each answer until its addresses are in a second set; decision 64)
    dnsgate_fill: str = "passive"
    # (namebound) off | count: tvgw-apply copies the TV's DNS answers and the first packets of its TLS
    # connections to tvgw-names, which counts each connection's name against the answers (decision 70)
    name_binding: str = "off"
    # (capture) full: tvgw-pcap filters eth0 by byte patterns; headers: the first packets of each
    # connection from NFLOG (docs/how-it-works/capture.md)
    capture_mode: str = "full"
    # (guard) the Pi's other services that get IPAddressDeny=TV_NET (design decision 42); `none` for none
    co_tenant_units: str = "smbd nmbd xrdp shairport-sync nqptp avahi-daemon ssh jupyterhub"
    # (acr) yes: tvgw-apply resets the TV's TCP connections to LG's ad-tech ports (4001, 4431, 4445, 4447,
    # 8180, 8883) under the "LG adtech port" counter, which drives the ACR red line; no: they fall to the
    # odd-port rules like any other port
    adtech_port_wall: str = "yes"
    # (ports) which clock servers the TV may send NTP (UDP port 123) to: profile, what the profile's
    # [firewall] ntp says (any for every bundled profile today); any; resolved, only an address one of its
    # own lookups returned; none (design decision 71). tvgw-apply holds a narrowing back on a live gateway
    # while the evidence says it would cut the TV's clock off
    clock_port: str = "profile"
    analyst_model: str = "claude-opus-5-5"  # the model `tvgw analyst` asks
    analyst_effort: str = "high"  # low | medium | high | xhigh | max: its reasoning depth
    analyst_window: str = "day"  # day (the previous calendar day) | Nh (the last N hours)
    analyst_schedule: str = "03:50"  # HH:MM daily | hourly | a systemd calendar expression
    analyst_weekly_model: str = "claude-fable-5-1"  # the weekly pass over the whole week; off disables it
    analyst_weekly_effort: str = "high"
    analyst_weekly_schedule: str = "Mon 04:10"  # Day HH:MM | a systemd calendar expression
    analyst_apply: str = "off"  # off | auto: vetted, verified block proposals are applied on their own
    analyst_verifier_model: str = (
        "claude-fable-5-1"  # the second key: tries to refute each block before it lands
    )
    analyst_verifier_effort: str = "xhigh"
    auto_rules: str = (
        "/var/lib/tvgw/auto.rules"  # the machine-owned rules file; the profile's .rules is never touched
    )
    # (ledger) on: `tvgw verify --record` samples the gateway's own counters, the ingest loads the change
    # spool and derives the ledger, and the hourly check runs judge v2 in shadow (design decision 48);
    # off: none of the three (the shell scripts still append their one line each to the spool)
    ledger: str = "on"
    # (ledger) clean demand TV hours judge v2 needs before it may pass a rule (shadow only for now)
    judge2_clean_hours: int = 6
    # (budget) the upload budget's ceiling, count-only (design decision 66): auto is the one the hourly
    # ingest sets once from the gateway's clean history (the floor until then); a size is the owner's
    upload_ceiling: str = "auto"
    # (threats) count: tvgw-threat-update.timer downloads the lists THREAT_LIST_URLS names once a day and the
    # hourly ingest matches each day's names against them, locally, counting only (design decision 80);
    # off: nothing is downloaded and nothing is matched
    threat_lists: str = "off"
    # (threats) kind=URL entries, comma-separated: tif for known malware, botnet and phishing servers, nrd for
    # newly registered domains; HTTPS only (threats.parse_urls). By default HaGeZi's Threat Intelligence
    # Feeds in their mini form alone (github.com/hagezi/dns-blocklists, GPL-3.0, rebuilt daily; 188,782
    # names and 3,979,770 bytes on 2026-11-08), as the profiles fetch theirs. HaGeZi's bands of newly
    # registered domains (nrd7.txt and nrd14-8.txt, about 50 MB each) are the owner's to add: their copies
    # go to a tmpfs (threats.RUN_DIR). Fetched at run time, never copied into the repository (decision 32)
    threat_list_urls: str = (
        "tif=https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.mini.txt"
    )
    profile: str = "lg-webos"
    # (listguard) the share of the last DoH list refresh taken, in percent, a refresh may drop:
    # tvgw-doh-update holds a refresh that would drop more back (design decision 68); 100 takes every one
    doh_drop_max: int = 20
    dns_upstreams: str = "https://1.1.1.1/dns-query,https://1.0.0.1/dns-query"  # DoH by IP (comma-separated)
    dns_bootstrap: str = "1.1.1.1,1.0.0.1"
    # (lists) a second operator for AdGuard's fallback_dns, by address and encrypted; empty keeps the
    # fallback list empty, as decision 6 had it (an owner decision:
    # docs/how-it-works/adguard.md#a-fallback-resolver)
    dns_fallback: str = ""
    # (adguard) keep: AdGuard Home's DNS listen addresses stay as they are, whatever set them; gateway:
    # `tvgw adguard apply` owns dns.bind_hosts as GW_IP and 127.0.0.1 and dns.port as 53, and install.sh
    # orders AdGuard after the network and restarts it until GW_IP exists (design decision 52)
    adguard_listen: str = "keep"
    # (adguard) Whether `tvgw adguard apply` takes over an AdGuard Home tvgw did not set up (aghinstall.
    # takeover_evidence, design decision 52). ask: refused when its query log answered another device in
    # the last 7 days; taken over, with one line, when it only listens beyond GW_IP and loopback (tvgw
    # setup asks then, defaulting to no); no: refused on either; yes: always taken over
    adguard_take_over: str = "ask"
    querylog_days: int = 90  # (lists) AdGuard's querylog.interval, in days (1 to 365)
    stats_days: int = 90  # (lists) AdGuard's statistics.interval, in days (1 to 365)
    db_days: int = 365
    # (autonomy) days of `decisions` rows the store keeps: `keep` (the default) keeps every one, as
    # auto_rules and judgments are kept; a whole number prunes older rows at the hourly ingest
    decisions_days: str = "keep"
    # (record) minimization at ingest (src/tvgw/minimize.py, docs/how-it-works/privacy-and-retention.md):
    # keep the query values of http.uri, or store each one's length; tag title-bearing names with a
    # keyed HMAC
    uri_values: str = "keep"  # keep | lengths
    name_hmac: str = "off"  # off | on
    # (record) days the journal keeps, through tvgw's journald drop-in; off ships none (install.sh reads it)
    journal_days: str = "14"
    pcap_days: int = 7
    pcap_max_gb: float = 1.5
    state_dir: str = "/var/lib/tvgw"
    db_path: str = "/var/lib/tvgw/tvgw.db"
    pcap_dir: str = "/var/lib/tvgw/pcap"
    flows_log: str = "/var/log/tvgw/flows.log"
    gfts_log: str = "/var/log/tvgw/gfts.log"
    adguard_querylog: str = "/opt/AdGuardHome/data/querylog.json"
    adguard_yaml: str = "/opt/AdGuardHome/AdGuardHome.yaml"
    nginx_conf: str = "/etc/nginx/conf.d/tvgw-gfts.conf"
    block4: str = "/etc/tvgw/block4.txt"
    tvcheck_history: str = "/var/lib/tvgw/tvcheck-history.log"
    tvcheck_txt: str = "/var/lib/tvgw/tvcheck.txt"
    reports_dir: str = "/var/lib/tvgw/reports"
    # (app in front) on: tvgw-tvlive holds one read-only session to an LG TV while the TV is on and records
    # each change of its power state and of the app in front (design decision 67); off: nothing connects,
    # and sessions come from the hourly readings alone
    live_reading: str = "off"
    # (app in front) days of that finer record the store keeps (1 to 365); the hourly readings are kept
    # for DB_DAYS as before
    tv_events_days: int = 14
    # (attention) where the live reading runs: count, the default, counts the TV's connections outside its
    # essentials while its screen saver is on or an input is in front (design decision 69); refuse is the
    # wall for later, refused on a live gateway (tvgw-apply's ATTENTION_REFUSE_SUPPORTED); off renders none
    attention_wall: str = "count"
    # (reserved) Keys accepted and checked before anything reads them. Each default is the value a file
    # without the key gets, and is how the gateway behaves today; a new key never changes what an old
    # key's value means. The values each one selects are in docs/reference/settings.md.
    brief_style: str = "full"  # full | plain: (plain) read: the brief's form, the daily files' first block
    # (updates) read since design decision 77: off | weekly, ask GitHub once a week whether a newer tvgw
    # release exists (tvgw-update.timer); the template sets weekly for new installs
    update_check: str = "off"
    update_repo: str = "kywwilson11/tvgw"  # (updates) the repository, owner/name, those checks ask about
    # (updates) off | security | all: what the gateway installs on its own, in the deploy window while the TV
    # is quiet (design decision 77). off, which a file without the key means, installs nothing, as before;
    # the template says off too, so a new install starts with the installs off
    update_install: str = "off"
    local_rules: str = "/etc/tvgw/local.rules"  # (site rules) read: tvgw allow and block write it
    tv_pair_manifest: str = "auto"  # auto | readonly | library: the permissions an LG pairing asks for
    tv_dhcp: str = "open"  # open | pinned: dnsmasq answers any device on TV_IF, or the pinned TV alone
    backup_keep: int = 7  # days of daily store copies kept, plus the newest (`tvgw backup --keep`)
    wan_gw_mode: str = "literal"  # (uplink) literal | auto: the router is WAN_GW, or WAN_IF's default route
    tv_port_manager: str = "auto"  # auto | networkmanager | tvgw: what puts GW_IP on TV_IF
    netwatch: str = "auto"  # auto | off | shadow | on: the netlink watcher beside the dispatcher
    deploy_window: str = "03:30-05:30"  # HH:MM-HH:MM local time when a deploy that changes the network runs
    # ---- (probe) begin: the probe from the TV's position and the apply's confirmation (design decision 65)
    # on: tvgw-apply gives a test client's port (probe.GW_IF) a twin of the TV's rules, and `tvgw probe`,
    # `tvgw verify --record` and a confirmed apply send its test traffic; off: none of it exists
    tv_probe: str = "off"
    # the test client's own address: a host of TV_NET outside the DHCP pool, not GW_IP and not TV_IP
    # (probe_side). It never appears on the TV's cable, and no source records it: each keeps TV_IP's rows
    tv_probe_ip: str = "10.10.10.30"
    # the neutral server the probe's one connection out goes to, by name; empty: the host one of the
    # profile's blocklists is fetched from. Never a host of the TV's vendor: probe.plan refuses a
    # must-allow one
    tv_probe_target: str = ""
    # off: an apply is as before; report: it is probed before and after and says what it would have undone;
    # revert: a probe that passed before and fails after puts the saved state back
    apply_confirm: str = "off"
    # (revert) no: APPLY_CONFIRM=revert acts as report, the shipped default; yes: the owner's word that revert
    # may undo an apply on this gateway (design decision 65, its note of 2026-11-08: two report-only weeks
    # with no false fail first)
    revert_supported: str = "no"
    # ---- (probe) end
    # (reliability) on: the gateway's own plain lookups (port 53) are refused on WAN_IF for a bounded time
    # while the VPN's tunnel is down: from the uplink coming up until the tunnel does, and from the VPN
    # client's stop (at shutdown too), each hold ending by itself (src/tvgw/seal.py, design decision 73).
    # Never the TV's lookups. off: as before, the leak counted (decision 44)
    vpn_dns_seal: str = "off"
    # (reliability) the owner's age recipient (`age1...`, a plugin's `age1<name>1...`, or an ssh public key):
    # `tvgw backup --export` encrypts the copy that leaves the gateway to it, and the key that opens it stays
    # on the owner's computer; empty: no export. Checked by the export alone, never here: an optional backup
    # key must not stop the ingest, verify or an install
    backup_recipient: str = ""
    # ---- (web) begin: the read-only page on the home network, behind a password (design decision 76)
    # on: tvgw-web.service serves it over HTTPS on the uplink's address (or loopback); off, which a file
    # without the key means: nothing listens. The template says off until the owner decides
    web: str = "off"
    web_port: int = 8443  # 1024 to 65535: the unit holds no capability, so no port below 1024
    web_bind: str = "uplink"  # uplink: WAN_IF's IPv4 address, found at start; loopback: 127.0.0.1 only
    # the page's own files: written by `sudo tvgw web cert` and `sudo tvgw web password`, root:tvgw-web
    web_cert: str = "/etc/tvgw/web-cert.pem"
    web_key: str = "/etc/tvgw/web-key.pem"
    web_password: str = "/etc/tvgw/web-password"
    # ---- (web) end
    # (trials) record: the hourly ingest draws a keyed coin for each viewing day before it begins and
    # measures each day's app starts once settled, refusing nothing (design decision 98); off: nothing is
    # drawn. A later stage's word (one, several) is refused until that stage has landed
    trial: str = "off"


# conf key -> Settings field (only the keys an operator is meant to set)
CONF_KEYS = {
    "TV_IP": "tv_ip",
    "TV_MAC": "tv_mac",
    "TV_NAME": "tv_name",
    "TV_COUNTRY": "tv_country",  # (W12) the TV's country, for the must-allow hosts named by country
    "GW_IP": "gw_ip",
    "TV_IF": "tv_if",  # (packaging) the TV side, templated: docs/reference/settings.md
    "TV_NET": "tv_net",
    "WAN_IF": "wan_if",
    "UPLINK": "uplink",
    "VPN_IF": "vpn_if",  # (events)
    "BLOCK_QUIC": "block_quic",
    "STRICT_PORTS": "strict_ports",
    "DNSGATE": "dnsgate",
    "DNSGATE_FILL": "dnsgate_fill",  # (inpath)
    "NAME_BINDING": "name_binding",  # (namebound)
    "CAPTURE_MODE": "capture_mode",  # (capture)
    "CO_TENANT_UNITS": "co_tenant_units",  # (guard)
    "ADTECH_PORT_WALL": "adtech_port_wall",  # (acr)
    "CLOCK_PORT": "clock_port",  # (ports)
    "PROFILE": "profile",
    "DOH_DROP_MAX": "doh_drop_max",  # (listguard) read by tvgw-doh-update
    "DNS_UPSTREAMS": "dns_upstreams",
    "DNS_BOOTSTRAP": "dns_bootstrap",
    "DNS_FALLBACK": "dns_fallback",  # (lists)
    "ADGUARD_LISTEN": "adguard_listen",  # (adguard)
    "ADGUARD_TAKE_OVER": "adguard_take_over",  # (adguard)
    "DB_DAYS": "db_days",
    "DECISIONS_DAYS": "decisions_days",  # (autonomy)
    "URI_VALUES": "uri_values",  # (record)
    "NAME_HMAC": "name_hmac",  # (record)
    "JOURNAL_DAYS": "journal_days",  # (record)
    "PCAP_DAYS": "pcap_days",
    "PCAP_MAX_GB": "pcap_max_gb",
    "QUERYLOG_DAYS": "querylog_days",  # (lists)
    "STATS_DAYS": "stats_days",  # (lists)
    "STATE_DIR": "state_dir",
    "DB_PATH": "db_path",
    "REPORTS_DIR": "reports_dir",
    "LIVE_READING": "live_reading",  # (app in front)
    "TV_EVENTS_DAYS": "tv_events_days",  # (app in front)
    "ATTENTION_WALL": "attention_wall",  # (attention) read by tvgw-apply, tvgw-attention and tvlive
    "ANALYST_MODEL": "analyst_model",
    "ANALYST_EFFORT": "analyst_effort",
    "ANALYST_WINDOW": "analyst_window",
    "ANALYST_SCHEDULE": "analyst_schedule",
    "ANALYST_WEEKLY_MODEL": "analyst_weekly_model",
    "ANALYST_WEEKLY_EFFORT": "analyst_weekly_effort",
    "ANALYST_WEEKLY_SCHEDULE": "analyst_weekly_schedule",
    "ANALYST_APPLY": "analyst_apply",
    "ANALYST_VERIFIER_MODEL": "analyst_verifier_model",
    "ANALYST_VERIFIER_EFFORT": "analyst_verifier_effort",
    "AUTO_RULES": "auto_rules",
    "LEDGER": "ledger",  # (ledger)
    "JUDGE2_CLEAN_HOURS": "judge2_clean_hours",  # (ledger)
    "UPLOAD_CEILING": "upload_ceiling",  # (budget)
    "THREAT_LISTS": "threat_lists",  # (threats) read by tvgw threats and the hourly ingest
    "THREAT_LIST_URLS": "threat_list_urls",  # (threats)
    # (reserved) checked by load(); nothing reads them yet
    "BRIEF_STYLE": "brief_style",  # (plain) read by tvgw brief and tvgw-analyze since the plain brief
    "UPDATE_CHECK": "update_check",  # (updates) read by tvgw updates and install.sh since decision 77
    "UPDATE_REPO": "update_repo",  # (updates) read by tvgw updates
    "UPDATE_INSTALL": "update_install",  # (updates) read by tvgw updates and install.sh (decision 77)
    "LOCAL_RULES": "local_rules",  # (site rules) read by tvgw adguard apply and tvgw allow since decision 59
    "TV_PAIR_MANIFEST": "tv_pair_manifest",
    "TV_DHCP": "tv_dhcp",
    "BACKUP_KEEP": "backup_keep",
    "WAN_GW_MODE": "wan_gw_mode",  # (uplink) read by tvgw-apply (wan_router, in the tvgw-net block)
    "TV_PORT_MANAGER": "tv_port_manager",
    "NETWATCH": "netwatch",
    "DEPLOY_WINDOW": "deploy_window",
    # (probe) read by tvgw-apply, tvgw probe and tvgw verify --record (design decision 65)
    "TV_PROBE": "tv_probe",
    "TV_PROBE_IP": "tv_probe_ip",
    "TV_PROBE_TARGET": "tv_probe_target",  # only Python reads it
    "APPLY_CONFIRM": "apply_confirm",
    "VPN_DNS_SEAL": "vpn_dns_seal",  # (reliability) read by tvgw seal and the dispatcher
    "BACKUP_RECIPIENT": "backup_recipient",  # (reliability) read by tvgw backup --export
    # (web) read by tvgw web, tvgw verify and install.sh (design decision 76)
    "WEB": "web",
    "WEB_PORT": "web_port",
    "WEB_BIND": "web_bind",
    "REVERT_SUPPORTED": "revert_supported",  # (revert) read by tvgw-apply; verify reads the hold it leaves
    "TRIAL": "trial",  # (trials) read by the hourly ingest and tvgw trial
}
# switches tvgw-apply reads with an exact `case`; a near miss (`Yes`, `on`) must fail here, not there
# the analyst's reasoning depth, checked here (tvgw-apply never reads it, so it is not in CHOICES)
EFFORTS = ("low", "medium", "high", "xhigh", "max")
APPLY_MODES = ("off", "auto")
LEDGER_MODES = ("on", "off")  # (ledger)
JUDGE2_MAX_CLEAN_HOURS = 14 * 24  # (ledger) every hour of judge v2's 14-day ceiling
# (record) checked here: tvgw-apply never reads them, so they are not in CHOICES
URI_MODES = ("keep", "lengths")
HMAC_MODES = ("off", "on")
JOURNAL_MAX_DAYS = 3650
TV_EVENTS_MAX_DAYS = 365  # (app in front) the finer record of the app in front is never kept past a year
CHOICES = {
    "UPLINK": ("direct", "vpn"),
    "BLOCK_QUIC": ("yes", "no"),
    "STRICT_PORTS": ("yes", "no"),
    "DNSGATE": ("off", "count"),
    "DNSGATE_FILL": ("passive", "inpath"),  # (inpath) the default first; read with DNSGATE=count only
    "NAME_BINDING": ("off", "count"),  # (namebound) the default first; tvgw-apply and tvgw-names read it
    "CAPTURE_MODE": ("full", "headers"),  # (capture) tvgw-apply and both capture units read it
    "ADTECH_PORT_WALL": ("yes", "no"),  # (acr)
    "CLOCK_PORT": ("profile", "any", "resolved", "none"),  # (ports) the default first
    "WAN_GW_MODE": ("literal", "auto"),  # (uplink) the default first: what a file without the key means
    "TV_PROBE": ("off", "on"),  # (probe) the default first, as for every switch tvgw-apply reads
    "APPLY_CONFIRM": ("off", "report", "revert"),  # (probe)
    "REVERT_SUPPORTED": ("no", "yes"),  # (revert) the default first
    # (attention) read by tvgw-apply since the attention count (design decision 69): the live reading's
    # dead-man entries and the count stand only where it runs
    "LIVE_READING": ("off", "on"),
    "ATTENTION_WALL": ("count", "off", "refuse"),  # (attention) the default first
}
# (reserved) switches only load() checks, the default first: no script has a `case` for them, so they
# stay out of CHOICES, which the deploy lint holds to tvgw-apply's case arms
MODES = {
    "BRIEF_STYLE": ("full", "plain"),
    "UPDATE_CHECK": ("off", "weekly"),  # (updates) read by tvgw updates and install.sh's timer block
    "UPDATE_INSTALL": ("off", "security", "all"),  # (updates) design decision 77
    "TV_PAIR_MANIFEST": ("auto", "readonly", "library"),
    "TV_DHCP": ("open", "pinned"),
    "TV_PORT_MANAGER": ("auto", "networkmanager", "tvgw"),
    "NETWATCH": ("auto", "off", "shadow", "on"),
    "VPN_DNS_SEAL": ("off", "on"),  # (reliability) read by tvgw seal; the dispatcher reads `on` alone
    "THREAT_LISTS": ("off", "count"),  # (threats) read by tvgw threats, the hourly ingest and tvgw check
    "WEB": ("off", "on"),  # (web) read by tvgw web serve, tvgw verify and install.sh
    "WEB_BIND": ("uplink", "loopback"),  # (web)
    "TRIAL": ("off", "record"),  # (trials) read by the hourly ingest and tvgw trial; nothing refuses
}
# (trials) the trial's later stages, each refused by name until it has landed: they would refuse
TRIAL_LATER = ("one", "several")
# (web) the page's port: no capability in its unit, so at least 1024
WEB_PORTS = range(1024, 65536)
# (updates) a GitHub repository as owner/name: the update check puts it into an API path, so nothing
# else (a URL, a query, a further path segment) may come through
_REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}")
# (probe) a host name with a dot in it, lower case; its last label has a letter, so no IPv4 address fits
_HOST = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?"
)
# (reserved) two times of day, start and end, in the gateway's local time; the end may be after midnight
_HHMM = r"(?:[01][0-9]|2[0-3]):[0-5][0-9]"
_WINDOW = re.compile(f"({_HHMM})-({_HHMM})")


def parse_conf(text: str) -> dict[str, str]:
    """KEY=VALUE lines; quotes and trailing comments handled; other lines ignored. An unquoted value
    with a space in it is refused: the shell scripts source this file, and to the shell `KEY=Mon 04:10`
    sets KEY for a command named `04:10`, which stops them under `set -e` while Python read the value."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = _LINE.match(line)
        if m:
            if m.group(5) is not None and any(ch.isspace() for ch in m.group(5)):
                raise ValueError(
                    f"{m.group(1)}={m.group(5).strip()!r} in tvgw.conf: a value with a space must be quoted"
                )
            out[m.group(1)] = next(g for g in (m.group(3), m.group(4), m.group(5)) if g is not None).strip()
    return out


def load(path: str | Path = "/etc/tvgw/tvgw.conf", **overrides) -> Settings:
    """Settings from the conf file (missing file = defaults), then keyword overrides. The two
    addresses are checked: every source keeps only the rows that equal `tv_ip`, so a typo there
    would record nothing from any source while every source counted as read. Any other failure to
    read the file propagates: a conf that is there but unreadable must not become the defaults."""
    try:
        conf = parse_conf(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        conf = {}
    defaults = Settings()
    changes: dict[str, object] = {}
    for key, name in CONF_KEYS.items():
        value = conf.get(key, "")
        if value != "":  # an empty value keeps the default
            # the annotations are strings under `from __future__ import annotations`; the default's
            # type is the fact
            parse = _PARSE.get(type(getattr(defaults, name)))
            changes[name] = parse(key, value) if parse else value
    changes.update(overrides)
    s = replace(defaults, **changes)
    for key, value in (("TV_IP", s.tv_ip), ("GW_IP", s.gw_ip)):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise ValueError(f"{key}={value!r} in tvgw.conf: not an IP address") from None
    try:  # (probe) its shape here; its place in TV_NET where it is used (probe_side), as for TV_IP
        ipaddress.IPv4Address(s.tv_probe_ip)
    except ValueError:
        raise ValueError(f"TV_PROBE_IP={s.tv_probe_ip!r} in tvgw.conf: not an IPv4 address") from None
    if s.tv_probe_target and not _HOST.fullmatch(s.tv_probe_target):  # (probe) a name, never an address
        raise ValueError(
            f"TV_PROBE_TARGET={s.tv_probe_target!r} in tvgw.conf: expected a host name,"
            " such as cdn.example.net"
        )
    _check_tv_shape(s)
    if s.tv_country and not re.fullmatch(r"[a-z]{2}", s.tv_country):  # (W12)
        raise ValueError(
            f"TV_COUNTRY={s.tv_country!r} in tvgw.conf: expected two lower-case letters, as us or de"
        )
    co_tenants(s.co_tenant_units)  # (guard) refused here, before install.sh writes a drop-in
    _check_vpn_shape(s)  # (events)
    for key, allowed in CHOICES.items():
        value = getattr(s, CONF_KEYS[key])
        if value not in allowed:
            raise ValueError(f"{key}={value!r} in tvgw.conf: expected one of {', '.join(allowed)}")
    for key, effort in (
        ("ANALYST_EFFORT", s.analyst_effort),
        ("ANALYST_WEEKLY_EFFORT", s.analyst_weekly_effort),
        ("ANALYST_VERIFIER_EFFORT", s.analyst_verifier_effort),
    ):
        if effort not in EFFORTS:
            raise ValueError(f"{key}={effort!r} in tvgw.conf: expected one of {', '.join(EFFORTS)}")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{2,60}", s.analyst_model):
        raise ValueError(f"ANALYST_MODEL={s.analyst_model!r} in tvgw.conf: not a model id")
    if s.analyst_weekly_model != "off" and not re.fullmatch(
        r"[a-z0-9][a-z0-9.-]{2,60}", s.analyst_weekly_model
    ):
        raise ValueError(
            f"ANALYST_WEEKLY_MODEL={s.analyst_weekly_model!r} in tvgw.conf: not a model id (or off)"
        )
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{2,60}", s.analyst_verifier_model):
        raise ValueError(f"ANALYST_VERIFIER_MODEL={s.analyst_verifier_model!r} in tvgw.conf: not a model id")
    if s.analyst_apply not in APPLY_MODES:
        raise ValueError(
            f"ANALYST_APPLY={s.analyst_apply!r} in tvgw.conf: expected one of {', '.join(APPLY_MODES)}"
        )
    # (autonomy) keep, or a whole number of days from 1 to 36500: a typo must never become "keep nothing"
    d = s.decisions_days
    if d != "keep" and not (re.fullmatch(r"\d{1,5}", d) and 1 <= int(d) <= 36500):
        raise ValueError(f"DECISIONS_DAYS={d!r} in tvgw.conf: expected keep or a whole number of days")
    if s.ledger not in LEDGER_MODES:  # (ledger)
        raise ValueError(f"LEDGER={s.ledger!r} in tvgw.conf: expected one of {', '.join(LEDGER_MODES)}")
    if not 1 <= s.judge2_clean_hours <= JUDGE2_MAX_CLEAN_HOURS:  # (ledger) at most the 14-day ceiling
        raise ValueError(
            f"JUDGE2_CLEAN_HOURS={s.judge2_clean_hours} in tvgw.conf: expected 1 to {JUDGE2_MAX_CLEAN_HOURS}"
        )
    upload_ceiling_bytes(s.upload_ceiling)  # (budget) refused here, before a brief reads it
    from tvgw import threats  # here: the module imports the store and the profile, which need no settings

    threats.parse_urls(s.threat_list_urls)  # (threats) refused here, before the timer downloads anything
    # (record) the minimization switches and the journal's span
    for key, value, allowed in (
        ("URI_VALUES", s.uri_values, URI_MODES),
        ("NAME_HMAC", s.name_hmac, HMAC_MODES),
    ):
        if value not in allowed:
            raise ValueError(f"{key}={value!r} in tvgw.conf: expected one of {', '.join(allowed)}")
    j = s.journal_days
    if j != "off" and not (re.fullmatch(r"[1-9][0-9]{0,3}", j) and int(j) <= JOURNAL_MAX_DAYS):
        raise ValueError(f"JOURNAL_DAYS={j!r} in tvgw.conf: expected 1 to {JOURNAL_MAX_DAYS} days, or off")
    w = s.analyst_window
    if w != "day" and not (re.fullmatch(r"\d{1,3}h", w) and 1 <= int(w[:-1]) <= 168):
        raise ValueError(f"ANALYST_WINDOW={w!r} in tvgw.conf: expected day or 1h..168h")
    schedules = (
        ("ANALYST_SCHEDULE", s.analyst_schedule),
        ("ANALYST_WEEKLY_SCHEDULE", s.analyst_weekly_schedule),
    )
    for key, sched in schedules:
        if not sched or len(sched) > 80 or any(ch in sched for ch in "\n;&|"):
            raise ValueError(
                f"{key}={sched!r} in tvgw.conf: a time, a day and time, or a calendar expression"
            )
    _check_adguard_keys(s)  # (lists)
    _check_seal(s)  # (reliability)
    _check_reserved(s)  # (reserved)
    if not 1 <= s.tv_events_days <= TV_EVENTS_MAX_DAYS:  # (app in front)
        raise ValueError(
            f"TV_EVENTS_DAYS={s.tv_events_days} in tvgw.conf: expected 1 to {TV_EVENTS_MAX_DAYS} days"
        )
    if not 1 <= s.doh_drop_max <= 100:  # (listguard) 0 would hold the daily refresh for its usual churn
        raise ValueError(f"DOH_DROP_MAX={s.doh_drop_max} in tvgw.conf: expected 1 to 100 (percent)")
    if s.web_port not in WEB_PORTS:  # (web)
        raise ValueError(f"WEB_PORT={s.web_port} in tvgw.conf: expected 1024 to 65535")
    return s


def _check_reserved(s: Settings) -> None:
    """(reserved) The keys nothing reads yet, refused on the same terms as the rest: a near miss
    (`TV_DHCP=Pinned`) must fail at the first command, not stay quiet until the change that reads the
    key ships and then mean something else."""
    if s.trial in TRIAL_LATER:
        raise ValueError(
            f"TRIAL={s.trial!r} in tvgw.conf: its stage has not landed, and only it may refuse; expected one"
            f" of {', '.join(MODES['TRIAL'])}"
        )
    for key, allowed in MODES.items():
        value = getattr(s, CONF_KEYS[key])
        if value not in allowed:
            raise ValueError(f"{key}={value!r} in tvgw.conf: expected one of {', '.join(allowed)}")
    repo = s.update_repo
    if not _REPO.fullmatch(repo) or repo.split("/")[1] in (".", ".."):
        raise ValueError(f"UPDATE_REPO={repo!r} in tvgw.conf: expected a GitHub repository as owner/name")
    rules = s.local_rules
    # normpath keeps a leading `//` (POSIX leaves two slashes to the system; Linux reads one), so that is
    # refused on its own, and `/` names no file
    if not os.path.isabs(rules) or os.path.normpath(rules) != rules or rules.startswith("//") or rules == "/":
        raise ValueError(f"LOCAL_RULES={rules!r} in tvgw.conf: expected an absolute path to a file")
    # the machine rewrites its own file, and the owner's rules would go with it
    if rules == _one_slash(os.path.normpath(s.auto_rules)):
        raise ValueError(f"LOCAL_RULES={rules!r} in tvgw.conf: the owner's rules cannot be AUTO_RULES")
    m = _WINDOW.fullmatch(s.deploy_window)
    if not m or m.group(1) == m.group(2):
        raise ValueError(
            f"DEPLOY_WINDOW={s.deploy_window!r} in tvgw.conf: expected HH:MM-HH:MM, a start and a"
            " different end"
        )


def _one_slash(path: str) -> str:
    """(reserved) `path` with a leading `//` read as `/`, as Linux reads it: normpath keeps exactly two."""
    return "/" + path.lstrip("/") if path.startswith("//") else path


# (guard) The co-tenants: units of other software on the Pi that never talk to the TV, and so get a
# cgroup filter against its subnet (deploy/install.sh, design decision 42). A name ending in `@` is a
# template, filtered for every instance. The TV's own services must never get one: they serve it.
_UNIT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,98}@?")
NOT_CO_TENANTS = ("AdGuardHome", "nginx", "dnsmasq")  # and every tvgw unit


def co_tenants(value: str) -> tuple[str, ...]:
    """The unit names CO_TENANT_UNITS lists, without `.service`, in order and once each; `none` is the
    empty list. A name that is not a unit name, or one of the units the TV depends on, is refused: a
    filter on dnsmasq or AdGuard Home would take the TV's DHCP or DNS away."""
    if value.strip() == "none":
        return ()
    out: list[str] = []
    for word in value.split():
        name = word.removesuffix(".service")
        if not _UNIT_NAME.fullmatch(name):
            raise ValueError(f"CO_TENANT_UNITS: {word!r} is not a systemd unit name")
        if name in NOT_CO_TENANTS or name.startswith("tvgw"):
            raise ValueError(f"CO_TENANT_UNITS: {name} serves the TV and must not be filtered from it")
        if name not in out:
            out.append(name)
    return tuple(out)


# (adguard) ADGUARD_LISTEN: checked here (install.sh reads it with a plain test, so it is not in CHOICES)
ADGUARD_LISTEN_MODES = ("keep", "gateway")
# (adguard) ADGUARD_TAKE_OVER, the default first; only Python reads it
ADGUARD_TAKE_OVER_MODES = ("ask", "no", "yes")
# (lists) AdGuard Home takes a query-log and statistics interval between an hour and a year (its
# configuration reference: 1h to 8760h); the settings count whole days
ADGUARD_DAYS = range(1, 366)
# (lists) the forms a fallback resolver may take: encrypted, and named by address, so it needs no
# bootstrap lookup and no resolver nobody configured is ever asked in plain DNS
_FALLBACK = re.compile(
    r"(?:https://(?P<h>[0-9.]+)(?::\d{1,5})?/\S*|(?:tls|quic)://(?P<t>[0-9.]+)(?::\d{1,5})?)"
)


def fallback_host(item: str) -> str | None:
    """The IPv4 address an encrypted upstream written by address names (`https://198.51.100.9/dns-query`,
    `tls://198.51.100.9`), or None for any other form: a host name, plain DNS, another scheme."""
    m = _FALLBACK.fullmatch(item)
    if not m:
        return None
    host = m.group("h") or m.group("t")
    try:
        return str(ipaddress.IPv4Address(host))
    except ValueError:
        return None


def _check_seal(s: Settings) -> None:
    """(reliability) VPN_DNS_SEAL=on only with every DNS upstream named by address: AdGuard Home looks an
    upstream named by host up in plain DNS on port 53 (its bootstrap), as root, and a hold would refuse
    that, so the TV's new lookups would fail for the hold's length. Refused here, where the combination is
    made, with the reason (src/tvgw/seal.py, design decision 73)."""
    if s.vpn_dns_seal != "on" or s.vpn_if == "none":
        return
    for item in (x.strip() for x in s.dns_upstreams.split(",") if x.strip()):
        if fallback_host(item) is None:
            raise ValueError(
                f"VPN_DNS_SEAL=on in tvgw.conf with DNS_UPSTREAMS item {item!r}: AdGuard Home looks an"
                " upstream named by host up in plain DNS, which the seal refuses while the tunnel is down,"
                " and the TV's new lookups would wait on it; name every upstream by address"
                " (https://<address>/...) or keep VPN_DNS_SEAL=off"
            )


def _check_adguard_keys(s: Settings) -> None:
    """(lists) The AdGuard settings the plan writes: intervals AdGuard accepts, and a fallback that is a
    second resolver by address, encrypted, and not one of the upstreams again (a fallback on the same
    addresses fails with them, which is the outage it exists for). (adguard) ADGUARD_LISTEN is keep or
    gateway, and ADGUARD_TAKE_OVER ask, no or yes."""
    if s.adguard_listen not in ADGUARD_LISTEN_MODES:  # (adguard)
        raise ValueError(f"ADGUARD_LISTEN={s.adguard_listen!r} in tvgw.conf: expected keep or gateway")
    if s.adguard_take_over not in ADGUARD_TAKE_OVER_MODES:  # (adguard)
        raise ValueError(f"ADGUARD_TAKE_OVER={s.adguard_take_over!r} in tvgw.conf: expected ask, no or yes")
    for key, days in (("QUERYLOG_DAYS", s.querylog_days), ("STATS_DAYS", s.stats_days)):
        if days not in ADGUARD_DAYS:
            raise ValueError(f"{key}={days} in tvgw.conf: AdGuard Home keeps 1 to 365 days")
    items = [x.strip() for x in s.dns_fallback.split(",") if x.strip()]
    upstreams = {fallback_host(x.strip()) or x.strip() for x in s.dns_upstreams.split(",") if x.strip()}
    for item in items:
        host = fallback_host(item)
        if host is None:
            raise ValueError(
                f"DNS_FALLBACK={item!r} in tvgw.conf: expected an encrypted resolver by IPv4 address,"
                " such as https://198.51.100.9/dns-query or tls://198.51.100.9"
            )
        if host in upstreams:
            raise ValueError(
                f"DNS_FALLBACK={item!r} in tvgw.conf: {host} is already an upstream; the fallback must be"
                " a second operator"
            )


def decisions_days(s: Settings) -> int | None:
    """(autonomy) DECISIONS_DAYS as days, or None for `keep`."""
    return None if s.decisions_days == "keep" else int(s.decisions_days)


# (budget) UPLOAD_CEILING's sizes: digits and an optional K, M or G, in powers of 1024 as the brief prints
# them, from 64K to 1G. Below 64K an hour of a few dozen handshakes to one destination would pass it,
# and every busy destination-hour would read as an event; above 1G none ever would
UPLOAD_CEILING_RANGE = (64 * 1024, 1024**3)
_SIZE = re.compile(r"([1-9][0-9]{0,9})([KMG]?)")
_UNITS = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3}


def upload_ceiling_bytes(value: str) -> int | None:
    """(budget) UPLOAD_CEILING as bytes of payload in a destination-hour, or None for `auto`: the ceiling
    the hourly ingest sets once from the gateway's own clean history. A near miss is refused, never
    read as `auto`."""
    if value == "auto":
        return None
    m = _SIZE.fullmatch(value)
    n = int(m.group(1)) * _UNITS[m.group(2)] if m else 0
    low, high = UPLOAD_CEILING_RANGE
    if not low <= n <= high:
        raise ValueError(
            f"UPLOAD_CEILING={value!r} in tvgw.conf: expected auto, or a size from 64K to 1G such as 4M"
        )
    return n


def _int(key: str, value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise ValueError(f"{key}={value!r} in tvgw.conf: expected a whole number") from None
    if n < 1:
        raise ValueError(f"{key}={value!r} in tvgw.conf: must be at least 1")
    return n


def _float(key: str, value: str) -> float:
    try:
        x = float(value)
    except ValueError:
        raise ValueError(f"{key}={value!r} in tvgw.conf: expected a number") from None
    if not (math.isfinite(x) and x > 0):  # a typo must never become "keep nothing"
        raise ValueError(f"{key}={value!r} in tvgw.conf: must be more than 0")
    return x


_PARSE = {int: _int, float: _float}  # by the default's type; every other field is text


# (packaging) The TV side: TV_IF, TV_NET and GW_IP feed tvgw-apply, the dnsmasq, nginx and NetworkManager
# files and the units, so a second site with other interfaces needs no edited script. The shell side
# checks the same rules in the `tvgw-net` block that install.sh and tvgw-apply share
# (tests/unit/test_packaging.py runs both on the same cases).
IFNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}")  # a kernel interface name: at most 15 bytes, no `/`
TV_PREFIXES = range(16, 28)  # /27 is the smallest subnet that holds the DHCP pool at .10 to .20
PRIVATE_NETS = tuple(ipaddress.IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
DHCP_POOL = (10, 20)  # the pool's first and last host, as offsets into TV_NET (the shipped .10 to .20)


@dataclass(frozen=True)
class TvSide:
    """What the shell side derives from TV_NET: the values the dnsmasq template and nmcli need."""

    network: ipaddress.IPv4Network
    gw: ipaddress.IPv4Address
    prefix: int
    netmask: str
    broadcast: str
    dhcp_first: str
    dhcp_last: str


def _check_tv_shape(s: Settings) -> None:
    """The two TV-side keys on their own, checked by every command: a typo in either would otherwise
    surface only when tvgw-apply refuses it at the next boot."""
    # (events) not lo, nor either PIA tunnel name (VPN_AUTO): the input chain drops new connections from both
    if not IFNAME.fullmatch(s.tv_if) or s.tv_if in ("lo", "tun0", "wgpia0"):
        raise ValueError(f"TV_IF={s.tv_if!r} in tvgw.conf: not an interface name for the TV")
    _tv_network(s.tv_net)


def _tv_network(value: str) -> ipaddress.IPv4Network:
    bad = f"TV_NET={value!r} in tvgw.conf: not an IPv4 network such as 10.10.10.0/24"
    try:
        net = ipaddress.IPv4Network(value, strict=True)
    except ValueError:
        raise ValueError(bad) from None
    if value != str(net):  # `10.10.10.0/08` or no prefix: the shell side reads only the canonical form
        raise ValueError(bad)
    if net.prefixlen not in TV_PREFIXES:
        raise ValueError(f"TV_NET={value!r} in tvgw.conf: the prefix must be /16 to /27")
    if not any(net.subnet_of(p) for p in PRIVATE_NETS):
        raise ValueError(f"TV_NET={value!r} in tvgw.conf: must be inside 10/8, 172.16/12 or 192.168/16")
    return net


# ---- (events) the VPN side: VPN_IF, as tvgw-apply and the dispatcher read it (design decision 44)
VPN_AUTO = ("tun0", "wgpia0")  # PIA's OpenVPN and WireGuard interfaces, in the order auto prefers them


def _check_vpn_shape(s: Settings) -> None:
    """VPN_IF on its own: auto, none or an interface name. A typo would otherwise surface only when
    tvgw-apply refuses it at the next boot, with the TV dark."""
    if s.vpn_if in ("auto", "none"):
        return
    if not IFNAME.fullmatch(s.vpn_if) or s.vpn_if == "lo":
        raise ValueError(f"VPN_IF={s.vpn_if!r} in tvgw.conf: expected auto, none or the tunnel's name")


def vpn_side(s: Settings) -> None:
    """VPN_IF against the other settings, the rules tvgw-apply refuses a conf by: not the TV's port or
    the uplink, and a tunnel to send the TV into when UPLINK=vpn. Not part of `load`, like `tv_side`:
    a reader must still work on a conf the apply would refuse."""
    _check_vpn_shape(s)
    if s.vpn_if in (s.tv_if, s.wan_if):
        raise ValueError(f"VPN_IF={s.vpn_if!r} in tvgw.conf: the tunnel cannot be TV_IF or WAN_IF")
    if s.uplink == "vpn" and s.vpn_if == "none":
        raise ValueError("UPLINK=vpn in tvgw.conf needs a tunnel, and VPN_IF is none")


def _iface_exists(dev: str) -> bool:
    return os.path.exists(f"/proc/sys/net/ipv4/conf/{dev}")


def vpn_interface(s: Settings, exists: Callable[[str], bool] = _iface_exists) -> str | None:
    """The tunnel as tvgw-apply resolves VPN_IF at its apply: the name it gives; for auto, tun0 or else
    wgpia0, whichever exists now (per deep dive 12 F1, PIA 3.8.0 made WireGuard the default for new
    installations, so a reinstalled client can change it); None when there is none or VPN_IF is none."""
    if s.vpn_if == "none":
        return None
    if s.vpn_if != "auto":
        return s.vpn_if
    return next((dev for dev in VPN_AUTO if exists(dev)), None)


def uplink_interface(s: Settings, exists: Callable[[str], bool] = _iface_exists) -> str:
    """Where tvgw-apply sends the TV: WAN_IF in direct mode, else the tunnel, tun0 before one exists
    (the boot apply runs before the VPN connects, and the dispatcher applies again when it does)."""
    if s.uplink == "direct":
        return s.wan_if
    return vpn_interface(s, exists) or "tun0"


def tv_side(s: Settings, with_tv_ip: bool = True) -> TvSide:
    """The TV side as the shell side builds it, or ValueError naming the first rule broken. Not part of
    `load`: membership is enforced where the values are written (install.sh, tvgw-apply), and a reader
    must still work on a conf the installer would refuse. A settings writer calls this before writing."""
    _check_tv_shape(s)
    if s.tv_if == s.wan_if:
        raise ValueError(f"TV_IF={s.tv_if!r} in tvgw.conf: the TV and the uplink need different interfaces")
    if s.wan_if in VPN_AUTO:  # (events) the input chain drops new connections from both PIA names
        raise ValueError(
            f"WAN_IF={s.wan_if!r} in tvgw.conf: a VPN tunnel's name;"
            " the uplink is the home network's interface"
        )
    net = _tv_network(s.tv_net)
    first, last = (net.network_address + n for n in DHCP_POOL)
    try:
        gw = ipaddress.IPv4Address(s.gw_ip)
    except ValueError:
        raise ValueError(f"GW_IP={s.gw_ip!r} in tvgw.conf: not an IPv4 address") from None
    if gw not in net or gw in (net.network_address, net.broadcast_address):
        raise ValueError(f"GW_IP={s.gw_ip} in tvgw.conf: must be a host address in TV_NET {net}")
    if first <= gw <= last:
        raise ValueError(f"GW_IP={s.gw_ip} in tvgw.conf: inside the DHCP pool {first} to {last}")
    if with_tv_ip:
        try:
            tv = ipaddress.IPv4Address(s.tv_ip)
        except ValueError:
            raise ValueError(f"TV_IP={s.tv_ip!r} in tvgw.conf: not an IPv4 address") from None
        if tv not in net or tv in (net.network_address, net.broadcast_address) or tv == gw:
            raise ValueError(
                f"TV_IP={s.tv_ip} in tvgw.conf: must be a host address in TV_NET {net}, not GW_IP"
            )
    return TvSide(net, gw, net.prefixlen, str(net.netmask), str(net.broadcast_address), str(first), str(last))


# ---- (probe) the test client's address, as tvgw-apply checks it (probe_ip_ok there) ----------------------
def probe_side(s: Settings) -> str:
    """TV_PROBE_IP when the probe may use it, or ValueError naming the rule it breaks: a host address of
    TV_NET that is not GW_IP, not TV_IP and not in the DHCP pool. tvgw-apply applies the same rules and
    loads no probe rules for an address that breaks one; it never stops for it. Not part of `load`: a
    gateway whose TV_NET is not the default one, and whose probe is off, must keep loading."""
    side = tv_side(s, with_tv_ip=False)
    try:
        ip = ipaddress.IPv4Address(s.tv_probe_ip)
    except ValueError:
        raise ValueError(f"TV_PROBE_IP={s.tv_probe_ip!r} in tvgw.conf: not an IPv4 address") from None
    net = side.network
    if ip not in net or ip in (net.network_address, net.broadcast_address):
        raise ValueError(f"TV_PROBE_IP={ip} in tvgw.conf: must be a host address in TV_NET {net}")
    if str(ip) in (s.gw_ip, s.tv_ip):
        raise ValueError(f"TV_PROBE_IP={ip} in tvgw.conf: the probe needs an address of its own")
    if ipaddress.IPv4Address(side.dhcp_first) <= ip <= ipaddress.IPv4Address(side.dhcp_last):
        raise ValueError(
            f"TV_PROBE_IP={ip} in tvgw.conf: inside the DHCP pool {side.dhcp_first} to {side.dhcp_last}"
        )
    return str(ip)


# ---- writing the settings file (tvgw setup) -------------------------------------------------------
# (setup) The writer edits the owner's file in place: comments, blank lines, order, keys it does not
# know and lines it cannot parse all stay as they were, and only the value of a changed key moves.
# Keys the shell scripts read but Settings does not, each with the check the scripts rely on.
SHELL_KEYS = {
    "WAN_GW": "ipv4",  # tvgw-apply: the home router, the direct uplink's next hop
    "URL_FILTER_RESOLVER": "ipv4",  # install.sh writes it into nginx with sed
    "DOH_LIST_URL": "url",  # tvgw-doh-update fetches it
}
PLACEHOLDER_MAC = "00:00:00:00:00:00"  # the template's "TV not identified yet"
_MAC = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
_TV_NAME = re.compile(r"[A-Za-z0-9_-]{1,63}")  # what install.sh lets through to dnsmasq
# What a value may contain. The file is sourced by bash as root, so a value must never be shell syntax:
# no `$`, backtick, quote, backslash, `;&|<>()`, `~` (tilde expansion runs in an assignment), `#`
# (parse_conf ends an unquoted value there) or a newline. A space is allowed and forces quotes.
_SAFE_VALUE = re.compile(r"[A-Za-z0-9 _.,:/@%+=*-]*")
_KEY_AT = re.compile(r"^\s*([A-Z][A-Z0-9_]*)=")
ADDED_HEADER = "# ---- set by tvgw setup ----"
BASH = "/bin/bash"  # check_conf syntax-checks the result with it where it exists


def writable_keys() -> frozenset[str]:
    """Every key the writer accepts: the operator keys Settings reads plus the shell-only ones. Read at
    call time, so a key another change adds to CONF_KEYS is writable without touching the writer."""
    return frozenset(CONF_KEYS) | frozenset(SHELL_KEYS)


def check_value(key: str, value: str) -> None:
    """Refuse one value before it reaches the file: an unknown key (an answers-file typo must not
    vanish into the file unread), shell syntax, and the formats the shell side checks itself
    (install.sh stops on a malformed TV_MAC or TV_NAME only after it has started changing things)."""
    if key not in writable_keys():
        raise ValueError(f"{key}: not a tvgw.conf setting (known: {', '.join(sorted(writable_keys()))})")
    if not _SAFE_VALUE.fullmatch(value):
        raise ValueError(
            f"{key}={value!r}: letters, digits, spaces and _ . , : / @ % + = * - only "
            "(the shell scripts source this file)"
        )
    if key == "TV_MAC" and value and not _MAC.fullmatch(value):
        raise ValueError(f"TV_MAC={value!r}: expected six hex pairs, aa:bb:cc:dd:ee:ff")
    if key == "TV_NAME" and value and not _TV_NAME.fullmatch(value):
        raise ValueError(f"TV_NAME={value!r}: 1 to 63 letters, digits, - and _")
    kind = SHELL_KEYS.get(key)
    if kind == "ipv4" and value:
        try:
            ipaddress.IPv4Address(value)
        except ValueError:
            raise ValueError(f"{key}={value!r}: not an IPv4 address") from None
    if kind == "url" and value and not re.fullmatch(r"https://[A-Za-z0-9.-]+(?::\d{1,5})?/\S*", value):
        raise ValueError(f"{key}={value!r}: expected an https:// URL")


def _render(value: str, quote: str) -> str:
    """The value as the file carries it: in the quotes the line already used, else in double quotes
    when it holds a space (bash would run the rest as a command), else bare."""
    if quote or " " in value:
        q = quote or '"'
        return f"{q}{value}{q}"
    return value


def update_conf(text: str, changes: dict[str, str]) -> str:
    """`text` with each key in `changes` set, everything else byte for byte as it was. A key already in
    the file keeps its line, its quoting and, where the new value fits, the column its comment started
    in; a key the file lacks is appended under one header. Every occurrence of a repeated key is set, so
    whichever one a reader takes, it reads the new value. The result must load: it is refused whole,
    and nothing is returned, when `load()` would refuse it, so no file the writer produced can stop the
    next command."""
    for key, value in changes.items():
        check_value(key, value)
    lines = text.splitlines(keepends=True)
    seen: set[str] = set()
    for i, line in enumerate(lines):
        km = _KEY_AT.match(line)
        if not km or km.group(1) not in changes:
            continue
        key = km.group(1)
        body = line.rstrip("\r\n")
        end = line[len(body) :]
        m = _LINE.match(body)
        # `KEY=` followed by something parse_conf never read (an unquoted `#`), or a bare value with a
        # quote in it (the first line of a quoted value that runs on over several lines): what bash
        # reads there is not what parse_conf reads, so the writer cannot know which lines the value
        # spans. Replacing the line could leave the rest of the value behind as shell syntax.
        if m is None or (m.group(5) is not None and any(q in m.group(5) for q in "\"'")):
            raise ValueError(f"{key}: line {i + 1} is not a plain KEY=VALUE line; edit it by hand")
        quote = '"' if m.group(3) is not None else "'" if m.group(4) is not None else ""
        start, stop = m.span(2)
        new = _render(changes[key], quote)
        rest = body[stop:]
        if m.group(6) is not None:  # keep the comment's column when the new value leaves room for it
            gap = len(rest) - len(rest.lstrip())
            pad = max(1, gap + (stop - start) - len(new))
            rest = " " * pad + rest.lstrip()
        lines[i] = body[:start] + new + rest + (end or "\n")
        seen.add(key)
    missing = [k for k in changes if k not in seen]
    if missing:
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        if not any(line.rstrip("\r\n") == ADDED_HEADER for line in lines):
            lines.append(("\n" if lines else "") + ADDED_HEADER + "\n")
        lines.extend(f"{k}={_render(changes[k], '')}\n" for k in missing)
    out = "".join(lines)
    check_conf(out)
    return out


def check_conf(text: str) -> Settings:
    """The Settings `text` gives, through the very `load()` every command starts with, or ValueError.
    The text goes through a private temporary file because `load()` reads a path; nothing else is
    written. Where bash is installed, the text must also pass `bash -n`: install.sh and tvgw-apply
    source it under `set -e`, and parse_conf skips lines it cannot read, so a file it accepts can
    still be one bash cannot parse. The TV side must pass `tv_side()`, the rules install.sh and
    tvgw-apply refuse a conf by: a file that broke them would leave the TV dark at the next boot."""
    import tempfile  # only the writer needs it

    with tempfile.TemporaryDirectory(prefix="tvgw-conf-") as d:
        p = Path(d) / "tvgw.conf"
        p.write_text(text, encoding="utf-8")
        settings = load(p)
    tv_side(settings)  # TV_IF, TV_NET, GW_IP and TV_IP together, as install.sh checks them
    vpn_side(settings)  # (events) VPN_IF against them, as tvgw-apply checks it
    if settings.tv_probe == "on":  # (probe) a writer never turns the probe on with an address it cannot use
        probe_side(settings)
    if Path(BASH).exists():
        import subprocess

        r = subprocess.run(
            [BASH, "-n"], input=text, capture_output=True, encoding="utf-8", errors="replace", check=False
        )
        if r.returncode != 0:
            why = (r.stderr.strip().splitlines() or ["syntax error"])[-1]
            raise ValueError(f"the shell scripts could not source the result (bash -n: {why})")
    return settings


def conf_diff(old: str, new: str, path: str = "tvgw.conf") -> list[str]:
    """A unified diff of two versions of the settings file, for the owner to read before it is
    written: empty when they are the same."""
    import difflib

    return list(
        difflib.unified_diff(
            old.splitlines(), new.splitlines(), f"{path} (now)", f"{path} (after)", lineterm=""
        )
    )


def save_conf(
    path: str | Path, changes: dict[str, str], template: str = "", dry_run: bool = False
) -> list[str]:
    """Set `changes` in the settings file at `path` and return the diff (empty: nothing to do, nothing
    written). A missing file starts from `template`, the shipped example, so its comments come along, and
    the diff is against the template.
    The write is atomic and keeps the file's mode and owner (discover.write_conf), and `dry_run`
    computes the same diff without writing."""
    p = Path(path)
    try:
        old = p.read_text(encoding="utf-8")
        exists = True
    except FileNotFoundError:
        old, exists = template, False
    new = update_conf(old, changes)
    if exists and new == old:
        return []
    diff = conf_diff(old, new, str(p))
    if not dry_run:
        from tvgw import discover  # the one atomic writer of this file, shared with `tvgw discover --write`

        p.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        discover.write_conf(p, new)
    # a missing file is always written, even when the template needs no change: say so in one line
    return diff or [f"+++ {p} (new, the template as it is)"]
