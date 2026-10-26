"""tvgw: a Raspberry Pi gateway that isolates, observes and filters a smart TV.

The TV plugs into the Pi; the Pi is its only route out. nftables isolates it from the LAN and
forces every DNS lookup through AdGuard Home; tcpdump and conntrack record what it does; a
plain-HTTP URL filter catches what DNS cannot; everything lands in one SQLite database that the
`tvgw` CLI queries. Vendor knowledge (categories, must-allow hosts, URL-filter rules) lives in
profiles, so a different TV is a different profile, not a different program.
"""

__version__ = "0.1.0"
