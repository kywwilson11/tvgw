"""(admit) The names the TV must always reach, each with the reason, which the admission check judges every
change of the TV's DNS policy against (design decision 104).

The profile promises them in four ways, and the store adds a fifth:

- MUST_ALLOW: each must-allow host, filled for the profile's country and for every country of its
  `[regions]`, so a set sold elsewhere is judged too when TV_COUNTRY is not set;
- CLOCK: the names the clock host patterns fill (`profile.pattern_names`), for the same countries;
- URL_FILTER: the URL filter's hosts, which must stay rewritten to the gateway's file proxy;
- ZONE: each never-block zone's apex and a made-up name under it (ZONE_PROBE), which only a rule over the
  whole zone reaches;
- EXPECTED: each name the TV looked up in the last 14 days that the profile files under an expected
  category, from the names the caller passes.

The text of a rule says nothing here: these are names, and the check asks what AdGuard would answer for
each. Nothing is read from the network and nothing is written.
"""

from __future__ import annotations

from collections.abc import Iterable

from tvgw.profile import Profile, pattern_names

MUST_ALLOW, CLOCK, URL_FILTER, ZONE, EXPECTED = "must-allow", "clock", "url-filter", "zone", "expected"
# a label no zone holds: a block of it can only come from a rule over the whole zone
ZONE_PROBE = "zz-probe."


def countries(prof: Profile) -> tuple[str, ...]:
    """The profile's own country ("") and every country its `[regions]` name, once each."""
    return ("", *dict.fromkeys(cc for ccs in prof.regions.values() for cc in ccs))


def names(prof: Profile, used: Iterable[str] = ()) -> dict[str, str]:
    """Every protected name with its reason, the first of MUST_ALLOW, CLOCK, URL_FILTER, ZONE, EXPECTED that
    holds, in that order. `used` is the TV's names of the last 14 days; those in an expected category are
    protected as EXPECTED."""
    out: dict[str, str] = {}
    filled = [prof.for_country(cc) for cc in countries(prof)]
    for p in filled:
        for host in p.must_allow:
            out.setdefault(host, MUST_ALLOW)
    for p in filled:
        for pattern in prof.clock_hosts:
            for name in pattern_names(pattern, p.country):
                out.setdefault(name, CLOCK)
    for host in prof.url_filter.hosts if prof.url_filter else ():
        out.setdefault(host, URL_FILTER)
    for apex in prof.never_block_apex:
        out.setdefault(apex, ZONE)
        out.setdefault(ZONE_PROBE + apex, ZONE)
    for name in used:
        if prof.is_expected(name):
            out.setdefault(name, EXPECTED)
    return out
