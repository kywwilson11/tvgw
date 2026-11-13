# Research proposals

This folder holds dated proposals: surveys and designs written for the owner to decide on. Nothing in them runs and none of them is a decision; what the owner adopts becomes a numbered entry in [the design decisions](../design-decisions.md), and [the documentation index](../project/README.md#records) says how the records fit together.

## Files

| File | What it is | Who uses it |
|---|---|---|
| [data-architecture-2026-10.md](data-architecture-2026-10.md) | The 2026-10-27 proposal for the data layer: defects found in the store and a target design, moved here from `docs/data-architecture.md`. | The owner, when deciding changes to the store. |
| [deep-dive-2026-11-04/](deep-dive-2026-11-04/README.md) | The 2026-11-04 third pass: four reports, on what adjacent projects do, LG's webOS 6 to 26, the documentation as its intended reader reads it, and Samsung's Tizen TVs in depth, with an index of what each changed in the code. | The owner, when choosing what to build next. |
| [screen-test.md](screen-test.md) | The 2026-11-12 research note behind the screen test: how screen recognition behaves on the wire by vendor, the exact rank test, false alarms, power and run length, and where each constant in `src/tvgw/screentest.py` comes from. | A reader of the screen test's code, or of design decision 88. |
| [state-of-the-art-2026-10.md](state-of-the-art-2026-10.md) | The 2026-10-27 survey of every tool tvgw depends on, with a verdict on each and proposals for new ones. | The owner, when choosing what to build next. |
| [state-of-the-art-2026-11-05.md](state-of-the-art-2026-11-05.md) | The 2026-11-05 fourth pass: what the research and products of 2025 and 2026 add on protection, visibility, reliability and invention, each gap set against the project's own record, and a ranked list of what to build. | The owner, when choosing what to build next. |
| [state-of-the-art-2026-11.md](state-of-the-art-2026-11.md) | The 2026-11-01 second pass: where the gateway's model of itself is wrong, re-verified claims, a ranked top ten, and an index of its fourteen section files in [deep-dive-2026-11/](deep-dive-2026-11/README.md). | The owner, when choosing what to build next. |
| [upstream-submissions.md](upstream-submissions.md) | The 2026-11-01 proposed additions and corrections to HaGeZi's LG webOS list and Perflyst's Smart-TV list, derived from the rules verified on the CX, with the evidence each submission needs. | The owner, when filing them upstream. |

## What the fourth pass concluded

The fourth pass ([state-of-the-art-2026-11-05.md](state-of-the-art-2026-11-05.md)) found that tvgw already does nearly all that the research and products of 2025 and 2026 recommend for a gateway that cannot decrypt, so its largest gaps are things it measures and does not act on: connections to addresses its filter never handed out, what the TV sends while it is switched off, and firewall changes that nothing undoes without a person. Because every new block starts count-only and each count needs about two weeks, it ranks first the counts that start those clocks, then the probe from the TV's position and the automatic undo that enforcement will need, and it keeps the rule limited to the app in front a report for now. Of its first build item, the day-one closures, these are done ([the changelog](../../CHANGELOG.md), under 2026-11-05): AdGuard Home's pin moved to v0.107.80 in the code, `vercel-ech.com` among the names that mark real ECH, a count of the clock servers the TV uses, the TV's side of tests T3 and T8 measured over the store, dnsmasq's CVE-2026-2291 checked in Debian's tracker for the build the reference gateway runs, the profiles compared with the 2026 study's ACR blocklist, and the limits of what the brief can see said plainly. These are owed: running `tvgw adguard upgrade --fetch` on the reference gateway and checking the clock, the store and a stream that evening; T8 as the November research wrote it, a query of the gateway's own resolver for `_dns.resolver.arpa`; and T5, whether any of the TV's UDP 443 is old-style Google QUIC. The rest of its ranked list stays a proposal until its own change lands.

## How a proposal relates to the code

A proposal describes the code as it stood on its date and argues for a change. Each proposal says at its top that it is a proposal and that nothing in it is implemented. Parts of the survey were built later: [design decision 18](../design-decisions.md#18-dns-gated-egress-starts-as-a-count-in-its-own-table) records one, and [the changelog](../../CHANGELOG.md) marks the others "from the R&D survey". For the gateway as built, read the pages under `docs/`, which describe the code now.

## Changing it

1. Add a proposal as a new file named for its topic and month, such as `<topic>-<YYYY-MM>.md`, with its date and status in its first lines.
2. Add a row for it to the Files table here.
3. When the owner adopts part of a proposal, record the choice in [the design decisions](../design-decisions.md) and leave the proposal as it was.

## Gotchas

- A proposal's defect lists and line numbers are as of its date. The code has changed since, so check a claim against the code before acting on it.
- The proposals link to pages under `docs/` by relative path, so a moved proposal needs its links rewritten for its new folder.
