# Research proposals

This folder holds dated proposals: surveys and designs written for the owner to decide on. Nothing in them runs and none of them is a decision; what the owner adopts becomes a numbered entry in [the design decisions](../design-decisions.md), and [the documentation index](../README.md#records) says how the records fit together.

## Files

| File | What it is | Who uses it |
|---|---|---|
| [data-architecture-2026-10.md](data-architecture-2026-10.md) | The 2026-10-27 proposal for the data layer: defects found in the store and a target design, moved here from `docs/data-architecture.md`. | The owner, when deciding changes to the store. |
| [state-of-the-art-2026-10.md](state-of-the-art-2026-10.md) | The 2026-10-27 survey of every tool tvgw depends on, with a verdict on each and proposals for new ones. | The owner, when choosing what to build next. |

## How a proposal relates to the code

A proposal describes the code as it stood on its date and argues for a change. Each proposal says at its top that it is a proposal and that nothing in it is implemented. Parts of the survey were built later: [design decision 18](../design-decisions.md#18-dns-gated-egress-starts-as-a-count-in-its-own-table) records one, and [the changelog](../../CHANGELOG.md) marks the others "from the R&D survey". For the gateway as built, read the pages under `docs/`, which describe the code now.

## Changing it

1. Add a proposal as a new file named for its topic and month, such as `<topic>-<YYYY-MM>.md`, with its date and status in its first lines.
2. Add a row for it to the Files table here.
3. When the owner adopts part of a proposal, record the choice in [the design decisions](../design-decisions.md) and leave the proposal as it was.

## Gotchas

- A proposal's defect lists and line numbers are as of its date. The code has changed since, so check a claim against the code before acting on it.
- The proposals link to pages under `docs/` by relative path, so a moved proposal needs its links rewritten for its new folder.
