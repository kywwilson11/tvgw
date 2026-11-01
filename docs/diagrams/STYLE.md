# Diagram style guide

Diagrams in this repository are Mermaid blocks rendered by GitHub. They exist for a cold reader to see a
mechanism they would otherwise assemble from prose: where data flows, which parts talk, what state a
request moves through. If a sentence says it faster, write the sentence.

## Rules

1. **One idea per diagram.** At most ten to twelve nodes. A flow with more stages becomes a numbered
   series of diagrams, each with its own title line, not one picture with everything.
2. **Label every arrow** with the thing that moves or the action (`every packet`, `blocked names`,
   `writes`, `reverts`). An unlabeled arrow means "related somehow".
3. **One direction.** Left to right for data paths, top to bottom for pipelines. No edge crossings; if
   edges cross, split the diagram.
4. **Roles have colours, always the same ones** (below). The reader learns the palette once.
5. **Short labels** (a word or three). Explanations go in the caption sentence under the block.
6. **No addresses, no host names of real machines** in diagrams (the repo rule); use role names.
7. **Legends only when an encoding repeats** (dashed = observation copy). Otherwise put the meaning on the
   arrow.

## Palette

Role colours are set per diagram with `classDef` lines, and the base theme with the init directive, so
GitHub's light and dark renderers both show them. Text on filled nodes is white on the dark fills and
near-black on the light ones.

| Role | classDef | Fill | Stroke | Text |
|---|---|---|---|---|
| The TV | `tv` | `#F59E0B` amber | `#B45309` | `#1F1300` |
| Gateway enforcement (firewall, resolver, URL filter, DHCP) | `gw` | `#2563EB` blue | `#1E3A8A` | `#FFFFFF` |
| Observation (capture, logs, ingest) | `obs` | `#10B981` green | `#047857` | `#062B1F` |
| The store and files | `store` | `#0F766E` teal | `#134E4A` | `#FFFFFF` |
| Judgement (the analyst, the judge, the models) | `mind` | `#7C3AED` violet | `#4C1D95` | `#FFFFFF` |
| The outside (internet, vendor servers, upstreams) | `out` | `#E5E7EB` grey | `#6B7280` | `#111827` |
| The owner (commands, the brief, the workstation) | `owner` | `#F43F5E` rose | `#9F1239` | `#FFFFFF` |

Every diagram starts with the same header:

```
%%{init: {"theme": "base", "themeVariables": {"fontFamily": "ui-sans-serif, system-ui, sans-serif", "fontSize": "14px", "lineColor": "#64748B", "primaryBorderColor": "#94A3B8", "clusterBkg": "#F8FAFC", "clusterBorder": "#CBD5E1"}, "flowchart": {"curve": "basis", "nodeSpacing": 40, "rankSpacing": 50, "padding": 12}}}%%
```

and ends with the classDef block from `docs/diagrams/palette.mmd` (copy it verbatim).

## Process

Draft the diagram, render it (GitHub preview, or a Mermaid live editor), look at it as a stranger would,
and cut until it reads in five seconds. The owner approves the look of a redesigned pair before a style
is applied across the documentation.
