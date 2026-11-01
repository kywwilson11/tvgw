# Figure style guide

Figures in this repository are HTML and CSS, rendered to PNG for GitHub. Why, and what else was
considered, is in [RESEARCH.md](RESEARCH.md). A figure exists for a cold reader to see a mechanism they
would otherwise assemble from prose. If a sentence says it faster, write the sentence.

## Files

| File | What it is |
|---|---|
| `diagram.css` | Tokens (colour, type, spacing, both themes) and components, listed below |
| `wires.js` | Draws connectors from `data-from` / `data-to` anchors (any element with a `data-id`, a table's column row included) and places their labels; options are documented at its top |
| `icons.svg` | Lucide icons (ISC licence, header kept) as `<symbol id="i-NAME">` |
| `art.svg` | The project's own illustrations: `art-cx` (the TV), `art-pi5`, `art-router`, `art-globe` |
| `fig-*.html` | One figure each, self-contained: the shared files are copied in between `<!-- inline:NAME -->` markers |
| `fig-*.light.png`, `fig-*.dark.png` | The renders, 2x |
| `build.py` | Refreshes the inlined copies and renders the PNGs; `--preview OUT.html` writes a page with every figure live |

Edit the shared files and the markup between `<!-- figure -->` markers, never the inlined copies, then run
`python3 docs/diagrams/build.py`. Open a figure with `#dark` or `#light` in the URL to force a theme.

## Components

| Component | Markup | Use it for |
|---|---|---|
| Card | `.card` with `.glyph`, `.title`, `.sub`, `.id`; role classes `gate`, `obs`, `judge`, `world`; `focus` for the one the figure is about | A program, a file, a service |
| Stage card | `.card.stage-card` with a `.step` number, `.drop` (brick) and `.pass` lines | One step of a pipeline and what it drops |
| Region | `.region` (`gate`, `judge`, `world`) and `.region-title` | A boundary: the Pi, a layer, a group |
| State | `.card.state` with `.sdot` (`accent`, `obs`, `stop`), and `.start-dot` | A state machine's states |
| Timeline | `.tl-axis`, `.tl-tick`, `.tl-bar` (`accent`, `judge`, `ink`, `dashed`), `.tl-note` | Durations on one time axis |
| Hour strip | `.hour` (`clean`, `confounded`, `no-demand`, `off`), `.marker` (`b` for a class-B change) with a `.marker-label`, `.count` | Clock hours as `ledger.classify_hour()` classes them, the changes pinned to them, and a running count |
| Table | `.tbl` with `.th` and `.col` rows (`k` key, `join` joined); `.ref` for a table shown only for its join | The store's tables and their joins; give each `.col` a `data-id` of `table.column` and land the wire on it with `data-end="dot"` |
| Ordered list | `.genlist` rows with a `.step` | An order the code fixes |
| Brief | `.brief` with mono `.row`s and `.bar`s | A printout of `tvgw brief` |
| Tag, legend, caption | `.tag`, `.legend` / `.legend-row`, `.fig-caption` | Small markers, a key when an encoding repeats, the caption in the HTML |
| Label on a wash | a `.wire-label.wash` written inside its `.wire` | A knocked-out wire label inside a `.region.gate`, so its background matches the region |

## Figures and where they are used

| Figure | Shows | Used in |
|---|---|---|
| `fig-1-gateway` | What the gateway is | `README.md` |
| `fig-2-data-path` | What enforces, on the TV side | `docs/architecture.md` |
| `fig-3-judgement` | Who may change the rules | `docs/architecture.md`, `docs/analyst-and-autonomy.md` |
| `fig-4-packet-path` | The firewall's stages in order, the guard after them | `docs/architecture.md` |
| `fig-5-policy-files` | Policy files to running configuration | `docs/architecture.md`, `docs/operations.md` |
| `fig-6-capture-to-store` | Six recorders and the change spool into the store, the verifier and its sampler beside | `docs/architecture.md` |
| `fig-7-rule-life` | A machine rule's states, the three watches and judge v2 | `docs/analyst-and-autonomy.md` |
| `fig-8-store-naming`, `fig-9-store-context`, `fig-10-store-records` | The store's joins, as a series | `docs/data-model.md` |
| `fig-11-install-paths` | Three ways in, one installer | `deploy/README.md`, `docs/packaging.md` |
| `fig-12-fail-closed` | The firewall's states, all inside the guard | `deploy/nftables/README.md` |
| `fig-13-retention` | How long each kind of data is kept | `docs/privacy-and-retention.md` |
| `fig-14-what-leaves` | What leaves the Pi | `docs/privacy-and-retention.md` |
| `fig-15-profile` | The anatomy of a profile | `docs/adding-a-profile.md` |
| `fig-16-modules` | The package's modules by layer | `src/tvgw/README.md` |
| `fig-17-two-walls` | What holds when `inet tvgw` is gone: the guard and the services' own walls | `docs/architecture.md`, `deploy/nftables/README.md` |
| `fig-18-trial-confounders` | One trial's hours as the ledger classes them, and what judge v2 records | `docs/analyst-and-autonomy.md` |

A new figure takes the next number. Copy the wrapper of an existing `fig-*.html`, keep the
`<!-- figure -->` markers, set the stage's `data-size`, and run `build.py NAME` to inline and render it.
Look at both PNGs before embedding: no overlaps, no clipped text, wires landing on edges. `tests/unit/test_figures.py` fails when a figure carries a stale copy of a shared file, lacks a render or is shown by no page, and when an embed points at a render that does not exist.

## Rules

1. **One idea per figure, eight to twelve elements.** The caption states the one fact a reader should
   leave with. A sequence of ideas is a numbered series of figures.
2. **Label every wire with what moves** (a 15 px main line, an optional 13 px second line). An
   unlabelled wire means "related somehow".
3. **Canvas 960 px wide**, the width GitHub shows it at, so labels stay 15 to 16 px on screen. Every
   coordinate on the 8 px grid.
4. **Colour carries meaning, and only one colour is loud.** Cobalt (`--accent`) marks the path the
   figure is about; reads and records are grey; brick (`--stop`) is only for what is refused. Roles
   tint only a card's glyph tile.
5. **Real objects for the actors** (the TV, the Pi, the router, the internet) from `art.svg`; cards
   for software. An illustration that competes with a label gets simpler.
6. **No addresses or host names of real machines.** Use role names.
7. **A legend only when an encoding repeats.** Otherwise the wire's label says it.

## Embedding in Markdown

```html
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="diagrams/fig-1-gateway.dark.png">
  <img alt="The TV's one cable runs to the Pi, which answers its DNS, lets allowed traffic out through the home router, refuses the home network, and keeps a record for a daily brief." src="diagrams/fig-1-gateway.light.png" width="960">
</picture>
```

Put the figure's caption in italics under it, one sentence ending with a period, as the other figures do ([A9 in how these pages are written](../README.md#how-these-pages-are-written)). The path is relative to the page: `diagrams/` from `docs/`, `docs/diagrams/` from the root, `../docs/diagrams/` from `deploy/`.
