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
| `fonts/` | Geist and Geist Mono 1.7.2 from Vercel's `geist` package, as variable WOFF2 files, with their licence, the SIL Open Font License 1.1, in `fonts/OFL.txt` |
| `art.svg` | The project's own illustrations: `art-tv` (a TV of no brand), `art-gateway` (a small computer of no brand with two network ports), `art-router`, `art-globe`, `art-phone`, `art-usb-eth` (a USB network adapter), and `art-cx` and `art-pi5`, the owner's LG CX and Raspberry Pi 5 |
| `fig-*.html` | One figure each, self-contained but for `fonts/` beside it: the shared files are copied in between `<!-- inline:NAME -->` markers, and generated blocks between `<!-- data:NAME -->` markers |
| `fig-*.light.png`, `fig-*.dark.png` | The renders, 2x |
| `social-preview.png` | fig-1 at 1280 x 640, light, for the repository's social preview (set in GitHub's settings by hand) |
| `build.py` | Refreshes the inlined copies and the generated blocks, renders the PNGs and checks each figure for overlaps; `--inline` only refreshes, `--check` only checks, `--preview OUT.html` writes a page with every figure live |

Edit the shared files, the generators in `build.py` and the markup between `<!-- figure -->` markers, never
the inlined copies or the generated blocks, then run `python3 docs/diagrams/build.py`. It runs Chrome
headless from a fresh profile in a temporary directory; `TVGW_CHROME` names another Chrome or Chromium
binary. The fonts are vendored in `fonts/`, so a render needs no network and a page that shows a figure
asks no font service for anything. Open a figure with `#dark` or `#light` in the URL to force a theme.

## Components

| Component | Markup | Use it for |
|---|---|---|
| Card | `.card` with `.glyph`, `.title`, `.sub`, `.id`; role classes `gate`, `obs`, `judge`, `world`; `focus` for the one the figure is about | A program, a file, a service |
| Stage card | `.card.stage-card` with a `.step` number, `.drop` (brick) and `.pass` lines | One step of a pipeline and what it drops |
| Region | `.region` (`gate`, `judge`, `world`) and `.region-title` | A boundary: the gateway, a layer, a group |
| State | `.card.state` with `.sdot` (`accent`, `obs`, `stop`), and `.start-dot` | A state machine's states |
| Timeline | `.tl-axis`, `.tl-tick`, `.tl-bar` (`accent`, `judge`, `ink`, `dashed`), `.tl-note` | Durations on one time axis |
| Hour strip | `.hour` (`clean`, `confounded`, `no-demand`, `off`), `.marker` (`b` for a class-B change) with a `.marker-label`, `.count` | Clock hours as `ledger.classify_hour()` classes them, the changes pinned to them, and a running count |
| Table | `.tbl` with `.th` and `.col` rows (`k` key, `join` joined); `.ref` for a table shown only for its join | The store's tables and their joins; give each `.col` a `data-id` of `table.column` and land the wire on it with `data-end="dot"` |
| Ordered list | `.genlist` rows with a `.step` | An order the code fixes |
| Brief | `.brief` with mono `.row`s and `.bar`s | A printout of `tvgw brief` |
| Tag, legend, caption | `.tag`, `.legend` / `.legend-row`, `.fig-caption` | Small markers, a key when an encoding repeats, the caption in the HTML |
| Label on a wash | a `.wire-label.wash` written inside its `.wire` | A knocked-out wire label inside a `.region.gate`, so its background matches the region |
| Home | `.region.home` with a `.region-title` | The household's side of the gateway, with the internet outside it |
| Tile | `.tile` behind its art, and a `.tile-text` with a `.head` (a `.step` for a journey), a `.sub` and an optional `.tag` | One of a row of alternatives, or one step of a numbered journey |
| Cable | a `path.cable` (`accent`, `ghost`) and a `rect.plug` in an `<svg class="art">` the size of the stage | A physical cable between objects: curved, plugged in, never labelled |
| Terminal | `.term` with a `.bar` of three `i`, a `.body` of `.ln` lines (`.p` prompt, `b` typed, `.ask`, `.ok`); `data-source="FILE"` | What the reader types and what tvgw prints; with `data-source`, its `.ask` lines must appear in that file |
| Badge | `.badge.ok` (`i-circle-check`) or `.badge.off` (`i-wifi-off`), `.on-tile` on a tile | A state pinned to an object: done, or a radio off |
| Bar of counts | `.hbar` with a `.refused` and a `.through` span, widths from the numbers | Counts on a linear scale from 0, the refused part in brick |
| Clock marks | `.tl-dot` (`muted`), `.tl-mark`, `.tl-comb` (`--every`), `.tl-span`, `.tl-line`, `.tl-time` on a `.tl-axis` | Jobs at their clock times: once, every hour, every few minutes, at a random time in a window, all the time |

## Figures and where they are used

| Figure | Shows | Audience | Used in |
|---|---|---|---|
| `fig-1-gateway` | What the gateway is | user | `README.md`, `docs/how-it-works/README.md` |
| `fig-2-data-path` | What enforces, on the TV side | engineer | `docs/how-it-works/architecture.md` |
| `fig-3-judgement` | Who may change the rules | engineer | `docs/how-it-works/architecture.md`, `docs/how-it-works/analyst-and-autonomy.md` |
| `fig-4-packet-path` | Where a TV packet can end: the gateway's services, out to the router, or a drop; the guard after both | engineer | `docs/how-it-works/architecture.md` |
| `fig-5-policy-files` | Policy files to running configuration | engineer | `docs/how-it-works/architecture.md` |
| `fig-6-capture-to-store` | Six recorders and the change spool into the store, the verifier and its sampler beside | engineer | `docs/how-it-works/architecture.md` |
| `fig-7-rule-life` | A machine rule's states, the three watches and judge v2 | engineer | `docs/how-it-works/analyst-and-autonomy.md` |
| `fig-8-store-naming`, `fig-9-store-context`, `fig-10-store-records`, `fig-24-autonomy-records` | The store's joins, as a series | engineer | `docs/reference/data-model.md` |
| `fig-11-install-paths` | Three ways in, one installer | engineer | `deploy/README.md`, `docs/project/packaging.md` |
| `fig-12-fail-closed` | The firewall's states, all inside the guard | engineer | `deploy/nftables/README.md` |
| `fig-13-retention` | How long each kind of data is kept | engineer | `docs/how-it-works/privacy-and-retention.md` |
| `fig-14-what-leaves` | What leaves the gateway | engineer | `docs/how-it-works/privacy-and-retention.md` |
| `fig-15-profile` | The anatomy of a profile | engineer | `docs/reference/profile-format.md` |
| `fig-16-modules` | The package's modules by layer | engineer | `src/tvgw/README.md` |
| `fig-17-two-walls` | What holds when `inet tvgw` is gone: the guard and the services' own walls | engineer | `docs/how-it-works/architecture.md`, `deploy/nftables/README.md` |
| `fig-18-trial-confounders` | One trial's hours as the ledger classes them, and what judge v2 records | engineer | `docs/how-it-works/analyst-and-autonomy.md` |
| `fig-19-what-it-stops` | What it stops, and what it cannot: the cable filtered, Wi-Fi that must be off, Bluetooth outside its reach | user | `docs/what-it-stops.md` |
| `fig-20-choosing-a-gateway` | Three computers that can be the gateway and where their cables go, each with its status | user | `docs/install/choosing-a-gateway.md` |
| `fig-21-tv-day` | What the LG CX tried in one measured day, by category, and what got through | user | `docs/tv/lg-cx-measured.md` |
| `fig-22-lookup` | What a lookup goes through: a real address, `0.0.0.0`, or the URL filter | engineer | `docs/how-it-works/adguard.md` |
| `fig-23-day` | A day in the gateway's life, its lanes generated from the timers | user | `docs/how-it-works/architecture.md` |

A new figure takes the next number. Copy the wrapper of an existing `fig-*.html`, keep the
`<!-- figure -->` markers, set the stage's `data-size` and the `<figure>`'s `data-audience` (`user` for a
figure on the front page or a page for the typical user, `engineer` otherwise, as the table above says),
and run `build.py NAME` to inline, render and check it. Look at both PNGs before embedding: no clipped
text, wires landing on edges, art legible on its ground. `build.py` fails a figure where wires.js counts an
overlap in either theme: two labels, cards, terminals, tables, captions or tile texts that intersect, or a
wire or cable through one of them (a wire may run through its own label; nothing is checked against art).

`tests/unit/test_figures.py` fails when a figure carries a stale copy of a shared file or a stale
generated block, lacks a render, its audience or a row in the table above, is shown by no page, or loads
anything from another site; when an embed points at a render that does not exist; when a figure says
Tested by hand; and when a terminal with `data-source` shows a line its file does not hold. Where
`TVGW_CHROME` is set it also runs the overlap check on every figure, and on a planted overlap that the
check must report.

## Rules

1. **One idea per figure, eight to twelve elements.** The caption states the one fact a reader should
   leave with. A sequence of ideas is a numbered series of figures.
2. **Label every wire with what moves** (a 15 px main line, an optional 13 px second line). An
   unlabelled wire means "related somehow".
3. **Canvas 960 px wide**, the width GitHub shows it at, so labels stay 15 to 16 px on screen. Every
   coordinate on the 8 px grid, except the markers and counts of an hour strip, which sit at their
   clock time.
4. **Colour carries meaning, and only one colour is loud.** Cobalt (`--accent`) marks the path the
   figure is about; reads and records are grey; brick (`--stop`) is only for what is refused. Roles
   tint only a card's glyph tile.
5. **Real objects for the actors** (the TV, the gateway, the router, the internet) from `art.svg`;
   cards for software. `art-tv` and `art-gateway` by default; `art-cx` and `art-pi5` only where the
   figure is about that set or that board. An illustration that competes with a label gets simpler.
6. **No addresses or host names of real machines.** Use role names.
7. **A legend only when an encoding repeats.** Otherwise the wire's label says it.

## User-path figures

A figure whose audience is `user` sits on a page written for the typical user: the front page, the
documentation index, and the pages on installing, everyday use and TVs. It follows
[A9](../project/writing-docs.md) as widened for those pages:

- **Plain words.** No settings keys, file names, chain or table names; "the filter" and "the gateway", with
  the mechanism named at most once, after the plain words.
- **No owner hardware.** The TV is `art-tv` and the computer is `art-gateway`, and no visible text says
  "LG CX" or "Raspberry Pi", except inside an element marked `data-names-hardware`: the source label of a
  measured set, or a figure about the hardware itself. The test reads the visible text, not the caption.
- **At most ten elements.** A user figure is read at a glance, often on a phone at 40% of its size.
- **Every number is measured or generated.** A measured number names its set and date in the figure or
  the caption, and the page links the measurement; a generated number comes from a `data:` block.
- **Status words only from the code.** Tested, Reported and Not yet tested for TVs; In daily use,
  CI-tested, Not yet tested and Not supported for gateways. A figure writes Tested only inside a block a
  generator builds from what the code records.
- **A physical arrangement, annotated output or a journey.** Besides the figures A9 allows everywhere, a
  user figure may show where the cables go, output whose text the build takes from the code, or a
  numbered journey of at most four steps that is also the numbered list directly below it. A journey shows
  no command the reader must copy from the picture.

## Cables and wires

A wire is a data flow: orthogonal, drawn by wires.js and labelled with what moves (rule 2). A cable is an
object: a curved `path.cable` with a `rect.plug` at each end it plugs into, drawn in an `<svg class="art">`
that covers the stage, so its coordinates are stage px. Cables are never labelled; the objects they join,
and a short caption at a loose end ("to the TV"), say what they connect. Port centres are in each art's
header comment in `art.svg` (`art-gateway`'s two jacks are at x 122 and 160, y 60 of its viewBox). An
accent cable is the TV's; the rest are grey.

## Generated figures

A fact that ordinary commits change is generated, never typed into a figure. `build.py`'s `GENERATORS`
maps a name to a function of the repository root that returns markup; `inline()` writes its output
between `<!-- data:NAME -->` and `<!-- /data:NAME -->`, and the test fails when the committed block
differs from what the code gives now. A generator reads only the forms it knows and stops the build on
anything else, so a figure is never drawn from a value it misread.

| Generator | Reads | Draws |
|---|---|---|
| `timers` | `deploy/systemd/*.timer` (`OnCalendar`, `OnUnitActiveSec`, `RandomizedDelaySec`) and `SETTLE` in `deploy/bin/tvgw-analyze` | One lane per timer of the day figure, its plain words in `TIMER_LANES`, and the day's report at the first hourly run after the day settles; the build stops when the lanes would not fit above the clock |

Marks of a generated clock sit at their clock time, off the 8 px grid, as an hour strip's do.

## Embedding in Markdown

```html
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="diagrams/fig-1-gateway.dark.png">
  <img alt="Inside your home, the smart TV's only cable runs to the gateway, which stops known tracking, lets the rest out through your router and keeps the TV away from your phones and laptops." src="diagrams/fig-1-gateway.light.png" width="960">
</picture>
```

Put the figure's caption in italics under it, one sentence ending with a period, as the other figures do ([A9 in writing these pages](../project/writing-docs.md)). The path is relative to the page: `diagrams/` from `docs/`, `docs/diagrams/` from the root, `../docs/diagrams/` from `deploy/`.
