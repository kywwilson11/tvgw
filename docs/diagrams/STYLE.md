# Diagram style guide

Figures in this repository are HTML and CSS, rendered to PNG for GitHub. Why, and what else was
considered, is in [RESEARCH.md](RESEARCH.md). A figure exists for a cold reader to see a mechanism they
would otherwise assemble from prose. If a sentence says it faster, write the sentence.

## Files

| File | What it is |
|---|---|
| `diagram.css` | Tokens (colour, type, spacing, both themes) and components: stage, region, card, tag, brief, legend, caption, wire styles |
| `wires.js` | Draws connectors from `data-from` / `data-to` anchors and places their labels; options are documented at its top |
| `icons.svg` | Lucide icons (ISC licence, header kept) as `<symbol id="i-NAME">` |
| `art.svg` | The project's own illustrations: `art-cx` (the TV), `art-pi5`, `art-router`, `art-globe` |
| `fig-*.html` | One figure each, self-contained: the shared files are copied in between `<!-- inline:NAME -->` markers |
| `fig-*.light.png`, `fig-*.dark.png` | The renders, 2x |
| `build.py` | Refreshes the inlined copies and renders the PNGs; `--preview OUT.html` writes a page with every figure live |

Edit the shared files and the markup between `<!-- figure -->` markers, never the inlined copies, then run
`python3 docs/diagrams/build.py`. Open a figure with `#dark` or `#light` in the URL to force a theme.

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

Put the figure's caption in italics under it, as the other figures do.
