# Diagram research and decision

Written 2026-11-01 for the redesign of tvgw's documentation figures. The owner rejected two attempts:
Mermaid ("cheap, cluttered, too much in one diagram, elementary colours") and hand-drawn SVG. The
target is the quality of HTML-built slide graphics: modern, very readable, restrained colour, and,
in the owner's later words, "the graphics look like the real thing": the TV drawn as an LG CX and the
gateway as a Raspberry Pi 5, without becoming clip art.

## The constraint that decides most of it: what GitHub will render

- GitHub renders Mermaid, GeoJSON, TopoJSON and ASCII STL natively in Markdown, and nothing else
  ([GitHub Docs, creating diagrams](https://docs.github.com/en/get-started/writing-on-github/working-with-advanced-formatting/creating-diagrams)).
  D2, Graphviz, Structurizr and Kroki output reach a README only as image files.
- GitHub's Markdown sanitizer strips `style` attributes, scripts and most raw HTML
  ([VS Code PR thread on matching GitHub's sanitizer](https://github.com/microsoft/vscode/pull/97793);
  [a gist on the undocumented allow-list](https://Gist.github.com/s-lindenau/starred)). An HTML/CSS
  diagram therefore cannot live in a README as HTML; it must arrive as an image.
- An SVG shown through `<img>` cannot fetch external resources, fonts included, so a web font falls
  back to a system font unless the font is embedded as a data URI or the text is outlined
  ([embedding fonts in SVG images](https://dzx.fr/blog/svg-font-embedding/);
  [svg-embed-font](https://github.com/BTBurke/svg-embed-font)). A PNG has no such problem.
- GitHub does support `<picture>` with `prefers-color-scheme` sources, so a README can show a light
  PNG to light-mode readers and a dark PNG to dark-mode readers
  ([GitHub blog](https://github.blog/developer-skills/github/how-to-make-your-images-in-markdown-on-github-adjust-for-dark-mode-and-light-mode/)).
- GitHub scales a wide image down to the text column (about 880 to 1010 CSS px). A figure laid out
  at 1600 px shows its 16 px labels at about 9 px. **The canvas must be designed at the width it is
  shown at** (960 CSS px here) and rendered at 2x for sharpness; that is the single biggest
  readability lever, and the reason most "nice" diagrams look tiny in READMEs.

## Options compared

| Option | Output quality ceiling | Authoring effort | Maintainable by future agents | GitHub | Dark mode | Illustration (real objects) |
|---|---|---|---|---|---|---|
| **Mermaid** (status quo) | Low: fixed shapes, dagre layout, limited type control, label boxes collide | Lowest | High | Native | GitHub re-themes it, colours partly lost | None |
| **D2** with ELK or TALA | Medium-high: good themes, real dark theme switch, sketch mode ([themes](https://d2lang.com/tour/themes/), [layouts](https://d2lang.com/tour/layouts/)) | Low | High (text) | Image only; SVG fonts need embedding | Yes, `dark-theme` and overrides | Icons/images per node, no composed art |
| **Graphviz** with a custom theme | Medium: excellent routing, dated typography unless heavily styled | Low-medium | High | Image only | Two renders | None |
| **Structurizr / C4** | Medium: consistent model-driven views ([C4](https://c4model.com/)) | Medium (a model to keep) | High for large systems; heavy for 20 figures | Image only | Theme files | Icons only |
| **Kroki** | Same as the engine behind it (Mermaid, D2, Graphviz, Excalidraw...) ([Kroki](https://docs.kroki.io/kroki/)) | Low, needs a server | High | Image only | Per engine | Per engine |
| **Penrose** | Very high for mathematical diagrams; not aimed at system architecture ([Penrose](https://penrose.cs.cmu.edu/)) | High | Low | Image only | Manual | No |
| **Excalidraw** | Friendly hand-drawn; reads informal, not premium | Low | Medium (JSON) | Image only | Its own export | Drawn by hand |
| **HTML/CSS + inline SVG**, computed connectors, rendered by headless Chrome | Highest: real typography, design tokens, composed illustrations, exact control | Medium-high per figure | High if the system is small: one CSS, one ~150-line connector helper, declarative markup | PNG via `<picture>`; live HTML on a docs site | First-class: tokens under `prefers-color-scheme`, two renders | Yes: vector product illustration in the same file |

Connector tooling for the HTML route: leader-line and its fork linkerline draw connectors between DOM
elements but are larger than needed and produce curvy, generic lines; perfect-arrows gives geometry
only ([perfect-arrows](https://npmjs.com/package/perfect-arrows), [arrow-line](https://www.npmjs.com/package/arrow-line),
[linkerline](https://npmjs.com/package/linkerline)). elkjs computes layered layouts with orthogonal routing
but renders nothing ([elkjs](https://classic.yarnpkg.com/en/package/elkjs);
[a team's ELK decision record](https://github.com/lambdasistemi/factory-dashboard/wiki/Graph-Layout-Review)).
With eight to twelve elements per figure, automatic layout buys little: hand placement on an 8 px grid
gives better composition, and a small helper that routes orthogonal, round-cornered wires between named
anchors and places their labels is enough and has no dependencies.

Docs sites, if the project grows one: Material for MkDocs renders Mermaid with theme-aware colours and
passes raw HTML through ([diagrams](https://squidfunk.github.io/mkdocs-material/reference/diagrams/));
Docusaurus needs JSX instead of raw HTML in MDX ([MDX and React](https://docusaurus.io/docs/markdown-features/react));
Starlight takes custom CSS in cascade layers and supports components in MDX
([Starlight CSS](https://starlight.astro.build/guides/css-and-tailwind/)). The figures here are plain
HTML with their CSS inside, so any of the three can include them in an iframe or as a raw HTML block;
MkDocs Material is the least work.

Rendering: Chrome's headless mode now shares code with normal Chrome
([Chrome headless](https://developer.chrome.com/docs/chromium/headless)), so the render is the browser's
own. Tested here: `--force-device-scale-factor=2` gives a true 2x bitmap and `--force-dark-mode` flips
`prefers-color-scheme`, so one HTML source yields both themes.

## What makes the best examples read as premium

From Vercel's published design guidance ([vercel.com/design.md](https://vercel.com/design.md),
[Geist](https://vercel.com/geist)), Stripe's documented colour and type discipline across docs and
product ([brandkit summary](https://brandkit.pro/brand/stripe)), Google Cloud's icon and diagram kit
(neutral icons at reduced opacity, product colour reserved for meaning) and Tailscale's explainer
diagrams, one picture per step of an argument
([How NAT traversal works](https://tailscale.com/blog/how-nat-traversal-works)):

1. **Monochrome first, colour only for meaning, paired with a non-colour cue.** Vercel says it
   outright: design in monochrome and use colour where it adds meaning. One accent marks the path the
   figure is about; everything else is ink and hairline.
2. **Few, consistent type sizes.** A tight scale (16 / 15 / 13 / 12 here) with weight, not size, for
   hierarchy; a mono face only for identifiers, paths and commands.
3. **Spacing does the grouping.** Borders only where spacing cannot express the group; no card inside
   a card inside a card.
4. **An 8 px grid** for every coordinate, so edges align across the figure and wires land square.
5. **Restrained radii and shadows.** Small radii (6-10 px), one soft shadow level, hairline borders.
6. **Connectors that look engineered:** orthogonal, rounded bends, one stroke weight per meaning,
   small solid arrowheads, a label on every wire saying what moves, the label knocked out of the line.
7. **One idea per figure and a sequence of figures for a sequence of ideas** (Tailscale's practice,
   and C4's levels): eight to twelve elements, read in five seconds.
8. **Dark mode designed, not inverted:** surfaces step up in lightness, the accent lightens, shadows
   become borders.
9. **Real-object illustration used sparingly:** product drawings in flat vector with one light
   direction and a touch of gradient (Apple and Stripe product pages), never isometric clutter, never
   decoration that competes with labels.

## Decision

**Author figures in HTML/CSS with inline SVG illustrations and computed SVG connectors; ship them to
GitHub as 2x PNGs in a `<picture>` element with light and dark sources; keep the HTML as the source
and as the live figure for any future docs site.**

Reasons:

- It is the only option whose quality ceiling meets the bar, and the only one that can draw the TV
  and the Pi as recognisable objects in the same file as the mechanism.
- The README constraint (images only) applies to every non-Mermaid option equally, so D2's
  text-only advantage does not buy GitHub rendering; it only buys easier authoring at a lower ceiling.
- Maintainability comes from keeping the system small and declarative: one `diagram.css` of tokens and
  components, one `wires.js` that reads `data-from` / `data-to` attributes, one icon sprite and one
  illustration sprite, all inlined into each figure by `build.py`, which also renders the PNGs. A
  future agent edits markup and coordinates, never path geometry.
- Fallback: if a figure must be text-diffable and quick, D2 with ELK, the `neutral-default` theme and a
  dark theme is the second choice, and the style rules below still apply.

Icons: Lucide (ISC licence, [lucide.dev/license](https://lucide.dev/license)), embedded as `<symbol>`
sprites with the licence header kept. The TV and Pi illustrations are drawn for this project in SVG
from public dimensions (the CX 55" panel is 1228 x 706 mm with a 998 mm wide stand,
[LG Canada](https://www.lg.com/ca_en/tv-soundbars/oled/oled55cxpua/); the Pi 5 board is 85 x 56 mm
with the fan connector between the GPIO header and the USB 2 ports,
[Raspberry Pi documentation](https://www.raspberrypi.com/documentation/computers/raspberry-pi.html)),
with no logos or wordmarks.
