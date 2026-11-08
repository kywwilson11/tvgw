#!/usr/bin/env python3
"""Build the tvgw figures.

    python3 docs/diagrams/build.py            inline, render every figure in both themes, check each one
    python3 docs/diagrams/build.py --inline   only refresh the inlined copies and the generated blocks
    python3 docs/diagrams/build.py --check    only check the figures for overlaps, rendering nothing
    python3 docs/diagrams/build.py fig-1-gateway   one figure
    python3 docs/diagrams/build.py --preview OUT.html   also write a page with every figure inline

Each fig-*.html is self-contained: between <!-- inline:NAME --> and <!-- /inline:NAME --> it carries a
copy of diagram.css, wires.js, icons.svg or art.svg, and between <!-- data:NAME --> and
<!-- /data:NAME --> the block GENERATORS[NAME] builds from the code. Edit the shared files and the
generators, never the copies. The stage's data-size="WxH" sets the render window; PNGs are written at
2x beside the HTML as NAME.light.png and NAME.dark.png. Embed them in Markdown with <picture> (see
STYLE.md). fig-1 is also written at 1280 x 640 as social-preview.png, the repository's social preview.
The fonts are vendored in fonts/, so a build needs no network.

A build fails when wires.js counts an overlap in either theme: two labels, cards, terminals or tables
that intersect, or a wire or cable through one of them. TVGW_CHROME names the Chrome or Chromium
binary; every run uses a fresh profile in a temporary directory, so an open browser does not matter.
"""

import math
import os
import pathlib
import re
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
FONTS = HERE / "fonts"  # diagram.css loads them by a URL relative to the figure: url("fonts/...")
CHROME = os.environ.get("TVGW_CHROME", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
SHARED = {"diagram.css": "style", "wires.js": "script", "icons.svg": None, "art.svg": None}
THEMES = ("light", "dark")
SOCIAL = {"fig-1-gateway": ("social-preview.png", 1280)}  # figure: (file, width); the height keeps its ratio


def shared(name):
    text = (HERE / name).read_text(encoding="utf-8")
    tag = SHARED[name]
    return f"<{tag}>\n{text}</{tag}>" if tag else text


# ---------- Generated blocks ----------

# Each .timer in deploy/systemd: its lane in the day figure, (what the job does, a note after its time),
# in plain words, or None for housekeeping the figure leaves out. A timer missing here stops the build,
# so a new one is placed.
TIMER_LANES = {
    "tvgw-verify": ("Checks itself", ""),
    "tvgw-analyze": ("Files the hour's record", ""),
    "tvgw-autoblock": ("Rechecks the blocks it added", ""),
    "tvgw-doh-update": ("Updates its DNS server list", ""),
    "tvgw-backup": ("Backs up its record", ""),
    "tvgw-analyst": ("Asks the analyst", "if it has a key"),
    "tvgw-analyst-weekly": ("Asks about the week", "if it has a key"),
    "tvgw-prune": None,  # trims the packet capture to its limits: housekeeping
    "tvgw-threat-update": None,  # (threats) does nothing unless THREAT_LISTS=count: left out of the day
}
DAY_REPORT = ("Writes yesterday's report", "once the day has settled")  # tvgw-analyze, after SETTLE
LANE_LEFT, LANE_TOP, LANE_PITCH = 32, 80, 48  # the first generated lane, under the static one at 32
LANES_END = 464  # fig-23-day's clock axis is at 480, so no lane may start at or below this
AXIS_X, PX_PER_HOUR = 320, 24  # 00:00 at x 320, 24:00 at x 896
WEEKDAYS = {
    "Mon": "Mondays",
    "Tue": "Tuesdays",
    "Wed": "Wednesdays",
    "Thu": "Thursdays",
    "Fri": "Fridays",
    "Sat": "Saturdays",
    "Sun": "Sundays",
}


def timer_keys(path):
    """The key=value lines of a .timer file, as a dict."""
    keys = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"(\w+)=(.*)$", line.strip())
        if m:
            keys[m.group(1)] = m.group(2).strip()
    return keys


def seconds(span):
    """A systemd time span of one unit ("3min", "10min", "1h", "30s") in seconds."""
    m = re.fullmatch(r"(\d+)\s*(s|sec|min|h)", span)
    if not m:
        raise ValueError(f"time span {span!r} is not one this generator reads")
    return int(m.group(1)) * {"s": 1, "sec": 1, "min": 60, "h": 3600}[m.group(2)]


def schedule(keys):
    """(kind, minute, plain words) for a timer's keys.

    kind is "every" (minute is the interval), "hourly" (minute past every hour), "daily" or "weekly"
    (minute of the day). Only the forms the gateway's timers use are read; any other stops the build
    rather than draw a wrong time.
    """
    if "OnUnitActiveSec" in keys:
        every = seconds(keys["OnUnitActiveSec"]) // 60
        return "every", every, f"every {every} min"
    cal = keys.get("OnCalendar", "")
    delay = seconds(keys["RandomizedDelaySec"]) if "RandomizedDelaySec" in keys else 0
    if cal == "hourly" and not delay:
        return "hourly", 0, "every hour"
    if cal == "daily" and delay == 3600:
        return "daily", 0, "daily, at a random time in its first hour"
    m = re.fullmatch(r"\*-\*-\* \*:(\d\d):00", cal)
    if m and not delay:
        return "hourly", int(m.group(1)), f"every hour at :{m.group(1)}"
    m = re.fullmatch(r"(?:(\w{3}) )?\*-\*-\* (\d\d):(\d\d):00", cal)
    if m and not delay:
        day, hh, mm = m.groups()
        minute = int(hh) * 60 + int(mm)
        if day is None:
            return "daily", minute, f"daily at {hh}:{mm}"
        if day in WEEKDAYS:
            return "weekly", minute, f"{WEEKDAYS[day]} at {hh}:{mm}"
    raise ValueError(f"timer schedule {keys!r} is not one this generator reads")


def day_report_minute(root, analyze_minute):
    """The minute of the day tvgw-analyze writes the day before: its first hourly run at least SETTLE
    seconds after midnight (deploy/bin/tvgw-analyze)."""
    text = (root / "deploy" / "bin" / "tvgw-analyze").read_text(encoding="utf-8")
    settle = int(re.search(r"^SETTLE=(\d+)$", text, re.M).group(1))
    return analyze_minute + 60 * math.ceil((settle / 60 - analyze_minute) / 60)


def x_at(minute):
    return AXIS_X + PX_PER_HOUR * minute / 60


def mark(cls, left, top, extra="", text=""):
    return f'<div class="{cls}" style="left:{left:g}px;top:{top:g}px{extra}">{text}</div>'


def lane_marks(kind, minute, y, span):
    """The marks of one lane, centred on y; span is the width of a job that runs at a random time."""
    if kind == "every":
        every = PX_PER_HOUR * minute / 60
        return [mark("tl-comb", AXIS_X, y, f";width:{24 * PX_PER_HOUR}px;--every:{every:g}px")]
    if kind == "hourly":
        return [mark("tl-mark", x_at(h * 60 + minute), y) for h in range(24)]
    if span:
        return [mark("tl-span", x_at(minute), y, f";width:{span}px")]
    dot = "tl-dot muted" if kind == "weekly" else "tl-dot"
    time = f"{minute // 60:02d}:{minute % 60:02d}"
    return [mark(dot, x_at(minute), y), mark("tl-time", x_at(minute) + 12, y, text=time)]


def gen_timers(root):
    """The day figure's lanes, one per timer in deploy/systemd and one for the day's report, ordered by
    how often each runs, then by time."""
    lanes = []
    analyze = None
    for path in sorted((root / "deploy" / "systemd").glob("*.timer")):
        unit = path.stem
        if unit not in TIMER_LANES:
            raise ValueError(f"{path.name} has no lane in build.py's TIMER_LANES")
        kind, minute, words = schedule(timer_keys(path))
        if unit == "tvgw-analyze":
            analyze = minute
        if TIMER_LANES[unit] is not None:
            title, note = TIMER_LANES[unit]
            span = PX_PER_HOUR if "random" in words else None
            lanes.append((kind, minute, title, f"{words}, {note}" if note else words, span))
    if analyze is None:
        raise ValueError("deploy/systemd has no tvgw-analyze.timer, which writes the day's report")
    report = day_report_minute(root, analyze)
    title, note = DAY_REPORT
    lanes.append(("daily", report, title, f"at {report // 60:02d}:{report % 60:02d}, {note}", None))
    rank = {"every": 0, "hourly": 1, "daily": 2, "weekly": 3}
    lanes.sort(key=lambda lane: (rank[lane[0]], lane[1]))
    if LANE_TOP + len(lanes) * LANE_PITCH > LANES_END:
        room = (LANES_END - LANE_TOP) // LANE_PITCH
        raise ValueError(
            f"the day figure has room for {room} lanes and the timers need {len(lanes)}: move the axis "
            "and the stage of fig-23-day.html down, and LANES_END with them"
        )
    out = []
    for i, (kind, minute, title, words, span) in enumerate(lanes):
        top = LANE_TOP + i * LANE_PITCH
        out.append(
            f'<div class="art-caption left" style="left:{LANE_LEFT}px;top:{top}px;width:264px">'
            f'<div class="title">{title}</div><div class="sub">{words}</div></div>'
        )
        out.extend(lane_marks(kind, minute, top + 20, span))
    return "\n".join(out)


GENERATORS = {"timers": gen_timers}


def generated(name, root=ROOT):
    if name not in GENERATORS:
        raise ValueError(f"no generator for <!-- data:{name} -->")
    return GENERATORS[name](root)


# ---------- Inline, render, check ----------


def inline_text(html, root=ROOT):
    """html with every inlined copy and generated block brought up to date."""
    for name in SHARED:
        pat = re.compile(rf"(<!-- inline:{re.escape(name)} -->).*?(<!-- /inline:{re.escape(name)} -->)", re.S)
        body = shared(name)
        html = pat.sub(lambda m, body=body: f"{m.group(1)}\n{body}\n{m.group(2)}", html)
    pat = re.compile(r"(<!-- data:([\w-]+) -->).*?(<!-- /data:\2 -->)", re.S)
    return pat.sub(lambda m: f"{m.group(1)}\n{generated(m.group(2), root)}\n{m.group(3)}", html)


def inline(path):
    html = inline_text(path.read_text(encoding="utf-8"))
    path.write_text(html, encoding="utf-8")
    return html


def size(path):
    m = re.search(r'data-size="(\d+)x(\d+)"', path.read_text(encoding="utf-8"))
    return int(m.group(1)), int(m.group(2))


def chrome(profile, width, height, theme, scale="2"):
    """Chrome's arguments for one headless load of a figure in a theme."""
    args = [
        CHROME,
        "--headless=new",
        "--disable-gpu",
        "--hide-scrollbars",
        "--no-first-run",
        "--no-default-browser-check",
        f"--user-data-dir={profile}",
        f"--force-device-scale-factor={scale}",
        f"--window-size={width},{height}",
        "--virtual-time-budget=8000",
    ]
    if theme == "dark":
        args.append("--force-dark-mode")
    return args


def render(path, profile):
    w, h = size(path)
    for theme in THEMES:
        out = path.with_name(f"{path.stem}.{theme}.png")
        args = [*chrome(profile, w, h, theme), f"--screenshot={out}", f"file://{path}#render-{theme}"]
        subprocess.run(args, check=True, capture_output=True)
        print("wrote", out.relative_to(HERE))
    if path.stem in SOCIAL:
        name, width = SOCIAL[path.stem]
        out = HERE / name
        scale = f"{width / w:.10f}"
        args = [*chrome(profile, w, h, "light", scale), f"--screenshot={out}", f"file://{path}#render-light"]
        subprocess.run(args, check=True, capture_output=True)
        print("wrote", out.relative_to(HERE))


def overlaps_in(dom):
    """(count, what) from a dumped DOM's <html data-overlaps>, or None when wires.js never finished."""
    tag = re.search(r"<html\b[^>]*>", dom)
    count = re.search(r'\sdata-overlaps="(\d+)"', tag.group(0)) if tag else None
    if not count:
        return None
    what = re.search(r'\sdata-overlap-list="([^"]*)"', tag.group(0))
    return int(count.group(1)), what.group(1) if what else ""


def check(path, profile):
    """The overlaps wires.js counts in each theme, as messages; empty when the figure is clean."""
    w, h = size(path)
    problems = []
    for theme in THEMES:
        args = [*chrome(profile, w, h, theme), "--dump-dom", f"file://{path}#render-{theme}"]
        dom = subprocess.run(args, check=True, capture_output=True, text=True).stdout
        got = overlaps_in(dom)
        if got is None:
            problems.append(f"{path.name} ({theme}): wires.js did not finish, so nothing was checked")
        elif got[0]:
            problems.append(f"{path.name} ({theme}): {got[0]} overlaps: {got[1]}")
    return problems


def figure_markup(path):
    html = path.read_text(encoding="utf-8")
    m = re.search(r"<!-- figure -->(.*?)<!-- /figure -->", html, re.S)
    return m.group(1).strip()


def preview(out):
    figs = figures()
    tpl = (HERE / "preview.template.html").read_text(encoding="utf-8")
    parts = []
    for n, f in enumerate(figs, 1):
        fig = figure_markup(f)
        cap = re.search(r"<figcaption[^>]*>(.*?)</figcaption>", fig, re.S).group(1)
        fig = re.sub(r"\s*<figcaption.*?</figcaption>", "", fig, flags=re.S)
        parts.append(
            f'<section class="pv-fig"><p class="pv-eyebrow">Figure {n}</p>'
            f'<div class="pv-scroll">{fig}</div>'
            f'<p class="pv-hint">Scroll the figure sideways to see all of it.</p>'
            f'<p class="fig-caption">{cap}</p></section>'
        )
    body = "\n".join(parts)
    page = tpl.replace("<!-- FIGURES -->", body)
    for name in SHARED:
        page = page.replace(f"<!-- inline:{name} -->", shared(name))
    out = pathlib.Path(out)
    fonts = pathlib.Path(os.path.relpath(FONTS, out.resolve().parent)).as_posix()
    page = page.replace('url("fonts/', f'url("{fonts}/')  # the preview may be written anywhere
    out.write_text(page, encoding="utf-8")
    print("wrote", out)


def figures():
    """Every fig-N-*.html, in figure-number order (fig-10 after fig-9)."""
    return sorted(HERE.glob("fig-*.html"), key=lambda p: int(p.name.split("-")[1]))


def main(argv):
    pv = None
    if "--preview" in argv:
        i = argv.index("--preview")
        pv = argv[i + 1]
        del argv[i : i + 2]
    only_inline = "--inline" in argv
    only_check = "--check" in argv
    names = [a for a in argv if not a.startswith("--")]
    figs = [HERE / f"{n}.html" for n in names] if names else figures()
    problems = []
    with tempfile.TemporaryDirectory(prefix="tvgw-figures-") as profile:
        for f in figs:
            if not only_check:
                inline(f)
            if not only_inline and not only_check:
                render(f, profile)
            if not only_inline:
                problems += check(f, profile)
    if pv:
        preview(pv)
    for p in problems:
        print(p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
