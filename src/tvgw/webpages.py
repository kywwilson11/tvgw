"""(web) The page's HTML: rendered on the gateway, no JavaScript, one stylesheet, readable at 360 px wide,
light and dark by the phone's own setting (design decision 76).

Every value from the record goes through `esc`: a TV app chooses the names it looks up, and the TV reports
its own device name and firmware, so any of it is attacker-controlled. `esc` first makes every character
that could steer a reader visible (`cli.clean`: controls, bidi overrides, zero-width marks), then escapes
HTML, quotes included. A name becomes a link only when it is a plain host name (`NAME`), so nothing else
ever reaches a URL. No page reflects the request's own path or query. The functions take plain data and
return a whole document; the server adds the headers.
"""

from __future__ import annotations

import html
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from tvgw import __version__
from tvgw.cli import clean

# a host name as a link may carry it: lower case, labels of letters, digits, `-` and `_` (DNS-SD and
# service names), each 1 to 63 long, at most 253 in all; never `..`, `%` or `/`
NAME = re.compile(
    r"(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*"
)
DAY = re.compile(r"\d{4}-\d{2}-\d{2}")

STYLE = """\
:root{color-scheme:light dark;--bg:#f7f7f5;--fg:#1b1c1e;--muted:#5b5f66;--line:#d8dadd;--card:#fff;
--accent:#1f4fd1;--act:#9a3412;--ok:#166534}
@media (prefers-color-scheme:dark){:root{--bg:#111214;--fg:#e7e8ea;--muted:#a0a4ab;--line:#2c2f34;
--card:#191b1e;--accent:#93b4ff;--act:#fdba8c;--ok:#86efac}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%;text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",
Roboto,"Helvetica Neue",sans-serif;overflow-wrap:anywhere}
header{border-bottom:1px solid var(--line);background:var(--card)}
.bar{max-width:46rem;margin:0 auto;padding:10px 16px;display:flex;flex-wrap:wrap;gap:6px 16px;
align-items:center}
.brand{font-weight:700;margin-right:auto}
nav a,.bar button{color:var(--accent);text-decoration:none;font:inherit;background:none;border:0;
padding:6px 0;cursor:pointer}
nav{display:flex;gap:16px;flex-wrap:wrap}
form.out{margin:0}
main{max-width:46rem;margin:0 auto;padding:16px}
h1{font-size:1.35rem;line-height:1.3;margin:8px 0 12px}
h2{font-size:1.1rem;margin:28px 0 8px}
p{margin:8px 0}
a{color:var(--accent)}
.muted{color:var(--muted)}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px;margin:12px 0}
.action{font-size:1.2rem;font-weight:600;border-left:5px solid var(--act)}
.action.calm{border-left-color:var(--ok);font-weight:500}
.status p{margin:2px 0}
.status.fine{border-left:5px solid var(--ok)}
.status.doctor,.status.act{border-left:5px solid var(--act)}
.line b{font-weight:600}
.pager{display:flex;justify-content:space-between;gap:12px;margin:16px 0}
table{border-collapse:collapse;width:100%;font-size:.95rem}
th,td{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{font-weight:600;color:var(--muted)}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.scroll{overflow-x:auto}
pre{overflow-x:auto;white-space:pre;font:13px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px;margin:12px 0}
code,.cmd{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.92em}
.cmd{display:block;background:var(--card);border:1px solid var(--line);border-radius:6px;padding:8px 10px;
margin:6px 0;user-select:all;-webkit-user-select:all;white-space:pre-wrap}
label{display:block;margin:12px 0 4px;font-weight:600}
input[type=password],input[type=text]{width:100%;max-width:24rem;font:inherit;padding:10px 12px;
border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg)}
button.go{font:inherit;margin-top:12px;padding:10px 18px;border:0;border-radius:6px;background:var(--accent);
color:var(--bg);font-weight:600;cursor:pointer}
form.find{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
form.find input{flex:1 1 12rem}
form.find button{margin-top:0}
.error{color:var(--act);font-weight:600}
footer{max-width:46rem;margin:24px auto;padding:0 16px 24px;color:var(--muted);font-size:.85rem}
"""


def esc(value) -> str:
    """A value from the record as HTML text: every non-printable character made visible, then escaped."""
    return html.escape(clean("" if value is None else value), quote=True)


def name_link(name: str) -> str:
    """A name, linked to its page when it is a plain host name; otherwise its escaped text alone."""
    if NAME.fullmatch(name or ""):
        return f'<a href="/name/{name}">{esc(name)}</a>'
    return esc(name)


def page(title: str, body: str, *, csrf: str | None = None) -> str:
    """A whole document. `csrf`, the session's token, adds the menu and the sign-out form; without it (the
    sign-in page, an error before sign-in) the header holds the name alone."""
    if csrf is None:
        menu = ""
    else:
        menu = (
            '<nav><a href="/">Today</a><a href="/rules">Your rules</a><a href="/about">About</a></nav>'
            '<form class="out" method="post" action="/logout">'
            f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
            '<button type="submit">Sign out</button></form>'
        )
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="referrer" content="no-referrer">'
        '<meta name="robots" content="noindex, nofollow">'
        f"<title>{esc(title)} - tvgw</title>"
        '<link rel="stylesheet" href="/style.css"></head><body>'
        f'<header><div class="bar"><span class="brand">tvgw</span>{menu}</div></header>'
        f"<main>{body}</main>"
        f"<footer>tvgw {esc(__version__)}. This page only shows; nothing on it changes the gateway.</footer>"
        "</body></html>\n"
    )


def _table(headers: Sequence[str], rows: Iterable[Sequence[str]], numeric: Sequence[int] = ()) -> str:
    """A table of cells that are already HTML; `numeric` columns are right-aligned."""
    head = "".join(f"<th{' class=n' if i in numeric else ''}>{esc(h)}</th>" for i, h in enumerate(headers))
    body = "".join(
        "<tr>"
        + "".join(f"<td{' class=n' if i in numeric else ''}>{c}</td>" for i, c in enumerate(r))
        + "</tr>"
        for r in rows
    )
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _line(text: str) -> str:
    """One line of the plain brief: its label (`Protection:`, `The TV:`) in bold, the rest as text."""
    label, sep, rest = text.strip().partition(": ")
    if sep and 0 < len(label) <= 16 and not any(ch.isdigit() for ch in label):
        return f'<p class="line"><b>{esc(label)}:</b> {esc(rest)}</p>'
    return f'<p class="line">{esc(text.strip())}</p>'


# ---- what the server hands the pages -------------------------------------------------------------------
@dataclass
class Brief:
    """One day's plain brief, split as the pages show it."""

    day: str
    title: str
    action: str | None  # the Action line's text, None when the brief has none (the first day)
    calm: bool  # nothing needs a person
    lines: list[str]  # the other lines, in order, without the title, the Action and the footer


@dataclass
class DayRow:
    day: str
    hours: str  # already words: "about 5", "off", "-"
    refused: str
    new: str


@dataclass
class NewName:
    name: str
    kind: str
    company: str | None
    blocked: bool


@dataclass
class NameView:
    name: str
    seen: bool
    kind: str = ""
    company: str | None = None
    first: str = ""
    last: str = ""
    blocked: bool | None = None
    decided: str = ""  # which kind of rule, in plain words
    days: list[tuple[str, int, int]] = field(default_factory=list)  # (day, lookups, blocked)
    under: list[tuple[str, str, bool | None]] = field(default_factory=list)  # a domain: (name, kind, blocked)


def brief_parts(day: str, lines: list[str], nothing: str, footer: str) -> Brief:
    """`plain.plain_brief`'s lines as the pages show them. `nothing` is the Action's words for a day with
    nothing to do and `footer` the line that names the engineering report, which a link replaces."""
    title, *rest = lines or [""]
    action, others = None, []
    for line in rest:
        text = line.strip()
        if text.startswith("Action: ") and action is None:
            action = text.removeprefix("Action: ")
        elif text != footer.strip():
            others.append(text)
    return Brief(day=day, title=title, action=action, calm=action == nothing, lines=others)


def _brief_body(b: Brief, *, heading: str = "h1") -> str:
    out = [f"<{heading}>{esc(b.title)}</{heading}>"]
    if b.action is not None:
        calm = " calm" if b.calm else ""
        out.append(f'<div class="card action{calm}">{esc(b.action)}</div>')
    out.extend(_line(x) for x in b.lines)
    out.append(f'<p><a href="/day/{b.day}/full">The engineering report for this day</a></p>')
    return "\n".join(out)


def _find_form() -> str:
    return (
        '<h2>Look up a name</h2><form class="find" method="get" action="/name">'
        '<input type="text" name="q" autocomplete="off" autocapitalize="none" spellcheck="false"'
        ' aria-label="A name, such as ads.example" placeholder="ads.example">'
        '<button class="go" type="submit">Look up</button></form>'
    )


# ---- the pages -----------------------------------------------------------------------------------------
def login(token: str, message: str = "") -> str:
    msg = f'<p class="error">{esc(message)}</p>' if message else ""
    body = (
        "<h1>Sign in</h1>"
        f"{msg}"
        '<form method="post" action="/login">'
        f'<input type="hidden" name="csrf" value="{esc(token)}">'
        '<label for="password">The page\'s password</label>'
        '<input id="password" type="password" name="password" autocomplete="current-password" required>'
        '<button class="go" type="submit">Sign in</button></form>'
        "<h2>Why your browser warned you</h2>"
        "<p>The gateway made its own certificate for this page, so your browser cannot check it with a"
        " company it trusts, and warns you once. On the gateway, <code>sudo tvgw web status</code> prints"
        " the certificate's fingerprint. If the warning page shows the same fingerprint, the page is your"
        " gateway's, and you can go on.</p>"
        '<p class="muted">Forgot the password? On the gateway, run <code>sudo tvgw web password</code>'
        " to set a new one.</p>"
    )
    return page("Sign in", body)


def today(status: list[str], tier: str, brief: Brief | None, csrf: str, none_yet: str) -> str:
    """`tvgw status`'s three lines, then yesterday's plain brief with its Action first."""
    cls = {"0": "fine", "1": "doctor", "2": "act"}.get(tier, "doctor")
    out = [f'<div class="card status {cls}">' + "".join(f"<p>{esc(x)}</p>" for x in status) + "</div>"]
    if brief is None:
        out.append(f"<p>{esc(none_yet)}</p>")
    else:
        out.append(_brief_body(brief))
        out.append(f'<p><a href="/day/{brief.day}">This day, and the 14 before it</a></p>')
    out.append(_find_form())
    return page("Today", "\n".join(out), csrf=csrf)


def day(
    brief: Brief | None,
    day_: str,
    prev: str | None,
    next_: str | None,
    rows: list[DayRow],
    news: list[NewName],
    csrf: str,
    note: str = "",
) -> str:
    """One day's plain brief, links to the days either side, the table of 14 days and the day's new names."""
    out = []
    pager = '<div class="pager">'
    pager += f'<a href="/day/{prev}">Earlier day</a>' if prev else "<span></span>"
    pager += f'<a href="/day/{next_}">Later day</a>' if next_ else "<span></span>"
    pager += "</div>"
    out.append(pager)
    if brief is None:
        out.append(f"<h1>{esc(day_)}</h1><p>{esc(note)}</p>")
    else:
        out.append(_brief_body(brief))
    if rows:
        out.append("<h2>14 days</h2>")
        cells = [
            (f'<a href="/day/{r.day}">{esc(r.day)}</a>', esc(r.hours), esc(r.refused), esc(r.new))
            for r in rows
        ]
        out.append(_table(["Day", "Hours on", "Tracker lookups refused", "New services"], cells, (1, 2, 3)))
    if news:
        out.append("<h2>Names first seen this day</h2>")
        cells = [
            (
                name_link(n.name),
                esc(n.kind + (f" ({n.company})" if n.company else "")),
                esc(_state(n.blocked)),
            )
            for n in news
        ]
        out.append(_table(["Name", "Kind", "Now"], cells))
    out.append(_find_form())
    return page(day_, "\n".join(out), csrf=csrf)


def full(day_: str, text: str, csrf: str) -> str:
    body = (
        f'<p><a href="/day/{day_}">Back to the short brief</a></p>'
        f"<h1>Engineering report, {esc(day_)}</h1>"
        f"<pre>{esc_block(text)}</pre>"
    )
    return page(f"Engineering report {day_}", body, csrf=csrf)


def esc_block(text: str) -> str:
    """A block of preformatted text: each line made visible and escaped, the line breaks kept."""
    return "\n".join(esc(line) for line in text.splitlines())


def _state(blocked: bool | None) -> str:
    return "blocked" if blocked else "allowed" if blocked is not None else "not known"


def name(v: NameView, csrf: str) -> str:
    """What the gateway has seen of one name, and the commands to run on the gateway to change it."""
    out = [f"<h1>{esc(v.name)}</h1>"]
    if not v.seen and not v.under:
        out.append("<p>The gateway has no record of this name.</p>")
        out.append(_find_form())
        return page(v.name, "\n".join(out), csrf=csrf)
    if v.under and not v.seen:
        out.append("<p>Not one name: these are the names under it the gateway has seen.</p>")
        cells = [(name_link(n), esc(k), esc(_state(b))) for n, k, b in v.under]
        out.append(_table(["Name", "Kind", "Now"], cells))
        out.append(_find_form())
        return page(v.name, "\n".join(out), csrf=csrf)
    kind = v.kind + (f", from {v.company}" if v.company else "")
    rows = [
        ("Kind", esc(kind)),
        ("First seen", esc(v.first)),
        ("Last seen", esc(v.last)),
        ("Now", esc(_state(v.blocked))),
        ("Decided by", esc(v.decided)),
    ]
    out.append(
        '<div class="scroll"><table><tbody>'
        + "".join(f"<tr><th>{esc(k)}</th><td>{c}</td></tr>" for k, c in rows)
        + "</tbody></table></div>"
    )
    out.append("<h2>Lookups in the last 14 days</h2>")
    if v.days:
        out.append(
            _table(
                ["Day", "Lookups", "Blocked"],
                [(esc(d), esc(f"{n:,}"), esc(f"{b:,}")) for d, n, b in v.days],
                (1, 2),
            )
        )
    else:
        out.append("<p>None in the last 14 days.</p>")
    out.append("<h2>To change it</h2><p>Nothing on this page changes anything. On the gateway, run:</p>")
    if NAME.fullmatch(v.name):
        if v.blocked:
            out.append(f"<p>To let it through:</p><code class=cmd>sudo tvgw allow {esc(v.name)}</code>")
        else:
            out.append(f"<p>To block it:</p><code class=cmd>sudo tvgw block {esc(v.name)}</code>")
        out.append(
            "<p>To see first what the filter does with it, and why:</p>"
            f"<code class=cmd>sudo tvgw check {esc(v.name)}</code>"
        )
    out.append(_find_form())
    return page(v.name, "\n".join(out), csrf=csrf)


def rules(message: str | None, rows: list[tuple[str, str, str, str]], csrf: str) -> str:
    """`tvgw rules --local`: the owner's own rules, with the day and reason each was written."""
    out = [
        "<h1>Your rules</h1>",
        "<p>The allows and blocks you wrote with <code>sudo tvgw allow</code> and"
        " <code>sudo tvgw block</code>.</p>",
    ]
    if message:
        out.append(f"<p>{esc(message)}</p>")
    if rows:
        cells = [(esc(k), name_link(h), esc(w), esc(st)) for k, h, w, st in rows]
        out.append(_table(["Kind", "Name", "Written", ""], cells))
    return page("Your rules", "\n".join(out), csrf=csrf)


def about(port: int, fingerprint: str | None, csrf: str) -> str:
    fp = (
        "<p>This page's certificate has the SHA-256 fingerprint:</p>"
        f"<code class=cmd>{esc(fingerprint)}</code>"
        if fingerprint
        else ""
    )
    body = f"""<h1>About this page</h1>
<p>tvgw {esc(__version__)}.</p>
<h2>What it shows</h2>
<p>The gateway's last check, and each day's short brief, as <code>tvgw status</code> and
<code>tvgw brief</code> print them on the gateway. A table of 14 days. What the gateway has seen of one name,
as <code>tvgw host</code> prints it. Your own allows and blocks. It shows what the daily reports show, and
never which app was in front minute by minute.</p>
<h2>Who can see it</h2>
<p>Anyone on your home network who has its password. The TV cannot reach it: the gateway refuses the TV's
connections to it. It answers only addresses inside your home network and this computer itself, and the
connection is encrypted. tvgw never opens a port on your router.</p>
{fp}
<h2>What it never does</h2>
<p>It changes nothing: no button allows, blocks, pauses or undoes anything, and no setting can be changed
here. To change something, run the command a page names on the gateway. It sends no alert or message of
any kind. It has no live view, no search of the whole history and no charts. It has one password and no
second step at sign-in. It is not for the TV's own browser.</p>
<h2>How to turn it off</h2>
<p>On the gateway, set <code>WEB=off</code> in the settings file and run the installer again, or run
<code>sudo systemctl disable --now tvgw-web</code>. Nothing then listens on port {port}.</p>
"""
    return page("About", body, csrf=csrf)


ERRORS = {
    400: ("Bad request", "The gateway could not read that request."),
    403: ("Not allowed", "The gateway refused that request."),
    404: ("Not found", "There is no such page."),
    405: ("Not allowed", "That page cannot be used that way."),
    408: ("Too slow", "The request took too long."),
    411: ("Bad request", "The request did not say how long it is."),
    413: ("Too large", "The request is too large."),
    414: ("Too long", "The address is too long."),
    415: ("Bad request", "The gateway does not read that kind of request."),
    421: (
        "Wrong address",
        "Open the page at the gateway's own address or its .local name, as sudo tvgw web status prints them.",
    ),
    429: ("Too many tries", "Too many failed sign-ins. Wait 15 minutes, then try again."),
    431: ("Too large", "The request's headers are too large."),
    500: ("Something went wrong", "The gateway could not make this page. Try again in a minute."),
    501: ("Not allowed", "That page cannot be used that way."),
    503: ("Busy", "The gateway is busy. Try again in a minute."),
    505: ("Bad request", "The gateway does not read that version of the web's protocol."),
}


def error(code: int, message: str = "", signed_in_csrf: str | None = None) -> str:
    title, default = ERRORS.get(code, ("Error", "Something went wrong."))
    body = f"<h1>{esc(title)}</h1><p>{esc(message or default)}</p>"
    if signed_in_csrf is not None:
        body += '<p><a href="/">Back to today</a></p>'
    return page(title, body, csrf=signed_in_csrf)
