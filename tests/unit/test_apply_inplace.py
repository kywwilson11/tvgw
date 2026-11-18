"""(inplace) tvgw-apply changes a table that stands in place, so an apply removes no hook, and every
table ends as a fresh load leaves it, object for object (design decision 110).

The script runs on test_apply's harness with an nft that remembers: each table is the texts that changed
it since its last `delete table`, which `list tables` names and `-s list table` prints, so a listing
changes exactly when something changed the table. What a kernel makes of the calls is worked out here by
`Kernel`, a model of nf_tables' objects that applies a transaction whole or refuses it as the kernel does
(a base chain added again with another hook or priority, a set with other properties, a chain or a set
still in use deleted). Every apply's calls are replayed on it, in order, and compared with a fresh load."""

import copy
import functools
import itertools
import re
import shutil
import subprocess
from dataclasses import dataclass, field

import pytest
import test_apply
from test_apply import PROC, run_apply
from test_clock_port import supported, tvgw_says
from test_fwcheck import COUNTING, SETTINGS, WALLS, vnet

# nft with a memory. A text names its tables in its `table` lines and its commands; it replaces a table's
# text when it deletes that table, and is added to it otherwise. Three files make it fail as nft can: a
# script that matches a line of `refuse` is refused, as the kernel refuses a transaction, and leaves a
# `#refused` line after its call; with `unlisted` the tables cannot be listed, and with
# `unlistable.<family>.<table>` that table cannot. `set.<table>.<set>` is that set's terse listing.
REMEMBERING_NFT = r"""#!/bin/sh
printf '%s\n' "$*" >>"$STUB_DIR/nft.calls"
named() {
	sed -nE -e 's/^[[:space:]]*(add |delete )?table ([a-z]+) ([a-z0-9_]+)( \{)?$/\2 \3/p' \
		-e 's/^[[:space:]]*(add|flush|insert|delete) (chain|set|rule|element) ([a-z]+) ([a-z0-9_]+)( .*)?$/\3 \4/p' | sort -u
}
remember() {
	text=$(cat)
	printf '%s\n' "$text" | named | while read -r family table; do
		if printf '%s\n' "$text" | grep -qx "delete table $family $table"; then
			printf '%s\n' "$text" >"$STUB_DIR/table.$family.$table"
		else
			printf '%s\n' "$text" >>"$STUB_DIR/table.$family.$table"
		fi
	done
}
case "$*" in
"-f -")
	n=$(ls "$STUB_DIR" | grep -c '^nft-script\.')
	cat >"$STUB_DIR/nft-script.$n"
	if [ -s "$STUB_DIR/refuse" ] && grep -qf "$STUB_DIR/refuse" "$STUB_DIR/nft-script.$n"; then
		echo '#refused' >>"$STUB_DIR/nft.calls"
		exit 1
	fi
	remember <"$STUB_DIR/nft-script.$n" ;;
"list tables")
	[ ! -e "$STUB_DIR/unlisted" ] || exit 1
	for f in "$STUB_DIR"/table.*; do [ ! -e "$f" ] || echo "table ${f##*/table.}"; done | tr . ' ' ;;
"-s list table "*) [ ! -e "$STUB_DIR/unlistable.$4.$5" ] && cat "$STUB_DIR/table.$4.$5" 2>/dev/null ;;
"list chain "*)
	[ -e "$STUB_DIR/table.$3.$4" ] && awk -v c="$5" '
		($1 == "chain" && $2 == c) || ($1 == "add" && $2 == "chain" && $5 == c) { on = 1 }
		$1 == "delete" && $2 == "chain" && $5 == c { on = 0 }
		END { exit !on }' "$STUB_DIR/table.$3.$4" ;;
"delete table "*) rm "$STUB_DIR/table.$3.$4" 2>/dev/null ;;
"-t list set "*) cat "$STUB_DIR/set.$5.$6" 2>/dev/null || true ;;
"-j -t list table "*) echo '{"nftables": []}' ;;
*) printf '%s\n' "$*" | tr ';' '\n' | sed 's/^ *//' | remember ;;
esac
"""
# the five tables the script loads with load_table
LOADED = (
    ("inet", "tvgw"),
    ("netdev", "tvgw_l2"),
    ("inet", "tvgw_capture"),
    ("inet", "tvgw_names"),
    ("inet", "tvgw_mint"),
)
DRAIN = "flush chain inet tvgw_gate answers; delete set inet tvgw_gate inpath_live"
ALL_ON = {**WALLS, **COUNTING}  # every table there is: the probe's chains, every counting switch's table


# ---- what a kernel makes of the calls ------------------------------------------------------------------
class Refused(Exception):
    """A transaction the kernel refuses whole."""


@dataclass
class Table:
    """One table's objects."""

    chains: dict = field(default_factory=dict)  # name -> [the base chain's `type` line or None, [rules]]
    sets: dict = field(default_factory=dict)  # name -> [its properties, sorted, and {its elements}]

    def defines(self) -> tuple:
        """What a load defines in this table: its chains with their hooks, its sets with their contents."""
        return (
            tuple(sorted((name, spec) for name, (spec, _rules) in self.chains.items())),
            tuple(
                sorted((name, props, frozenset(elements)) for name, (props, elements) in self.sets.items())
            ),
        )


def props_and_elements(declaration: str) -> tuple[tuple, set]:
    """A set's properties, sorted, and its elements, from what its braces hold."""
    head, _, tail = declaration.partition("elements = {")
    props = tuple(sorted(p.strip() for p in re.split(r"[;\n]", head) if p.strip()))
    return props, {e.strip() for e in tail.partition("}")[0].split(",") if e.strip()}


def statements(script: str) -> list[tuple]:
    """A script's statements in the order nft sends them. A table's block is sent as nft expands it: the
    table, its chains, its sets with their elements, then the rules, so a rule may jump to a chain the
    block declares after it."""
    out: list[tuple] = []
    block: dict | None = None  # the table block being read: its chains, sets and rules
    chain = None
    pending = False  # a chain opened, its `type` line not yet read
    inset: tuple | None = None
    for raw in script.splitlines():
        line = " ".join(raw.split())
        if not line or line.startswith("#"):
            continue
        if inset is not None:  # a set over several lines, read whole once it closes
            if line == "}":
                block["sets"].append((inset[0], *props_and_elements("\n".join(inset[1]))))
                inset = None
            else:
                inset[1].append(line)
        elif chain is not None:
            if pending:
                block["chains"].append((chain, line if line.startswith("type ") else None))
                pending = False
                if line.startswith("type "):
                    continue
            if line == "}":
                chain = None
            else:
                block["rules"].append((chain, line))
        elif block is not None and line == "}":
            t = block["table"]
            out += [("chain", *t, name, spec) for name, spec in block["chains"]]
            for name, props, elements in block["sets"]:
                out += [("set", *t, name, props), ("element", *t, name, elements)]
            out += [("rule", *t, name, rule, "add") for name, rule in block["rules"]]
            block = None
        elif block is not None and (m := re.fullmatch(r"chain (\w+) \{", line)):
            chain, pending = m[1], True
        elif block is not None and (m := re.fullmatch(r"set (\w+) \{(.*)", line)):
            if m[2].rstrip().endswith("}"):
                block["sets"].append((m[1], *props_and_elements(m[2].rstrip()[:-1])))
            else:
                inset = (m[1], [m[2]])
        elif m := re.fullmatch(r"table (\w+) (\w+) \{", line):
            block = {"table": (m[1], m[2]), "chains": [], "sets": [], "rules": []}
            out.append(("table", m[1], m[2]))
        else:
            out.append(command(line))
    return out


def command(line: str) -> tuple:
    """One command as a statement."""
    if m := re.fullmatch(r"(?:add )?table (\w+) (\w+)", line):
        return ("table", m[1], m[2])
    if m := re.fullmatch(r"(delete|flush) (table|chain|set) (\w+) (\w+)(?: (\w+))?", line):
        return (f"{m[1]} {m[2]}", m[3], m[4], *([m[5]] if m[5] else []))
    if m := re.fullmatch(r"add chain (\w+) (\w+) (\w+)(?: \{ (.*) \})?", line):
        return ("chain", m[1], m[2], m[3], m[4])
    if m := re.fullmatch(r"add set (\w+) (\w+) (\w+) \{ (.*) \}", line):
        return ("set", m[1], m[2], m[3], props_and_elements(m[4])[0])
    if m := re.fullmatch(r"add element (\w+) (\w+) (\w+) \{ (.*) \}", line):
        return ("element", m[1], m[2], m[3], {e.strip() for e in m[4].split(",")})
    if m := re.fullmatch(r"(add|insert) rule (\w+) (\w+) (\w+) (.*)", line):
        return ("rule", m[2], m[3], m[4], m[5], m[1])
    raise AssertionError(f"a statement this model does not know: {line!r}")


def commands(call: str) -> list[str]:
    """One call's commands: split at each `;` outside braces, where a chain's `type` line has its own."""
    parts, depth, start = [], 0, 0
    for i, c in enumerate(call):
        depth += {"{": 1, "}": -1}.get(c, 0)
        if c == ";" and depth == 0:
            parts.append(call[start:i])
            start = i + 1
    return [*parts, call[start:]]


def hook(spec: str) -> str:
    """A base chain's hook and priority, without its policy: what the kernel will not change in place."""
    return spec.partition("; policy")[0]


class Kernel:
    """nf_tables' objects as the calls leave them. `gone` lists each base chain whose hook was removed, as
    (family, table, chain, the index of the call that removed it); a chain that a transaction makes and
    deletes again never had a hook."""

    def __init__(self):
        self.tables: dict[tuple[str, str], Table] = {}
        self.gone: list[tuple[str, str, str, int]] = []

    def apply(self, stmts: list[tuple], at: int = -1) -> bool:
        tables, gone = copy.deepcopy(self.tables), []
        try:
            for s in stmts:
                self._do(tables, gone, s)
        except Refused:
            return False
        self.tables = tables
        self.gone += [(*g, at) for g in gone]
        return True

    def _hooked(self, family: str, name: str, chain: str) -> bool:
        before = self.tables.get((family, name))
        return before is not None and before.chains.get(chain, [None])[0] is not None

    def _do(self, tables: dict, gone: list, s: tuple) -> None:
        verb, family, name, *rest = s
        if verb == "table":
            tables.setdefault((family, name), Table())
            return
        if (family, name) not in tables:
            raise Refused
        t = tables[family, name]
        if verb == "delete table":
            gone += [(family, name, c) for c in t.chains if self._hooked(family, name, c)]
            del tables[family, name]
        elif verb == "chain":
            chain, spec = rest
            if chain not in t.chains:
                t.chains[chain] = [spec, []]
            elif spec is not None:
                was = t.chains[chain][0]
                if was is None or hook(was) != hook(spec):
                    raise Refused
                t.chains[chain][0] = spec  # the policy is the one thing an `add` changes
        elif verb in ("flush chain", "delete chain"):
            (chain,) = rest
            if chain not in t.chains:
                raise Refused
            if verb == "flush chain":
                t.chains[chain][1] = []
                return
            if any(
                re.search(rf"\b(jump|goto) {chain}\b", r) for _, rules in t.chains.values() for r in rules
            ):
                raise Refused
            if self._hooked(family, name, chain):
                gone.append((family, name, chain))
            del t.chains[chain]
        elif verb == "set":
            set_name, props = rest
            if set_name in t.sets and t.sets[set_name][0] != props:
                raise Refused
            t.sets.setdefault(set_name, [props, set()])
        elif verb in ("flush set", "delete set", "element"):
            set_name = rest[0]
            if set_name not in t.sets:
                raise Refused
            if verb == "flush set":
                t.sets[set_name][1] = set()
            elif verb == "element":
                t.sets[set_name][1] |= rest[1]
            elif any(f"@{set_name}" in r for _, rules in t.chains.values() for r in rules):
                raise Refused
            else:
                del t.sets[set_name]
        elif verb == "rule":
            chain, text, where = rest
            if chain not in t.chains or any(s not in t.sets for s in re.findall(r"@(\w+)", text)):
                raise Refused
            if any(c not in t.chains for c in re.findall(r"\b(?:jump|goto) (\w+)", text)):
                raise Refused
            rules = t.chains[chain][1]
            rules.insert(len(rules) if where == "add" else 0, text)


def replay(kernel: Kernel, tmp_path, start: int = 0) -> tuple[int, list[str]]:
    """The calls of nft.calls from line `start` on, applied to `kernel` in order: (where they end, the
    loads the kernel refused). A listing changes nothing; a load the stub refused is skipped."""
    calls = (tmp_path / "stub" / "nft.calls").read_text(encoding="utf-8").splitlines()
    scripts = sorted((tmp_path / "stub").glob("nft-script.*"), key=lambda p: int(p.suffix[1:]))
    loads = calls[:start].count("-f -")
    refused = []
    for i in range(start, len(calls)):
        skipped = i + 1 < len(calls) and calls[i + 1] == "#refused"
        if calls[i] == "-f -":
            text = scripts[loads].read_text(encoding="utf-8")
            loads += 1
            if not skipped and not kernel.apply(statements(text), i):
                refused.append(text)
        elif re.match(r"(add|insert|flush|delete) ", calls[i]):
            kernel.apply([command(part.strip()) for part in commands(calls[i])], i)
    return len(calls), refused


# ---- applying on a gateway that remembers ---------------------------------------------------------------
def gateway(tmp_path):
    """Where the applies run: the suite's two address lists, as the namespace tier has them."""
    for path, text in (
        (tmp_path / "state" / "doh4.txt", vnet.DOH4),
        (tmp_path / "etc" / "tvgw" / "block4.txt", vnet.BLOCK4),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return tmp_path


def apply(tmp_path, settings: dict, script: str | None = None):
    """One apply of `settings` as the gateway runs it, /run/tvgw and the tables kept from the last one: the
    copy of the script in which ntp=resolved is built (its variants are among test_fwcheck's), with a tvgw
    that names no clock rule, as test_fwcheck renders them. `script` is another version of the script."""
    script = supported(script or test_apply.APPLY).replace("/usr/local/bin/tvgw", f"{tmp_path}/bin/tvgw")
    proc = (*PROC, f"net/ipv4/conf/{vnet.VPN_IF}/forwarding")
    stubs = {"nft": REMEMBERING_NFT, "tvgw": tvgw_says("")}
    original, test_apply.APPLY = test_apply.APPLY, script
    try:
        out = run_apply(tmp_path, conf=vnet.render_conf(settings), proc=proc, stubs=stubs)
    finally:
        test_apply.APPLY = original
    assert out.returncode == 0, out.stderr
    return out


@dataclass
class Step:
    out: object
    calls: list[str]  # its nft calls
    first: int  # the index in nft.calls of its first call
    gone: list[tuple[str, str, str, int]]  # the hooks it removed

    @property
    def word(self) -> str:
        """How the apply says its tables went in: `in place`, or `remade: ` and each table and why."""
        (line,) = [ln for ln in self.out.stdout.splitlines() if ln.startswith("tvgw: load: ")]
        return line.removeprefix("tvgw: load: ")

    def at(self, call: str) -> int:
        return self.first + self.calls.index(call)


class Gateway:
    """A gateway the applies run on one after another, and the kernel their calls leave."""

    def __init__(self, tmp_path):
        self.path, self.kernel, self.seen = gateway(tmp_path), Kernel(), 0

    def apply(self, settings: dict, script: str | None = None) -> Step:
        out = apply(self.path, settings, script)
        calls = (self.path / "stub" / "nft.calls").read_text(encoding="utf-8").splitlines()
        first, had = self.seen, len(self.kernel.gone)
        self.seen, refused = replay(self.kernel, self.path, first)
        assert refused == [], f"the kernel refuses a load the script sent:\n{refused[0][:600]}"
        return Step(out, calls[first:], first, self.kernel.gone[had:])

    def nft(self, *args: str) -> None:
        """A command typed by hand, through the same nft."""
        env = {"STUB_DIR": str(self.path / "stub"), "PATH": "/usr/bin:/bin"}
        assert subprocess.run([self.path / "bin" / "nft", *args], env=env, check=False).returncode == 0


@pytest.fixture(scope="session")
def fresh(tmp_path_factory):
    """The kernel after one apply of some settings on a gateway that held nothing, by its settings. One
    directory is emptied for each, so its stubs are written once."""
    where = gateway(tmp_path_factory.mktemp("fresh"))

    @functools.cache
    def of(*settings: tuple[str, str]) -> Kernel:
        for made in (where / "stub").glob("*"):
            made.unlink()
        shutil.rmtree(where / "run", ignore_errors=True)
        gw = Gateway(where)
        assert gw.apply(dict(settings)).gone == []
        return gw.kernel

    return of


def remade(word: str) -> set[tuple[str, str]]:
    """The tables a load word names as remade."""
    return {tuple(t.split()) for t in re.findall(r"(?:^remade: |; )(\w+ \w+) \(", word)}


def changes(fresh, was: dict | None, now: dict) -> set[tuple[str, str]]:
    """The tables whose objects one apply of `now` defines otherwise than one of `was`: a table made, taken
    away, or with other chains, hooks, sets or set contents."""
    before = fresh(*sorted(was.items())).tables if was is not None else {}
    after = fresh(*sorted(now.items())).tables
    return {
        t
        for t in before.keys() | after.keys()
        if (t in before) != (t in after) or (t in before and before[t].defines() != after[t].defines())
    }


def check(fresh, gw: Gateway, was: dict | None, now: dict) -> Step:
    """One apply of `now` after one of `was` (None: on a gateway that held nothing): it ends as a fresh load
    ends, object for object; it removes a hook only of a table whose objects it changes, after it has
    quieted the in-path queue; and it remakes, and says it remakes, exactly the tables that stand and
    change. Every other table is changed in place."""
    answers = (
        was is not None
        and "answers" in fresh(*sorted(was.items())).tables.get(("inet", "tvgw_gate"), Table()).chains
    )
    step = gw.apply(now)
    assert gw.kernel.tables == fresh(*sorted(now.items())).tables
    changed = changes(fresh, was, now)
    drained = DRAIN in step.calls
    assert step.calls.count(DRAIN) <= 1  # once an apply at most
    others = [g for g in step.gone if not (drained and g[:3] == ("inet", "tvgw_gate", "answers"))]
    assert {g[:2] for g in others} <= changed
    assert drained == (bool(others) and answers)
    if drained:
        assert step.at(DRAIN) < min(g[3] for g in others)
    stood = {t for t in changed if was is not None and t in fresh(*sorted(was.items())).tables}
    assert remade(step.word) == {t for t in LOADED if t in stood and t in fresh(*sorted(now.items())).tables}
    return step


# ---- the fault, and the change in place --------------------------------------------------------------------
def test_a_second_apply_removes_no_hook_and_keeps_the_queue_live(tmp_path, fresh):
    """Pass 6, L4-14: every apply deleted and made again each of its tables, eight base chains in inet tvgw
    alone, and the kernel drops whatever waits in a netfilter queue when a hook goes. So the apply took the
    in-path filler's switch away first, held no answer while it ran, and lost one held by a filler that
    stalled past its wait."""
    gw = Gateway(tmp_path)
    first, again = gw.apply(ALL_ON), gw.apply(ALL_ON)
    assert again.gone == [] and DRAIN not in again.calls
    assert not [c for c in again.calls if c.startswith(("delete table", "delete chain"))]
    assert gw.kernel.tables == fresh(*sorted(ALL_ON.items())).tables
    # nothing stood at first: the tables were made, and nothing was removed
    assert (first.word, again.word) == ("in place", "in place")
    loads = sorted((tmp_path / "stub").glob("nft-script.*"), key=lambda p: int(p.suffix[1:]))
    texts = [p.read_text(encoding="utf-8") for p in loads[-again.calls.count("-f -") :]]
    for family, table in LOADED:
        (text,) = [t for t in texts if f"table {family} {table} {{" in t]
        assert text.startswith(f"flush chain {family} {table} ") and "delete table" not in text
        # it touches no set: each holds what the last load put in it, which is what this one would
        assert not re.search(r"^\s*(set \w+ \{|add (set|element) )", text, re.M)
    spool = (tmp_path / "state" / "changes.spool").read_text(encoding="utf-8").splitlines()
    assert [line.split("\t")[4] for line in spool] == ["load: in place"] * 2


def test_the_first_apply_after_an_install_remakes_its_tables_once_and_quiets_the_queue_first(tmp_path, fresh):
    """The deploy: the tables stand, made by an older version that left no record of them."""
    gw = Gateway(tmp_path)
    gw.apply(ALL_ON)
    for record in (tmp_path / "run" / "tvgw" / "loaded").iterdir():
        record.unlink()
    step = gw.apply(ALL_ON)
    assert gw.kernel.tables == fresh(*sorted(ALL_ON.items())).tables
    why = "no record of its last load"
    assert step.word == "remade: " + "; ".join(f"{f} {t} ({why})" for f, t in LOADED)
    assert step.at(DRAIN) < min(g[3] for g in step.gone if g[1] != "tvgw_gate")
    assert (
        (tmp_path / "state" / "changes.spool").read_text(encoding="utf-8").endswith(f"\tload: {step.word}\n")
    )
    assert check(fresh, gw, ALL_ON, ALL_ON).gone == []  # and from then on, in place


def test_a_table_changed_after_its_load_is_remade_and_what_was_added_to_it_is_gone(tmp_path, fresh):
    direct = SETTINGS["the matrix's direct"]
    gw = Gateway(tmp_path)
    gw.apply(direct)
    gw.nft("add", "chain", "inet", "tvgw", "foreign", "{ type filter hook forward priority 0; policy drop; }")
    step = gw.apply(direct)
    assert step.word == "remade: inet tvgw (it was changed after its last load)"
    assert gw.kernel.tables == fresh(*sorted(direct.items())).tables


@pytest.mark.parametrize(
    ("knob", "content", "why", "tables"),
    [
        ("refuse", "^flush chain inet tvgw \n", "nft refused the change in place", [("inet", "tvgw")]),
        ("unlisted", "", "the tables could not be listed", [("inet", "tvgw"), ("netdev", "tvgw_l2")]),
        ("unlistable.netdev.tvgw_l2", "", "it could not be listed", [("netdev", "tvgw_l2")]),
    ],
    ids=["refused", "no list of the tables", "no listing of the table"],
)
def test_a_doubt_remakes_the_table_as_before(tmp_path, fresh, knob, content, why, tables):
    """What nft refuses or cannot say is no table this can vouch for: it is remade, the queue quieted first."""
    direct = SETTINGS["the matrix's direct"]
    gw = Gateway(tmp_path)
    gw.apply(direct)
    (tmp_path / "stub" / knob).write_text(content, encoding="utf-8")
    step = gw.apply(direct)
    assert step.word == "remade: " + "; ".join(f"{f} {t} ({why})" for f, t in tables)
    assert gw.kernel.tables == fresh(*sorted(direct.items())).tables


def test_an_address_list_that_changed_remakes_its_table_alone(tmp_path):
    """The set is never emptied and filled again in place: what that leaves would rest on how nft merges
    the intervals it adds with those it read before the flush."""
    direct = SETTINGS["the matrix's direct"]
    gw = Gateway(tmp_path)
    gw.apply(direct)
    (tmp_path / "state" / "doh4.txt").write_text(vnet.DOH4 + "192.0.2.53\n", encoding="utf-8")
    step = gw.apply(direct)
    assert step.word == "remade: inet tvgw (this load defines other chains, sets or addresses)"
    assert {g[:2] for g in step.gone} == {("inet", "tvgw")}  # the in-path half is off here: nothing to quiet
    assert "192.0.2.53" in gw.kernel.tables["inet", "tvgw"].sets["doh4"][1]


def test_a_version_that_moves_a_chain_remakes_its_table_and_says_why(tmp_path):
    """The kernel will not move a hook in place (and adds a netdev chain's new device beside the old on
    some versions): the definitions differ, so the table is made again, and nothing rests on nft refusing."""
    moved = test_apply.APPLY.replace("priority mangle + 10;", "priority mangle + 11;", 1)
    direct = SETTINGS["the matrix's direct"]
    gw = Gateway(tmp_path)
    gw.apply(direct)
    step = gw.apply(direct, moved)
    assert step.word == "remade: inet tvgw (this load defines other chains, sets or addresses)"
    assert "priority mangle + 11;" in gw.kernel.tables["inet", "tvgw"].chains["pre_mangle"][0]


@pytest.mark.parametrize(
    ("table", "listed"),
    [
        ("tvgw_ntp", "table inet tvgw_ntp {\n\tset ntp4 {\n\t\ttype ipv4_addr\n\t\tsize 64\n\t}\n}\n"),
        ("tvgw_attn", "table inet tvgw_attn {\n\tset idle4 {\n\t\ttype ipv4_addr\n\t\tsize 64\n\t}\n}\n"),
    ],
    ids=["the NTP count", "the attention count"],
)
def test_a_count_with_a_set_of_other_properties_goes_after_the_queue_is_quieted(tmp_path, table, listed):
    """Its `add set` would fail the whole load, so the table is made again, empty: a hook goes."""
    gw = Gateway(tmp_path)
    gw.apply(ALL_ON)
    set_name = re.search(r"set (\w+) \{", listed)[1]
    (tmp_path / "stub" / f"set.{table}.{set_name}").write_text(listed, encoding="utf-8")
    step = gw.apply(ALL_ON)
    assert step.at(DRAIN) < step.at(f"delete table inet {table}")


def test_the_probe_switched_off_takes_its_chains_and_its_rules_with_it(tmp_path, fresh):
    probe = SETTINGS["the matrix's probe"]
    gw = Gateway(tmp_path)
    gw.apply(probe)
    step = check(fresh, gw, probe, {**probe, "TV_PROBE": "off"})
    assert step.word == "remade: inet tvgw (this load defines other chains, sets or addresses)"
    assert not [c for c in gw.kernel.tables["inet", "tvgw"].chains if c.startswith("probe_")]


# ---- every variant, and every pair of them --------------------------------------------------------------
def circuit(nodes: list[str]) -> list[str]:
    """A walk that takes every pair of nodes, either way and each to itself, exactly once (Hierholzer's)."""
    left = {n: list(nodes) for n in nodes}
    stack, walk = [nodes[0]], []
    while stack:
        if left[stack[-1]]:
            stack.append(left[stack[-1]].pop())
        else:
            walk.append(stack.pop())
    return walk[::-1]


WALK = circuit(sorted(SETTINGS))
LEG = len(SETTINGS)  # pairs a test takes; the walk is cut into legs that run apart


def test_the_walk_takes_every_pair_once():
    pairs = list(itertools.pairwise(WALK))
    assert len(pairs) == len(set(pairs)) == len(SETTINGS) ** 2


@pytest.mark.parametrize("leg", range(0, len(WALK) - 1, LEG))
def test_after_any_variant_any_other_ends_as_its_fresh_load(tmp_path, fresh, leg):
    """Old loaded, new applied in place, for every pair of test_fwcheck's variants, each to itself too."""
    gw = Gateway(tmp_path)
    check(fresh, gw, None, SETTINGS[WALK[leg]])
    for was, now in itertools.pairwise(WALK[leg : leg + LEG + 1]):
        check(fresh, gw, SETTINGS[was], SETTINGS[now])


@pytest.mark.parametrize("name", SETTINGS)
def test_the_tables_changed_in_place_hold_only_sets_the_apply_fills(fresh, name):
    """The change in place keeps a set's contents and writes every chain's rules again: right only for
    sets the apply fills, with no timeout and not dynamic, which no daemon adds to."""
    tables = fresh(*sorted(SETTINGS[name].items())).tables
    for key in set(LOADED) & tables.keys():
        for set_name, (props, _) in tables[key].sets.items():
            flags = " ".join(p for p in props if p.startswith(("flags", "timeout")))
            assert "timeout" not in flags and "dynamic" not in flags, (key, set_name)
