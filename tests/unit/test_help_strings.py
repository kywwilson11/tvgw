"""Every command's `--help` can be printed. argparse %-formats help strings, and Python 3.14 checks them
when an option is added: a bare % (an f-string's `{x:.0%}` followed by text) stops the program there before
it does anything, and on every earlier version it crashes `--help`. Formatting each parser's help on any
version catches both. Found when Ubuntu 26.04 (Python 3.14) failed the platform check on
tools/companies_snapshot.py."""

from __future__ import annotations

import argparse

import pytest
from conftest import load_tool

from tvgw import cli


def parsers(p: argparse.ArgumentParser):
    yield p
    for action in p._actions:  # argparse names no public way to walk subcommands
        if isinstance(action, argparse._SubParsersAction):
            for sub in action.choices.values():
                yield from parsers(sub)


def test_every_tvgw_command_formats_its_help():
    seen = [p.prog for p in parsers(cli.build_parser()) if p.format_help()]
    assert len(seen) > 20  # the walk found the subcommands, not only `tvgw`


@pytest.mark.parametrize(
    "name",
    [
        "companies_snapshot",
        "check_docs_links",
        "check_deploy_window",
        "rewrite_doc_paths",
        "docgen",
    ],
)
def test_every_tool_prints_its_help(name, capsys):
    with pytest.raises(SystemExit) as ended:
        load_tool(name).main(["--help"])
    assert ended.value.code == 0 and "usage:" in capsys.readouterr().out
