"""The gateway ran under a system locale of en_US with no charset, which Python takes as latin-1, and
the first ellipsis in the analyst's own prose crashed a dry run. Every text file the package reads or
writes names UTF-8, and the CLI's streams are UTF-8: a child interpreter pinned to an ASCII locale with
UTF-8 mode off exercises the paths that used to inherit the locale."""

import os
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def run_ascii(code: str, tmp_path: Path) -> subprocess.CompletedProcess:
    env = {
        **os.environ,
        "LC_ALL": "C",
        "LANG": "C",
        "PYTHONCOERCECLOCALE": "0",
        "PYTHONUTF8": "0",
        "PYTHONIOENCODING": "",
        "PYTHONPATH": str(ROOT / "src"),
    }
    return subprocess.run(
        [sys.executable, "-X", "utf8=0", "-c", textwrap.dedent(code)],
        capture_output=True,
        env=env,
        cwd=tmp_path,
        timeout=120,
    )


def test_text_files_and_output_are_utf8_under_an_ascii_locale(tmp_path):
    key = tmp_path / "key"
    key.write_text("sk-ant-…\n", encoding="utf-8")
    key.chmod(0o600)
    reports = tmp_path / "reports" / "proposals"
    reports.mkdir(parents=True)
    (reports / "2026-10-29.md").write_text("# Proposals\n\nOneTrust’s consent dialog…\n", encoding="utf-8")  # noqa: RUF001 - the curly quote is the point
    conf = tmp_path / "tvgw.conf"
    conf.write_text(
        f"# café — a comment the shell ignores\nREPORTS_DIR={tmp_path / 'reports'}\nSTATE_DIR={tmp_path}\nDB_PATH={tmp_path / 'db'}\n",
        encoding="utf-8",
    )
    out = run_ascii(
        f"""
        import sys
        assert not sys.flags.utf8_mode, "the probe must run with UTF-8 mode off"
        from tvgw import analyst, autoblock, cli, config, verify
        analyst._write({str(tmp_path / "p.md")!r}, "ellipsis \\u2026 quote \\u2019\\n")  # noqa: RUF001 - the curly quote is the point
        assert open({str(tmp_path / "p.md")!r}, encoding="utf-8").read().startswith("ellipsis \\u2026")
        assert analyst.read_key({str(key)!r}) == "sk-ant-\\u2026"
        rules = {str(tmp_path / "auto.rules")!r}
        autoblock.add_rule(rules, "||a.example^", "note \\u2014 dash")
        assert autoblock.read_rules(rules) == ["||a.example^"]
        assert "\\u2014" in verify.read_file(rules)
        s = config.load({str(conf)!r})
        assert s.reports_dir == {str(tmp_path / "reports")!r}
        sys.exit(cli.main(["--conf", {str(conf)!r}, "analyst", "--show"]))
    """,
        tmp_path,
    )
    assert out.returncode == 0, out.stderr.decode("utf-8", "replace")
    assert "OneTrust’s consent dialog…".encode() in out.stdout  # noqa: RUF001 - the curly quote is the point
