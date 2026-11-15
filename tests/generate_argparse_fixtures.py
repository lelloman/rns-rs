#!/usr/bin/env python3
"""Generate the upstream command-line parsers table and its fixtures.

PYTHONPATH=/path/to/Reticulum python3 tests/generate_argparse_fixtures.py

Captures the ArgumentParser each RNS 1.6.0 utility builds (its main() runs
until parse_args, which is intercepted) and writes:

- rns-cli/src/upstream_parsers.rs: every action, help text and metavar, for
  rns-cli's port of argparse's help formatter and error reporting;
- tests/fixtures/argparse/<tool>.pickle: the parser's own --help output at
  several terminal widths, and its stdout, stderr and exit code for a set
  of invalid command lines, to compare the port against byte for byte.

The formatting is Python 3.12's argparse (3.10 to 3.12 print the same).
"""
import argparse
import contextlib
import importlib
import io
import os
import pickle
import sys
from pathlib import Path

import RNS

assert RNS.__version__ == "1.6.0", RNS.__version__
assert sys.version_info[:2] in ((3, 10), (3, 11), (3, 12)), sys.version

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ["rnsd", "rnstatus", "rnpath", "rnprobe", "rnid", "rncp", "rnx", "rnir", "rnpkg"]
WIDTHS = [12, 30, 50, 80, 100, 160]
ERROR_WIDTH = 80

original_parse_args = argparse.ArgumentParser.parse_args


def capture(tool):
    captured = {}

    def intercept(self, *args, **kwargs):
        captured["parser"] = self
        raise SystemExit(0)

    argparse.ArgumentParser.parse_args = intercept
    sys.argv = [tool]
    module = importlib.import_module("RNS.Utilities." + tool)
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        try:
            module.main()
        except SystemExit:
            pass
    argparse.ArgumentParser.parse_args = original_parse_args
    parser = captured["parser"]
    parser.prog = tool
    return parser


def rust_str(value):
    if value is None:
        return "None"
    out = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'Some("{out}")'


KINDS = {"_StoreAction": "Store", "_StoreTrueAction": "StoreTrue", "_CountAction": "Count",
         "_AppendAction": "Append", "_HelpAction": "Help", "_VersionAction": "Version"}
NARGS = {None: "One", 0: "Zero", "?": "Optional", "*": "ZeroOrMore"}
TYPES = {None: "Str", str: "Str", float: "Float", int: "Int"}


def rust_parser(tool, parser):
    assert parser.usage is None and parser.epilog is None
    assert not parser._mutually_exclusive_groups
    assert [g.title for g in parser._action_groups] == ["positional arguments", "options"]
    lines = [f"pub const {tool.upper()}: Parser = Parser {{",
             f'    name: "{tool}",',
             f"    description: {rust_str(parser.description)},",
             "    actions: &["]
    for a in parser._actions:
        assert a.choices is None and "%" not in (a.help or ""), (tool, a.dest)
        metavar = rust_str(a.metavar) if a.metavar is not None else "None"
        opts = ", ".join(f'"{o}"' for o in a.option_strings)
        lines.append(
            f'        Action {{ opts: &[{opts}], dest: "{a.dest}", kind: Kind::{KINDS[type(a).__name__]}, '
            f"nargs: Nargs::{NARGS[a.nargs]}, metavar: {metavar}, help: {rust_str(a.help)}, "
            f"ty: Ty::{TYPES[a.type]}, required: {'true' if a.required else 'false'} }},")
    lines += ["    ],", "};", ""]
    return "\n".join(lines)


def run(parser, argv):
    out, err = io.StringIO(), io.StringIO()
    code = 0
    os.environ["COLUMNS"] = str(ERROR_WIDTH)
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            parser.parse_args(argv)
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else 0
    return {"argv": argv, "code": code, "stdout": out.getvalue(), "stderr": err.getvalue()}


def error_cases(parser):
    optionals = [a for a in parser._actions if a.option_strings]
    cases = [["--bogus"], ["-Z"], ["-Zq"], ["--bogus", "x", "y", "z"], ["a", "b", "c", "d"],
             ["--bogus", "--also-bogus"], ["-h", "--bogus"], ["--bogus", "-h"], ["--he"]]
    longs = [o for a in optionals for o in a.option_strings if o.startswith("--")]
    for a in optionals:
        first = a.option_strings[0]
        if a.nargs is None:
            cases.append([first])
            if a.type in (float, int):
                cases.append([first, "x"])
                cases.append([first, " 5 "])
                cases.append([first, "1_0"])
                cases.append(["--bogus", first, "nope"])
        if a.nargs == "*":
            cases.append([first, "p1", "p2", "p3"])
            cases.append([first, "p1", "--bogus", "p2"])
        if a.nargs == 0 and type(a).__name__ in ("_StoreTrueAction", "_CountAction"):
            for o in a.option_strings:
                cases.append([o + "=1"])
            shorts = [o for o in a.option_strings if len(o) == 2]
            if shorts:
                cases.append([shorts[0] + "Z"])
    for long in longs:
        for k in range(3, len(long)):
            prefix = long[:k]
            matches = [o for o in longs if o.startswith(prefix)]
            if len(matches) > 1 and [prefix] not in cases:
                cases.append([prefix])
    return cases


table = ["// @generated by tests/generate_argparse_fixtures.py from RNS 1.6.0's own",
         "// parsers; regenerate rather than edit.", "",
         "use crate::argparse::{Action, Kind, Nargs, Parser, Ty};", ""]
fixtures = ROOT / "tests/fixtures/argparse"
fixtures.mkdir(parents=True, exist_ok=True)
for tool in TOOLS:
    parser = capture(tool)
    table.append(rust_parser(tool, parser))
    helps = {}
    for width in WIDTHS:
        os.environ["COLUMNS"] = str(width)
        helps[width] = parser.format_help()
    errors = [run(parser, argv) for argv in error_cases(parser)]
    (fixtures / f"{tool}.pickle").write_bytes(
        pickle.dumps({"help": helps, "errors": errors}, protocol=2))
    print(f"{tool}: {len(errors)} error cases")

table.append("/// The upstream parser of a tool, by its name.")
table.append("pub fn by_name(name: &str) -> Option<&'static Parser> {")
table.append("    match name {")
for tool in TOOLS:
    table.append(f'        "{tool}" => Some(&{tool.upper()}),')
table += ["        _ => None,", "    }", "}", ""]
(ROOT / "rns-cli/src/upstream_parsers.rs").write_text("\n".join(table))
