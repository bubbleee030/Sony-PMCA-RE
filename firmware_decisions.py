"""Render a validated offline firmware feasibility decision report."""

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from pmca.analysis.decisions import DecisionError, render_markdown


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    render = commands.add_parser(
        "render",
        help="render a validated evidence document",
        allow_abbrev=False,
    )
    render.add_argument("--evidence", required=True, type=Path)
    render.add_argument("--output", required=True, type=Path)
    return parser


def _reject_duplicate_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DecisionError("Evidence JSON contains duplicate object members")
        result[key] = value
    return result


def _load_evidence(path: Path) -> dict:
    with Path(path).open("r", encoding="utf-8") as stream:
        return json.load(stream, object_pairs_hook=_reject_duplicate_members)


def _write_markdown(path: Path, markdown: str) -> None:
    path = Path(path)
    if path.suffix.casefold() != ".md":
        raise DecisionError("Output path must use a .md suffix")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(markdown)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def _render(args: argparse.Namespace) -> None:
    document = _load_evidence(args.evidence)
    markdown = render_markdown(document)
    _write_markdown(args.output, markdown)


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        _render(args)
    except (DecisionError, json.JSONDecodeError, OSError, UnicodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
