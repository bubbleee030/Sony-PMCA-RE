"""Validate and render the α6400 Creative Look translation guide."""

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from pmca.analysis.creative_looks import (
    CreativeLookError,
    render_recipe_guide,
    validate_recipe_document,
)


MAX_RECIPE_BYTES = 256 * 1024


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    subparsers = parser.add_subparsers(dest="command", required=True)
    render = subparsers.add_parser("render", allow_abbrev=False)
    render.add_argument("--recipes", required=True, type=Path)
    render.add_argument("--output", required=True, type=Path)
    return parser


def _load(path: Path) -> dict:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise CreativeLookError("Recipe input must be a real regular file")
    if path.stat().st_size > MAX_RECIPE_BYTES:
        raise CreativeLookError("Recipe input exceeds the metadata size limit")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CreativeLookError("Recipe input is not valid UTF-8 JSON") from error
    return validate_recipe_document(document)


def _output_path(path: Path) -> Path:
    path = Path(path)
    if path.suffix.casefold() != ".md" or path.is_symlink():
        raise CreativeLookError("Guide output must be a non-symlink .md path")
    resolved = path.resolve(strict=False)
    if any(part.casefold() == ".artifacts" for part in resolved.parts):
        raise CreativeLookError("Guide output must not be below .artifacts")
    return resolved


def _write(path: Path, content: str) -> None:
    resolved = _output_path(path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=resolved.parent,
        prefix=f".{resolved.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, resolved)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _render(args: argparse.Namespace) -> None:
    document = _load(args.recipes)
    _write(args.output, render_recipe_guide(document))
    print(
        f"looks={len(document['defaults'])} "
        f"community={len(document['community_experiments'])}"
    )


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        _render(args)
    except (CreativeLookError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
