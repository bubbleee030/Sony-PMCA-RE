"""Inspect the manifest-pinned alpha 6400 updater without executing it."""

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from pmca.analysis.manifest import (
    ManifestError,
    load_manifest,
    verify_manifest_entry,
)
from pmca.analysis.updater_pe import (
    UpdaterPeError,
    inspect_updater_pe,
    validate_updater_pe_report,
)


SOURCE_KEY = "a6400-tw-v2.00"
REPORT_RELATIVE_PATH = Path("analysis") / "a6400-updater-static.json"


def write_updater_report(repository_root: Path, document: dict) -> Path:
    """Atomically write only the fixed, metadata-only repository report."""
    validate_updater_pe_report(document)
    root = Path(repository_root)
    if root.is_symlink():
        raise UpdaterPeError("Repository root must not be a symbolic link")
    try:
        resolved_root = root.resolve(strict=True)
        analysis = (resolved_root / "analysis").resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise UpdaterPeError("Repository analysis directory is unavailable") from error
    if not resolved_root.is_dir() or not analysis.is_dir():
        raise UpdaterPeError("Repository analysis directory is invalid")
    try:
        analysis.relative_to(resolved_root)
    except ValueError as error:
        raise UpdaterPeError("Repository analysis directory escapes its root") from error
    output = analysis / REPORT_RELATIVE_PATH.name
    if output.is_symlink():
        raise UpdaterPeError("Updater report path must not be a symbolic link")
    serialized = json.dumps(document, sort_keys=True, indent=2) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        dir=analysis,
        prefix=f".{output.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return output


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    subparsers = parser.add_subparsers(dest="command", required=True)
    inspect = subparsers.add_parser("inspect", allow_abbrev=False)
    inspect.add_argument("--repository-root", type=Path, required=True)
    inspect.add_argument("--artifacts-root", type=Path, required=True)
    inspect.add_argument("--manifest", type=Path, required=True)
    inspect.add_argument("--input", type=Path, required=True)
    return parser


def _inspect(args: argparse.Namespace) -> None:
    manifest = load_manifest(args.manifest)
    matches = [
        entry
        for entry in manifest["artifacts"]
        if entry["source_key"] == SOURCE_KEY
    ]
    if len(matches) != 1:
        raise UpdaterPeError("Manifest lacks one unique alpha 6400 updater")
    verify_manifest_entry(matches[0], args.input, args.artifacts_root)
    document = inspect_updater_pe(args.input)
    output = write_updater_report(args.repository_root, document)
    print(
        f"report={output} resources={len(document['resources'])} "
        f"embedded_pe_candidates={len(document['embedded_pe_candidates'])} "
        "executed=false camera=disconnected"
    )


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        _inspect(args)
    except (ManifestError, OSError, UpdaterPeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
