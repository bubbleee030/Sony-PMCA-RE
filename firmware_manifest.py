"""Record and verify allowlisted Sony firmware artifacts."""

import argparse
import sys
from pathlib import Path

from pmca.analysis.manifest import (
    ManifestError,
    load_manifest,
    record_artifact,
    verify_manifest_entry,
    write_manifest,
)
from pmca.analysis.sources import SourceError


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    subparsers = parser.add_subparsers(dest="command", required=True)

    add = subparsers.add_parser(
        "add", help="record an allowlisted artifact", allow_abbrev=False
    )
    add.add_argument("--source", required=True)
    add.add_argument("--file", required=True, type=Path)
    add.add_argument("--artifacts-root", required=True, type=Path)
    add.add_argument("--manifest", required=True, type=Path)
    add.add_argument("--acquired-at", required=True)

    verify = subparsers.add_parser(
        "verify", help="verify a recorded artifact", allow_abbrev=False
    )
    verify.add_argument("--file", required=True, type=Path)
    verify.add_argument("--artifacts-root", required=True, type=Path)
    verify.add_argument("--manifest", required=True, type=Path)
    return parser


def _add(args: argparse.Namespace) -> None:
    if args.manifest.exists():
        manifest = load_manifest(args.manifest)
    else:
        manifest = {"schema_version": 1, "artifacts": []}
    entry = record_artifact(
        args.source,
        args.file,
        args.artifacts_root,
        args.acquired_at,
    )
    write_manifest(
        args.manifest,
        {
            "schema_version": manifest["schema_version"],
            "artifacts": [*manifest["artifacts"], entry],
        },
    )


def _verify(args: argparse.Namespace) -> None:
    manifest = load_manifest(args.manifest)
    entries = [
        entry
        for entry in manifest["artifacts"]
        if entry["filename"] == args.file.name
    ]
    matching_entries = []
    for entry in entries:
        try:
            verify_manifest_entry(entry, args.file, args.artifacts_root)
        except ManifestError:
            continue
        matching_entries.append(entry)
    if len(matching_entries) != 1:
        raise ManifestError(
            "Manifest must contain exactly one matching entry for the file"
        )


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "add":
            _add(args)
        else:
            _verify(args)
    except (ManifestError, SourceError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
