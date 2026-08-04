"""Generate bounded metadata reports for verified Sony firmware artifacts."""

import argparse
import sys
from pathlib import Path

from pmca.analysis.manifest import ManifestError, load_manifest
from pmca.analysis.report import (
    ReportError,
    analyze_verified_artifact,
    write_report,
)
from pmca.analysis.sources import SourceError


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser(
        "inspect", help="write a bounded metadata report", allow_abbrev=False
    )
    inspect.add_argument("--source", required=True)
    inspect.add_argument("--file", required=True, type=Path)
    inspect.add_argument("--artifacts-root", required=True, type=Path)
    inspect.add_argument("--manifest", required=True, type=Path)
    inspect.add_argument("--report", required=True, type=Path)
    return parser


def _inspect(args: argparse.Namespace) -> dict:
    manifest = load_manifest(args.manifest)
    entries = [
        entry
        for entry in manifest["artifacts"]
        if entry["source_key"] == args.source
    ]
    if len(entries) != 1:
        raise ReportError("Manifest must contain exactly one requested source")
    report = analyze_verified_artifact(
        entries[0],
        args.file,
        args.artifacts_root,
    )
    write_report(args.report, report, args.artifacts_root)
    return report


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        report = _inspect(args)
    except (ManifestError, ReportError, SourceError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(
        f"source={report['source_key']} size={report['size']} "
        f"sha256={report['sha256']} format={report['format']} "
        f"report={args.report}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
