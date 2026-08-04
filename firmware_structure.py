"""Map authenticated firmware container boundaries without extracting payloads."""

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from pmca.analysis.dat import (
    CHUNK_HEADER_SIZE,
    DAT_MAGIC,
    MAX_CHUNKS,
    DatError,
    parse_dat_chunks,
)
from pmca.analysis.manifest import (
    ManifestError,
    _validated_artifact_path,
    load_manifest,
    sha256_file,
    verify_manifest_entry,
)
from pmca.analysis.ranges import (
    ByteRange,
    RangeError,
    unknown_ranges,
    validate_ranges,
)
from pmca.analysis.report import ReportError, _resolved_report_path


SCHEMA_VERSION = 1
MAX_ARTIFACT_SIZE = 8 * 1024**4
MAX_SERIALIZED_REPORT_BYTES = 256 * 1024
_REPORT_FIELDS = {
    "schema_version",
    "source_key",
    "filename",
    "size",
    "sha256",
    "format",
    "dat_chunks",
    "unknown_ranges",
}
_CHUNK_FIELDS = {"kind", "header_offset", "payload_offset", "size"}
_UNKNOWN_FIELDS = {"offset", "size"}


class StructureError(ValueError):
    """Raised when a structure report cannot be proven safe and complete."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    subparsers = parser.add_subparsers(dest="command", required=True)
    mapping = subparsers.add_parser(
        "map",
        help="map authenticated container boundaries",
        allow_abbrev=False,
    )
    mapping.add_argument("--source", required=True)
    mapping.add_argument("--file", required=True, type=Path)
    mapping.add_argument("--artifacts-root", required=True, type=Path)
    mapping.add_argument("--manifest", required=True, type=Path)
    mapping.add_argument("--report", required=True, type=Path)
    return parser


def _bounded_int(value: object, minimum: int, maximum: int, name: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise StructureError(f"{name} is outside the supported range")
    return value


def _bounded_text(value: object, name: str, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or not value.isprintable()
    ):
        raise StructureError(f"{name} must be bounded printable text")
    return value


def _validate_digest(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise StructureError("Structure SHA-256 must be lowercase hexadecimal")
    return value


def _known_dat_ranges(file_size: int, chunks: list[dict]) -> tuple[ByteRange, ...]:
    known = [ByteRange("sony-dat-magic", 0, len(DAT_MAGIC), "validated magic")]
    fdat_count = 0
    for index, value in enumerate(chunks):
        if not isinstance(value, dict) or set(value) != _CHUNK_FIELDS:
            raise StructureError("DAT chunk fields do not match schema version 1")
        kind = _bounded_text(value["kind"], "DAT chunk kind", maximum=4)
        if len(kind) != 4 or any(ord(character) > 0x7E for character in kind):
            raise StructureError("DAT chunk kind must be four printable ASCII bytes")
        header_offset = _bounded_int(
            value["header_offset"], 0, file_size, "DAT header offset"
        )
        if header_offset > file_size - CHUNK_HEADER_SIZE:
            raise StructureError("DAT chunk header exceeds the file")
        payload_offset = _bounded_int(
            value["payload_offset"], 0, file_size, "DAT payload offset"
        )
        if payload_offset != header_offset + CHUNK_HEADER_SIZE:
            raise StructureError("DAT payload offset does not follow its header")
        payload_size = _bounded_int(
            value["size"], 0, file_size, "DAT payload size"
        )
        if payload_size > file_size - payload_offset:
            raise StructureError("DAT payload exceeds the file")
        if kind == "FDAT":
            fdat_count += 1

        known.append(
            ByteRange(
                f"chunk-{index}-header",
                header_offset,
                CHUNK_HEADER_SIZE,
                "parsed DAT header",
            )
        )
        if payload_size:
            known.append(
                ByteRange(
                    f"chunk-{index}-payload",
                    payload_offset,
                    payload_size,
                    "declared DAT payload",
                )
            )
    if fdat_count != 1:
        raise StructureError("Structure report must contain exactly one FDAT chunk")
    try:
        return validate_ranges(file_size, tuple(known))
    except RangeError as error:
        raise StructureError("DAT chunk ranges are invalid") from error


def validate_structure_report(report: object) -> dict:
    """Validate a metadata-only DAT structure report and complete range ledger."""
    if not isinstance(report, dict) or set(report) != _REPORT_FIELDS:
        raise StructureError("Structure report fields do not match schema version 1")
    if type(report["schema_version"]) is not int or report["schema_version"] != 1:
        raise StructureError("Unsupported structure report schema version")
    _bounded_text(report["source_key"], "Structure source key")
    filename = _bounded_text(report["filename"], "Structure filename")
    if Path(filename).name != filename or "/" in filename or "\\" in filename:
        raise StructureError("Structure filename must be a basename")
    file_size = _bounded_int(
        report["size"], len(DAT_MAGIC), MAX_ARTIFACT_SIZE, "Artifact size"
    )
    _validate_digest(report["sha256"])
    if report["format"] != "sony-dat":
        raise StructureError("Task 2 structure format must be sony-dat")

    chunks = report["dat_chunks"]
    if not isinstance(chunks, list) or not 1 <= len(chunks) <= MAX_CHUNKS:
        raise StructureError("DAT chunks must be a bounded non-empty list")
    known = _known_dat_ranges(file_size, chunks)
    expected_unknown = unknown_ranges(file_size, known)

    unknown = report["unknown_ranges"]
    if not isinstance(unknown, list) or len(unknown) > len(chunks) * 2 + 2:
        raise StructureError("Unknown ranges must be a bounded list")
    observed_unknown = []
    for value in unknown:
        if not isinstance(value, dict) or set(value) != _UNKNOWN_FIELDS:
            raise StructureError("Unknown range fields do not match schema version 1")
        observed_unknown.append(
            ByteRange(
                "unknown",
                _bounded_int(value["offset"], 0, file_size, "Unknown offset"),
                _bounded_int(value["size"], 1, file_size, "Unknown size"),
                "computed complement",
            )
        )
    if tuple(observed_unknown) != expected_unknown:
        raise StructureError("Unknown ranges are not the exact known-range complement")
    try:
        complete = validate_ranges(file_size, known + tuple(observed_unknown))
        if unknown_ranges(file_size, complete):
            raise StructureError("Structure range ledger does not cover the file")
    except RangeError as error:
        raise StructureError("Structure range ledger is invalid") from error

    try:
        serialized = json.dumps(
            report,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        ) + "\n"
        size = len(serialized.encode("utf-8"))
    except (TypeError, ValueError, UnicodeError) as error:
        raise StructureError("Structure report could not be serialized") from error
    if size > MAX_SERIALIZED_REPORT_BYTES:
        raise StructureError("Structure report exceeds the metadata size limit")
    return report


def build_structure_report(
    entry: dict,
    artifact: Path,
    artifacts_root: Path,
) -> dict:
    """Verify one DAT artifact and build a complete metadata-only range map."""
    try:
        resolved_artifact = _validated_artifact_path(artifact, artifacts_root)
    except ManifestError as error:
        raise StructureError("Firmware path is outside the approved artifact tree") from error
    before_digest = sha256_file(resolved_artifact)
    verify_manifest_entry(entry, resolved_artifact, artifacts_root)
    chunks = parse_dat_chunks(resolved_artifact)
    after_digest = sha256_file(resolved_artifact)
    if before_digest != after_digest or before_digest != entry["sha256"]:
        raise StructureError("Firmware changed or failed its manifest digest")

    file_size = entry["measured_size"]
    chunk_records = [
        {
            "kind": value.kind,
            "header_offset": value.header_offset,
            "payload_offset": value.payload_offset,
            "size": value.size,
        }
        for value in chunks
    ]
    known = _known_dat_ranges(file_size, chunk_records)
    report = {
        "schema_version": SCHEMA_VERSION,
        "source_key": entry["source_key"],
        "filename": entry["filename"],
        "size": file_size,
        "sha256": before_digest,
        "format": "sony-dat",
        "dat_chunks": chunk_records,
        "unknown_ranges": [
            {"offset": value.offset, "size": value.size}
            for value in unknown_ranges(file_size, known)
        ],
    }
    return validate_structure_report(report)


def write_structure_report(
    path: Path,
    report: dict,
    artifacts_root: Path,
) -> None:
    """Atomically write one validated metadata-only structure report."""
    validate_structure_report(report)
    resolved_path = _resolved_report_path(path, artifacts_root)
    serialized = json.dumps(
        report,
        sort_keys=True,
        indent=2,
        allow_nan=False,
    ) + "\n"
    resolved_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=resolved_path.parent,
        prefix=f".{resolved_path.name}.",
        suffix=".tmp",
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, resolved_path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def _entry_for_source(manifest: dict, source_key: str) -> dict:
    entries = [
        entry
        for entry in manifest["artifacts"]
        if entry["source_key"] == source_key
    ]
    if len(entries) != 1:
        raise StructureError("Manifest must contain exactly one requested source")
    return entries[0]


def _map(args: argparse.Namespace) -> None:
    manifest = load_manifest(args.manifest)
    entry = _entry_for_source(manifest, args.source)
    report = build_structure_report(entry, args.file, args.artifacts_root)
    write_structure_report(args.report, report, args.artifacts_root)
    print(
        f"source={report['source_key']} size={report['size']} "
        f"sha256={report['sha256']} format={report['format']} "
        f"chunks={len(report['dat_chunks'])} "
        f"unknown={len(report['unknown_ranges'])} report={args.report}"
    )


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        _map(args)
    except (
        DatError,
        ManifestError,
        OSError,
        RangeError,
        ReportError,
        StructureError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
