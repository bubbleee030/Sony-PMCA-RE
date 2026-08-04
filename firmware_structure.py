"""Map authenticated firmware container boundaries without extracting payloads."""

import argparse
import json
import os
import struct
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
from pmca.analysis.fingerprints import (
    MAGICS,
    FingerprintError,
    scan_magics,
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
from pmca.analysis.static import PE_SECTION_HEADER_SIZE, parse_pe_summary


SCHEMA_VERSION = 1
MAX_ARTIFACT_SIZE = 8 * 1024**4
MAX_STRUCTURE_MAGIC_HITS = 65_536
MAX_SERIALIZED_REPORT_BYTES = 8 * 1024 * 1024
_REPORT_FIELDS = {
    "schema_version",
    "source_key",
    "filename",
    "size",
    "sha256",
    "format",
    "dat_chunks",
    "unknown_ranges",
    "pe",
    "scan_ranges",
    "magic_hits",
}
_CHUNK_FIELDS = {"kind", "header_offset", "payload_offset", "size"}
_UNKNOWN_FIELDS = {"offset", "size"}
_SCAN_FIELDS = {"label", "offset", "size"}
_HIT_FIELDS = {"label", "offset"}
_PE_FIELDS = {
    "machine",
    "section_count",
    "optional_header_kind",
    "pe_header_offset",
    "pe_header_size",
    "section_table_offset",
    "section_table_size",
    "certificate_offset",
    "certificate_size",
    "overlay_offset",
    "overlay_size",
}


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


def parse_pe_layout(path: Path) -> dict:
    """Return validated numeric PE header, table, certificate, and overlay ranges."""
    path = Path(path)
    summary = parse_pe_summary(path)
    if summary is None or summary["overlay_offset"] is None:
        raise StructureError("Updater is not a supported PE with an overlay")
    file_size = path.stat().st_size
    try:
        with path.open("rb") as stream:
            dos_header = stream.read(64)
            if len(dos_header) != 64:
                raise StructureError("PE DOS header is truncated")
            pe_offset = struct.unpack_from("<I", dos_header, 0x3C)[0]
            stream.seek(pe_offset)
            pe_header = stream.read(24)
            if len(pe_header) != 24 or pe_header[:4] != b"PE\0\0":
                raise StructureError("PE header could not be revalidated")
            optional_header_size = struct.unpack_from("<H", pe_header, 20)[0]
    except StructureError:
        raise
    except OSError as error:
        raise StructureError("PE layout could not be read") from error

    pe_header_size = 24 + optional_header_size
    section_table_offset = pe_offset + pe_header_size
    section_table_size = summary["section_count"] * PE_SECTION_HEADER_SIZE
    overlay_offset = summary["overlay_offset"]
    return {
        "machine": summary["machine"],
        "section_count": summary["section_count"],
        "optional_header_kind": summary["optional_header_kind"],
        "pe_header_offset": pe_offset,
        "pe_header_size": pe_header_size,
        "section_table_offset": section_table_offset,
        "section_table_size": section_table_size,
        "certificate_offset": summary["certificate_offset"],
        "certificate_size": summary["certificate_size"],
        "overlay_offset": overlay_offset,
        "overlay_size": file_size - overlay_offset,
    }


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


def _validate_dat_section(
    file_size: int,
    chunks: object,
    unknown: object,
) -> ByteRange:
    if not isinstance(chunks, list) or not 1 <= len(chunks) <= MAX_CHUNKS:
        raise StructureError("DAT chunks must be a bounded non-empty list")
    known = _known_dat_ranges(file_size, chunks)
    expected_unknown = unknown_ranges(file_size, known)
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

    fdat = next(value for value in chunks if value["kind"] == "FDAT")
    if fdat["size"] <= 0:
        raise StructureError("FDAT payload must be non-empty for bounded scanning")
    return ByteRange(
        "fdat-payload",
        fdat["payload_offset"],
        fdat["size"],
        "validated FDAT payload",
    )


def _validate_pe_section(value: object, file_size: int) -> ByteRange:
    if not isinstance(value, dict) or set(value) != _PE_FIELDS:
        raise StructureError("PE layout fields do not match schema version 1")
    _bounded_int(value["machine"], 0, 65_535, "PE machine")
    _bounded_int(value["section_count"], 1, 96, "PE section count")
    if value["optional_header_kind"] not in {"PE32", "PE32+"}:
        raise StructureError("PE optional header kind is unsupported")

    ranges = (
        ByteRange(
            "pe-header",
            _bounded_int(value["pe_header_offset"], 0, file_size, "PE header offset"),
            _bounded_int(value["pe_header_size"], 1, file_size, "PE header size"),
            "validated PE header",
        ),
        ByteRange(
            "section-table",
            _bounded_int(
                value["section_table_offset"], 0, file_size, "Section table offset"
            ),
            _bounded_int(
                value["section_table_size"], 1, file_size, "Section table size"
            ),
            "validated section table",
        ),
        ByteRange(
            "certificate",
            _bounded_int(
                value["certificate_offset"], 0, file_size, "Certificate offset"
            ),
            _bounded_int(value["certificate_size"], 1, file_size, "Certificate size"),
            "validated certificate table",
        ),
        ByteRange(
            "pe-overlay",
            _bounded_int(value["overlay_offset"], 0, file_size, "Overlay offset"),
            _bounded_int(value["overlay_size"], 1, file_size, "Overlay size"),
            "validated PE overlay",
        ),
    )
    for value_range in ranges:
        try:
            validate_ranges(file_size, (value_range,))
        except RangeError as error:
            raise StructureError(f"{value_range.label} exceeds the updater") from error
    pe_header, section_table, certificate, overlay = ranges
    if section_table.offset != pe_header.offset + pe_header.size:
        raise StructureError("Section table does not follow the PE header")
    if overlay.offset + overlay.size != file_size:
        raise StructureError("PE overlay must extend exactly to EOF")
    if certificate.offset < overlay.offset:
        raise StructureError("Certificate table is outside the PE overlay")
    return overlay


def _validate_scan_ranges(
    value: object,
    file_size: int,
    expected: tuple[ByteRange, ...],
) -> tuple[ByteRange, ...]:
    if not isinstance(value, list) or len(value) != len(expected):
        raise StructureError("Scan ranges do not match the required narrow scope")
    observed = []
    for item in value:
        if not isinstance(item, dict) or set(item) != _SCAN_FIELDS:
            raise StructureError("Scan range fields do not match schema version 1")
        observed.append(
            ByteRange(
                _bounded_text(item["label"], "Scan range label"),
                _bounded_int(item["offset"], 0, file_size, "Scan range offset"),
                _bounded_int(item["size"], 1, file_size, "Scan range size"),
                expected[len(observed)].evidence,
            )
        )
    try:
        observed = validate_ranges(file_size, tuple(observed))
    except RangeError as error:
        raise StructureError("Scan ranges are invalid") from error
    if observed != expected:
        raise StructureError("Scan ranges are not the narrowest approved ranges")
    return observed


def _validate_magic_hits(
    value: object,
    file_size: int,
    scan_ranges: tuple[ByteRange, ...],
) -> None:
    if not isinstance(value, list) or len(value) > MAX_STRUCTURE_MAGIC_HITS:
        raise StructureError("Magic hits must be a bounded complete list")
    specs = {spec.label: spec for spec in MAGICS}
    observed = []
    seen = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != _HIT_FIELDS:
            raise StructureError("Magic hit fields do not match schema version 1")
        label = item["label"]
        if label not in specs:
            raise StructureError("Magic hit label is not allowlisted")
        offset = _bounded_int(item["offset"], 0, file_size - 1, "Magic hit offset")
        identity = (label, offset)
        if identity in seen:
            raise StructureError("Magic hits must be unique")
        spec = specs[label]
        if not any(
            len(spec.value) <= approved.size
            and approved.offset <= offset
            and offset <= approved.offset + approved.size - len(spec.value)
            for approved in scan_ranges
        ):
            raise StructureError("Magic hit falls outside the approved scan ranges")
        if spec.alignment is not None and offset % spec.alignment:
            raise StructureError("Magic hit violates its alignment requirement")
        seen.add(identity)
        observed.append(identity)
    if observed != sorted(observed, key=lambda item: (item[1], item[0])):
        raise StructureError("Magic hits must be ordered by offset and label")


def validate_structure_report(report: object) -> dict:
    """Validate a metadata-only DAT or PE structure and fingerprint report."""
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

    artifact_format = report["format"]
    if artifact_format == "sony-dat":
        if report["pe"] is not None:
            raise StructureError("DAT structure report must not contain PE metadata")
        required_scan = _validate_dat_section(
            file_size,
            report["dat_chunks"],
            report["unknown_ranges"],
        )
    elif artifact_format == "pe-updater":
        if report["dat_chunks"] != [] or report["unknown_ranges"] != []:
            raise StructureError("PE structure report must not contain DAT ranges")
        required_scan = _validate_pe_section(report["pe"], file_size)
    else:
        raise StructureError("Structure format is unsupported")

    scan_ranges = _validate_scan_ranges(
        report["scan_ranges"],
        file_size,
        (required_scan,),
    )
    _validate_magic_hits(report["magic_hits"], file_size, scan_ranges)

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
    """Verify one firmware artifact and map only approved metadata ranges."""
    try:
        resolved_artifact = _validated_artifact_path(artifact, artifacts_root)
    except ManifestError as error:
        raise StructureError("Firmware path is outside the approved artifact tree") from error
    before_digest = sha256_file(resolved_artifact)
    verify_manifest_entry(entry, resolved_artifact, artifacts_root)
    file_size = entry["measured_size"]

    pe_summary = parse_pe_summary(resolved_artifact)
    if pe_summary is not None:
        pe = parse_pe_layout(resolved_artifact)
        artifact_format = "pe-updater"
        chunk_records = []
        unknown_records = []
        scan_ranges = (
            ByteRange(
                "pe-overlay",
                pe["overlay_offset"],
                pe["overlay_size"],
                "validated PE overlay",
            ),
        )
    else:
        chunks = parse_dat_chunks(resolved_artifact)
        artifact_format = "sony-dat"
        pe = None
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
        unknown_records = [
            {"offset": value.offset, "size": value.size}
            for value in unknown_ranges(file_size, known)
        ]
        fdat = next(value for value in chunks if value.kind == "FDAT")
        scan_ranges = (
            ByteRange(
                "fdat-payload",
                fdat.payload_offset,
                fdat.size,
                "validated FDAT payload",
            ),
        )

    hits = scan_magics(
        resolved_artifact,
        scan_ranges,
        MAGICS,
        max_hits=MAX_STRUCTURE_MAGIC_HITS,
    )
    after_digest = sha256_file(resolved_artifact)
    if before_digest != after_digest or before_digest != entry["sha256"]:
        raise StructureError("Firmware changed or failed its manifest digest")

    report = {
        "schema_version": SCHEMA_VERSION,
        "source_key": entry["source_key"],
        "filename": entry["filename"],
        "size": file_size,
        "sha256": before_digest,
        "format": artifact_format,
        "dat_chunks": chunk_records,
        "unknown_ranges": unknown_records,
        "pe": pe,
        "scan_ranges": [
            {"label": value.label, "offset": value.offset, "size": value.size}
            for value in scan_ranges
        ],
        "magic_hits": [
            {"label": value.label, "offset": value.offset}
            for value in hits
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
        FingerprintError,
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
