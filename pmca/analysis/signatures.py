"""Host PE Authenticode coverage metadata, not camera boot-signature proof."""

import struct
from dataclasses import dataclass
from pathlib import Path

from .quarantine import Patch
from .ranges import ByteRange, RangeError, unknown_ranges, validate_ranges
from .static import parse_pe_summary


class SignatureError(ValueError):
    """Raised when host Authenticode coverage cannot be bounded exactly."""


@dataclass(frozen=True, slots=True)
class PeCoverage:
    signed: tuple[ByteRange, ...]
    excluded: tuple[ByteRange, ...]


def pe_authenticode_coverage(path: Path) -> PeCoverage:
    """Return host Authenticode ranges; this says nothing about camera boot checks."""
    path = Path(path)
    summary = parse_pe_summary(path)
    if (
        summary is None
        or not summary["certificate_offset"]
        or not summary["certificate_size"]
    ):
        raise SignatureError("PE does not contain a bounded certificate table")
    file_size = path.stat().st_size
    try:
        with path.open("rb") as stream:
            dos_header = stream.read(64)
            if len(dos_header) != 64:
                raise SignatureError("PE DOS header is truncated")
            pe_offset = struct.unpack_from("<I", dos_header, 0x3C)[0]
            optional_offset = pe_offset + 24
            stream.seek(optional_offset)
            optional_magic = stream.read(2)
            if len(optional_magic) != 2:
                raise SignatureError("PE optional header is truncated")
            magic = struct.unpack("<H", optional_magic)[0]
    except SignatureError:
        raise
    except OSError as error:
        raise SignatureError("PE coverage fields could not be read") from error

    if magic == 0x10B:
        certificate_directory_offset = optional_offset + 96 + (4 * 8)
    elif magic == 0x20B:
        certificate_directory_offset = optional_offset + 112 + (4 * 8)
    else:
        raise SignatureError("PE optional header kind is unsupported")
    exclusions = (
        ByteRange(
            "pe-checksum",
            optional_offset + 64,
            4,
            "Authenticode exclusion",
        ),
        ByteRange(
            "certificate-directory",
            certificate_directory_offset,
            8,
            "Authenticode exclusion",
        ),
        ByteRange(
            "certificate-blob",
            summary["certificate_offset"],
            summary["certificate_size"],
            "Authenticode exclusion",
        ),
    )
    try:
        excluded = validate_ranges(file_size, exclusions)
        complement = unknown_ranges(file_size, excluded)
    except RangeError as error:
        raise SignatureError("Authenticode exclusions are invalid") from error
    signed = tuple(
        ByteRange(
            "authenticode-signed",
            value.offset,
            value.size,
            "computed complement",
        )
        for value in complement
    )
    return PeCoverage(signed=signed, excluded=excluded)


def _intersects(patch: Patch, value: ByteRange) -> bool:
    patch_end = patch.offset + len(patch.replacement)
    range_end = value.offset + value.size
    return patch.offset < range_end and value.offset < patch_end


def classify_patch_impact(
    patches: tuple[Patch, ...],
    coverage: PeCoverage,
) -> tuple[str, ...]:
    """Classify patch overlap with host Authenticode signed/excluded ranges."""
    if not isinstance(patches, tuple) or not isinstance(coverage, PeCoverage):
        raise SignatureError("Patch impact inputs are invalid")
    results = []
    for patch in patches:
        if not isinstance(patch, Patch) or not patch.replacement:
            raise SignatureError("Patch impact requires bounded Patch values")
        signed = any(_intersects(patch, value) for value in coverage.signed)
        excluded = any(_intersects(patch, value) for value in coverage.excluded)
        if signed and excluded:
            results.append("mixed")
        elif signed:
            results.append("signed")
        elif excluded:
            results.append("excluded")
        else:
            results.append("unknown")
    return tuple(results)
