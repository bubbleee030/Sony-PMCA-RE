"""Bounded streaming scans for fixed firmware structure magics."""

from dataclasses import dataclass
from pathlib import Path

from .ranges import ByteRange, RangeError, validate_ranges


SCAN_CHUNK_SIZE = 1_048_576
MAX_MAGIC_LENGTH = 64
MAX_HITS = 65_536


class FingerprintError(ValueError):
    """Raised when a bounded magic scan cannot remain complete and safe."""


@dataclass(frozen=True, slots=True)
class MagicSpec:
    label: str
    value: bytes
    alignment: int | None


@dataclass(frozen=True, slots=True)
class MagicHit:
    label: str
    offset: int


MAGICS = (
    MagicSpec("sony-dat", b"\x89UFU\r\n\x1a\n", None),
    MagicSpec("pe", b"MZ", None),
    MagicSpec("elf", b"\x7fELF", None),
    MagicSpec("squashfs-le", b"hsqs", 4),
    MagicSpec("squashfs-be", b"sqsh", 4),
    MagicSpec("gzip", b"\x1f\x8b\x08", None),
    MagicSpec("xz", b"\xfd7zXZ\x00", None),
    MagicSpec("zip", b"PK\x03\x04", None),
    MagicSpec("cpio-newc", b"070701", None),
)


def _validate_specs(specs: object) -> tuple[MagicSpec, ...]:
    if not isinstance(specs, tuple):
        raise FingerprintError("Magic specifications must be a tuple")
    labels = set()
    signatures = set()
    for spec in specs:
        if not isinstance(spec, MagicSpec):
            raise FingerprintError("Every magic specification must be a MagicSpec")
        if (
            not isinstance(spec.label, str)
            or not 1 <= len(spec.label) <= 64
            or not spec.label.isprintable()
            or spec.label in labels
        ):
            raise FingerprintError("Magic labels must be unique bounded text")
        if (
            not isinstance(spec.value, bytes)
            or not 1 <= len(spec.value) <= MAX_MAGIC_LENGTH
            or spec.value in signatures
        ):
            raise FingerprintError("Magic values must be unique bounded bytes")
        if spec.alignment is not None and (
            type(spec.alignment) is not int
            or not 1 <= spec.alignment <= SCAN_CHUNK_SIZE
        ):
            raise FingerprintError("Magic alignment is outside the supported range")
        labels.add(spec.label)
        signatures.add(spec.value)
    return specs


def scan_magics(
    path: Path,
    ranges: tuple[ByteRange, ...],
    specs: tuple[MagicSpec, ...],
    max_hits: int = 64,
) -> tuple[MagicHit, ...]:
    """Scan only validated ranges and return a complete bounded hit list."""
    if type(max_hits) is not int or not 1 <= max_hits <= MAX_HITS:
        raise FingerprintError("Magic hit limit is outside the supported range")
    path = Path(path)
    if path.is_symlink():
        raise FingerprintError("Magic scan path must not be a symlink")
    try:
        file_size = path.stat().st_size
        approved = validate_ranges(file_size, ranges)
    except (OSError, RangeError) as error:
        raise FingerprintError("Magic scan ranges could not be validated") from error
    specs = _validate_specs(specs)
    if not specs or not approved:
        return ()

    maximum_length = max(len(spec.value) for spec in specs)
    hits = []
    try:
        with path.open("rb") as stream:
            for approved_range in approved:
                stream.seek(approved_range.offset)
                remaining = approved_range.size
                file_offset = approved_range.offset
                carry = b""
                while remaining:
                    requested = min(SCAN_CHUNK_SIZE, remaining)
                    block = stream.read(requested)
                    if len(block) != requested:
                        raise FingerprintError("Magic scan input ended unexpectedly")
                    combined = carry + block
                    combined_offset = file_offset - len(carry)
                    for spec in specs:
                        search_offset = 0
                        while True:
                            match_offset = combined.find(spec.value, search_offset)
                            if match_offset < 0:
                                break
                            absolute_offset = combined_offset + match_offset
                            extends_past_carry = (
                                match_offset + len(spec.value) > len(carry)
                            )
                            aligned = (
                                spec.alignment is None
                                or absolute_offset % spec.alignment == 0
                            )
                            if extends_past_carry and aligned:
                                hits.append(MagicHit(spec.label, absolute_offset))
                                if len(hits) > max_hits:
                                    raise FingerprintError(
                                        "Magic hit limit was exhausted"
                                    )
                            search_offset = match_offset + 1

                    carry_size = maximum_length - 1
                    carry = combined[-carry_size:] if carry_size else b""
                    file_offset += len(block)
                    remaining -= len(block)
    except FingerprintError:
        raise
    except OSError as error:
        raise FingerprintError("Magic scan input could not be read") from error

    return tuple(sorted(hits, key=lambda hit: (hit.offset, hit.label)))
