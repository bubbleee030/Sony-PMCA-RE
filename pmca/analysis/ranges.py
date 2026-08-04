"""Validated byte-range ledgers for metadata-only firmware analysis."""

from dataclasses import dataclass


MAX_TEXT_LENGTH = 128


class RangeError(ValueError):
    """Raised when byte ranges cannot safely describe one finite file."""


@dataclass(frozen=True, slots=True)
class ByteRange:
    label: str
    offset: int
    size: int
    evidence: str


def _validate_file_size(file_size: object) -> int:
    if type(file_size) is not int or file_size < 0:
        raise RangeError("File size must be a non-negative integer")
    return file_size


def _validate_text(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= MAX_TEXT_LENGTH
        or not value.isprintable()
    ):
        raise RangeError(f"{name} must be bounded printable text")
    return value


def validate_ranges(
    file_size: int,
    ranges: tuple[ByteRange, ...],
) -> tuple[ByteRange, ...]:
    """Validate, sort, and return non-overlapping ranges within *file_size*."""
    file_size = _validate_file_size(file_size)
    if not isinstance(ranges, tuple):
        raise RangeError("Ranges must be provided as a tuple")

    validated = []
    for value in ranges:
        if not isinstance(value, ByteRange):
            raise RangeError("Every range must be a ByteRange")
        _validate_text(value.label, "Range label")
        _validate_text(value.evidence, "Range evidence")
        if type(value.offset) is not int or value.offset < 0:
            raise RangeError("Range offset must be a non-negative integer")
        if type(value.size) is not int or value.size <= 0:
            raise RangeError("Range size must be a positive integer")
        if value.size > file_size or value.offset > file_size - value.size:
            raise RangeError("Range exceeds the file")
        validated.append(value)

    ordered = tuple(
        sorted(
            validated,
            key=lambda value: (
                value.offset,
                value.size,
                value.label,
                value.evidence,
            ),
        )
    )
    previous_end = 0
    for index, value in enumerate(ordered):
        if index and value.offset < previous_end:
            raise RangeError("Ranges overlap")
        previous_end = value.offset + value.size
    return ordered


def unknown_ranges(
    file_size: int,
    known: tuple[ByteRange, ...],
) -> tuple[ByteRange, ...]:
    """Return the exact complement of validated *known* byte ranges."""
    file_size = _validate_file_size(file_size)
    ordered = validate_ranges(file_size, known)
    unknown = []
    cursor = 0
    for value in ordered:
        if value.offset > cursor:
            unknown.append(
                ByteRange(
                    "unknown",
                    cursor,
                    value.offset - cursor,
                    "computed complement",
                )
            )
        cursor = value.offset + value.size
    if cursor < file_size:
        unknown.append(
            ByteRange(
                "unknown",
                cursor,
                file_size - cursor,
                "computed complement",
            )
        )
    return tuple(unknown)
