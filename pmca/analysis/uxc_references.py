"""Find bounded exact references in pinned Sony UXC resource blobs."""

from __future__ import annotations

import unicodedata


MAX_UXC_SIZE = 2 * 1024 * 1024
MAX_NEEDLES = 128
MAX_NAME_CHARS = 512
MAX_REFERENCES = 10_000


class UxcReferenceError(ValueError):
    """Raised when a UXC scan request is malformed or exceeds a fixed cap."""


def _validate_names(names: object) -> tuple[str, ...]:
    if not isinstance(names, tuple) or len(names) > MAX_NEEDLES:
        raise UxcReferenceError("UXC names must be a bounded tuple")
    if any(not isinstance(name, str) for name in names):
        raise UxcReferenceError("UXC name is invalid")
    if len(set(names)) != len(names):
        raise UxcReferenceError("UXC names must be unique")
    for name in names:
        if (
            not name
            or len(name) > MAX_NAME_CHARS
            or any(unicodedata.category(character).startswith("C") for character in name)
        ):
            raise UxcReferenceError("UXC name is invalid")
    return names


def _validate_class_ids(class_ids: object) -> tuple[int, ...]:
    if not isinstance(class_ids, tuple) or len(class_ids) > MAX_NEEDLES:
        raise UxcReferenceError("UXC class ids must be a bounded tuple")
    if any(type(class_id) is not int for class_id in class_ids):
        raise UxcReferenceError("UXC class id is invalid")
    if len(set(class_ids)) != len(class_ids):
        raise UxcReferenceError("UXC class ids must be unique")
    for class_id in class_ids:
        if not 0 <= class_id <= 0xFFFF_FFFF:
            raise UxcReferenceError("UXC class id is invalid")
    return class_ids


def _is_identifier_byte(value: int) -> bool:
    return (
        value >= 0x80
        or value == 0x5F
        or 0x30 <= value <= 0x39
        or 0x41 <= value <= 0x5A
        or 0x61 <= value <= 0x7A
    )


def _has_exact_boundaries(blob: bytes, offset: int, length: int) -> bool:
    before = None if offset == 0 else blob[offset - 1]
    after_offset = offset + length
    after = None if after_offset == len(blob) else blob[after_offset]
    return (before is None or not _is_identifier_byte(before)) and (
        after is None or not _is_identifier_byte(after)
    )


def _append_reference(results: list[dict], reference: dict) -> None:
    if len(results) >= MAX_REFERENCES:
        raise UxcReferenceError("UXC reference count exceeds the fixed cap")
    results.append(reference)


def scan_exact_references(
    blob: bytes,
    names: tuple[str, ...],
    class_ids: tuple[int, ...],
) -> list[dict]:
    """Return exact name and little-endian class-ID offsets without semantics."""

    if type(blob) is not bytes:
        raise UxcReferenceError("UXC input must be immutable bytes")
    if len(blob) > MAX_UXC_SIZE:
        raise UxcReferenceError("UXC input exceeds size cap")
    names = _validate_names(names)
    class_ids = _validate_class_ids(class_ids)

    results = []
    for name in names:
        needle = name.encode("utf-8")
        start = 0
        while True:
            offset = blob.find(needle, start)
            if offset < 0:
                break
            if _has_exact_boundaries(blob, offset, len(needle)):
                _append_reference(
                    results,
                    {
                        "kind": "name",
                        "value": name,
                        "offset": offset,
                        "semantic": "reference-only",
                    },
                )
            start = offset + 1

    for class_id in class_ids:
        needle = class_id.to_bytes(4, "little")
        start = 0
        while True:
            offset = blob.find(needle, start)
            if offset < 0:
                break
            _append_reference(
                results,
                {
                    "kind": "class-id",
                    "value": f"0x{class_id:08x}",
                    "offset": offset,
                    "semantic": "reference-only",
                },
            )
            start = offset + 1

    return sorted(
        results, key=lambda item: (item["offset"], item["kind"], item["value"])
    )
