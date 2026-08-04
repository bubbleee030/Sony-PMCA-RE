"""Bounded, read-only metadata inspection for approved firmware artifacts."""

import math
import struct
from collections import Counter
from pathlib import Path


DEFAULT_WINDOW_SIZE = 1_048_576
MAX_PE_OFFSET = 16 * 1024 * 1024
MAX_PE_SECTIONS = 96
PE_SECTION_HEADER_SIZE = 40
TOKEN_CHUNK_SIZE = 1_048_576

ALLOWED_TOKENS = (
    b"ILCE-6400",
    b"ILCE6400",
    b"ILCE-6700",
    b"ILCE6700",
    b"2.00",
    b"BODYDATA.DAT",
    b"Update_ILCE6400V200",
)


def shannon_entropy(block: bytes) -> float:
    """Return the Shannon entropy, in bits per byte, for one bounded block."""
    if not block:
        return 0.0
    block_length = len(block)
    return -sum(
        (count / block_length) * math.log2(count / block_length)
        for count in Counter(block).values()
    )


def _bounded_range(offset: int, size: int, file_size: int) -> bool:
    return offset >= 0 and size >= 0 and offset <= file_size - size


def parse_pe_summary(path: Path) -> dict | None:
    """Return bounded PE metadata, or ``None`` for unsupported/malformed input."""
    file_size = path.stat().st_size
    if file_size < 64:
        return None

    with path.open("rb") as stream:
        dos_header = stream.read(64)
        if len(dos_header) != 64 or dos_header[:2] != b"MZ":
            return None

        pe_offset = struct.unpack_from("<I", dos_header, 0x3C)[0]
        if pe_offset >= MAX_PE_OFFSET or not _bounded_range(pe_offset, 24, file_size):
            return None

        stream.seek(pe_offset)
        pe_header = stream.read(24)
        if len(pe_header) != 24 or pe_header[:4] != b"PE\0\0":
            return None

        machine, section_count = struct.unpack_from("<HH", pe_header, 4)
        optional_header_size = struct.unpack_from("<H", pe_header, 20)[0]
        if not 1 <= section_count <= MAX_PE_SECTIONS:
            return None

        optional_offset = pe_offset + 24
        section_table_offset = optional_offset + optional_header_size
        section_table_size = section_count * PE_SECTION_HEADER_SIZE
        if not _bounded_range(optional_offset, optional_header_size, file_size):
            return None
        if not _bounded_range(section_table_offset, section_table_size, file_size):
            return None

        stream.seek(optional_offset)
        optional_header = stream.read(optional_header_size)
        if len(optional_header) != optional_header_size or optional_header_size < 64:
            return None

        magic = struct.unpack_from("<H", optional_header, 0)[0]
        if magic == 0x10B:
            optional_header_kind = "PE32"
            directory_count_offset = 92
            directory_offset = 96
        elif magic == 0x20B:
            optional_header_kind = "PE32+"
            directory_count_offset = 108
            directory_offset = 112
        else:
            return None

        if optional_header_size < directory_count_offset + 4:
            return None
        size_of_headers = struct.unpack_from("<I", optional_header, 60)[0]
        if not section_table_offset + section_table_size <= size_of_headers <= file_size:
            return None

        directory_count = struct.unpack_from(
            "<I", optional_header, directory_count_offset
        )[0]
        if directory_offset + (directory_count * 8) > optional_header_size:
            return None
        certificate_offset = 0
        certificate_size = 0
        if directory_count > 4:
            certificate_entry_offset = directory_offset + (4 * 8)
            if optional_header_size < certificate_entry_offset + 8:
                return None
            certificate_offset, certificate_size = struct.unpack_from(
                "<II", optional_header, certificate_entry_offset
            )
            if bool(certificate_offset) != bool(certificate_size):
                return None
            if certificate_size and not _bounded_range(
                certificate_offset, certificate_size, file_size
            ):
                return None

        image_end = size_of_headers
        stream.seek(section_table_offset)
        for _ in range(section_count):
            section_header = stream.read(PE_SECTION_HEADER_SIZE)
            if len(section_header) != PE_SECTION_HEADER_SIZE:
                return None
            raw_size, raw_offset = struct.unpack_from("<II", section_header, 16)
            if raw_size:
                if not _bounded_range(raw_offset, raw_size, file_size):
                    return None
                image_end = max(image_end, raw_offset + raw_size)

    return {
        "machine": machine,
        "section_count": section_count,
        "optional_header_kind": optional_header_kind,
        "certificate_offset": certificate_offset,
        "certificate_size": certificate_size,
        "overlay_offset": image_end if image_end < file_size else None,
    }


def scan_entropy(path: Path, window_size: int = DEFAULT_WINDOW_SIZE) -> dict:
    """Measure per-window entropy without retaining input bytes."""
    if window_size <= 0:
        raise ValueError("window_size must be positive")

    windows = []
    offset = 0
    with path.open("rb") as stream:
        while True:
            block = stream.read(window_size)
            if not block:
                break
            windows.append(
                {
                    "offset": offset,
                    "size": len(block),
                    "entropy": round(shannon_entropy(block), 6),
                }
            )
            offset += len(block)

    return {
        "window_size": window_size,
        "window_count": len(windows),
        "windows": windows,
    }


def scan_allowlisted_tokens(
    path: Path, tokens: tuple[bytes, ...], max_offsets: int = 8
) -> list[dict]:
    """Count allowlisted ASCII tokens while retaining only bounded offsets."""
    if max_offsets < 0:
        raise ValueError("max_offsets must not be negative")
    if any(token not in ALLOWED_TOKENS for token in tokens):
        raise ValueError("tokens must come from the fixed allowlist")
    if not tokens:
        return []

    counts = {token: 0 for token in tokens}
    offsets = {token: [] for token in tokens}
    max_token_length = max(len(token) for token in tokens)
    carry = b""
    file_offset = 0

    with path.open("rb") as stream:
        while True:
            chunk = stream.read(TOKEN_CHUNK_SIZE)
            if not chunk:
                break
            combined = carry + chunk
            combined_offset = file_offset - len(carry)
            for token in tokens:
                search_offset = 0
                while True:
                    match_offset = combined.find(token, search_offset)
                    if match_offset < 0:
                        break
                    if match_offset + len(token) > len(carry):
                        counts[token] += 1
                        if len(offsets[token]) < max_offsets:
                            offsets[token].append(combined_offset + match_offset)
                    search_offset = match_offset + 1

            carry_size = max_token_length - 1
            carry = combined[-carry_size:] if carry_size else b""
            file_offset += len(chunk)

    return [
        {
            "token": token.decode("ascii"),
            "count": counts[token],
            "offsets": offsets[token],
        }
        for token in tokens
        if counts[token]
    ]


def inspect_artifact(path: Path, source_key: str) -> dict:
    """Return deterministic metadata only for one approved artifact path."""
    pe_summary = parse_pe_summary(path)
    return {
        "source_key": source_key,
        "format": "pe" if pe_summary is not None else "opaque-dat",
        "pe": pe_summary,
        "entropy": scan_entropy(path),
        "token_hits": scan_allowlisted_tokens(path, ALLOWED_TOKENS),
    }
