"""Bounded Sony DAT container boundary parsing without payload extraction."""

import struct
from dataclasses import dataclass
from pathlib import Path


DAT_MAGIC = b"\x89UFU\r\n\x1a\n"
CHUNK_HEADER_SIZE = 8
MAX_CHUNKS = 4096


class DatError(ValueError):
    """Raised when a DAT container boundary cannot be proven safely."""


@dataclass(frozen=True, slots=True)
class DatChunk:
    kind: str
    header_offset: int
    payload_offset: int
    size: int


def _decode_kind(value: bytes) -> str:
    if len(value) != 4 or any(byte < 0x20 or byte > 0x7E for byte in value):
        raise DatError("DAT chunk kind must be four printable ASCII bytes")
    return value.decode("ascii")


def parse_dat_chunks(
    path: Path,
    max_chunks: int = MAX_CHUNKS,
) -> tuple[DatChunk, ...]:
    """Return validated DAT chunk boundaries without reading chunk payloads."""
    if type(max_chunks) is not int or not 1 <= max_chunks <= MAX_CHUNKS:
        raise DatError("DAT chunk limit is outside the supported range")

    path = Path(path)
    if path.is_symlink():
        raise DatError("DAT path must not be a symlink")
    try:
        file_size = path.stat().st_size
    except OSError as error:
        raise DatError("DAT file metadata could not be read") from error
    if file_size < len(DAT_MAGIC):
        raise DatError("DAT header is truncated")

    chunks = []
    fdat_count = 0
    try:
        with path.open("rb") as stream:
            if stream.read(len(DAT_MAGIC)) != DAT_MAGIC:
                raise DatError("DAT magic does not match")

            offset = len(DAT_MAGIC)
            while offset < file_size:
                remaining = file_size - offset
                if remaining < CHUNK_HEADER_SIZE:
                    if fdat_count == 1:
                        break
                    raise DatError("DAT chunk header is truncated")
                if len(chunks) >= max_chunks:
                    raise DatError("DAT chunk limit was exhausted")

                header_offset = offset
                header = stream.read(CHUNK_HEADER_SIZE)
                if len(header) != CHUNK_HEADER_SIZE:
                    raise DatError("DAT chunk header could not be read")
                payload_size, encoded_kind = struct.unpack(">I4s", header)
                kind = _decode_kind(encoded_kind)
                payload_offset = header_offset + CHUNK_HEADER_SIZE
                if payload_size > file_size - payload_offset:
                    raise DatError("DAT chunk payload exceeds the file")

                if kind == "FDAT":
                    fdat_count += 1
                    if fdat_count > 1:
                        raise DatError("DAT container contains duplicate FDAT chunks")
                chunks.append(
                    DatChunk(
                        kind=kind,
                        header_offset=header_offset,
                        payload_offset=payload_offset,
                        size=payload_size,
                    )
                )
                stream.seek(payload_size, 1)
                offset = payload_offset + payload_size
    except DatError:
        raise
    except OSError as error:
        raise DatError("DAT file could not be parsed") from error

    if fdat_count != 1:
        raise DatError("DAT container must contain exactly one FDAT chunk")
    return tuple(chunks)
