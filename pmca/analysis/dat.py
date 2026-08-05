"""Bounded Sony DAT container discovery and exact ignored-artifact extraction."""

import hashlib
import struct
import zlib
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


@dataclass(frozen=True, slots=True)
class DatContainer:
    offset: int
    size: int
    end: int
    crc32: int
    chunks: tuple[DatChunk, ...]


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


def _crc32_region(stream, offset: int, size: int) -> int:
    stream.seek(offset)
    remaining = size
    checksum = 0
    while remaining:
        data = stream.read(min(1024 * 1024, remaining))
        if not data:
            raise DatError("DAT checksum region is truncated")
        checksum = zlib.crc32(data, checksum)
        remaining -= len(data)
    return checksum


def locate_dat_container(
    path: Path,
    offset: int,
    max_chunks: int = MAX_CHUNKS,
) -> DatContainer:
    """Locate one terminated DAT at an exact offset and verify its container CRC."""
    if type(offset) is not int or offset < 0:
        raise DatError("DAT offset is invalid")
    if type(max_chunks) is not int or not 1 <= max_chunks <= MAX_CHUNKS:
        raise DatError("DAT chunk limit is outside the supported range")

    path = Path(path)
    if path.is_symlink():
        raise DatError("DAT path must not be a symlink")
    try:
        file_size = path.stat().st_size
    except OSError as error:
        raise DatError("DAT file metadata could not be read") from error
    if offset + len(DAT_MAGIC) > file_size:
        raise DatError("DAT header is truncated")

    chunks = []
    try:
        with path.open("rb") as stream:
            stream.seek(offset)
            if stream.read(len(DAT_MAGIC)) != DAT_MAGIC:
                raise DatError("DAT magic does not match")
            position = offset + len(DAT_MAGIC)
            stored_crc = None
            dend_header_offset = None
            while len(chunks) < max_chunks:
                if file_size - position < CHUNK_HEADER_SIZE:
                    raise DatError("DAT terminator is missing")
                stream.seek(position)
                header = stream.read(CHUNK_HEADER_SIZE)
                payload_size, encoded_kind = struct.unpack(">I4s", header)
                kind = _decode_kind(encoded_kind)
                payload_offset = position + CHUNK_HEADER_SIZE
                if payload_size > file_size - payload_offset:
                    raise DatError("DAT chunk payload exceeds the file")
                chunks.append(
                    DatChunk(
                        kind=kind,
                        header_offset=position,
                        payload_offset=payload_offset,
                        size=payload_size,
                    )
                )
                position = payload_offset + payload_size
                if kind == "DEND":
                    if payload_size != 4:
                        raise DatError("DAT terminator size is invalid")
                    stream.seek(payload_offset)
                    stored_crc = struct.unpack(">I", stream.read(4))[0]
                    dend_header_offset = chunks[-1].header_offset
                    break
            else:
                raise DatError("DAT chunk limit was exhausted")

            kinds = [chunk.kind for chunk in chunks]
            if kinds != ["DATV", "PROV", "UDID", "FDAT", "DEND"]:
                raise DatError("DAT chunk sequence is invalid")
            calculated_crc = _crc32_region(
                stream,
                offset,
                dend_header_offset - offset,
            )
            if calculated_crc != stored_crc:
                raise DatError("DAT container checksum does not match")
    except DatError:
        raise
    except (OSError, struct.error) as error:
        raise DatError("DAT container could not be located") from error

    return DatContainer(
        offset=offset,
        size=position - offset,
        end=position,
        crc32=stored_crc,
        chunks=tuple(chunks),
    )


def extract_dat_container(
    source_path: Path,
    output_path: Path,
    *,
    offset: int,
    artifacts_root: Path,
) -> dict:
    """Copy one verified DAT slice to a new file below an explicit artifact root."""
    source_path = Path(source_path)
    output_path = Path(output_path)
    artifacts_root = Path(artifacts_root)
    container = locate_dat_container(source_path, offset)

    if (
        not artifacts_root.exists()
        or not artifacts_root.is_dir()
        or artifacts_root.is_symlink()
        or not output_path.parent.exists()
        or not output_path.parent.is_dir()
        or output_path.parent.is_symlink()
    ):
        raise DatError("Artifact output directory is invalid")
    try:
        resolved_root = artifacts_root.resolve(strict=True)
        resolved_output = output_path.resolve(strict=False)
    except OSError as error:
        raise DatError("Artifact output path could not be resolved") from error
    if not resolved_output.is_relative_to(resolved_root):
        raise DatError("DAT output must stay below the artifact root")
    if output_path.exists() or output_path.is_symlink():
        raise DatError("DAT output already exists")

    digest = hashlib.sha256()
    try:
        with source_path.open("rb") as source, output_path.open("xb") as output:
            source.seek(container.offset)
            remaining = container.size
            while remaining:
                data = source.read(min(1024 * 1024, remaining))
                if not data:
                    raise DatError("DAT extraction source is truncated")
                output.write(data)
                digest.update(data)
                remaining -= len(data)
        extracted = locate_dat_container(output_path, 0)
        if extracted.size != container.size or output_path.stat().st_size != container.size:
            raise DatError("Extracted DAT size does not match")
    except Exception:
        if output_path.exists() and output_path.is_file() and not output_path.is_symlink():
            output_path.unlink()
        raise

    return {
        "source_offset": container.offset,
        "size": container.size,
        "sha256": digest.hexdigest(),
        "crc32": f"{container.crc32:08x}",
        "chunk_kinds": [chunk.kind for chunk in container.chunks],
    }
