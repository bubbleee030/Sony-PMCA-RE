"""Fail-closed inspection and bounded CAB extraction for Sony Packman wrappers."""

import copy
import hashlib
import re
import struct
from pathlib import Path

from .updater_pe import UpdaterPeError, inspect_updater_pe


class PackmanError(ValueError):
    """Raised when a Packman container boundary is unsupported or ambiguous."""


MARKER = "!!!53AAED7C-68E7-413C-A5FD-D9F76477D66A"
CAB_NAME = "E8FF0748-2339-49f9-9A79-824D7561736C.cab"
SETTINGS_NAME = "Settings.ini"
MAX_NAME_CHARS = 128
MAX_SETTINGS_SIZE = 1024 * 1024
MAX_CAB_SIZE = 8 * 1024**3
COPY_CHUNK_SIZE = 8 * 1024 * 1024
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_TOP_FIELDS = {"schema_version", "file", "pe", "container", "certificate"}
_CONTAINER_FIELDS = {
    "offset",
    "header_end",
    "payload_end",
    "padding_size",
    "format_version",
    "marker",
    "entries",
}
_ENTRY_FIELDS = {"name", "offset", "size", "transformation"}


def _read_at(stream, offset: int, size: int, end: int, label: str) -> bytes:
    if (
        type(offset) is not int
        or type(size) is not int
        or offset < 0
        or size < 0
        or offset > end
        or size > end - offset
    ):
        raise PackmanError(f"{label} is outside the updater")
    try:
        stream.seek(offset)
        value = stream.read(size)
    except OSError as error:
        raise PackmanError(f"{label} could not be read") from error
    if len(value) != size:
        raise PackmanError(f"{label} is truncated")
    return value


def _decode_utf16(value: bytes, label: str) -> str:
    try:
        decoded = value.decode("utf-16le")
    except UnicodeDecodeError as error:
        raise PackmanError(f"{label} is not valid UTF-16LE") from error
    if not decoded or not decoded.isprintable():
        raise PackmanError(f"{label} is not printable")
    return decoded


def _cab_header(decoded: bytes, expected_size: int) -> None:
    if len(decoded) < 36:
        raise PackmanError("Decoded CAB header is truncated")
    if decoded[:4] != b"MSCF":
        raise PackmanError("Decoded CAB magic does not match")
    reserved1, cabinet_size, reserved2, files_offset, reserved3 = struct.unpack_from(
        "<IIIII", decoded, 4
    )
    minor, major = decoded[24:26]
    folders, files = struct.unpack_from("<HH", decoded, 26)
    if reserved1 or reserved2 or reserved3:
        raise PackmanError("Decoded CAB reserved fields are nonzero")
    if cabinet_size != expected_size:
        raise PackmanError("Decoded CAB size contradicts the Packman entry")
    if minor != 3 or major != 1 or not folders or not files:
        raise PackmanError("Decoded CAB version or counts are unsupported")
    if files_offset < 36 or files_offset >= expected_size:
        raise PackmanError("Decoded CAB file table is outside the entry")


def _parse(path: Path, pe_report: dict) -> dict:
    file_size = pe_report["file"]["size"]
    overlay = pe_report["overlay"]
    certificate = pe_report["certificate"]
    if overlay is None or certificate is None:
        raise PackmanError("Packman updater requires an overlay and certificate")
    start = overlay["offset"]
    certificate_offset = certificate["offset"]
    if certificate_offset <= start:
        raise PackmanError("Packman certificate does not follow the container")

    try:
        with path.open("rb") as stream:
            fixed = _read_at(stream, start, 36, certificate_offset, "Packman header")
            _, _, version, reserved, group_count, marker_chars, entry_count = struct.unpack(
                "<QQIIIII", fixed
            )
            if version != 2 or reserved != 0 or group_count != 1:
                raise PackmanError("Packman header version or grouping is unsupported")
            if marker_chars != len(MARKER) or entry_count != 2:
                raise PackmanError("Packman marker length or entry count is unsupported")

            position = start + len(fixed)
            marker = _decode_utf16(
                _read_at(
                    stream,
                    position,
                    marker_chars * 2,
                    certificate_offset,
                    "Packman marker",
                ),
                "Packman marker",
            )
            if marker != MARKER:
                raise PackmanError("Packman marker is unknown")
            position += marker_chars * 2

            headers = []
            for _ in range(entry_count):
                raw = _read_at(
                    stream, position, 8, certificate_offset, "Packman entry header"
                )
                name_chars, size = struct.unpack("<II", raw)
                position += 8
                if not 1 <= name_chars <= MAX_NAME_CHARS or not size:
                    raise PackmanError("Packman entry dimensions are unsupported")
                name = _decode_utf16(
                    _read_at(
                        stream,
                        position,
                        name_chars * 2,
                        certificate_offset,
                        "Packman entry name",
                    ),
                    "Packman entry name",
                )
                position += name_chars * 2
                _read_at(
                    stream, position, 8, certificate_offset, "Packman entry timestamp"
                )
                position += 8
                headers.append((name, size))

            if [item[0] for item in headers] != [SETTINGS_NAME, CAB_NAME]:
                raise PackmanError("Packman entry sequence is unsupported")
            if not 1 <= headers[0][1] <= MAX_SETTINGS_SIZE:
                raise PackmanError("Packman settings entry size is unsupported")
            if not 36 <= headers[1][1] <= MAX_CAB_SIZE:
                raise PackmanError("Packman CAB entry size is unsupported")

            header_end = position
            entries = []
            for index, (name, size) in enumerate(headers):
                if size > certificate_offset - position:
                    raise PackmanError("Packman entry exceeds the certificate boundary")
                entries.append(
                    {
                        "name": name,
                        "offset": position,
                        "size": size,
                        "transformation": "identity" if index == 0 else "xor-ff",
                    }
                )
                position += size

            payload_end = position
            padding_size = certificate_offset - payload_end
            if padding_size != (-payload_end) % 8 or padding_size > 7:
                raise PackmanError("Packman certificate alignment is inconsistent")
            if _read_at(
                stream,
                payload_end,
                padding_size,
                certificate_offset,
                "Packman alignment padding",
            ) != bytes(padding_size):
                raise PackmanError("Packman alignment padding is nonzero")

            settings = entries[0]
            if _read_at(
                stream,
                settings["offset"],
                2,
                certificate_offset,
                "Packman settings BOM",
            ) != b"\xff\xfe":
                raise PackmanError("Packman settings encoding is unsupported")
            cab = entries[1]
            stored_header = _read_at(
                stream,
                cab["offset"],
                36,
                certificate_offset,
                "Packman CAB header",
            )
            _cab_header(bytes(value ^ 0xFF for value in stored_header), cab["size"])
    except PackmanError:
        raise
    except OSError as error:
        raise PackmanError("Packman updater could not be parsed") from error

    report = {
        "schema_version": 1,
        "file": copy.deepcopy(pe_report["file"]),
        "pe": copy.deepcopy(pe_report["pe"]),
        "container": {
            "offset": start,
            "header_end": header_end,
            "payload_end": payload_end,
            "padding_size": padding_size,
            "format_version": version,
            "marker": marker,
            "entries": entries,
        },
        "certificate": copy.deepcopy(certificate),
    }
    return validate_packman_report(report)


def inspect_packman(path: Path) -> dict:
    """Inspect one signed Packman updater without executing it."""
    candidate = Path(path)
    try:
        pe_report = inspect_updater_pe(candidate)
    except UpdaterPeError as error:
        raise PackmanError("Packman PE boundary is invalid") from error
    return _parse(candidate, pe_report)


def validate_packman_report(document: object) -> dict:
    """Validate and independently copy a Packman metadata report."""
    if not isinstance(document, dict) or set(document) != _TOP_FIELDS:
        raise PackmanError("Packman report fields are invalid")
    if document["schema_version"] != 1 or type(document["schema_version"]) is not int:
        raise PackmanError("Packman report schema is unsupported")

    file_item = document["file"]
    if not isinstance(file_item, dict) or set(file_item) != {"size", "sha256"}:
        raise PackmanError("Packman file fields are invalid")
    file_size = file_item["size"]
    if type(file_size) is not int or file_size < 64:
        raise PackmanError("Packman file size is invalid")
    if not isinstance(file_item["sha256"], str) or not _DIGEST.fullmatch(
        file_item["sha256"]
    ):
        raise PackmanError("Packman file digest is invalid")

    pe = document["pe"]
    if not isinstance(pe, dict) or set(pe) != {
        "machine",
        "kind",
        "section_count",
        "size_of_headers",
    }:
        raise PackmanError("Packman PE fields are invalid")
    if pe["kind"] not in {"PE32", "PE32+"}:
        raise PackmanError("Packman PE kind is invalid")
    for field in ("machine", "section_count", "size_of_headers"):
        if type(pe[field]) is not int or pe[field] <= 0:
            raise PackmanError("Packman PE numeric field is invalid")

    container = document["container"]
    if not isinstance(container, dict) or set(container) != _CONTAINER_FIELDS:
        raise PackmanError("Packman container fields are invalid")
    if container["format_version"] != 2 or container["marker"] != MARKER:
        raise PackmanError("Packman container identity is invalid")
    for field in ("offset", "header_end", "payload_end", "padding_size"):
        if type(container[field]) is not int or container[field] < 0:
            raise PackmanError("Packman container span is invalid")
    if not 0 <= container["padding_size"] <= 7:
        raise PackmanError("Packman padding size is invalid")
    entries = container["entries"]
    if not isinstance(entries, list) or len(entries) != 2:
        raise PackmanError("Packman entries are invalid")
    expected = ((SETTINGS_NAME, "identity"), (CAB_NAME, "xor-ff"))
    position = container["header_end"]
    for item, (name, transformation) in zip(entries, expected):
        if not isinstance(item, dict) or set(item) != _ENTRY_FIELDS:
            raise PackmanError("Packman entry fields are invalid")
        if item["name"] != name or item["transformation"] != transformation:
            raise PackmanError("Packman entry identity is invalid")
        if item["offset"] != position or type(item["size"]) is not int or item["size"] <= 0:
            raise PackmanError("Packman entry span is invalid")
        position += item["size"]
    if position != container["payload_end"]:
        raise PackmanError("Packman payload end is inconsistent")

    certificate = document["certificate"]
    if not isinstance(certificate, dict) or set(certificate) != {
        "offset",
        "size",
        "sha256",
    }:
        raise PackmanError("Packman certificate fields are invalid")
    if (
        type(certificate["offset"]) is not int
        or type(certificate["size"]) is not int
        or certificate["size"] <= 0
        or certificate["offset"] != container["payload_end"] + container["padding_size"]
        or certificate["offset"] % 8
        or certificate["offset"] + certificate["size"] > file_size
    ):
        raise PackmanError("Packman certificate span is invalid")
    if not isinstance(certificate["sha256"], str) or not _DIGEST.fullmatch(
        certificate["sha256"]
    ):
        raise PackmanError("Packman certificate digest is invalid")
    if not container["offset"] < container["header_end"] <= container["payload_end"]:
        raise PackmanError("Packman container ordering is invalid")
    return copy.deepcopy(document)


def extract_packman_cab(
    source_path: Path,
    output_path: Path,
    *,
    artifacts_root: Path,
) -> dict:
    """Decode only the proven CAB entry into a new file below an artifact root."""
    source_path = Path(source_path)
    output_path = Path(output_path)
    artifacts_root = Path(artifacts_root)
    report = inspect_packman(source_path)
    if (
        not artifacts_root.exists()
        or not artifacts_root.is_dir()
        or artifacts_root.is_symlink()
        or not output_path.parent.exists()
        or not output_path.parent.is_dir()
        or output_path.parent.is_symlink()
    ):
        raise PackmanError("Packman output directory is invalid")
    try:
        resolved_root = artifacts_root.resolve(strict=True)
        resolved_output = output_path.resolve(strict=False)
    except OSError as error:
        raise PackmanError("Packman output path could not be resolved") from error
    if not resolved_output.is_relative_to(resolved_root):
        raise PackmanError("Packman output must stay below the artifact root")
    if output_path.exists() or output_path.is_symlink():
        raise PackmanError("Packman output already exists")

    cab = report["container"]["entries"][1]
    digest = hashlib.sha256()
    translation = bytes.maketrans(bytes(range(256)), bytes(reversed(range(256))))
    try:
        with source_path.open("rb") as source, output_path.open("xb") as output:
            source.seek(cab["offset"])
            remaining = cab["size"]
            while remaining:
                chunk = source.read(min(COPY_CHUNK_SIZE, remaining))
                if not chunk:
                    raise PackmanError("Packman CAB source is truncated")
                decoded = chunk.translate(translation)
                output.write(decoded)
                digest.update(decoded)
                remaining -= len(chunk)
        if output_path.stat().st_size != cab["size"]:
            raise PackmanError("Decoded CAB size does not match")
        with output_path.open("rb") as decoded_stream:
            _cab_header(decoded_stream.read(36), cab["size"])
    except Exception:
        if output_path.exists() and output_path.is_file() and not output_path.is_symlink():
            output_path.unlink()
        raise
    return {
        "size": cab["size"],
        "sha256": digest.hexdigest(),
        "magic": "MSCF",
        "transformation": "xor-ff",
    }
