"""Bounded, metadata-only inspection of a Sony Windows updater PE."""

import copy
import hashlib
import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from .ranges import ByteRange, RangeError, validate_ranges
from .signatures import SignatureError, pe_authenticode_coverage


class UpdaterPeError(ValueError):
    """Raised when updater metadata is malformed, ambiguous, or unbounded."""


MAX_E_LFANEW = 16 * 1024 * 1024
MAX_OPTIONAL_HEADER = 4096
MAX_SECTIONS = 96
MAX_DIRECTORIES = 32
MAX_IMPORT_DESCRIPTORS = 1024
MAX_IMPORTS_PER_DLL = 8192
MAX_RESOURCES = 4096
MAX_RESOURCE_DEPTH = 3
MAX_RESOURCE_NAME_CHARS = 128
MAX_EMBEDDED_CANDIDATES = 64
MAX_MZ_HITS = 262_144
SCAN_CHUNK_SIZE = 1024 * 1024
HASH_CHUNK_SIZE = 1024 * 1024
MAX_REPORT_BYTES = 256 * 1024

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_RESOURCE_TYPES = {
    1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG",
    6: "STRING", 7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR",
    10: "RCDATA", 11: "MESSAGETABLE", 12: "GROUP_CURSOR",
    14: "GROUP_ICON", 16: "VERSION", 17: "DLGINCLUDE", 19: "PLUGPLAY",
    20: "VXD", 21: "ANICURSOR", 22: "ANIICON", 23: "HTML", 24: "MANIFEST",
}
_ALLOWED_IMPORTS = {
    "advapi32.dll": {
        "RegCloseKey", "RegCreateKeyExW", "RegOpenKeyExW",
        "RegQueryValueExW", "RegSetValueExW",
    },
    "crypt32.dll": {"CertCloseStore", "CertOpenStore", "CryptQueryObject"},
    "kernel32.dll": {
        "CloseHandle", "CreateFileW", "CreateProcessW", "DeviceIoControl",
        "GetFileSizeEx", "GetProcAddress", "LoadLibraryW", "ReadFile",
        "VirtualAlloc", "VirtualProtect", "WriteFile",
    },
    "setupapi.dll": {
        "SetupDiDestroyDeviceInfoList", "SetupDiEnumDeviceInterfaces",
        "SetupDiGetClassDevsW", "SetupDiGetDeviceInterfaceDetailW",
    },
    "shell32.dll": {"ShellExecuteExW", "ShellExecuteW"},
    "user32.dll": {"DialogBoxParamW", "MessageBoxW"},
    "winhttp.dll": {
        "WinHttpCloseHandle", "WinHttpConnect", "WinHttpOpen",
        "WinHttpOpenRequest", "WinHttpReceiveResponse", "WinHttpSendRequest",
    },
    "winusb.dll": {
        "WinUsb_Free", "WinUsb_Initialize", "WinUsb_ReadPipe",
        "WinUsb_WritePipe",
    },
}


@dataclass(frozen=True, slots=True)
class _Section:
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int


@dataclass(frozen=True, slots=True)
class _Layout:
    base: int
    source_end: int
    machine: int
    kind: str
    pointer_size: int
    section_count: int
    size_of_headers: int
    sections: tuple[_Section, ...]
    directories: tuple[tuple[int, int], ...]
    image_end: int
    extent: int


def _bounded(offset: int, size: int, end: int, start: int = 0) -> bool:
    return (
        type(offset) is int
        and type(size) is int
        and offset >= start
        and size >= 0
        and offset <= end
        and size <= end - offset
    )


def _read_at(
    stream: BinaryIO,
    offset: int,
    size: int,
    end: int,
    label: str,
) -> bytes:
    if not _bounded(offset, size, end):
        raise UpdaterPeError(f"{label} is outside its bounded source")
    try:
        stream.seek(offset)
        value = stream.read(size)
    except OSError as error:
        raise UpdaterPeError(f"{label} could not be read") from error
    if len(value) != size:
        raise UpdaterPeError(f"{label} is truncated")
    return value


def _hash_range(path: Path, offset: int, size: int) -> str:
    file_size = path.stat().st_size
    if not _bounded(offset, size, file_size):
        raise UpdaterPeError("Hash range exceeds the updater")
    digest = hashlib.sha256()
    remaining = size
    try:
        with path.open("rb") as stream:
            stream.seek(offset)
            while remaining:
                block = stream.read(min(HASH_CHUNK_SIZE, remaining))
                if not block:
                    raise UpdaterPeError("Hash range is truncated")
                digest.update(block)
                remaining -= len(block)
    except UpdaterPeError:
        raise
    except OSError as error:
        raise UpdaterPeError("Updater range could not be hashed") from error
    return digest.hexdigest()


def _parse_layout(stream: BinaryIO, base: int, source_end: int) -> _Layout:
    if not _bounded(base, 64, source_end):
        raise UpdaterPeError("PE DOS header is truncated")
    dos = _read_at(stream, base, 64, source_end, "PE DOS header")
    if dos[:2] != b"MZ":
        raise UpdaterPeError("PE DOS signature is absent")
    pe_relative = struct.unpack_from("<I", dos, 0x3C)[0]
    if pe_relative < 64 or pe_relative > MAX_E_LFANEW:
        raise UpdaterPeError("PE header offset is unsupported")
    pe_offset = base + pe_relative
    coff = _read_at(stream, pe_offset, 24, source_end, "PE header")
    if coff[:4] != b"PE\0\0":
        raise UpdaterPeError("PE signature is invalid")
    machine, section_count = struct.unpack_from("<HH", coff, 4)
    optional_size = struct.unpack_from("<H", coff, 20)[0]
    if not 1 <= section_count <= MAX_SECTIONS:
        raise UpdaterPeError("PE section count is unsupported")
    if not 64 <= optional_size <= MAX_OPTIONAL_HEADER:
        raise UpdaterPeError("PE optional header size is unsupported")

    optional_offset = pe_offset + 24
    optional = _read_at(
        stream, optional_offset, optional_size, source_end, "PE optional header"
    )
    magic = struct.unpack_from("<H", optional, 0)[0]
    if magic == 0x10B:
        kind, pointer_size, count_offset, directory_offset = "PE32", 4, 92, 96
    elif magic == 0x20B:
        kind, pointer_size, count_offset, directory_offset = "PE32+", 8, 108, 112
    else:
        raise UpdaterPeError("PE optional header kind is unsupported")
    if optional_size < count_offset + 4:
        raise UpdaterPeError("PE data-directory count is truncated")
    size_of_headers = struct.unpack_from("<I", optional, 60)[0]
    directory_count = struct.unpack_from("<I", optional, count_offset)[0]
    if directory_count > MAX_DIRECTORIES:
        raise UpdaterPeError("PE data-directory count is unsupported")
    if directory_offset + directory_count * 8 > optional_size:
        raise UpdaterPeError("PE data directories are truncated")
    directories = tuple(
        struct.unpack_from("<II", optional, directory_offset + index * 8)
        for index in range(directory_count)
    )

    section_table = optional_offset + optional_size
    section_bytes = section_count * 40
    relative_table_end = section_table + section_bytes - base
    if (
        size_of_headers < relative_table_end
        or not _bounded(base, size_of_headers, source_end)
    ):
        raise UpdaterPeError("PE header span is invalid")
    raw_sections = []
    sections = []
    image_end = base + size_of_headers
    for index in range(section_count):
        header = _read_at(
            stream, section_table + index * 40, 40, source_end, "PE section header"
        )
        virtual_size, virtual_address, raw_size, raw_relative = struct.unpack_from(
            "<IIII", header, 8
        )
        if raw_size:
            raw_offset = base + raw_relative
            if raw_relative < size_of_headers or not _bounded(
                raw_offset, raw_size, source_end, base
            ):
                raise UpdaterPeError("PE section data is out of bounds")
            raw_sections.append((raw_offset, raw_size))
            image_end = max(image_end, raw_offset + raw_size)
        else:
            raw_offset = base + raw_relative
        sections.append(
            _Section(virtual_address, virtual_size, raw_offset, raw_size)
        )
    try:
        validate_ranges(
            source_end,
            tuple(
                ByteRange("pe-section", offset, size, "PE section header")
                for offset, size in raw_sections
            ),
        )
    except RangeError as error:
        raise UpdaterPeError("PE section data overlaps") from error

    extent_end = image_end
    if len(directories) > 4:
        certificate_relative, certificate_size = directories[4]
        if bool(certificate_relative) != bool(certificate_size):
            raise UpdaterPeError("PE certificate directory is incomplete")
        if certificate_size:
            certificate_offset = base + certificate_relative
            if not _bounded(certificate_offset, certificate_size, source_end, base):
                raise UpdaterPeError("PE certificate blob is out of bounds")
            extent_end = max(extent_end, certificate_offset + certificate_size)
    return _Layout(
        base, source_end, machine, kind, pointer_size, section_count,
        size_of_headers, tuple(sections), directories, image_end, extent_end - base
    )


def _rva_to_offset(layout: _Layout, rva: int, size: int) -> int:
    if type(rva) is not int or rva < 0 or type(size) is not int or size < 0:
        raise UpdaterPeError("PE RVA is invalid")
    matches = []
    if rva < layout.size_of_headers and size <= layout.size_of_headers - rva:
        matches.append(layout.base + rva)
    for section in layout.sections:
        span = max(section.virtual_size, section.raw_size)
        if rva >= section.virtual_address and rva - section.virtual_address < span:
            delta = rva - section.virtual_address
            if delta <= section.raw_size and size <= section.raw_size - delta:
                matches.append(section.raw_offset + delta)
    matches = sorted(set(matches))
    if len(matches) != 1 or not _bounded(
        matches[0], size, layout.source_end, layout.base
    ):
        raise UpdaterPeError("PE RVA mapping is absent or ambiguous")
    return matches[0]


def _directory(layout: _Layout, index: int) -> tuple[int, int]:
    if index >= len(layout.directories):
        return (0, 0)
    rva, size = layout.directories[index]
    if bool(rva) != bool(size):
        raise UpdaterPeError("PE data directory is incomplete")
    return rva, size


def _read_ascii_rva(
    stream: BinaryIO, layout: _Layout, rva: int, maximum: int, label: str
) -> str:
    data = bytearray()
    for index in range(maximum + 1):
        offset = _rva_to_offset(layout, rva + index, 1)
        value = _read_at(stream, offset, 1, layout.source_end, label)[0]
        if value == 0:
            if not data:
                raise UpdaterPeError(f"{label} is empty")
            try:
                text = bytes(data).decode("ascii")
            except UnicodeDecodeError as error:
                raise UpdaterPeError(f"{label} is not ASCII") from error
            if not text.isprintable():
                raise UpdaterPeError(f"{label} is not printable")
            return text
        data.append(value)
    raise UpdaterPeError(f"{label} is not bounded")


def _inspect_imports(stream: BinaryIO, layout: _Layout) -> dict:
    rva, size = _directory(layout, 1)
    if not size:
        return {"allowlisted": [], "unlisted_dll_count": 0}
    if size < 20 or size > MAX_IMPORT_DESCRIPTORS * 20:
        raise UpdaterPeError("PE import directory size is unsupported")
    start = _rva_to_offset(layout, rva, size)
    allowlisted = []
    unlisted_count = 0
    terminated = False
    for index in range(min(size // 20, MAX_IMPORT_DESCRIPTORS)):
        descriptor = _read_at(
            stream, start + index * 20, 20, start + size, "PE import descriptor"
        )
        values = struct.unpack("<IIIII", descriptor)
        if not any(values):
            terminated = True
            break
        original_thunk, _, _, name_rva, first_thunk = values
        if not name_rva or not (original_thunk or first_thunk):
            raise UpdaterPeError("PE import descriptor is incomplete")
        dll = _read_ascii_rva(stream, layout, name_rva, 128, "PE import DLL")
        dll_key = dll.casefold()
        thunk_rva = original_thunk or first_thunk
        names = []
        ordinal_count = 0
        thunk_terminated = False
        ordinal_flag = 1 << (layout.pointer_size * 8 - 1)
        value_format = "<I" if layout.pointer_size == 4 else "<Q"
        for thunk_index in range(MAX_IMPORTS_PER_DLL):
            thunk_offset = _rva_to_offset(
                layout,
                thunk_rva + thunk_index * layout.pointer_size,
                layout.pointer_size,
            )
            thunk_value = struct.unpack(
                value_format,
                _read_at(
                    stream,
                    thunk_offset,
                    layout.pointer_size,
                    layout.source_end,
                    "PE import thunk",
                ),
            )[0]
            if thunk_value == 0:
                thunk_terminated = True
                break
            if thunk_value & ordinal_flag:
                ordinal_count += 1
                continue
            if thunk_value > 0xFFFFFFFF:
                raise UpdaterPeError("PE import-name RVA is unsupported")
            hint_offset = _rva_to_offset(layout, thunk_value, 2)
            _read_at(stream, hint_offset, 2, layout.source_end, "PE import hint")
            names.append(
                _read_ascii_rva(
                    stream, layout, thunk_value + 2, 256, "PE import function"
                )
            )
        if not thunk_terminated:
            raise UpdaterPeError("PE import thunk table is not bounded")
        if dll_key in _ALLOWED_IMPORTS:
            allowlisted.append(
                {
                    "dll": dll_key,
                    "function_count": len(names),
                    "ordinal_count": ordinal_count,
                    "allowlisted_functions": sorted(
                        set(names) & _ALLOWED_IMPORTS[dll_key]
                    ),
                }
            )
        else:
            unlisted_count += 1
    if not terminated:
        raise UpdaterPeError("PE import directory lacks a terminator")
    allowlisted.sort(key=lambda item: item["dll"])
    if len({item["dll"] for item in allowlisted}) != len(allowlisted):
        raise UpdaterPeError("PE import DLL descriptors are duplicated")
    return {"allowlisted": allowlisted, "unlisted_dll_count": unlisted_count}


def _resource_name(
    stream: BinaryIO, directory_start: int, directory_end: int, raw: int
) -> tuple[int | None, str | None]:
    if not raw & 0x80000000:
        return raw, None
    offset = directory_start + (raw & 0x7FFFFFFF)
    length_data = _read_at(stream, offset, 2, directory_end, "PE resource name")
    length = struct.unpack("<H", length_data)[0]
    if not 1 <= length <= MAX_RESOURCE_NAME_CHARS:
        raise UpdaterPeError("PE resource name length is unsupported")
    value = _read_at(
        stream, offset + 2, length * 2, directory_end, "PE resource name"
    )
    try:
        decoded = value.decode("utf-16le")
    except UnicodeDecodeError as error:
        raise UpdaterPeError("PE resource name is invalid UTF-16") from error
    if not decoded.isprintable():
        raise UpdaterPeError("PE resource name is not printable")
    return None, hashlib.sha256(value).hexdigest()


def _inspect_resources(stream: BinaryIO, layout: _Layout, path: Path) -> list[dict]:
    rva, size = _directory(layout, 2)
    if not size:
        return []
    directory_start = _rva_to_offset(layout, rva, size)
    directory_end = directory_start + size
    resources = []
    active_directories: set[int] = set()

    def walk(
        relative: int,
        depth: int,
        identifiers: tuple[tuple[int | None, str | None], ...],
    ) -> None:
        if depth >= MAX_RESOURCE_DEPTH or relative in active_directories:
            raise UpdaterPeError("PE resource directory is cyclic or too deep")
        offset = directory_start + relative
        header = _read_at(
            stream, offset, 16, directory_end, "PE resource directory"
        )
        named_count, id_count = struct.unpack_from("<HH", header, 12)
        entry_count = named_count + id_count
        if (
            entry_count > MAX_RESOURCES
            or len(resources) + entry_count > MAX_RESOURCES * 3
        ):
            raise UpdaterPeError("PE resource directory is too large")
        entries_offset = offset + 16
        _read_at(
            stream,
            entries_offset,
            entry_count * 8,
            directory_end,
            "PE resource entries",
        )
        active_directories.add(relative)
        try:
            for index in range(entry_count):
                entry = _read_at(
                    stream,
                    entries_offset + index * 8,
                    8,
                    directory_end,
                    "PE resource entry",
                )
                name_raw, target_raw = struct.unpack("<II", entry)
                identifier = _resource_name(
                    stream, directory_start, directory_end, name_raw
                )
                target_relative = target_raw & 0x7FFFFFFF
                is_directory = bool(target_raw & 0x80000000)
                next_identifiers = identifiers + (identifier,)
                if depth < 2:
                    if not is_directory:
                        raise UpdaterPeError("PE resource tree ends too early")
                    walk(target_relative, depth + 1, next_identifiers)
                    continue
                if is_directory or len(next_identifiers) != 3:
                    raise UpdaterPeError("PE resource leaf is ambiguous")
                type_id, type_digest = next_identifiers[0]
                name_id, name_digest = next_identifiers[1]
                language_id, language_digest = next_identifiers[2]
                if language_id is None or language_digest is not None:
                    raise UpdaterPeError("PE resource language must be numeric")
                data_offset = directory_start + target_relative
                data = _read_at(
                    stream,
                    data_offset,
                    16,
                    directory_end,
                    "PE resource data entry",
                )
                data_rva, data_size, _, reserved = struct.unpack("<IIII", data)
                if not data_size or reserved:
                    raise UpdaterPeError("PE resource data entry is invalid")
                payload_offset = _rva_to_offset(layout, data_rva, data_size)
                item = {
                    "type": (
                        _RESOURCE_TYPES.get(type_id, f"ID_{type_id}")
                        if type_id is not None
                        else "NAMED"
                    ),
                    "name_id": name_id,
                    "language_id": language_id,
                    "offset": payload_offset,
                    "size": data_size,
                    "sha256": _hash_range(path, payload_offset, data_size),
                }
                if type_digest is not None:
                    item["type_name_sha256"] = type_digest
                if name_digest is not None:
                    item["name_sha256"] = name_digest
                resources.append(item)
                if len(resources) > MAX_RESOURCES:
                    raise UpdaterPeError("PE resource count is too large")
        finally:
            active_directories.remove(relative)

    walk(0, 0, ())
    resources.sort(
        key=lambda item: (
            item["offset"],
            item["size"],
            item["type"],
            -1 if item["name_id"] is None else item["name_id"],
            item["language_id"],
            item.get("name_sha256", ""),
        )
    )
    return resources


def _scan_candidates(
    stream: BinaryIO,
    path: Path,
    source: str,
    start: int,
    size: int,
) -> list[dict]:
    if not size:
        return []
    end = start + size
    position = start
    carry = b""
    hits = 0
    candidates = []
    seen = set()
    while position < end:
        chunk_size = min(SCAN_CHUNK_SIZE, end - position)
        chunk = _read_at(stream, position, chunk_size, end, "PE candidate source")
        combined = carry + chunk
        combined_start = position - len(carry)
        search = 0
        while True:
            relative = combined.find(b"MZ", search)
            if relative < 0:
                break
            candidate_offset = combined_start + relative
            search = relative + 1
            if candidate_offset in seen:
                continue
            seen.add(candidate_offset)
            hits += 1
            if hits > MAX_MZ_HITS:
                raise UpdaterPeError("PE candidate scan is ambiguous")
            try:
                candidate_layout = _parse_layout(stream, candidate_offset, end)
            except UpdaterPeError:
                continue
            declared_size = candidate_layout.extent
            if declared_size < 64 or not _bounded(
                candidate_offset, declared_size, end, start
            ):
                continue
            candidates.append(
                {
                    "source": source,
                    "offset": candidate_offset,
                    "declared_size": declared_size,
                    "sha256": _hash_range(path, candidate_offset, declared_size),
                }
            )
            if len(candidates) > MAX_EMBEDDED_CANDIDATES:
                raise UpdaterPeError("Too many embedded PE candidates")
        carry = combined[-1:]
        position += chunk_size
    return candidates


def _range_document(value: ByteRange) -> dict:
    return {
        "label": value.label,
        "offset": value.offset,
        "size": value.size,
        "evidence": value.evidence,
    }


def inspect_updater_pe(path: Path) -> dict:
    """Inspect one updater without executing it or retaining payload bytes."""
    candidate = Path(path)
    try:
        if candidate.is_symlink():
            raise UpdaterPeError("Updater path must not be a symbolic link")
        resolved = candidate.resolve(strict=True)
        file_size = resolved.stat().st_size
    except UpdaterPeError:
        raise
    except (OSError, RuntimeError) as error:
        raise UpdaterPeError("Updater path could not be resolved") from error
    if not resolved.is_file() or file_size < 64:
        raise UpdaterPeError("Updater must be a non-empty regular file")

    try:
        with resolved.open("rb") as stream:
            layout = _parse_layout(stream, 0, file_size)
            imports = _inspect_imports(stream, layout)
            resources = _inspect_resources(stream, layout, resolved)
            overlay = None
            if layout.image_end < file_size:
                overlay = {
                    "offset": layout.image_end,
                    "size": file_size - layout.image_end,
                    "sha256": _hash_range(
                        resolved, layout.image_end, file_size - layout.image_end
                    ),
                }
            certificate = None
            certificate_offset, certificate_size = _directory(layout, 4)
            if certificate_size:
                certificate = {
                    "offset": certificate_offset,
                    "size": certificate_size,
                    "sha256": _hash_range(
                        resolved, certificate_offset, certificate_size
                    ),
                }

            embedded = []
            for resource in resources:
                embedded.extend(
                    _scan_candidates(
                        stream,
                        resolved,
                        "resource",
                        resource["offset"],
                        resource["size"],
                    )
                )
            if overlay is not None:
                embedded.extend(
                    _scan_candidates(
                        stream,
                        resolved,
                        "overlay",
                        overlay["offset"],
                        overlay["size"],
                    )
                )
    except UpdaterPeError:
        raise
    except OSError as error:
        raise UpdaterPeError("Updater could not be inspected") from error

    unique_embedded = {}
    for item in embedded:
        key = (item["offset"], item["declared_size"])
        if key in unique_embedded and unique_embedded[key] != item:
            raise UpdaterPeError("Embedded PE candidate source is ambiguous")
        unique_embedded[key] = item
    embedded = sorted(
        unique_embedded.values(), key=lambda item: (item["offset"], item["source"])
    )
    try:
        coverage = pe_authenticode_coverage(resolved)
    except SignatureError as error:
        raise UpdaterPeError("Updater Authenticode coverage is unavailable") from error
    report = {
        "schema_version": 1,
        "file": {
            "size": file_size,
            "sha256": _hash_range(resolved, 0, file_size),
        },
        "pe": {
            "machine": layout.machine,
            "kind": layout.kind,
            "section_count": layout.section_count,
            "size_of_headers": layout.size_of_headers,
        },
        "imports": imports,
        "resources": resources,
        "overlay": overlay,
        "certificate": certificate,
        "embedded_pe_candidates": embedded,
        "authenticode": {
            "signed_ranges": [_range_document(value) for value in coverage.signed],
            "excluded_ranges": [
                _range_document(value) for value in coverage.excluded
            ],
        },
    }
    return validate_updater_pe_report(report)


def _validate_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise UpdaterPeError(f"{label} digest is invalid")
    return value


def _validate_span(
    item: object, fields: set[str], file_size: int, label: str
) -> dict:
    if not isinstance(item, dict) or set(item) != fields:
        raise UpdaterPeError(f"{label} fields are invalid")
    offset = item["offset"]
    size = item["size"]
    if type(offset) is not int or type(size) is not int or size <= 0:
        raise UpdaterPeError(f"{label} span is invalid")
    if not _bounded(offset, size, file_size):
        raise UpdaterPeError(f"{label} exceeds the updater")
    _validate_digest(item["sha256"], label)
    return item


def _validate_range_documents(
    values: object, file_size: int, label: str
) -> tuple[ByteRange, ...]:
    if not isinstance(values, list):
        raise UpdaterPeError(f"{label} ranges are invalid")
    ranges = []
    for item in values:
        expected = {"label", "offset", "size", "evidence"}
        if not isinstance(item, dict) or set(item) != expected:
            raise UpdaterPeError(f"{label} range fields are invalid")
        if not all(
            isinstance(item[name], str) for name in ("label", "evidence")
        ):
            raise UpdaterPeError(f"{label} range text is invalid")
        ranges.append(
            ByteRange(
                item["label"], item["offset"], item["size"], item["evidence"]
            )
        )
    try:
        return validate_ranges(file_size, tuple(ranges))
    except RangeError as error:
        raise UpdaterPeError(f"{label} ranges are invalid") from error


def validate_updater_pe_report(document: object) -> dict:
    """Validate and independently copy a bounded updater report."""
    fields = {
        "schema_version",
        "file",
        "pe",
        "imports",
        "resources",
        "overlay",
        "certificate",
        "embedded_pe_candidates",
        "authenticode",
    }
    if not isinstance(document, dict) or set(document) != fields:
        raise UpdaterPeError("Updater report fields are invalid")
    try:
        encoded_size = len(
            json.dumps(document, separators=(",", ":")).encode("utf-8")
        )
    except (TypeError, ValueError) as error:
        raise UpdaterPeError("Updater report is not JSON-compatible") from error
    if encoded_size > MAX_REPORT_BYTES:
        raise UpdaterPeError("Updater report is too large")
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != 1
    ):
        raise UpdaterPeError("Updater report schema version is unsupported")

    file_item = document["file"]
    if not isinstance(file_item, dict) or set(file_item) != {"size", "sha256"}:
        raise UpdaterPeError("Updater file fields are invalid")
    file_size = file_item["size"]
    if type(file_size) is not int or file_size < 64:
        raise UpdaterPeError("Updater file size is invalid")
    _validate_digest(file_item["sha256"], "Updater file")

    pe = document["pe"]
    expected_pe = {"machine", "kind", "section_count", "size_of_headers"}
    if not isinstance(pe, dict) or set(pe) != expected_pe:
        raise UpdaterPeError("Updater PE fields are invalid")
    if type(pe["machine"]) is not int or not 0 <= pe["machine"] <= 0xFFFF:
        raise UpdaterPeError("Updater PE machine is invalid")
    if pe["kind"] not in {"PE32", "PE32+"}:
        raise UpdaterPeError("Updater PE kind is invalid")
    if (
        type(pe["section_count"]) is not int
        or not 1 <= pe["section_count"] <= MAX_SECTIONS
    ):
        raise UpdaterPeError("Updater PE section count is invalid")
    if (
        type(pe["size_of_headers"]) is not int
        or not 64 <= pe["size_of_headers"] <= file_size
    ):
        raise UpdaterPeError("Updater PE header size is invalid")

    imports = document["imports"]
    expected_imports = {"allowlisted", "unlisted_dll_count"}
    if not isinstance(imports, dict) or set(imports) != expected_imports:
        raise UpdaterPeError("Updater import fields are invalid")
    if (
        type(imports["unlisted_dll_count"]) is not int
        or not 0
        <= imports["unlisted_dll_count"]
        <= MAX_IMPORT_DESCRIPTORS
    ):
        raise UpdaterPeError("Updater unlisted import count is invalid")
    allowed_items = imports["allowlisted"]
    if (
        not isinstance(allowed_items, list)
        or len(allowed_items) > len(_ALLOWED_IMPORTS)
    ):
        raise UpdaterPeError("Updater allowlisted imports are invalid")
    previous_dll = ""
    for item in allowed_items:
        expected = {
            "dll",
            "function_count",
            "ordinal_count",
            "allowlisted_functions",
        }
        if not isinstance(item, dict) or set(item) != expected:
            raise UpdaterPeError("Updater import item fields are invalid")
        dll = item["dll"]
        if dll not in _ALLOWED_IMPORTS or dll <= previous_dll:
            raise UpdaterPeError("Updater import DLL is invalid or duplicated")
        previous_dll = dll
        for name in ("function_count", "ordinal_count"):
            if (
                type(item[name]) is not int
                or not 0 <= item[name] <= MAX_IMPORTS_PER_DLL
            ):
                raise UpdaterPeError("Updater import count is invalid")
        functions = item["allowlisted_functions"]
        if (
            not isinstance(functions, list)
            or functions != sorted(set(functions))
            or not set(functions) <= _ALLOWED_IMPORTS[dll]
        ):
            raise UpdaterPeError("Updater allowlisted function list is invalid")
        if len(functions) > item["function_count"]:
            raise UpdaterPeError("Updater import function count is contradictory")

    resources = document["resources"]
    if not isinstance(resources, list) or len(resources) > MAX_RESOURCES:
        raise UpdaterPeError("Updater resource list is invalid")
    resource_keys = set()
    for item in resources:
        base_fields = {
            "type",
            "name_id",
            "language_id",
            "offset",
            "size",
            "sha256",
        }
        optional_fields = set(item) - base_fields if isinstance(item, dict) else set()
        if optional_fields - {"type_name_sha256", "name_sha256"}:
            raise UpdaterPeError("Updater resource fields are invalid")
        _validate_span(
            item, base_fields | optional_fields, file_size, "Updater resource"
        )
        if (
            not isinstance(item["type"], str)
            or not 1 <= len(item["type"]) <= 32
            or not item["type"].isprintable()
        ):
            raise UpdaterPeError("Updater resource type is invalid")
        if item["name_id"] is not None and (
            type(item["name_id"]) is not int
            or not 0 <= item["name_id"] <= 0x7FFFFFFF
        ):
            raise UpdaterPeError("Updater resource name ID is invalid")
        if (
            type(item["language_id"]) is not int
            or not 0 <= item["language_id"] <= 0x7FFFFFFF
        ):
            raise UpdaterPeError("Updater resource language ID is invalid")
        if item["type"] == "NAMED" and "type_name_sha256" not in item:
            raise UpdaterPeError("Named updater resource type lacks a digest")
        if item["name_id"] is None and "name_sha256" not in item:
            raise UpdaterPeError("Named updater resource lacks a digest")
        for digest_name in optional_fields:
            _validate_digest(item[digest_name], "Updater resource name")
        key = tuple((name, repr(item[name])) for name in sorted(item))
        if key in resource_keys:
            raise UpdaterPeError("Updater resource is duplicated")
        resource_keys.add(key)

    overlay = document["overlay"]
    if overlay is not None:
        _validate_span(
            overlay,
            {"offset", "size", "sha256"},
            file_size,
            "Updater overlay",
        )
        if overlay["offset"] + overlay["size"] != file_size:
            raise UpdaterPeError("Updater overlay does not reach end of file")
    certificate = document["certificate"]
    if certificate is None:
        raise UpdaterPeError("Updater certificate metadata is required")
    _validate_span(
        certificate,
        {"offset", "size", "sha256"},
        file_size,
        "Updater certificate",
    )

    candidates = document["embedded_pe_candidates"]
    if (
        not isinstance(candidates, list)
        or len(candidates) > MAX_EMBEDDED_CANDIDATES
    ):
        raise UpdaterPeError("Updater embedded candidate list is invalid")
    candidate_keys = set()
    previous_candidate = (-1, "")
    for item in candidates:
        expected = {"source", "offset", "declared_size", "sha256"}
        if not isinstance(item, dict) or set(item) != expected:
            raise UpdaterPeError("Updater embedded candidate fields are invalid")
        if item["source"] not in {"resource", "overlay"}:
            raise UpdaterPeError("Updater embedded candidate source is invalid")
        if (
            type(item["offset"]) is not int
            or type(item["declared_size"]) is not int
            or item["declared_size"] < 64
        ):
            raise UpdaterPeError("Updater embedded candidate span is invalid")
        if not _bounded(item["offset"], item["declared_size"], file_size):
            raise UpdaterPeError("Updater embedded candidate exceeds the updater")
        _validate_digest(item["sha256"], "Updater embedded candidate")
        candidate_end = item["offset"] + item["declared_size"]
        if item["source"] == "resource":
            source_is_bounded = any(
                item["offset"] >= resource["offset"]
                and candidate_end <= resource["offset"] + resource["size"]
                for resource in resources
            )
        else:
            source_is_bounded = (
                overlay is not None
                and item["offset"] >= overlay["offset"]
                and candidate_end <= overlay["offset"] + overlay["size"]
            )
        if not source_is_bounded:
            raise UpdaterPeError(
                "Updater embedded candidate contradicts its source"
            )
        key = (item["offset"], item["declared_size"])
        order_key = (item["offset"], item["source"])
        if key in candidate_keys or order_key <= previous_candidate:
            raise UpdaterPeError(
                "Updater embedded candidate is duplicated or unordered"
            )
        candidate_keys.add(key)
        previous_candidate = order_key

    authenticode = document["authenticode"]
    expected_authenticode = {"signed_ranges", "excluded_ranges"}
    if (
        not isinstance(authenticode, dict)
        or set(authenticode) != expected_authenticode
    ):
        raise UpdaterPeError("Updater Authenticode fields are invalid")
    signed = _validate_range_documents(
        authenticode["signed_ranges"], file_size, "Signed"
    )
    excluded = _validate_range_documents(
        authenticode["excluded_ranges"], file_size, "Excluded"
    )
    if [value.label for value in excluded] != [
        "pe-checksum",
        "certificate-directory",
        "certificate-blob",
    ]:
        raise UpdaterPeError("Updater Authenticode exclusions are invalid")
    if any(
        value.label != "authenticode-signed"
        or value.evidence != "computed complement"
        for value in signed
    ) or any(value.evidence != "Authenticode exclusion" for value in excluded):
        raise UpdaterPeError("Updater Authenticode evidence is invalid")
    certificate_blob = excluded[2]
    if (
        certificate["offset"] != certificate_blob.offset
        or certificate["size"] != certificate_blob.size
    ):
        raise UpdaterPeError(
            "Updater certificate contradicts Authenticode coverage"
        )
    try:
        combined = validate_ranges(file_size, signed + excluded)
    except RangeError as error:
        raise UpdaterPeError("Updater Authenticode coverage overlaps") from error
    if (
        not combined
        or combined[0].offset != 0
        or combined[-1].offset + combined[-1].size != file_size
    ):
        raise UpdaterPeError("Updater Authenticode coverage is incomplete")
    for left, right in zip(combined, combined[1:]):
        if left.offset + left.size != right.offset:
            raise UpdaterPeError("Updater Authenticode coverage has gaps")
    return copy.deepcopy(document)
