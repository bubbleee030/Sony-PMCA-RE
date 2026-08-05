"""Fail-closed structural analysis of Sony SA containers and registries.

This module only parses caller-supplied byte strings.  It has no camera,
transport, cryptographic, or executable-loading capability.
"""

from __future__ import annotations

import copy
import re
import struct


class SaRegistryError(ValueError):
    """Raised when SA evidence is malformed, ambiguous, or overclaimed."""


_SABIN_MAGIC = bytes.fromhex("aa0a1391")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_REPORT_FIELDS = {
    "schema_version",
    "subject",
    "camera_policy",
    "camera_executed",
    "installable",
    "aes_program_registered",
    "udrt_program_registered",
    "programs_loaded_by_updater",
    "imdb_namespace_link",
    "firmware_decryption_link",
    "evidence",
    "observations",
    "unresolved",
    "conclusion",
}
_EVIDENCE_FIELDS = {
    "registry_sha256",
    "sabin_sha256",
    "names_offset",
    "name_slot_size",
    "record_length_offset",
    "record_bytes",
    "record_count",
    "filename_index",
    "record_u16_le",
    "container_identity",
    "container_module",
    "container_header_u16_be",
    "udrt_sabin_sha256",
    "udrt_filename_index",
    "udrt_record_u16_le",
    "udrt_container_identity",
    "udrt_container_module",
    "udrt_container_header_u16_be",
    "registry_type_interpretation",
}
_CLAIM_FIELDS = {"classification", "source", "claim"}


def _cstring(data: bytes, offset: int, size: int, label: str) -> str:
    field = data[offset : offset + size]
    if len(field) != size:
        raise SaRegistryError(f"{label} is truncated")
    value = field.split(b"\0", 1)[0]
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SaRegistryError(f"{label} is not ASCII") from exc
    if not text or not text.isprintable():
        raise SaRegistryError(f"{label} is invalid")
    return text


def parse_sabin_identity(data: bytes) -> dict:
    """Return only directly observed outer-container identity fields."""
    if not isinstance(data, bytes) or len(data) < 0x60:
        raise SaRegistryError("SA container is truncated")
    if data[:4] != _SABIN_MAGIC:
        raise SaRegistryError("SA container magic is unknown")
    return {
        "identity": _cstring(data, 0x14, 0x0C, "SA identity"),
        "module": _cstring(data, 0x48, 0x18, "SA module"),
        "header_u16_be": list(struct.unpack_from(">2H", data, 8)),
    }


def _registry_record(
    data: bytes,
    *,
    names_offset: int,
    name_slot_size: int,
    record_length_offset: int,
    target_name: str,
) -> dict:
    if not isinstance(data, bytes) or not data:
        raise SaRegistryError("Registry image is invalid")
    if (
        type(names_offset) is not int
        or type(name_slot_size) is not int
        or type(record_length_offset) is not int
        or names_offset < 0
        or not 16 <= name_slot_size <= 256
        or record_length_offset < 0
        or not isinstance(target_name, str)
        or not target_name
        or not target_name.isascii()
    ):
        raise SaRegistryError("Registry geometry is invalid")
    if record_length_offset + 2 > len(data):
        raise SaRegistryError("Registry record-length field is truncated")
    record_bytes = struct.unpack_from("<H", data, record_length_offset)[0]
    if record_bytes == 0 or record_bytes % 8:
        raise SaRegistryError("Registry record length is not eight-byte aligned")
    records_offset = record_length_offset + 2
    if records_offset + record_bytes > len(data):
        raise SaRegistryError("Registry records are truncated")
    record_count = record_bytes // 8
    if names_offset + record_count * name_slot_size > len(data):
        raise SaRegistryError("Registry filename slots are truncated")

    matches = []
    for index in range(record_count):
        offset = names_offset + index * name_slot_size
        slot = data[offset : offset + name_slot_size]
        value = slot.split(b"\0", 1)[0]
        try:
            name = value.decode("ascii")
        except UnicodeDecodeError:
            continue
        if name == target_name:
            matches.append(index)
    if len(matches) != 1:
        raise SaRegistryError("Target filename is missing or ambiguous")

    index = matches[0]
    record = list(struct.unpack_from("<4H", data, records_offset + index * 8))
    return {
        "record_bytes": record_bytes,
        "record_count": record_count,
        "filename_index": index,
        "record_u16_le": record,
    }


def analyze_sa_boundary(
    *,
    registry_data: bytes,
    sabin_data: bytes,
    names_offset: int,
    name_slot_size: int,
    record_length_offset: int,
    target_name: str,
) -> dict:
    """Cross-check one registry record against one SA outer header."""
    registry = _registry_record(
        registry_data,
        names_offset=names_offset,
        name_slot_size=name_slot_size,
        record_length_offset=record_length_offset,
        target_name=target_name,
    )
    container = parse_sabin_identity(sabin_data)
    record = registry["record_u16_le"]
    return {
        "registry": registry,
        "container": container,
        "cross_checks": {
            "record_first_matches_filename_index": record[0]
            == registry["filename_index"],
            "record_tail_matches_container_header": record[2:]
            == container["header_u16_be"],
        },
        "firmware_decryption_link": "unproven",
        "camera_executed": False,
        "installable": False,
    }


def _require_fields(value: object, fields: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise SaRegistryError(f"{label} fields are invalid")
    return value


def _bounded_text(value: object, label: str, maximum: int = 1000) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or "\r" in value
        or "\n" in value
        or not value.isprintable()
    ):
        raise SaRegistryError(f"{label} is invalid")
    return value


def validate_sa_boundary_report(document: object) -> dict:
    """Reject reports that promote registration evidence into an update link."""
    _require_fields(document, _REPORT_FIELDS, "SA boundary report")
    if document["schema_version"] != 1:
        raise SaRegistryError("SA boundary schema is unsupported")
    if document["subject"] != "ILCE-6400 SA updater-crypto registry boundary":
        raise SaRegistryError("SA boundary subject is invalid")
    if document["camera_policy"] != "physically-disconnected":
        raise SaRegistryError("SA boundary camera policy is invalid")
    if document["camera_executed"] is not False or document["installable"] is not False:
        raise SaRegistryError("SA boundary execution was overclaimed")
    if (
        document["aes_program_registered"] is not True
        or document["udrt_program_registered"] is not True
    ):
        raise SaRegistryError("SA registry observation is invalid")
    if document["programs_loaded_by_updater"] is not False:
        raise SaRegistryError("SA updater-load evidence was overclaimed")
    if document["imdb_namespace_link"] != "unproven":
        raise SaRegistryError("SA and IMDB namespaces were conflated")
    if document["firmware_decryption_link"] != "unproven":
        raise SaRegistryError("SA firmware link was overclaimed")

    evidence = _require_fields(document["evidence"], _EVIDENCE_FIELDS, "SA evidence")
    for field in ("registry_sha256", "sabin_sha256", "udrt_sabin_sha256"):
        if not isinstance(evidence[field], str) or not _DIGEST.fullmatch(evidence[field]):
            raise SaRegistryError(f"{field} is invalid")
    if evidence["names_offset"] != 0xAC204:
        raise SaRegistryError("SA filename-table offset is invalid")
    if evidence["name_slot_size"] != 0x20:
        raise SaRegistryError("SA filename-slot size is invalid")
    if evidence["record_length_offset"] != 0xAD6CA:
        raise SaRegistryError("SA record-length offset is invalid")
    if evidence["record_bytes"] != 0x4B0 or evidence["record_count"] != 150:
        raise SaRegistryError("SA record-table geometry is invalid")
    if evidence["filename_index"] != 0x36:
        raise SaRegistryError("SA AES filename index is invalid")
    if evidence["record_u16_le"] != [0x36, 0x93, 0x13, 0x1]:
        raise SaRegistryError("SA AES record is invalid")
    if evidence["container_identity"] != "SA_AESSH0x01":
        raise SaRegistryError("SA container identity is invalid")
    if evidence["container_module"] != "AES_SHA20x01":
        raise SaRegistryError("SA container module is invalid")
    if evidence["container_header_u16_be"] != [0x13, 0x1]:
        raise SaRegistryError("SA container header observation is invalid")
    if evidence["udrt_filename_index"] != 0x5B:
        raise SaRegistryError("SA UDRT filename index is invalid")
    if evidence["udrt_record_u16_le"] != [0x5B, 0x93, 0x3F, 0x1]:
        raise SaRegistryError("SA UDRT record is invalid")
    if evidence["udrt_container_identity"] != "SA_UDRT_0x04":
        raise SaRegistryError("SA UDRT identity is invalid")
    if evidence["udrt_container_module"] != "UDRT____0x04":
        raise SaRegistryError("SA UDRT module is invalid")
    if evidence["udrt_container_header_u16_be"] != [0x3F, 0x1]:
        raise SaRegistryError("SA UDRT header observation is invalid")
    if evidence["registry_type_interpretation"] != "common-type-not-program-id":
        raise SaRegistryError("SA registry type was overinterpreted")


    for field, classification in (
        ("observations", "OBSERVATION"),
        ("unresolved", "UNRESOLVED"),
    ):
        claims = document[field]
        if not isinstance(claims, list) or not 1 <= len(claims) <= 16:
            raise SaRegistryError(f"{field} claims are invalid")
        for claim in claims:
            _require_fields(claim, _CLAIM_FIELDS, "SA claim")
            if claim["classification"] != classification:
                raise SaRegistryError("SA claim classification is invalid")
            _bounded_text(claim["source"], "SA claim source", 300)
            _bounded_text(claim["claim"], "SA claim")
    _bounded_text(document["conclusion"], "SA boundary conclusion")
    return copy.deepcopy(document)
