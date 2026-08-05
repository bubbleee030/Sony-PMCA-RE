"""Fail-closed metadata checks for the alpha 6400 updater crypto boundary.

The module performs size arithmetic and validates bounded evidence reports. It has
no camera transport, cryptographic primitive, executable loader, or firmware
writer.
"""

from __future__ import annotations

import copy
import re


class UpdaterCryptoBoundaryError(ValueError):
    """Raised when updater-boundary evidence is malformed or overclaimed."""


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_TOP_FIELDS = {
    "schema_version",
    "subject",
    "camera_policy",
    "camera_executed",
    "bypass_established",
    "installable",
    "model_mismatch_safe",
    "host_transfer",
    "normal_runtime",
    "updater_mode_receiver",
    "crypter",
    "integrity",
    "sa_boundary",
    "observations",
    "inferences",
    "unresolved",
    "conclusion",
}
_HOST_FIELDS = {
    "engine_sha256",
    "raw_fdat_bytes",
    "dat_chunk_order",
    "fdat_payload_start_recorded",
    "negotiated_request_bytes",
    "maximum_data_bytes",
    "guard_command",
    "guard_sequence1_payload_bytes",
    "guard_sequence2_scope",
    "guard_stops_on_status_ok_before_eof",
    "reconnect_resets_to_fdat_start",
    "full_write_command",
}
_NORMAL_FIELDS = {
    "library",
    "role",
    "guard_decryption",
    "guard_decrypted_prefix_bytes",
    "guard_fields",
    "mode_switch_scripts",
    "mode_switch_reboots",
    "full_write_scope",
    "accessory_tmpfs_bytes",
    "accessory_output",
    "system_full_fdat_receiver",
}
_RECEIVER_FIELDS = {
    "status",
    "system_receiver_located",
    "libupdaterufp_is_system_receiver",
    "reason",
}
_CRYPTER_FIELDS = {
    "input_modes",
    "frame_bytes",
    "decrypt_api",
    "decrypt_mode",
    "cbc_implementation_present",
    "missing_cbc_stage",
    "decoded_fdat_bytes",
    "header_bytes",
    "updater_image_bytes",
    "firmware_archive_bytes",
}
_INTEGRITY_FIELDS = {
    "dat_outer_crc32",
    "decoded_inner_crc32",
    "component_sum_crc32",
    "outer_trailer_bytes",
    "outer_iv_bytes",
    "outer_suffix_bytes",
    "outer_suffix_role",
    "signature_plausible",
    "signature_proven",
}
_SA_FIELDS = {
    "aes_program_registered",
    "aes_program_sha256",
    "aes_program_id",
    "udrt_program_registered",
    "udrt_program_sha256",
    "udrt_program_id",
    "registry_type",
    "imdb_namespace_link_proven",
    "updater_invocation_proven",
}
_CLAIM_FIELDS = {"classification", "source", "claim"}
_FORBIDDEN_KEYS = {
    "raw",
    "raw_payload",
    "payload",
    "base64",
    "hex_dump",
    "decrypted_bytes",
    "private" + "_key",
}


def _require_fields(value: object, fields: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise UpdaterCryptoBoundaryError(f"{label} fields are invalid")
    return value


def _positive_int(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise UpdaterCryptoBoundaryError(f"{label} is invalid")
    return value


def _bounded_text(value: object, label: str, maximum: int = 1200) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or "\r" in value
        or "\n" in value
        or not value.isprintable()
    ):
        raise UpdaterCryptoBoundaryError(f"{label} is invalid")
    return value


def _reject_reconstructive_fields(value: object) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str) or key.casefold() in _FORBIDDEN_KEYS:
                raise UpdaterCryptoBoundaryError(
                    "Updater-boundary report contains a forbidden field"
                )
            _reject_reconstructive_fields(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_reconstructive_fields(nested)


def describe_protection_profile(
    *,
    raw_fdat_bytes: int,
    decoded_fdat_bytes: int,
    header_bytes: int,
    updater_image_bytes: int,
    firmware_archive_bytes: int,
    outer_trailer_bytes: int,
) -> dict:
    """Validate observed size relationships without decrypting or emitting bytes."""
    values = {
        "raw_fdat_bytes": raw_fdat_bytes,
        "decoded_fdat_bytes": decoded_fdat_bytes,
        "header_bytes": header_bytes,
        "updater_image_bytes": updater_image_bytes,
        "firmware_archive_bytes": firmware_archive_bytes,
        "outer_trailer_bytes": outer_trailer_bytes,
    }
    for label, value in values.items():
        _positive_int(value, label)

    if outer_trailer_bytes != 0x110 or raw_fdat_bytes <= outer_trailer_bytes:
        raise UpdaterCryptoBoundaryError("Outer protection geometry is unknown")
    ciphertext_bytes = raw_fdat_bytes - outer_trailer_bytes
    if ciphertext_bytes % 0x400:
        raise UpdaterCryptoBoundaryError("Outer ciphertext is not frame aligned")
    if decoded_fdat_bytes != header_bytes + updater_image_bytes + firmware_archive_bytes:
        raise UpdaterCryptoBoundaryError("Decoded FDAT layout is inconsistent")
    if header_bytes != 0x200:
        raise UpdaterCryptoBoundaryError("Decoded FDAT header size is unknown")

    return {
        "raw_fdat_bytes": raw_fdat_bytes,
        "ciphertext_bytes": ciphertext_bytes,
        "decoded_fdat_bytes": decoded_fdat_bytes,
        "outer_trailer_bytes": outer_trailer_bytes,
        "outer_iv_bytes": 0x10,
        "outer_suffix_bytes": 0x100,
        "outer_suffix_role": "unresolved",
        "missing_cbc_stage": "inferred-before-crypter",
        "signature_proven": False,
        "camera_executed": False,
        "installable": False,
    }


def _validate_claims(document: dict) -> None:
    for field, classification in (
        ("observations", "OBSERVATION"),
        ("inferences", "INFERENCE"),
        ("unresolved", "UNRESOLVED"),
    ):
        claims = document[field]
        if not isinstance(claims, list) or not 1 <= len(claims) <= 24:
            raise UpdaterCryptoBoundaryError(f"{field} claims are invalid")
        for claim in claims:
            _require_fields(claim, _CLAIM_FIELDS, "Updater-boundary claim")
            if claim["classification"] != classification:
                raise UpdaterCryptoBoundaryError(
                    "Updater-boundary claim classification is invalid"
                )
            _bounded_text(claim["source"], "Updater-boundary claim source", 300)
            _bounded_text(claim["claim"], "Updater-boundary claim")


def validate_updater_crypto_boundary_report(document: object) -> dict:
    """Validate observations without promoting hypotheses into a bypass."""
    _require_fields(document, _TOP_FIELDS, "Updater-boundary report")
    _reject_reconstructive_fields(document)
    if document["schema_version"] != 1:
        raise UpdaterCryptoBoundaryError("Updater-boundary schema is unsupported")
    if document["subject"] != "ILCE-6400 updater crypto and receiver boundary":
        raise UpdaterCryptoBoundaryError("Updater-boundary subject is invalid")
    if document["camera_policy"] != "physically-disconnected":
        raise UpdaterCryptoBoundaryError("Updater-boundary camera policy is invalid")
    for field in (
        "camera_executed",
        "bypass_established",
        "installable",
        "model_mismatch_safe",
    ):
        if document[field] is not False:
            raise UpdaterCryptoBoundaryError(f"{field} must remain false")

    host = _require_fields(document["host_transfer"], _HOST_FIELDS, "Host transfer")
    expected_host = {
        "engine_sha256": "8f2e8b229ef9e49a874cbf920301aba078727cebc490c891a992de60ff8a3528",
        "raw_fdat_bytes": 304_833_808,
        "dat_chunk_order": ["UDID", "FDAT"],
        "fdat_payload_start_recorded": True,
        "negotiated_request_bytes": 0x10000,
        "maximum_data_bytes": 0xFFD8,
        "guard_command": "0x0010",
        "guard_sequence1_payload_bytes": 0,
        "guard_sequence2_scope": "first-negotiated-chunk",
        "guard_stops_on_status_ok_before_eof": True,
        "reconnect_resets_to_fdat_start": True,
        "full_write_command": "0x0040",
    }
    if host != expected_host:
        raise UpdaterCryptoBoundaryError("Host-transfer evidence is invalid")
    if not _DIGEST.fullmatch(host["engine_sha256"]):
        raise UpdaterCryptoBoundaryError("Host engine digest is invalid")

    normal = _require_fields(
        document["normal_runtime"], _NORMAL_FIELDS, "Normal-runtime updater"
    )
    if normal != {
        "library": "libupdaterufp.so",
        "role": "header-guard-mode-switch-and-accessory-update",
        "guard_decryption": "aes-128-ecb",
        "guard_decrypted_prefix_bytes": 0x200,
        "guard_fields": ["model", "region", "version"],
        "mode_switch_scripts": ["up.sh ver", "up.sh user"],
        "mode_switch_reboots": True,
        "full_write_scope": "accessory-only",
        "accessory_tmpfs_bytes": 5 * 1024 * 1024,
        "accessory_output": "ACCYFIRM.BIN",
        "system_full_fdat_receiver": False,
    }:
        raise UpdaterCryptoBoundaryError("Normal-runtime evidence is invalid")

    receiver = _require_fields(
        document["updater_mode_receiver"], _RECEIVER_FIELDS, "Updater-mode receiver"
    )
    if (
        receiver["status"] != "unresolved"
        or receiver["system_receiver_located"] is not False
        or receiver["libupdaterufp_is_system_receiver"] is not False
    ):
        raise UpdaterCryptoBoundaryError("Updater-mode receiver was overclaimed")
    _bounded_text(receiver["reason"], "Updater-mode receiver reason")

    crypter = _require_fields(document["crypter"], _CRYPTER_FIELDS, "Crypter")
    if crypter != {
        "input_modes": ["chunk=fdat", "chunk=full"],
        "frame_bytes": 0x400,
        "decrypt_api": "Dec_Scramble",
        "decrypt_mode": "aes-128-ecb",
        "cbc_implementation_present": False,
        "missing_cbc_stage": "inferred-before-crypter",
        "decoded_fdat_bytes": 303_642_112,
        "header_bytes": 0x200,
        "updater_image_bytes": 143_360,
        "firmware_archive_bytes": 303_498_240,
    }:
        raise UpdaterCryptoBoundaryError("Crypter evidence is invalid")

    integrity = _require_fields(document["integrity"], _INTEGRITY_FIELDS, "Integrity")
    if integrity != {
        "dat_outer_crc32": True,
        "decoded_inner_crc32": True,
        "component_sum_crc32": True,
        "outer_trailer_bytes": 0x110,
        "outer_iv_bytes": 0x10,
        "outer_suffix_bytes": 0x100,
        "outer_suffix_role": "unresolved",
        "signature_plausible": True,
        "signature_proven": False,
    }:
        raise UpdaterCryptoBoundaryError("Integrity evidence was overclaimed")

    sa = _require_fields(document["sa_boundary"], _SA_FIELDS, "SA boundary")
    if sa["aes_program_registered"] is not True or sa["udrt_program_registered"] is not True:
        raise UpdaterCryptoBoundaryError("SA registry evidence is incomplete")
    for field in ("aes_program_sha256", "udrt_program_sha256"):
        if not isinstance(sa[field], str) or not _DIGEST.fullmatch(sa[field]):
            raise UpdaterCryptoBoundaryError(f"{field} is invalid")
    if sa != {
        "aes_program_registered": True,
        "aes_program_sha256": "8966f450591d7253058d4cbe9146d63831e0da128136c03d7c392ba830b25692",
        "aes_program_id": "0x13",
        "udrt_program_registered": True,
        "udrt_program_sha256": "bd634220c7a48eb4611de09f8abf29459306c403cc2e70119eb10623d838806a",
        "udrt_program_id": "0x3f",
        "registry_type": "0x93",
        "imdb_namespace_link_proven": False,
        "updater_invocation_proven": False,
    }:
        raise UpdaterCryptoBoundaryError("SA boundary was overclaimed")

    profile = describe_protection_profile(
        raw_fdat_bytes=host["raw_fdat_bytes"],
        decoded_fdat_bytes=crypter["decoded_fdat_bytes"],
        header_bytes=crypter["header_bytes"],
        updater_image_bytes=crypter["updater_image_bytes"],
        firmware_archive_bytes=crypter["firmware_archive_bytes"],
        outer_trailer_bytes=integrity["outer_trailer_bytes"],
    )
    if profile["outer_suffix_role"] != integrity["outer_suffix_role"]:
        raise UpdaterCryptoBoundaryError("Protection profile is inconsistent")

    _validate_claims(document)
    _bounded_text(document["conclusion"], "Updater-boundary conclusion")
    return copy.deepcopy(document)
