"""Fail-closed validation for the alpha 6400 updater pipeline report.

The validator accepts metadata and bounded claims only. It has no camera,
transport, cryptographic, executable-loading, or firmware-writing backend.
"""

from __future__ import annotations

import copy
import re

from pmca.analysis.updater_pipeline_profile import describe_updater_pipeline


class UpdaterPipelineReportError(ValueError):
    """Raised when pipeline evidence is malformed or overclaimed."""


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_TOP_FIELDS = {
    "schema_version",
    "subject",
    "supersedes",
    "camera_policy",
    "camera_executed",
    "bypass_established",
    "installable",
    "model_mismatch_safe",
    "receiver",
    "crypter",
    "body_pipeline",
    "secure_apps",
    "integrity",
    "observations",
    "inferences",
    "unresolved",
    "conclusion",
}
_RECEIVER_FIELDS = {
    "library",
    "sha256",
    "system_receiver_located",
    "receive_command",
    "stored_path",
    "maximum_data_bytes",
    "completion_command",
    "completion_action",
    "second_host_transfer",
    "reason",
}
_CRYPTER_FIELDS = {
    "executable",
    "sha256",
    "talk_library",
    "talk_library_sha256",
    "input_modes",
    "frame_bytes",
    "decrypt_api",
    "decrypt_mode",
    "decrypt_key_family",
    "key_material_omitted",
    "cbc_implementation_present",
    "pre_crypter_transform",
    "pre_crypter_transform_implementation",
    "raw_fdat_bytes",
    "decoded_fdat_bytes",
    "header_bytes",
    "updater_image_bytes",
    "firmware_archive_bytes",
}
_BODY_FIELDS = {
    "body_library",
    "body_library_sha256",
    "ring_buffer_library",
    "ring_buffer_library_sha256",
    "factory_symbols",
    "consumer_entry",
    "consumer_input",
    "producer",
    "producer_frame_bytes",
    "body_images",
    "second_host_transfer",
    "role",
}
_SECURE_FIELDS = {
    "aes_program",
    "aes_program_sha256",
    "aes_program_id",
    "aes_program_architecture",
    "aes_pointer_derived_image_base",
    "aes_ttable_offset",
    "sha256_constant_offsets",
    "udrt_program",
    "udrt_program_sha256",
    "udrt_program_id",
    "udrt_program_architecture",
    "generic_decoder_status",
    "key_material_omitted",
    "updater_invocation_proven",
    "generation4_transform_link_proven",
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
_CLAIM_FIELDS = {"classification", "source", "claim"}
_FORBIDDEN_KEYS = {
    "raw_payload",
    "payload",
    "base64",
    "hex_dump",
    "decrypted_bytes",
    "key_bytes",
    "private" + "_key",
}


def _require_fields(value: object, fields: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise UpdaterPipelineReportError(f"{label} fields are invalid")
    return value


def _bounded_text(value: object, label: str, maximum: int = 1200) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or "\r" in value
        or "\n" in value
        or not value.isprintable()
    ):
        raise UpdaterPipelineReportError(f"{label} is invalid")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise UpdaterPipelineReportError(f"{label} is invalid")
    return value


def _reject_reconstructive_fields(value: object) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str) or key.casefold() in _FORBIDDEN_KEYS:
                raise UpdaterPipelineReportError(
                    "Pipeline report contains a forbidden field"
                )
            _reject_reconstructive_fields(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_reconstructive_fields(nested)


def _validate_claims(document: dict) -> None:
    for field, classification in (
        ("observations", "OBSERVATION"),
        ("inferences", "INFERENCE"),
        ("unresolved", "UNRESOLVED"),
    ):
        claims = document[field]
        if not isinstance(claims, list) or not 1 <= len(claims) <= 24:
            raise UpdaterPipelineReportError(f"{field} claims are invalid")
        for claim in claims:
            _require_fields(claim, _CLAIM_FIELDS, "Pipeline claim")
            if claim["classification"] != classification:
                raise UpdaterPipelineReportError(
                    "Pipeline claim classification is invalid"
                )
            _bounded_text(claim["source"], "Pipeline claim source", 300)
            _bounded_text(claim["claim"], "Pipeline claim")


def validate_updater_pipeline_report(document: object) -> dict:
    """Validate proven structure while rejecting a claimed bypass or flash path."""
    _require_fields(document, _TOP_FIELDS, "Pipeline report")
    _reject_reconstructive_fields(document)
    if document["schema_version"] != 2:
        raise UpdaterPipelineReportError("Pipeline schema is unsupported")
    if document["subject"] != (
        "ILCE-6400 updater receiver, transcode, and body pipeline boundary"
    ):
        raise UpdaterPipelineReportError("Pipeline subject is invalid")
    if document["supersedes"] != "analysis/a6400-updater-crypto-boundary.json":
        raise UpdaterPipelineReportError("Superseded report is invalid")
    if document["camera_policy"] != "physically-disconnected":
        raise UpdaterPipelineReportError("Camera policy is invalid")
    for field in (
        "camera_executed",
        "bypass_established",
        "installable",
        "model_mismatch_safe",
    ):
        if document[field] is not False:
            raise UpdaterPipelineReportError(f"{field} must remain false")

    receiver = _require_fields(document["receiver"], _RECEIVER_FIELDS, "Receiver")
    if receiver != {
        "library": "libupdaterufp.so",
        "sha256": "93ddfa0212f19ad0d204cc41a241ca3dadb0b049725812d48e2df50ba2f16f4f",
        "system_receiver_located": True,
        "receive_command": "0x0040",
        "stored_path": "/tmp_updater/Firm.dat",
        "maximum_data_bytes": 0xFFD8,
        "completion_command": "0x0100",
        "completion_action": "launch-crypter.elf",
        "second_host_transfer": False,
        "reason": receiver["reason"],
    }:
        raise UpdaterPipelineReportError("Receiver evidence is invalid")
    _digest(receiver["sha256"], "Receiver digest")
    _bounded_text(receiver["reason"], "Receiver reason")

    crypter = _require_fields(document["crypter"], _CRYPTER_FIELDS, "Crypter")
    if crypter != {
        "executable": "crypter.elf",
        "sha256": "ec971fc3ae7452ff3c5a46959fdb6fa6d9a27087cb226b23cc2cce0289c84653",
        "talk_library": "libupdatertalk.so",
        "talk_library_sha256": "1e36b989214aafb0a426a45ee06a578d17814926226e3d39307a0124fdf90587",
        "input_modes": ["chunk=fdat", "chunk=full"],
        "frame_bytes": 0x400,
        "decrypt_api": "Dec_Scramble",
        "decrypt_mode": "aes-128-ecb",
        "decrypt_key_family": "historical-first-stage",
        "key_material_omitted": True,
        "cbc_implementation_present": False,
        "pre_crypter_transform": "generation4-to-legacy-ecb-transcode-required",
        "pre_crypter_transform_implementation": "unresolved",
        "raw_fdat_bytes": 304_833_808,
        "decoded_fdat_bytes": 303_642_112,
        "header_bytes": 0x200,
        "updater_image_bytes": 143_360,
        "firmware_archive_bytes": 303_498_240,
    }:
        raise UpdaterPipelineReportError("Crypter evidence is invalid")
    _digest(crypter["sha256"], "Crypter digest")
    _digest(crypter["talk_library_sha256"], "Talk-library digest")

    body = _require_fields(document["body_pipeline"], _BODY_FIELDS, "Body pipeline")
    if body != {
        "body_library": "libupdaterbody.so",
        "body_library_sha256": "6daad7d8be8807e068563d09436f83b1eadb93a365248c78e6add2f15cfea01d",
        "ring_buffer_library": "libupdatercommon.so",
        "ring_buffer_library_sha256": "78ee7c1c9fbd62fdf395fe3ca9c71e440f33794d591bb37b93d77d12b62a11de",
        "factory_symbols": ["GetBody", "ReleaseBody"],
        "consumer_entry": "UpdaterBody::Execute",
        "consumer_input": "Updater::RingBuffer",
        "producer": "MsDecryptorModule",
        "producer_frame_bytes": 0x400,
        "body_images": [
            "/usr/bin/udtrbody.bin",
            "/tmp_updater/updater/bodyimg",
        ],
        "second_host_transfer": False,
        "role": "decrypted-stream-archive-consumer",
    }:
        raise UpdaterPipelineReportError("Body-pipeline evidence is invalid")
    _digest(body["body_library_sha256"], "Body-library digest")
    _digest(body["ring_buffer_library_sha256"], "Ring-buffer-library digest")

    secure = _require_fields(document["secure_apps"], _SECURE_FIELDS, "Secure apps")
    if secure != {
        "aes_program": "sa_aes_sha2.bin",
        "aes_program_sha256": "8966f450591d7253058d4cbe9146d63831e0da128136c03d7c392ba830b25692",
        "aes_program_id": "0x13",
        "aes_program_architecture": "xtensa-custom-extension-image",
        "aes_pointer_derived_image_base": "0x00048000",
        "aes_ttable_offset": "0x00004b70",
        "sha256_constant_offsets": ["0x00001758", "0x000024a8"],
        "udrt_program": "sa_udrt.bin",
        "udrt_program_sha256": "bd634220c7a48eb4611de09f8abf29459306c403cc2e70119eb10623d838806a",
        "udrt_program_id": "0x3f",
        "udrt_program_architecture": "xtensa-custom-extension-image",
        "generic_decoder_status": "partial-unsupported-custom-instructions",
        "key_material_omitted": True,
        "updater_invocation_proven": False,
        "generation4_transform_link_proven": False,
    }:
        raise UpdaterPipelineReportError("Secure-app evidence was overclaimed")
    _digest(secure["aes_program_sha256"], "AES-program digest")
    _digest(secure["udrt_program_sha256"], "UDRT-program digest")

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
        raise UpdaterPipelineReportError("Integrity evidence was overclaimed")

    profile = describe_updater_pipeline(
        raw_fdat_bytes=crypter["raw_fdat_bytes"],
        decoded_fdat_bytes=crypter["decoded_fdat_bytes"],
        header_bytes=crypter["header_bytes"],
        updater_image_bytes=crypter["updater_image_bytes"],
        firmware_archive_bytes=crypter["firmware_archive_bytes"],
        outer_trailer_bytes=integrity["outer_trailer_bytes"],
    )
    if (
        profile["pre_crypter_transform"] != crypter["pre_crypter_transform"]
        or profile["pre_crypter_transform_implementation"]
        != crypter["pre_crypter_transform_implementation"]
    ):
        raise UpdaterPipelineReportError("Pipeline geometry is inconsistent")

    _validate_claims(document)
    _bounded_text(document["conclusion"], "Pipeline conclusion")
    return copy.deepcopy(document)
