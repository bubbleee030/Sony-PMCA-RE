"""Fail-closed validation for the alpha 6400 updater transition boundary.

This module validates evidence metadata only. It deliberately has no camera
transport, cryptographic primitive, executable loader, or firmware writer.
"""

from __future__ import annotations

import copy
import re


class UpdaterTransitionReportError(ValueError):
    """Raised when transition evidence is malformed or overclaimed."""


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_TOP_FIELDS = {
    "schema_version",
    "subject",
    "supersedes",
    "camera_policy",
    "package_target_version",
    "analyzed_system_version",
    "installing_system_version",
    "same_receiver_artifact_proven",
    "camera_executed",
    "bypass_established",
    "installable",
    "model_mismatch_safe",
    "host_path",
    "v2_system_path",
    "installing_receiver",
    "observations",
    "inferences",
    "unresolved",
    "conclusion",
}
_HOST_FIELDS = {
    "signed_updater_sha256",
    "fdat_source",
    "raw_fdat_sent",
    "transform_before_usb",
    "transfer_command",
    "completion_command",
}
_V2_FIELDS = {
    "receiver_sha256",
    "crypter_sha256",
    "artifact_role",
    "raw_fdat_written",
    "direct_file_read",
    "module_chain",
    "frame_bytes",
    "block_bytes",
    "decrypt_api",
    "decrypt_mode",
    "cbc_stage_present",
    "key_material_omitted",
}
_INSTALLING_FIELDS = {
    "version_relationship",
    "artifact_located",
    "artifact_source_needed",
    "generation4_transform_location",
    "v2_system_crypter_is_installing_crypter",
    "safe_next_evidence",
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
        raise UpdaterTransitionReportError(f"{label} fields are invalid")
    return value


def _bounded_text(value: object, label: str, maximum: int = 1200) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or "\r" in value
        or "\n" in value
        or not value.isprintable()
    ):
        raise UpdaterTransitionReportError(f"{label} is invalid")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise UpdaterTransitionReportError(f"{label} is invalid")
    return value


def _reject_reconstructive_fields(value: object) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str) or key.casefold() in _FORBIDDEN_KEYS:
                raise UpdaterTransitionReportError(
                    "Transition report contains a forbidden field"
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
        if not isinstance(claims, list) or not 1 <= len(claims) <= 20:
            raise UpdaterTransitionReportError(f"{field} claims are invalid")
        for claim in claims:
            _require_fields(claim, _CLAIM_FIELDS, "Transition claim")
            if claim["classification"] != classification:
                raise UpdaterTransitionReportError(
                    "Transition claim classification is invalid"
                )
            _bounded_text(claim["source"], "Transition claim source", 300)
            _bounded_text(claim["claim"], "Transition claim")


def validate_updater_transition_report(document: object) -> dict:
    """Validate version-separated evidence while rejecting a flash claim."""
    _require_fields(document, _TOP_FIELDS, "Transition report")
    _reject_reconstructive_fields(document)
    if document["schema_version"] != 3:
        raise UpdaterTransitionReportError("Transition schema is unsupported")
    if document["subject"] != (
        "ILCE-6400 v2.00 updater transition and receiver-version boundary"
    ):
        raise UpdaterTransitionReportError("Transition subject is invalid")
    if document["supersedes"] != "analysis/a6400-updater-pipeline-boundary-v2.json":
        raise UpdaterTransitionReportError("Superseded report is invalid")
    if document["camera_policy"] != "physically-disconnected":
        raise UpdaterTransitionReportError("Camera policy is invalid")
    if document["package_target_version"] != "2.00":
        raise UpdaterTransitionReportError("Package target version is invalid")
    if document["analyzed_system_version"] != "2.00":
        raise UpdaterTransitionReportError("Analyzed system version is invalid")
    if document["installing_system_version"] != "pre-2.00":
        raise UpdaterTransitionReportError("Installing system version is invalid")
    for field in (
        "same_receiver_artifact_proven",
        "camera_executed",
        "bypass_established",
        "installable",
        "model_mismatch_safe",
    ):
        if document[field] is not False:
            raise UpdaterTransitionReportError(f"{field} must remain false")

    host = _require_fields(document["host_path"], _HOST_FIELDS, "Host path")
    _digest(host["signed_updater_sha256"], "Signed updater digest")
    if host != {
        "signed_updater_sha256": host["signed_updater_sha256"],
        "fdat_source": "direct-DAT-file-read",
        "raw_fdat_sent": True,
        "transform_before_usb": False,
        "transfer_command": "0x0040",
        "completion_command": "0x0100",
    }:
        raise UpdaterTransitionReportError("Host-path evidence is invalid")

    system = _require_fields(document["v2_system_path"], _V2_FIELDS, "V2 path")
    _digest(system["receiver_sha256"], "Receiver digest")
    _digest(system["crypter_sha256"], "Crypter digest")
    if system != {
        "receiver_sha256": "93ddfa0212f19ad0d204cc41a241ca3dadb0b049725812d48e2df50ba2f16f4f",
        "crypter_sha256": "ec971fc3ae7452ff3c5a46959fdb6fa6d9a27087cb226b23cc2cce0289c84653",
        "artifact_role": "post-install-v2-system",
        "raw_fdat_written": True,
        "direct_file_read": True,
        "module_chain": [
            "BaseFirmware",
            "MsDecryptorModule",
            "FileInputBodyLoaderModule",
        ],
        "frame_bytes": 0x400,
        "block_bytes": 0x10,
        "decrypt_api": "Dec_Scramble",
        "decrypt_mode": "aes-128-ecb",
        "cbc_stage_present": False,
        "key_material_omitted": True,
    }:
        raise UpdaterTransitionReportError("V2 system-path evidence is invalid")

    receiver = _require_fields(
        document["installing_receiver"], _INSTALLING_FIELDS, "Installing receiver"
    )
    if receiver != {
        "version_relationship": "runs-before-v2-system-partitions-are-installed",
        "artifact_located": False,
        "artifact_source_needed": "pre-2.00-camera-system-image",
        "generation4_transform_location": "unresolved",
        "v2_system_crypter_is_installing_crypter": False,
        "safe_next_evidence": "authentic-pre-2.00-receiver-or-equivalent-transition-build",
    }:
        raise UpdaterTransitionReportError("Installing-receiver evidence is invalid")

    _validate_claims(document)
    _bounded_text(document["conclusion"], "Transition conclusion")
    return copy.deepcopy(document)
