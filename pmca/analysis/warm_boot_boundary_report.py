"""Fail-closed validation for the CXD90045 warm-boot boundary report.

This module validates bounded static evidence only. It deliberately has no
camera transport, executable loader, cryptographic primitive, or writer.
"""

from __future__ import annotations

import copy
import re


class WarmBootBoundaryReportError(ValueError):
    """Raised when warm-boot evidence is malformed or overclaimed."""


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
    "warm_boot_images",
    "release_comparison",
    "resume_path",
    "string_attribution",
    "normal_main_partition",
    "loader_driver",
    "secure_start",
    "service_acquisition_route",
    "observations",
    "inferences",
    "unresolved",
    "conclusion",
}
_WBI_FIELDS = {
    "source",
    "model",
    "version",
    "file_bytes",
    "sha256",
    "sections",
    "resume_vector",
    "sector_bytes",
    "compressed_bytes",
    "uncompressed_bytes",
    "first_section_sha256",
}
_COMPARISON_FIELDS = {
    "pair",
    "left_sections",
    "right_sections",
    "shared_addresses",
    "same_at_address",
    "changed_at_address",
    "identical_content_anywhere",
    "left_only_addresses",
    "right_only_addresses",
}
_RESUME_FIELDS = {
    "role",
    "entries",
    "restores",
    "reads_boot_mode",
    "reads_updater_partition",
    "verifies_firmware",
    "updater_selector",
}
_ENTRY_FIELDS = {"source", "entry", "decompiled", "core_id_written"}
_STRING_FIELDS = {
    "ldr_boot_mode_updater_hits",
    "ldr_string_owner",
    "exact_updater_partition_path_hits",
    "path_string_owners",
    "selector_evidence",
}
_MAIN_FIELDS = {
    "partition",
    "a6400_init_sha256",
    "a7m3_init_sha256",
    "init_copies_identical",
    "mounted_partitions",
    "init_mounts_updater_partition",
    "kernel_updater_partition_mentions",
}
_LOADER_FIELDS = {
    "filename",
    "bytes",
    "sha256",
    "identical_across_packages",
    "role",
    "dispatch_record_bytes",
    "filesystem_access",
    "boot_mode_policy",
    "signature_verifier",
    "cryptographic_transform",
}
_SECURE_FIELDS = {
    "identical_across_packages",
    "artifacts",
    "decoder_result",
    "firmware_verifier_proven",
    "firmware_crypto_role_proven",
}
_SECURE_ARTIFACT_FIELDS = {"name", "bytes", "sha256"}
_SERVICE_FIELDS = {
    "backend",
    "read_primitive",
    "existing_shell_command",
    "candidate_source",
    "expected_bytes",
    "read_primitive_present",
    "write_required",
    "camera_validated",
    "dump_acquired",
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
        raise WarmBootBoundaryReportError(f"{label} fields are invalid")
    return value


def _bounded_text(value: object, label: str, maximum: int = 1400) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or "\r" in value
        or "\n" in value
        or not value.isprintable()
    ):
        raise WarmBootBoundaryReportError(f"{label} is invalid")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise WarmBootBoundaryReportError(f"{label} is invalid")
    return value


def _reject_reconstructive_fields(value: object) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str) or key.casefold() in _FORBIDDEN_KEYS:
                raise WarmBootBoundaryReportError(
                    "Warm-boot report contains a forbidden field"
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
            raise WarmBootBoundaryReportError(f"{field} claims are invalid")
        for claim in claims:
            _require_fields(claim, _CLAIM_FIELDS, "Warm-boot claim")
            if claim["classification"] != classification:
                raise WarmBootBoundaryReportError(
                    "Warm-boot claim classification is invalid"
                )
            _bounded_text(claim["source"], "Warm-boot claim source", 320)
            _bounded_text(claim["claim"], "Warm-boot claim")


def validate_warm_boot_boundary_report(document: object) -> dict:
    """Validate static findings while rejecting a bypass or flash claim."""
    _require_fields(document, _TOP_FIELDS, "Warm-boot report")
    _reject_reconstructive_fields(document)
    if document["schema_version"] != 5:
        raise WarmBootBoundaryReportError("Warm-boot schema is unsupported")
    if document["subject"] != (
        "ILCE-6400 CXD90045 warm-boot and pre-updater selection boundary"
    ):
        raise WarmBootBoundaryReportError("Warm-boot subject is invalid")
    if document["supersedes"] != (
        "analysis/a6400-cxd90045-transition-boundary.json"
    ):
        raise WarmBootBoundaryReportError("Superseded report is invalid")
    if document["camera_policy"] != "physically-disconnected":
        raise WarmBootBoundaryReportError("Camera policy is invalid")
    for field in (
        "camera_executed",
        "bypass_established",
        "installable",
        "model_mismatch_safe",
    ):
        if document[field] is not False:
            raise WarmBootBoundaryReportError(f"{field} must remain false")

    expected_images = [
        {
            "source": "a6400-tw-v2.00",
            "model": "ILCE-6400",
            "version": "2.00",
            "file_bytes": 33_486_976,
            "sha256": "19a702b030306a32f4287131da314e5c89d66163997f0f9a23b0967981b0001b",
            "sections": 644,
            "resume_vector": "0x00124b9c",
            "sector_bytes": 512,
            "compressed_bytes": 33_204_224,
            "uncompressed_bytes": 145_162_240,
            "first_section_sha256": "ea837bce378e9db3c6d87440075538cf60a92ba4a2a93a3afc4904654046f6e5",
        },
        {
            "source": "a7m3-jp-v4.00",
            "model": "ILCE-7M3",
            "version": "4.00",
            "file_bytes": 30_654_368,
            "sha256": "91e9ab602a2a23a6295d222c216c086b41ad41409ca9ddd6501b972e63dc1652",
            "sections": 621,
            "resume_vector": "0x0012463c",
            "sector_bytes": 512,
            "compressed_bytes": 30_372_352,
            "uncompressed_bytes": 128_307_200,
            "first_section_sha256": "9000955b8c849a83d8a77820330ffda070fde5cdaa65756a823c9638e4e5711f",
        },
        {
            "source": "a7m3-jp-v4.01",
            "model": "ILCE-7M3",
            "version": "4.01",
            "file_bytes": 30_351_392,
            "sha256": "03d431d292c1b04cebd13b12defb177d88571712f48644322efcd97846e5641c",
            "sections": 625,
            "resume_vector": "0x0012463c",
            "sector_bytes": 512,
            "compressed_bytes": 30_069_248,
            "uncompressed_bytes": 128_126_976,
            "first_section_sha256": "16a8ad70b75c93a20efc92946f7b3d775ef24391c9ee872de4758a2c80f3e4e9",
        },
    ]
    images = document["warm_boot_images"]
    if not isinstance(images, list) or len(images) != len(expected_images):
        raise WarmBootBoundaryReportError("Warm-boot image list is invalid")
    for image, expected in zip(images, expected_images):
        _require_fields(image, _WBI_FIELDS, "Warm-boot image")
        _digest(image["sha256"], "Warm-boot image digest")
        _digest(image["first_section_sha256"], "First-section digest")
        if image != expected:
            raise WarmBootBoundaryReportError("Warm-boot image evidence is invalid")

    comparison = _require_fields(
        document["release_comparison"], _COMPARISON_FIELDS, "Release comparison"
    )
    if comparison != {
        "pair": "ILCE-7M3 v4.00 -> v4.01",
        "left_sections": 621,
        "right_sections": 625,
        "shared_addresses": 167,
        "same_at_address": 75,
        "changed_at_address": 92,
        "identical_content_anywhere": 77,
        "left_only_addresses": 454,
        "right_only_addresses": 458,
    }:
        raise WarmBootBoundaryReportError("Release comparison is invalid")

    resume = _require_fields(document["resume_path"], _RESUME_FIELDS, "Resume path")
    if resume["role"] != "cpu-context-restore-trampoline":
        raise WarmBootBoundaryReportError("Resume role is invalid")
    expected_entries = [
        {
            "source": "a6400-tw-v2.00",
            "entry": "0x00124b9c",
            "decompiled": True,
            "core_id_written": 4,
        },
        {
            "source": "a7m3-jp-v4.00",
            "entry": "0x0012463c",
            "decompiled": True,
            "core_id_written": 4,
        },
    ]
    if resume["entries"] != expected_entries:
        raise WarmBootBoundaryReportError("Resume entries are invalid")
    for entry in resume["entries"]:
        _require_fields(entry, _ENTRY_FIELDS, "Resume entry")
    if resume["restores"] != [
        "barriers",
        "tlb",
        "mmu-control",
        "translation-tables",
        "thread-context",
        "saved-resume-target",
    ]:
        raise WarmBootBoundaryReportError("Resume state list is invalid")
    for field in (
        "reads_boot_mode",
        "reads_updater_partition",
        "verifies_firmware",
        "updater_selector",
    ):
        if resume[field] is not False:
            raise WarmBootBoundaryReportError(f"resume_path.{field} must remain false")

    attribution = _require_fields(
        document["string_attribution"], _STRING_FIELDS, "String attribution"
    )
    if attribution != {
        "ldr_boot_mode_updater_hits": 3,
        "ldr_string_owner": "loaded-upm-power-management-module",
        "exact_updater_partition_path_hits": [3, 2, 3],
        "path_string_owners": [
            "generic-media-device-table",
            "ordinary-application-memory",
        ],
        "selector_evidence": False,
    }:
        raise WarmBootBoundaryReportError("String attribution is invalid")

    main = _require_fields(
        document["normal_main_partition"], _MAIN_FIELDS, "Normal main partition"
    )
    _digest(main["a6400_init_sha256"], "alpha 6400 init digest")
    _digest(main["a7m3_init_sha256"], "alpha 7 III init digest")
    if main != {
        "partition": "/dev/nflasha3",
        "a6400_init_sha256": "0af5724ece7f60db2831b7a4e61829be369868027877cca0f921f981ae8dc7ad",
        "a7m3_init_sha256": "1dbe18fea1aad7c78e0f87bfd2e3184885ed13309d29a13da4e146f750251b21",
        "init_copies_identical": True,
        "mounted_partitions": [
            "nflasha2",
            "nflasha3",
            "nflasha7",
            "nflasha10",
            "nflasha11",
            "nflasha12",
            "nflasha15",
            "nflasha18",
            "nflasha23",
            "nflasha24",
            "nflasha25",
        ],
        "init_mounts_updater_partition": False,
        "kernel_updater_partition_mentions": 0,
    }:
        raise WarmBootBoundaryReportError("Normal main-partition evidence is invalid")

    loader = _require_fields(
        document["loader_driver"], _LOADER_FIELDS, "Loader driver"
    )
    _digest(loader["sha256"], "Loader-driver digest")
    if loader != {
        "filename": "ldr_drv.bin",
        "bytes": 6796,
        "sha256": "d5cec3780a459f490d1f14046864249538da2e1d9703f58e7f4966025cdd3ac7",
        "identical_across_packages": True,
        "role": "register-and-transfer-dispatch",
        "dispatch_record_bytes": 80,
        "filesystem_access": False,
        "boot_mode_policy": False,
        "signature_verifier": False,
        "cryptographic_transform": False,
    }:
        raise WarmBootBoundaryReportError("Loader-driver evidence is invalid")

    secure = _require_fields(document["secure_start"], _SECURE_FIELDS, "Secure start")
    if secure["identical_across_packages"] is not True:
        raise WarmBootBoundaryReportError("Secure-start identity is invalid")
    expected_secure_artifacts = [
        {
            "name": "ssboot.bin",
            "bytes": 11_280,
            "sha256": "a707c285f8f1768481d0602e367c791efc850ab5a770ee59286c752b7ec38b8e",
        },
        {
            "name": "ssboot_any.bin",
            "bytes": 9_648,
            "sha256": "a018e8879afafce75e9881b0bf3f14199fe01028354562bc4567af9fcba310d4",
        },
        {
            "name": "sa_dfdet.bin",
            "bytes": 156_292,
            "sha256": "356d7483edc74a082a10864f517d8f76f71986dee5334d7dcb564edbe98ebf3f",
        },
        {
            "name": "idt_cam.bin",
            "bytes": 176_528,
            "sha256": "d21e2c0b6b87f49f70ccf451781093037db8093b5a378587ec0029a16dcaef92",
        },
    ]
    if secure["artifacts"] != expected_secure_artifacts:
        raise WarmBootBoundaryReportError("Secure-start artifacts are invalid")
    for artifact in secure["artifacts"]:
        _require_fields(artifact, _SECURE_ARTIFACT_FIELDS, "Secure-start artifact")
        _digest(artifact["sha256"], "Secure-start digest")
    if secure["decoder_result"] != "custom-instruction-boundary":
        raise WarmBootBoundaryReportError("Secure-start decoder result is invalid")
    for field in ("firmware_verifier_proven", "firmware_crypto_role_proven"):
        if secure[field] is not False:
            raise WarmBootBoundaryReportError(f"secure_start.{field} must remain false")

    service = _require_fields(
        document["service_acquisition_route"],
        _SERVICE_FIELDS,
        "Service acquisition route",
    )
    if service != {
        "backend": "SenserPlatformBackend",
        "read_primitive": "readFile",
        "existing_shell_command": "pull",
        "candidate_source": "/dev/nflasha1",
        "expected_bytes": 8_323_072,
        "read_primitive_present": True,
        "write_required": False,
        "camera_validated": False,
        "dump_acquired": False,
    }:
        raise WarmBootBoundaryReportError("Service acquisition route is invalid")

    _validate_claims(document)
    _bounded_text(document["conclusion"], "Warm-boot conclusion", 2200)
    return copy.deepcopy(document)
