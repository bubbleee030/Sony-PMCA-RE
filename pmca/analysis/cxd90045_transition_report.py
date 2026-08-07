"""Fail-closed validation for the CXD90045 persistent-updater boundary.

This module validates bounded evidence metadata only. It deliberately has no
camera transport, cryptographic primitive, executable loader, or writer.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re


class Cxd90045TransitionReportError(ValueError):
    """Raised when transition evidence is malformed or overclaimed."""


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
    "host_transfer",
    "generation4_packages",
    "shared_static_artifacts",
    "updater_partition",
    "visible_runtime",
    "packaged_selector_scan",
    "packaged_selector_evidence",
    "observations",
    "inferences",
    "unresolved",
    "conclusion",
}
_HOST_FIELDS = {
    "engine_sha256",
    "engine_bytes",
    "observed_packages",
    "fdat_source",
    "raw_fdat_sent",
    "transform_before_usb",
    "transfer_command",
    "completion_command",
}
_PACKAGE_FIELDS = {"crypter_name", "trailer_bytes", "examples"}
_EXAMPLE_FIELDS = {
    "source_key",
    "artifact_kind",
    "artifact_sha256",
    "artifact_bytes",
    "version",
    "model",
    "region",
    "raw_fdat_bytes",
    "offline_decode_validated",
}
_SHARED_FIELDS = {
    "partinf_sha256",
    "partinf_identical",
    "up_sh_sha256",
    "up_sh_identical",
    "secure_apps_identical",
    "aes_program_sha256",
    "udrt_program_sha256",
    "a7m3_v400_v401_runtime_identical",
    "a7m3_crypter_sha256",
    "a7m3_ufp_sha256",
    "a7m3_talk_sha256",
}
_PARTITION_FIELDS = {
    "device",
    "label",
    "start_offset",
    "size_bytes",
    "filesystem",
    "payload_partition_images",
    "packages_checked",
    "included_in_payload",
    "mode_files_set_by_up_sh",
    "lsi_handoff_present",
    "normal_init_mounts_partition",
    "selection_stage",
    "contents_acquired",
    "cbc_stage_located",
    "signature_verifier_located",
    "trust_anchor_located",
}
_RUNTIME_FIELDS = {
    "normal_init_bootmode_path",
    "normal_init_bootmode_values",
    "lsi_utility_sha256",
    "lsi_handoff",
    "a6400_crypter_sha256",
    "a7m3_crypter_sha256",
    "decrypt_api",
    "decrypt_mode",
    "cbc_stage_present",
    "raw_fdat_written_before_crypter",
}
_PACKAGED_SELECTOR_SCAN_FIELDS = {
    "updater_flag_state_proven",
    "lsi_notification_proven",
    "packaged_flag_consumer_proven",
    "nflasha1_selector_join_proven",
    "updater_partition_selector_present",
    "bootin_direct_updater_selector",
    "external_or_opaque_selector_unresolved",
}
PACKAGED_SELECTOR_SCAN = {
    "updater_flag_state_proven": True,
    "lsi_notification_proven": True,
    "packaged_flag_consumer_proven": True,
    "nflasha1_selector_join_proven": False,
    "updater_partition_selector_present": False,
    "bootin_direct_updater_selector": False,
    "external_or_opaque_selector_unresolved": True,
}
PACKAGED_SELECTOR_EVIDENCE = {
    "sources": {
        "libobj": {
            "path": "lib/libObj.so",
            "bytes": 20860436,
            "sha256": "60ffd2b0f31f4bc139a7c13a4f62c25cdeb6a531ad5ef35df48471e6e36e88b1",
        },
        "up_sh": {
            "path": "bin/up.sh",
            "bytes": 5008,
            "sha256": "03a70fd0d0ef269c0de9530398d1e4d7cd8fcb089286cff682ee32d097ad16bd",
        },
        "crypter": {
            "path": "bin/crypter.elf",
            "bytes": 39084,
            "sha256": "ec971fc3ae7452ff3c5a46959fdb6fa6d9a27087cb226b23cc2cce0289c84653",
        },
        "bootin": {
            "path": "bin/bootin.elf",
            "bytes": 13116,
            "sha256": "44788cd57d3befcb5552006d73e7b5a3d92847a5710c084c696564673e09aad7",
        },
        "nested_body": {
            "path": "bin/udtrbody.bin",
            "bytes": 143360,
            "sha256": "09ee888c8a5242a292eec30dff3eff3e017761a573dab0a9f89d80f2a1c96f81",
        },
        "nested_script": {
            "path": "bin/udtrbody.bin_unpacked/bin/us_crc32sum_appli.sh",
            "bytes": 1888,
            "sha256": "991c31024ec077d6c43599df4f04d8c0b7e82f93e04b2a275368ea2c313bae41",
        },
    },
    "libobj_literal_consumers": [
        {
            "owner": {"start": 0x83E5B8, "end": 0x83E6B4},
            "classification": "mode-flag-literal-reference-owner",
            "xrefs": [
                {"path": "/setting/updater/mode", "load": 0x83E5DE, "add": 0x83E5E0},
                {"path": "/setting/updater/mode6", "load": 0x83E604, "add": 0x83E606},
                {"path": "/setting/updater/mode1", "load": 0x83E614, "add": 0x83E616},
                {"path": "/setting/updater/mode3", "load": 0x83E61A, "add": 0x83E61C},
            ],
        },
        {
            "owner": {"start": 0x83E79C, "end": 0x83EBA8},
            "classification": "mode-flag-literal-reference-owner",
            "xrefs": [
                {"path": "/setting/updater/mode", "load": 0x83E892, "add": 0x83E894},
                {"path": "/setting/updater/mode", "load": 0x83E8BA, "add": 0x83E8BC},
                {"path": "/setting/updater/mode3", "load": 0x83E8D0, "add": 0x83E8D2},
                {"path": "/setting/updater/mode", "load": 0x83E8F8, "add": 0x83E8FA},
                {"path": "/setting/updater/mode1", "load": 0x83E90E, "add": 0x83E910},
                {"path": "/setting/updater/mode", "load": 0x83E934, "add": 0x83E936},
                {"path": "/setting/updater/mode6", "load": 0x83E94A, "add": 0x83E94C},
                {"path": "/setting/updater/mode", "load": 0x83E9C4, "add": 0x83E9C6},
                {"path": "/setting/updater/mode3", "load": 0x83E9DA, "add": 0x83E9DC},
            ],
        },
        {
            "owner": {"start": 0x83F854, "end": 0x83FA4C},
            "classification": "dat4-literal-reference-owner",
            "xrefs": [
                {"path": "/setting/updater/dat4", "load": 0x83F86E, "add": 0x83F872},
            ],
        },
        {
            "owner": {"start": 0x83FA4C, "end": 0x83FACC},
            "classification": "dat4-literal-reference-owner",
            "xrefs": [
                {"path": "/setting/updater/dat4", "load": 0x83FA50, "add": 0x83FA58},
            ],
        },
    ],
    "up_sh": {
        "mode_flags": ["mode", "mode1", "mode3", "mode6"],
        "lsi_modes": [2, 3, 4, 6],
        "nflasha1_role": "dat2-dat3-metadata-storage",
        "dat4_role": "setting-partition-state",
    },
    "nested_updater_component": {
        "mode_flags_written": ["mode", "mode6"],
        "nflasha1_files_written": ["dat2", "dat3"],
        "setting_files_written": ["dat4"],
    },
    "crypter": {
        "flag_classes": [
            "ModeFlagFile", "Mode3FlagFile", "Mode5FlagFile", "Mode6FlagFile"
        ],
        "nested_body_paths_present": True,
    },
    "bootin": {
        "documented_application_modes": ["normal", "adj", "usbj"],
        "named_reference_search": {
            "scope": "printable-strings",
            "needles": ["updater", "nflasha1"],
            "hits": 0,
        },
    },
    "selector_assessment": {
        "nflasha1_selector_join_proven": False,
        "bounded_named_reference_search_only": True,
        "numeric_or_indirect_selector_analysis_complete": False,
        "external_or_opaque_selector_unresolved": True,
    },
    "first_unresolved_edge": "pre-normal-or-opaque-mode-to-updater-partition-selector",
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
        raise Cxd90045TransitionReportError(f"{label} fields are invalid")
    return value


def _bounded_text(value: object, label: str, maximum: int = 1400) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or "\r" in value
        or "\n" in value
        or not value.isprintable()
    ):
        raise Cxd90045TransitionReportError(f"{label} is invalid")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise Cxd90045TransitionReportError(f"{label} is invalid")
    return value


def _reject_reconstructive_fields(value: object) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str) or key.casefold() in _FORBIDDEN_KEYS:
                raise Cxd90045TransitionReportError(
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
        if not isinstance(claims, list) or not 1 <= len(claims) <= 24:
            raise Cxd90045TransitionReportError(f"{field} claims are invalid")
        for claim in claims:
            _require_fields(claim, _CLAIM_FIELDS, "Transition claim")
            if claim["classification"] != classification:
                raise Cxd90045TransitionReportError(
                    "Transition claim classification is invalid"
                )
            _bounded_text(claim["source"], "Transition claim source", 320)
            _bounded_text(claim["claim"], "Transition claim")


def _validate_packaged_selector_scan(value: object) -> dict:
    """Accept only the bounded false-lead result from packaged components.

    The scan covers four identified libObj path-literal owners, parsed up.sh
    and nested updater components, the crypter flag-file path, and bootin.elf
    normal/adj/usbj mode handling.  False ``*_proven`` values mean the join is
    not established, not that every numeric or indirect implementation has
    been excluded.  The unavailable/opaque selector boundary stays explicit.
    """
    scan = _require_fields(value, _PACKAGED_SELECTOR_SCAN_FIELDS, "Packaged selector scan")
    if scan != PACKAGED_SELECTOR_SCAN:
        raise Cxd90045TransitionReportError("Packaged selector scan was altered or promoted")
    return scan


def _validate_packaged_selector_evidence(value: object) -> dict:
    if value != PACKAGED_SELECTOR_EVIDENCE:
        raise Cxd90045TransitionReportError(
            "Packaged selector source evidence was altered or promoted"
        )
    return value


def canonical_cxd90045_transition_digest(document: object) -> str:
    """Return the canonical digest of a validated transition report."""
    validated = validate_cxd90045_transition_report(document)
    encoded = json.dumps(
        validated, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def build_cxd90045_transition_report(
    document: object, *, packaged_selector_evidence: object | None = None
) -> dict:
    """Upgrade a validated legacy report with the bounded selector result."""
    if not isinstance(document, dict):
        raise Cxd90045TransitionReportError("Transition source is invalid")
    report = copy.deepcopy(document)
    report["schema_version"] = 5
    report["packaged_selector_scan"] = copy.deepcopy(PACKAGED_SELECTOR_SCAN)
    evidence = (
        PACKAGED_SELECTOR_EVIDENCE
        if packaged_selector_evidence is None else packaged_selector_evidence
    )
    _validate_packaged_selector_evidence(evidence)
    report["packaged_selector_evidence"] = copy.deepcopy(evidence)
    return validate_cxd90045_transition_report(report)


def validate_cxd90045_transition_report(document: object) -> dict:
    """Validate static evidence while rejecting a bypass or flash claim."""
    _require_fields(document, _TOP_FIELDS, "Transition report")
    _reject_reconstructive_fields(document)
    if document["schema_version"] != 5:
        raise Cxd90045TransitionReportError("Transition schema is unsupported")
    if document["subject"] != (
        "ILCE-6400 CXD90045 transition, boot-mode, and persistent-updater boundary"
    ):
        raise Cxd90045TransitionReportError("Transition subject is invalid")
    if document["supersedes"] != (
        "analysis/a6400-updater-transition-boundary.json"
    ):
        raise Cxd90045TransitionReportError("Superseded report is invalid")
    if document["camera_policy"] != "physically-disconnected":
        raise Cxd90045TransitionReportError("Camera policy is invalid")
    for field in (
        "camera_executed",
        "bypass_established",
        "installable",
        "model_mismatch_safe",
    ):
        if document[field] is not False:
            raise Cxd90045TransitionReportError(f"{field} must remain false")

    host = _require_fields(document["host_transfer"], _HOST_FIELDS, "Host transfer")
    _digest(host["engine_sha256"], "Host engine digest")
    if host != {
        "engine_sha256": "8f2e8b229ef9e49a874cbf920301aba078727cebc490c891a992de60ff8a3528",
        "engine_bytes": 122_864,
        "observed_packages": ["ILCE-6400 v2.00", "ILCE-7M3 v4.00"],
        "fdat_source": "direct-DAT-file-read",
        "raw_fdat_sent": True,
        "transform_before_usb": False,
        "transfer_command": "0x0040",
        "completion_command": "0x0100",
    }:
        raise Cxd90045TransitionReportError("Host-transfer evidence is invalid")

    packages = _require_fields(
        document["generation4_packages"], _PACKAGE_FIELDS, "Package evidence"
    )
    if packages["crypter_name"] != "CXD90045" or packages["trailer_bytes"] != 0x110:
        raise Cxd90045TransitionReportError("Package protection is invalid")
    expected_examples = [
        {
            "source_key": "a6400-tw-v2.00",
            "artifact_kind": "official-updater-exe",
            "artifact_sha256": "ea460cbec5f8b62119630f0a653eeca4f4ffad887670e60c0fd9c0345e6b30a6",
            "artifact_bytes": 314_230_712,
            "version": "2.00",
            "model": "0x81030011",
            "region": 0,
            "raw_fdat_bytes": 304_833_808,
            "offline_decode_validated": True,
        },
        {
            "source_key": "a7m3-jp-v4.00",
            "artifact_kind": "FirmwareData.dat",
            "artifact_sha256": "89e85c102bffa8fcd3d7dd9879d5eb6f618c45d5f5102faa34df6b6425e84359",
            "artifact_bytes": 315_131_304,
            "version": "4.00",
            "model": "0x71030014",
            "region": 0,
            "raw_fdat_bytes": 315_131_152,
            "offline_decode_validated": True,
        },
        {
            "source_key": "a7m3-jp-v4.01",
            "artifact_kind": "FirmwareData.dat",
            "artifact_sha256": "e6e924dc5b2f6e127f50598989aa3b5fcdd7d97efc136b852092bc3904ca8134",
            "artifact_bytes": 314_827_176,
            "version": "4.01",
            "model": "0x71030014",
            "region": 0,
            "raw_fdat_bytes": 314_827_024,
            "offline_decode_validated": True,
        },
    ]
    if packages["examples"] != expected_examples:
        raise Cxd90045TransitionReportError("Package examples are invalid")
    for example in packages["examples"]:
        _require_fields(example, _EXAMPLE_FIELDS, "Package example")
        _digest(example["artifact_sha256"], "Package artifact digest")

    shared = _require_fields(
        document["shared_static_artifacts"], _SHARED_FIELDS, "Shared artifacts"
    )
    expected_shared = {
        "partinf_sha256": "fc23dc2edb8e378e7985fb5da4d09a0e4c5f2445d679a730fd1d544dde831f78",
        "partinf_identical": True,
        "up_sh_sha256": "03a70fd0d0ef269c0de9530398d1e4d7cd8fcb089286cff682ee32d097ad16bd",
        "up_sh_identical": True,
        "secure_apps_identical": True,
        "aes_program_sha256": "8966f450591d7253058d4cbe9146d63831e0da128136c03d7c392ba830b25692",
        "udrt_program_sha256": "bd634220c7a48eb4611de09f8abf29459306c403cc2e70119eb10623d838806a",
        "a7m3_v400_v401_runtime_identical": True,
        "a7m3_crypter_sha256": "5721d6f3147d54ff7bba7b246f080d0edd0e4378ae67ed9608a7df82c67a3fa1",
        "a7m3_ufp_sha256": "976661b9e0e6baac27eb092d69fa1745733d536f406ddd2fe1ef6790a3ca8b70",
        "a7m3_talk_sha256": "5a22e281c8ae0cac52058a5ad97c23dce08fe14948e4f2492b9a1e4dbaf9dd64",
    }
    if shared != expected_shared:
        raise Cxd90045TransitionReportError("Shared-artifact evidence is invalid")
    for key, value in shared.items():
        if key.endswith("_sha256"):
            _digest(value, f"{key} digest")

    partition = _require_fields(
        document["updater_partition"], _PARTITION_FIELDS, "Updater partition"
    )
    expected_partition = {
        "device": "/dev/nflasha1",
        "label": "System Group SYSTEM (Updater)",
        "start_offset": 0x0001_0000,
        "size_bytes": 0x007F_0000,
        "filesystem": "vfat",
        "payload_partition_images": ["nflasha3", "nflasha5", "nflasha7", "nflasha15"],
        "packages_checked": [
            "ILCE-6400 v2.00",
            "ILCE-7M3 v4.00",
            "ILCE-7M3 v4.01",
        ],
        "included_in_payload": False,
        "mode_files_set_by_up_sh": True,
        "lsi_handoff_present": True,
        "normal_init_mounts_partition": False,
        "selection_stage": "before-normal-userspace",
        "contents_acquired": False,
        "cbc_stage_located": False,
        "signature_verifier_located": False,
        "trust_anchor_located": False,
    }
    if partition != expected_partition:
        raise Cxd90045TransitionReportError("Updater-partition evidence is invalid")

    runtime = _require_fields(
        document["visible_runtime"], _RUNTIME_FIELDS, "Visible runtime"
    )
    expected_runtime = {
        "normal_init_bootmode_path": "/proc/udm/upm_bootmode",
        "normal_init_bootmode_values": ["USB_CHARGE", "ADJUST", "BIS"],
        "lsi_utility_sha256": "2a9abc332aadf118c5b99fff3539fd9e702202c8f928c1e619d1b3a689fc30a6",
        "lsi_handoff": "numeric-mode-via-message-queue",
        "a6400_crypter_sha256": "ec971fc3ae7452ff3c5a46959fdb6fa6d9a27087cb226b23cc2cce0289c84653",
        "a7m3_crypter_sha256": "5721d6f3147d54ff7bba7b246f080d0edd0e4378ae67ed9608a7df82c67a3fa1",
        "decrypt_api": "Dec_Scramble",
        "decrypt_mode": "aes-128-ecb",
        "cbc_stage_present": False,
        "raw_fdat_written_before_crypter": True,
    }
    if runtime != expected_runtime:
        raise Cxd90045TransitionReportError("Visible-runtime evidence is invalid")
    _digest(runtime["lsi_utility_sha256"], "LSI utility digest")
    _digest(runtime["a6400_crypter_sha256"], "Alpha 6400 crypter digest")
    _digest(runtime["a7m3_crypter_sha256"], "Alpha 7 III crypter digest")

    _validate_packaged_selector_scan(document["packaged_selector_scan"])
    _validate_packaged_selector_evidence(document["packaged_selector_evidence"])

    _validate_claims(document)
    _bounded_text(document["conclusion"], "Transition conclusion")
    return copy.deepcopy(document)
