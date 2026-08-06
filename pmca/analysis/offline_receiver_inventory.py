"""Validate the fail-closed offline inventory for an α6400 installing receiver."""

from copy import deepcopy


class OfflineReceiverInventoryError(ValueError):
    """Raised when offline receiver inventory evidence is promoted or malformed."""


_FORBIDDEN_KEYS = {
    "firmware_path",
    "key_material",
    "partition_bytes",
    "private_key",
    "raw_bytes",
    "raw_payload",
    "write_command",
}

EXPECTED_INVENTORY = {
    "schema_version": 1,
    "subject": "ILCE-6400 offline pre-2.00 receiver and selector source inventory",
    "snapshot_date": "2026-08-06",
    "camera_policy": "physically-disconnected",
    "camera_executed": False,
    "sony_binary_executed": False,
    "installable": False,
    "search_scopes": [
        {
            "id": "canonical-workspace",
            "root_kind": "repository-ignored-artifacts",
            "exact_target_packages": 1,
            "exact_pre_2_00_target_packages": 0,
            "inventory_method": "recursive-filename-and-metadata-only",
        },
        {
            "id": "offline-downloads",
            "root_kind": "existing-download-directory",
            "exact_target_packages": 1,
            "exact_pre_2_00_target_packages": 0,
            "inventory_method": "recursive-filename-extension-size-and-hash",
        },
    ],
    "exact_target": {
        "model": "ILCE-6400",
        "model_id": "0x81030011",
        "region": "TW",
        "region_code": 0,
        "stock_version": "2.00",
        "stock_source_key": "a6400-tw-v2.00",
        "stock_updater_sha256": "ea460cbec5f8b62119630f0a653eeca4f4ffad887670e60c0fd9c0345e6b30a6",
        "pre_2_00_package_present": False,
        "installing_receiver_located": False,
        "pre_normal_selector_located": False,
    },
    "control_samples": [
        {
            "id": "a6400a-eu-v1.01",
            "model": "ILCE-6400A",
            "model_id": "0x81030017",
            "region": "EU",
            "version": "1.01",
            "updater_sha256": "fd6ae50755a9202a8b506b6b77aa27ab41ae717e96f05a0d4e2ad699b40d9ad1",
            "updater_partition_sha256": "c9040270ad886214c5656894b90fb1e839a3ab942cb65726633d8f1f1221c093",
            "relationship": "older-same-family-different-model-control",
            "persistent_updater_partition_present": True,
            "target_transferable": False,
            "target_recovery_supported": False,
            "limit": "The control maps updater architecture and enforced guards only; it cannot establish original ILCE-6400 selection, acceptance, write scope, verification, or recovery.",
        }
    ],
    "evidence": [
        {
            "source": "analysis/a6400-updater-transition-boundary.json",
            "claim": "The available 2.00 target-system receiver is post-install; an authentic pre-2.00 receiver or equivalent transition build is still required.",
        },
        {
            "source": "analysis/a6400-warm-boot-boundary.json",
            "claim": "Packaged warm-resume and normal-system artifacts do not contain the pre-normal-runtime updater selector.",
        },
        {
            "source": "analysis/a6400a-updater-and-creative-style-deep-dive.md",
            "claim": "The α6400A control contains a persistent updater partition and enforced different-model guard boundary but is not an original α6400 recovery image.",
        },
    ],
    "classification": "BLOCKED_MISSING_EXACT_PRE_2_00_SOURCE",
    "next_action": "Obtain an authentic official original ILCE-6400 package older than 2.00 for offline analysis; until then, use α6400A only for non-transferable architecture control tracing and keep recovery readiness false.",
}


def _reject_forbidden_fields(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise OfflineReceiverInventoryError("Inventory keys must be text")
            normalized = key.strip().lower().replace("-", "_")
            if normalized in _FORBIDDEN_KEYS:
                raise OfflineReceiverInventoryError(
                    "Raw, secret, or operational inventory fields are forbidden"
                )
            _reject_forbidden_fields(item)
    elif isinstance(value, list):
        for item in value:
            _reject_forbidden_fields(item)


def validate_offline_receiver_inventory(document: object) -> dict:
    """Return an isolated inventory only when it matches the pinned negative result."""

    _reject_forbidden_fields(document)
    if not isinstance(document, dict) or document != EXPECTED_INVENTORY:
        raise OfflineReceiverInventoryError(
            "Offline receiver inventory is not the pinned fail-closed result"
        )
    return deepcopy(document)
