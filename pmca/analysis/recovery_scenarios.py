"""Fail-closed failure-state model for external ILCE-6400 stock recovery."""

from __future__ import annotations

import copy
import json
import re
import unicodedata
from pathlib import Path

from .stock_restore import StockRestoreError, validate_stock_restore_bundle


SCENARIO_IDS = (
    "modified-ui-runtime-failure",
    "interrupted-feature-update",
    "nonbooting-application-layer",
    "version-or-downgrade-rejection",
    "boot-chain-failure",
    "power-loss-during-stock-restore",
)
STATUSES = {"RECOVERABLE", "PARTIAL", "UNRECOVERABLE", "UNESTABLISHED"}

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_BUNDLE_REFERENCE = "analysis/a6400-stock-200-bundle.json"
_TOP_FIELDS = {
    "schema_version",
    "subject",
    "camera_policy",
    "camera_connected",
    "camera_executed",
    "recovery_validated",
    "stock_bundle",
    "scenarios",
    "conclusion",
}
_STOCK_FIELDS = {
    "reference",
    "source_key",
    "model_id",
    "region",
    "region_code",
    "version",
}
_SCENARIO_FIELDS = {
    "id",
    "status",
    "entry_available",
    "runtime_independent",
    "write_scope_known",
    "verification_available",
    "power_loss_behavior_known",
    "evidence",
    "blocker",
}
_EVIDENCE_FIELDS = {"classification", "source", "direct", "claim"}
_CAPABILITY_FIELDS = (
    "entry_available",
    "runtime_independent",
    "write_scope_known",
    "verification_available",
    "power_loss_behavior_known",
)
_RECOVERY_FIELDS = (
    "entry_available",
    "runtime_independent",
    "write_scope_known",
    "verification_available",
)
_STATIC_EVIDENCE_SOURCES = {
    "analysis/a6400-updater-transition-boundary.json",
    "analysis/a6400-updater-crypto-boundary.json",
    "analysis/a6400-warm-boot-boundary.json",
    "analysis/a6400-updater-gates.json",
    "analysis/a6400-trust-boundary.json",
}
_DIRECT_EVIDENCE_SOURCE = "future-authorized-physical-validation"
_UNCERTAINTY_WORDS = {
    "not",
    "no",
    "remain",
    "remains",
    "unknown",
    "unresolved",
    "unidentified",
    "unavailable",
    "unestablished",
}
_FORBIDDEN_KEY_PARTS = {
    "command",
    "commands",
    "device_path",
    "hex_dump",
    "partition_payload",
    "payload",
    "raw_bytes",
    "script",
    "steps",
}
_OPERATIONAL_PATTERNS = (
    re.compile(r"(?i)(?:^|[\s\"'])[a-z]:[\\/]"),
    re.compile(r"(?i)\\\\\.\\"),
    re.compile(r"(?i)/dev/"),
    re.compile(r"(?i)\bdd\s+if\s*="),
    re.compile(r"(?i)\bfastboot\b"),
    re.compile(r"(?i)\badb\b"),
    re.compile(r"(?i)\bdiskpart\b"),
    re.compile(r"(?i)\b(?:mkfs|format-volume|deviceiocontrol)\b"),
    re.compile(r"(?i)\b(?:flash|erase|format)\s+(?:firmware|partition|system|device)\b"),
)
_HEX_BLOB_RE = re.compile(r"(?:[0-9a-fA-F]{2}){64,}")
_BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{256,}={0,2}")
_MAX_TEXT_CHARS = 2048
_EXPECTED_CONCLUSION = (
    "All six mandatory failure scenarios remain unestablished. The exact stock "
    "source is authenticated, but static evidence does not establish an external "
    "runtime-independent entry, complete write scope, post-write verification, "
    "downgrade acceptance, boot-chain recovery, or power-loss safety."
)


class RecoveryScenarioError(ValueError):
    """Raised when recovery coverage is malformed, unsafe, or overclaimed."""


def _reject_operational_content(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise RecoveryScenarioError("recovery report keys must be text")
            normalized = key.strip().lower().replace("-", "_")
            if normalized in _FORBIDDEN_KEY_PARTS:
                raise RecoveryScenarioError("operational recovery fields are forbidden")
            _reject_operational_content(item)
        return
    if isinstance(value, list):
        for item in value:
            _reject_operational_content(item)
        return
    if isinstance(value, (bytes, bytearray, memoryview)):
        raise RecoveryScenarioError("partition or firmware bytes are forbidden")
    if isinstance(value, str):
        if len(value) > _MAX_TEXT_CHARS:
            raise RecoveryScenarioError("recovery report text exceeds its bound")
        if any(
            unicodedata.category(character).startswith("C") for character in value
        ):
            raise RecoveryScenarioError("recovery report text contains controls")
        if any(pattern.search(value) for pattern in _OPERATIONAL_PATTERNS):
            raise RecoveryScenarioError("operational camera or storage content is forbidden")
        compact = re.sub(r"\s+", "", value)
        if _HEX_BLOB_RE.search(compact) or _BASE64_BLOB_RE.search(compact):
            raise RecoveryScenarioError("partition or firmware material is forbidden")
        return
    if value is not None and not isinstance(value, (int, float, bool)):
        raise RecoveryScenarioError("recovery report contains a non-JSON value")


def _require_fields(value: object, fields: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise RecoveryScenarioError(f"{label} fields are not exact")
    return value


def _require_text(value: object, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise RecoveryScenarioError(f"{label} must be text")
    if not allow_empty and not value.strip():
        raise RecoveryScenarioError(f"{label} must be nonempty text")
    if len(value) > _MAX_TEXT_CHARS:
        raise RecoveryScenarioError(f"{label} exceeds its text bound")
    return value


def _contains_uncertainty(value: str) -> bool:
    words = set(re.findall(r"[a-z]+", value.lower()))
    return bool(words & _UNCERTAINTY_WORDS)


def _load_stock_bundle() -> dict:
    try:
        document = json.loads(
            (_REPOSITORY_ROOT / _BUNDLE_REFERENCE).read_text(encoding="utf-8")
        )
        return validate_stock_restore_bundle(document)
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        StockRestoreError,
    ) as error:
        raise RecoveryScenarioError("authenticated stock bundle is unavailable") from error


def _expected_stock_identity(stock_bundle: dict) -> dict:
    return {
        "reference": _BUNDLE_REFERENCE,
        "source_key": stock_bundle["source_key"],
        "model_id": stock_bundle["model_id"],
        "region": stock_bundle["region"],
        "region_code": stock_bundle["region_code"],
        "version": stock_bundle["version"],
    }


def _validate_evidence(
    value: object, scenario_id: str, camera_executed: bool
) -> list[dict]:
    if not isinstance(value, list) or len(value) > 8:
        raise RecoveryScenarioError(f"{scenario_id} evidence must be a bounded list")
    for item in value:
        evidence = _require_fields(item, _EVIDENCE_FIELDS, f"{scenario_id} evidence")
        if evidence["classification"] != "BOUNDED_STATIC":
            raise RecoveryScenarioError(f"{scenario_id} evidence classification is invalid")
        if type(evidence["direct"]) is not bool:
            raise RecoveryScenarioError(f"{scenario_id} evidence direct flag is invalid")
        if evidence["direct"]:
            if evidence["source"] != _DIRECT_EVIDENCE_SOURCE or not camera_executed:
                raise RecoveryScenarioError(
                    f"{scenario_id} direct evidence lacks authorized camera validation"
                )
        elif evidence["source"] not in _STATIC_EVIDENCE_SOURCES:
            raise RecoveryScenarioError(f"{scenario_id} evidence source is invalid")
        claim = _require_text(evidence["claim"], f"{scenario_id} evidence claim")
        if not evidence["direct"] and not _contains_uncertainty(claim):
            raise RecoveryScenarioError(
                f"{scenario_id} bounded static evidence must remain non-promotional"
            )
    return value


def _can_be_recoverable(item: dict) -> bool:
    if not all(item[field] is True for field in _RECOVERY_FIELDS):
        return False
    if item["id"] == "power-loss-during-stock-restore" and not item[
        "power_loss_behavior_known"
    ]:
        return False
    return bool(item["evidence"])


def validate_recovery_scenarios(document: dict) -> dict:
    """Validate all mandatory recovery failures without claiming recovery works."""

    _reject_operational_content(document)
    report = _require_fields(document, _TOP_FIELDS, "Recovery scenario report")
    if type(report["schema_version"]) is not int or report["schema_version"] != 1:
        raise RecoveryScenarioError("recovery scenario schema version is invalid")
    if report["subject"] != "ILCE-6400 external stock 2.00 recovery failure scenarios":
        raise RecoveryScenarioError("recovery scenario subject is invalid")
    if report["camera_policy"] != "physically-disconnected":
        raise RecoveryScenarioError("recovery scenario camera policy is invalid")
    for field in ("camera_connected", "camera_executed", "recovery_validated"):
        if report[field] is not False:
            raise RecoveryScenarioError(f"{field} must remain false in static research")

    stock_bundle = _load_stock_bundle()
    stock_identity = _require_fields(
        report["stock_bundle"], _STOCK_FIELDS, "Recovery stock bundle identity"
    )
    if type(stock_identity["region_code"]) is not int:
        raise RecoveryScenarioError("recovery stock region code is invalid")
    if stock_identity != _expected_stock_identity(stock_bundle):
        raise RecoveryScenarioError("recovery stock bundle identity is invalid")

    scenarios = report["scenarios"]
    if not isinstance(scenarios, list) or [
        item.get("id") if isinstance(item, dict) else None for item in scenarios
    ] != list(SCENARIO_IDS):
        raise RecoveryScenarioError("recovery scenario membership or order is invalid")

    for item in scenarios:
        scenario = _require_fields(item, _SCENARIO_FIELDS, "Recovery scenario")
        scenario_id = scenario["id"]
        if scenario["status"] not in STATUSES:
            raise RecoveryScenarioError(f"{scenario_id} status is invalid")
        for field in _CAPABILITY_FIELDS:
            if type(scenario[field]) is not bool:
                raise RecoveryScenarioError(f"{scenario_id} {field} must be boolean")
        evidence = _validate_evidence(
            scenario["evidence"], scenario_id, report["camera_executed"]
        )
        blocker = _require_text(
            scenario["blocker"],
            f"{scenario_id} blocker",
            allow_empty=scenario["status"] == "RECOVERABLE",
        )
        if (
            scenario["status"] != "UNESTABLISHED"
            and not report["recovery_validated"]
        ):
            raise RecoveryScenarioError(
                f"{scenario_id} static evidence cannot promote scenario status"
            )

        if scenario["status"] == "UNESTABLISHED":
            if any(scenario[field] for field in _CAPABILITY_FIELDS):
                raise RecoveryScenarioError(
                    f"{scenario_id} unestablished status cannot promote a capability"
                )
            if not _contains_uncertainty(blocker):
                raise RecoveryScenarioError(
                    f"{scenario_id} blocker must state the unresolved boundary"
                )
        elif scenario["status"] == "PARTIAL":
            if not any(scenario[field] for field in _CAPABILITY_FIELDS) or not evidence:
                raise RecoveryScenarioError(
                    f"{scenario_id} partial status requires evidence and a capability"
                )
            if _can_be_recoverable(scenario):
                raise RecoveryScenarioError(
                    f"{scenario_id} fully covered capabilities cannot be partial"
                )
            if not _contains_uncertainty(blocker):
                raise RecoveryScenarioError(
                    f"{scenario_id} partial blocker must remain explicit"
                )
        elif scenario["status"] == "UNRECOVERABLE":
            if not any(record["direct"] for record in evidence):
                raise RecoveryScenarioError(
                    f"{scenario_id} unrecoverable status requires direct evidence"
                )
        elif scenario["status"] == "RECOVERABLE":
            if not _can_be_recoverable(scenario):
                raise RecoveryScenarioError(
                    f"{scenario_id} recoverable status lacks mandatory coverage"
                )
            if not any(record["direct"] for record in evidence):
                raise RecoveryScenarioError(
                    f"{scenario_id} recoverable status requires direct validation"
                )
            if not report["recovery_validated"]:
                raise RecoveryScenarioError(
                    f"{scenario_id} recoverable status contradicts readiness"
                )

    if report["conclusion"] != _EXPECTED_CONCLUSION:
        raise RecoveryScenarioError("recovery scenario conclusion is invalid")
    return copy.deepcopy(report)
