"""Validate bounded static evidence for an external ILCE-6400 stock restore path."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import unicodedata
from pathlib import Path

from .recovery_scenarios import (
    RecoveryScenarioError,
    validate_recovery_scenarios,
)
from .stock_restore import StockRestoreError, validate_stock_restore_bundle
from .trust_boundary import TrustBoundaryError, validate_trust_boundary_report
from .updater_crypto_boundary import (
    UpdaterCryptoBoundaryError,
    validate_updater_crypto_boundary_report,
)
from .updater_gates import UpdaterGateError, validate_updater_gate_map
from .updater_transition_report import (
    UpdaterTransitionReportError,
    validate_updater_transition_report,
)
from .warm_boot_boundary_report import (
    WarmBootBoundaryReportError,
    validate_warm_boot_boundary_report,
)


GATE_IDS = (
    "host_updater",
    "transport",
    "camera_updater",
    "boot_chain",
    "runtime_integrity",
)
DETAIL_IDS = (
    "signed_ranges",
    "model_check",
    "version_check",
    "write_scope",
    "write_order",
    "post_write_verification",
    "downgrade_or_reinstall",
    "power_loss_behavior",
)
STATUSES = {"ESTABLISHED", "PARTIAL", "UNESTABLISHED"}

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_STOCK_REFERENCE = "analysis/a6400-stock-200-bundle.json"
_SCENARIO_REFERENCE = "analysis/a6400-recovery-scenarios.json"
_PROGRAM = "signed-updater-engine-8f2e8b22.exe"
_PROGRAM_SHA256 = "8f2e8b229ef9e49a874cbf920301aba078727cebc490c891a992de60ff8a3528"
_PROGRAM_SIZE = 122864
_RAW_EXPORT_SHA256 = "11fc0537326d887205accacd80284db7f4af00db22317dffeb7e3bb14dabd36b"
_SCALAR_COUNT = 35
_CALL_COUNT = 359
_UNRESOLVED_DIRECT_COUNT = 308
_UNRESOLVED_INDIRECT_COUNT = 29
_ADDRESS_MIN = 0x400000
_ADDRESS_MAX = 0x420000
_MAX_RECORDS = 512

_ROOTS = (
    ("dat-parser", 0x4012D0, "FUN_004012d0"),
    ("response-validator", 0x405A50, "FUN_00405a50"),
    ("request-builder", 0x4061C0, "FUN_004061c0"),
    ("raw-fdat-transfer", 0x406900, "FUN_00406900"),
    ("state-machine", 0x406A70, "FUN_00406a70"),
    ("request-dispatch", 0x4071B0, "FUN_004071b0"),
    ("volume-open", 0x4073B0, "FUN_004073b0"),
    ("volume-io", 0x407500, "FUN_00407500"),
    ("storage-probe", 0x407770, "FUN_00407770"),
    ("pass-through-submit", 0x407A50, "FUN_00407a50"),
    ("status-decoder", 0x408B30, "FUN_00408b30"),
)
_ROOT_MAP = {root_id: (address, symbol) for root_id, address, symbol in _ROOTS}
_IMPORTS = {"CreateFileW", "DeviceIoControl"}
_SCALAR_SEMANTICS = {
    ("state-machine", 0x01): "initialization-command",
    ("state-machine", 0x10): "guard-command",
    ("state-machine", 0x20): "version-command",
    ("state-machine", 0x30): "mode-switch-command",
    ("state-machine", 0x40): "firmware-write-command",
    ("state-machine", 0x100): "completion-command",
    ("state-machine", 0x200): "state-command",
    ("request-builder", 0x20): "request-header-size",
    ("request-builder", 0x40): "firmware-write-command",
    ("request-builder", 0x100): "completion-command",
    ("raw-fdat-transfer", 0x40): "firmware-write-command",
    ("raw-fdat-transfer", 0x100): "completion-command",
    ("request-dispatch", 0x01): "initialization-command",
    ("request-dispatch", 0x10): "guard-command",
    ("request-dispatch", 0x20): "version-command",
    ("request-dispatch", 0x30): "mode-switch-command",
    ("request-dispatch", 0x40): "firmware-write-command",
    ("request-dispatch", 0x100): "completion-command",
    ("request-dispatch", 0x200): "state-command",
    ("pass-through-submit", 0x4D014): "pass-through-control-code",
    ("status-decoder", 0x140): "invalid-model-status",
    ("status-decoder", 0x141): "invalid-model-status",
    ("status-decoder", 0x142): "invalid-version-status",
}
_REQUIRED_SCALARS = {
    ("firmware-write-command", 0x40),
    ("completion-command", 0x100),
    ("invalid-model-status", 0x140),
    ("invalid-model-status", 0x141),
    ("invalid-version-status", 0x142),
}

_RAW_EXPORT_FIELDS = {
    "schema_version",
    "program",
    "sha256",
    "file_size",
    "analysis_mode",
    "roots",
    "scalar_comparisons",
    "imports",
    "calls",
    "unresolved_direct_calls",
    "unresolved_indirect_calls",
    "truncated",
}
_ANALYSIS_MODE_FIELDS = {"read_only", "noanalysis"}
_ROOT_FIELDS = {"id", "address", "symbol"}
_SCALAR_FIELDS = {"root_id", "site", "value", "semantic"}
_CALL_FIELDS = {
    "caller_root",
    "site",
    "target",
    "target_root",
    "target_symbol",
    "kind",
}
_CALL_KINDS = {"direct", "external-direct", "unresolved-direct", "unresolved-indirect"}

_TOP_FIELDS = {
    "schema_version",
    "subject",
    "camera_policy",
    "camera_connected",
    "camera_executed",
    "installable",
    "recovery_validated",
    "camera_test_eligible",
    "stock_bundle",
    "recovery_scenarios",
    "static_gate_export",
    "gates",
    "details",
    "readiness_basis",
    "readiness",
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
_SCENARIO_REFERENCE_FIELDS = {"reference", "scenario_count", "recoverable_count"}
_BOUNDARY_FIELDS = {"id", "status", "evidence", "blocker"}
_EVIDENCE_FIELDS = {"evidence_id", "source", "claim"}
_READINESS_FIELDS = {
    "authenticated_stock_bundle",
    "runtime_independent_entry_established",
    "write_scope_established",
    "write_order_established",
    "post_write_verification_established",
    "scenario_overclaim_count",
}
_FORBIDDEN_KEYS = {
    "bypass",
    "bytes",
    "hex_dump",
    "key_material",
    "payload",
    "private_key",
    "raw",
    "raw_bytes",
    "raw_payload",
}
_MAX_TEXT = 2048
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")

_EVIDENCE_REGISTRY = {
    "host-dat-parser-static": {
        "semantic": "host_updater",
        "support": "PARTIAL",
        "source": "analysis/a6400-updater-gates.json",
        "claim": "The signed host engine parses and integrity-checks the DAT container, while complete host authenticity behavior remains unresolved.",
    },
    "transport-boundary-static": {
        "semantic": "transport",
        "support": "PARTIAL",
        "source": "analysis/a6400-updater-gates.json",
        "claim": "Storage and pass-through transport functions are statically mapped, but no physical protocol exchange was observed.",
    },
    "camera-status-boundary-static": {
        "semantic": "camera_updater",
        "support": "PARTIAL",
        "source": "analysis/a6400-updater-gates.json",
        "claim": "The host decodes camera-returned model and version statuses, but the enforcing camera receiver remains unresolved.",
    },
    "boot-selector-unlocated": {
        "semantic": "boot_chain",
        "support": "UNESTABLISHED",
        "source": "analysis/a6400-warm-boot-boundary.json",
        "claim": "The pre-normal-runtime component that selects the updater system has not been identified.",
    },
    "runtime-integrity-unlocated": {
        "semantic": "runtime_integrity",
        "support": "UNESTABLISHED",
        "source": "analysis/a6400-trust-boundary.json",
        "claim": "Boot-time and runtime integrity enforcement for a modified application image remains unresolved.",
    },
    "signed-ranges-unlocated": {
        "semantic": "signed_ranges",
        "support": "UNESTABLISHED",
        "source": "analysis/a6400-trust-boundary.json",
        "claim": "The camera verifier, signed byte range, trust anchor, and failure mapping remain unlocated.",
    },
    "model-status-static": {
        "semantic": "model_check",
        "support": "PARTIAL",
        "source": "analysis/a6400-updater-gates.json",
        "claim": "Invalid-model return statuses are mapped on the host, without the camera-side comparison implementation or safe mismatch behavior.",
    },
    "version-status-static": {
        "semantic": "version_check",
        "support": "PARTIAL",
        "source": "analysis/a6400-updater-gates.json",
        "claim": "An invalid-version return status is mapped on the host, without same-version reinstall or downgrade acceptance behavior.",
    },
    "write-scope-unlocated": {
        "semantic": "write_scope",
        "support": "UNESTABLISHED",
        "source": "analysis/a6400-updater-transition-boundary.json",
        "claim": "The available 2.00 receiver is post-install; the earlier receiver and complete stock restore write scope remain unavailable.",
    },
    "write-order-unlocated": {
        "semantic": "write_order",
        "support": "UNESTABLISHED",
        "source": "analysis/a6400-updater-transition-boundary.json",
        "claim": "The installing receiver and its complete ordered write and commit sequence have not been located.",
    },
    "post-write-verification-unlocated": {
        "semantic": "post_write_verification",
        "support": "UNESTABLISHED",
        "source": "analysis/a6400-updater-crypto-boundary.json",
        "claim": "The updater-mode authenticity verifier and terminal post-write verification behavior remain unresolved.",
    },
    "downgrade-reinstall-unestablished": {
        "semantic": "downgrade_or_reinstall",
        "support": "UNESTABLISHED",
        "source": "analysis/a6400-updater-gates.json",
        "claim": "Host-side status decoding does not establish camera acceptance of an exact same-version reinstall or downgrade.",
    },
    "power-loss-unestablished": {
        "semantic": "power_loss_behavior",
        "support": "UNESTABLISHED",
        "source": "analysis/a6400-updater-transition-boundary.json",
        "claim": "No bounded evidence establishes restart, resume, rollback, or safe terminal behavior after power loss.",
    },
}

_EXPECTED_CONCLUSION = (
    "The exact stock source and several host-side updater boundaries are mapped, "
    "but no runtime-independent entry, camera-side signed range, complete write "
    "scope or order, post-write verification, reinstall acceptance, or power-loss "
    "behavior is established. Recovery remains unvalidated and camera testing is "
    "ineligible."
)


class RecoveryPathError(ValueError):
    """Raised when a recovery path report is malformed or overclaims evidence."""


def _forbidden_key(value: str) -> bool:
    normalized = value.strip().lower().replace("-", "_")
    return (
        normalized in _FORBIDDEN_KEYS
        or normalized.startswith("raw_")
        or normalized.endswith("_raw")
        or normalized.endswith("_payload")
        or normalized.endswith("_bytes")
        or "private_key" in normalized
        or "key_material" in normalized
        or "hex_dump" in normalized
    )


def _reject_forbidden_material(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise RecoveryPathError("recovery path keys must be text")
            if _forbidden_key(key):
                raise RecoveryPathError("aggregate bypass or firmware material is forbidden")
            _reject_forbidden_material(item)
        return
    if isinstance(value, list):
        for item in value:
            _reject_forbidden_material(item)
        return
    if isinstance(value, (bytes, bytearray, memoryview)):
        raise RecoveryPathError("recovery path must not contain firmware bytes")
    if isinstance(value, str):
        if len(value) > _MAX_TEXT or any(
            unicodedata.category(character).startswith("C") for character in value
        ):
            raise RecoveryPathError("recovery path text is invalid")
        return
    if value is not None and not isinstance(value, (int, float, bool)):
        raise RecoveryPathError("recovery path contains a non-JSON value")


def _require_fields(value: object, fields: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise RecoveryPathError(f"{label} fields are not exact")
    return value


def _require_text(value: object, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise RecoveryPathError(f"{label} must be text")
    if not allow_empty and not value.strip():
        raise RecoveryPathError(f"{label} must be nonempty text")
    if len(value) > _MAX_TEXT:
        raise RecoveryPathError(f"{label} exceeds its text bound")
    return value


def _bounded_address(value: object, label: str) -> int:
    if type(value) is not int or not _ADDRESS_MIN <= value < _ADDRESS_MAX:
        raise RecoveryPathError(f"{label} is outside the pinned program")
    return value


def _bounded_count(value: object, label: str) -> int:
    if type(value) is not int or not 0 <= value <= 10000:
        raise RecoveryPathError(f"{label} is invalid")
    return value


def normalize_restore_gate_export(raw: dict) -> dict:
    """Validate and canonicalize metadata-only Ghidra restore-gate output."""

    _reject_forbidden_material(raw)
    document = _require_fields(raw, _RAW_EXPORT_FIELDS, "Restore gate export")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise RecoveryPathError("restore gate export schema is invalid")
    if (
        document["program"] != _PROGRAM
        or document["sha256"] != _PROGRAM_SHA256
        or document["file_size"] != _PROGRAM_SIZE
        or not _DIGEST_RE.fullmatch(document["sha256"])
    ):
        raise RecoveryPathError("restore gate program identity is invalid")
    mode = _require_fields(document["analysis_mode"], _ANALYSIS_MODE_FIELDS, "Analysis mode")
    if mode != {"read_only": True, "noanalysis": True}:
        raise RecoveryPathError("restore gate export was not read-only and noanalysis")
    if document["truncated"] is not False:
        raise RecoveryPathError("truncated restore gate export is invalid")

    roots = document["roots"]
    if not isinstance(roots, list) or len(roots) != len(_ROOTS):
        raise RecoveryPathError("restore gate roots are incomplete")
    normalized_roots = []
    for item, expected in zip(roots, _ROOTS):
        root = _require_fields(item, _ROOT_FIELDS, "Restore gate root")
        expected_id, expected_address, expected_symbol = expected
        if root != {
            "id": expected_id,
            "address": expected_address,
            "symbol": expected_symbol,
        }:
            raise RecoveryPathError("restore gate root identity or order is invalid")
        _bounded_address(root["address"], "Restore gate root address")
        normalized_roots.append(dict(root))

    scalars = document["scalar_comparisons"]
    if not isinstance(scalars, list) or not 1 <= len(scalars) <= _MAX_RECORDS:
        raise RecoveryPathError("restore gate scalar comparisons are invalid")
    normalized_scalars = []
    occupied_sites = set()
    for item in scalars:
        scalar = _require_fields(item, _SCALAR_FIELDS, "Restore scalar comparison")
        root_id = scalar["root_id"]
        if root_id not in _ROOT_MAP:
            raise RecoveryPathError("restore scalar root is invalid")
        site = _bounded_address(scalar["site"], "Restore scalar site")
        if site in occupied_sites:
            raise RecoveryPathError("restore metadata contains duplicate sites")
        occupied_sites.add(site)
        if type(scalar["value"]) is not int:
            raise RecoveryPathError("restore scalar value must be an integer")
        expected_semantic = _SCALAR_SEMANTICS.get((root_id, scalar["value"]))
        if scalar["semantic"] != expected_semantic:
            raise RecoveryPathError("restore scalar semantic or value is invalid")
        normalized_scalars.append(dict(scalar))
    observed_required = {
        (item["semantic"], item["value"]) for item in normalized_scalars
    }
    if not _REQUIRED_SCALARS.issubset(observed_required):
        raise RecoveryPathError("restore gate export lacks required model/write evidence")

    imports = document["imports"]
    if (
        not isinstance(imports, list)
        or len(imports) != len(set(imports))
        or set(imports) != _IMPORTS
    ):
        raise RecoveryPathError("restore gate imports are invalid")

    calls = document["calls"]
    if not isinstance(calls, list) or len(calls) > _MAX_RECORDS:
        raise RecoveryPathError("restore gate calls are invalid")
    normalized_calls = []
    for item in calls:
        call = _require_fields(item, _CALL_FIELDS, "Restore gate call")
        caller_root = call["caller_root"]
        if caller_root not in _ROOT_MAP:
            raise RecoveryPathError("restore call owner is invalid")
        site = _bounded_address(call["site"], "Restore call site")
        if site in occupied_sites:
            raise RecoveryPathError("restore metadata contains duplicate sites")
        occupied_sites.add(site)
        if call["kind"] not in _CALL_KINDS:
            raise RecoveryPathError("restore call kind is invalid")
        if call["kind"] == "direct":
            if call["target_root"] not in _ROOT_MAP:
                raise RecoveryPathError("direct restore call target root is invalid")
            expected_address, expected_symbol = _ROOT_MAP[call["target_root"]]
            if (
                call["target"] != expected_address
                or call["target_symbol"] != expected_symbol
            ):
                raise RecoveryPathError("direct restore call target is inconsistent")
            _bounded_address(call["target"], "Direct restore call target")
        elif call["kind"] == "external-direct":
            if (
                call["target"] is not None
                or call["target_root"] is not None
                or call["target_symbol"] not in _IMPORTS
            ):
                raise RecoveryPathError("external restore call is invalid")
        elif any(
            call[field] is not None
            for field in ("target", "target_root", "target_symbol")
        ):
            raise RecoveryPathError("unresolved restore call contains a target")
        normalized_calls.append(dict(call))

    unresolved_direct = _bounded_count(
        document["unresolved_direct_calls"], "Unresolved direct-call count"
    )
    unresolved_indirect = _bounded_count(
        document["unresolved_indirect_calls"], "Unresolved indirect-call count"
    )
    if unresolved_direct != sum(
        item["kind"] == "unresolved-direct" for item in normalized_calls
    ) or unresolved_indirect != sum(
        item["kind"] == "unresolved-indirect" for item in normalized_calls
    ):
        raise RecoveryPathError("unresolved restore call counts are inconsistent")
    normalized_scalars.sort(key=lambda item: (item["site"], item["root_id"], item["value"]))
    normalized_calls.sort(key=lambda item: (item["site"], item["caller_root"]))
    normalized = {
        "schema_version": 1,
        "program": _PROGRAM,
        "sha256": _PROGRAM_SHA256,
        "file_size": _PROGRAM_SIZE,
        "analysis_mode": {"read_only": True, "noanalysis": True},
        "roots": normalized_roots,
        "scalar_comparisons": normalized_scalars,
        "imports": sorted(imports),
        "calls": normalized_calls,
        "unresolved_direct_calls": document["unresolved_direct_calls"],
        "unresolved_indirect_calls": document["unresolved_indirect_calls"],
        "truncated": False,
    }
    if (
        len(normalized_scalars) != _SCALAR_COUNT
        or len(normalized_calls) != _CALL_COUNT
        or unresolved_direct != _UNRESOLVED_DIRECT_COUNT
        or unresolved_indirect != _UNRESOLVED_INDIRECT_COUNT
    ):
        raise RecoveryPathError("restore gate export is incomplete")
    encoded = (
        json.dumps(normalized, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    if hashlib.sha256(encoded).hexdigest() != _RAW_EXPORT_SHA256:
        raise RecoveryPathError("restore gate export does not match the pinned trace")
    return normalized


def _load_json(relative_path: str, label: str) -> dict:
    try:
        value = json.loads(
            (_REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RecoveryPathError(f"{label} is unavailable") from error
    if not isinstance(value, dict):
        raise RecoveryPathError(f"{label} is invalid")
    return value


def _validated_dependencies() -> tuple[dict, dict]:
    try:
        stock = validate_stock_restore_bundle(
            _load_json(_STOCK_REFERENCE, "Authenticated stock bundle")
        )
        scenarios = validate_recovery_scenarios(
            _load_json(_SCENARIO_REFERENCE, "Recovery scenarios")
        )
    except (StockRestoreError, RecoveryScenarioError) as error:
        raise RecoveryPathError("recovery dependencies are invalid") from error
    return stock, scenarios


def _validate_cited_reports() -> None:
    validators = (
        (
            "analysis/a6400-updater-gates.json",
            validate_updater_gate_map,
            UpdaterGateError,
        ),
        (
            "analysis/a6400-updater-crypto-boundary.json",
            validate_updater_crypto_boundary_report,
            UpdaterCryptoBoundaryError,
        ),
        (
            "analysis/a6400-updater-transition-boundary.json",
            validate_updater_transition_report,
            UpdaterTransitionReportError,
        ),
        (
            "analysis/a6400-warm-boot-boundary.json",
            validate_warm_boot_boundary_report,
            WarmBootBoundaryReportError,
        ),
        (
            "analysis/a6400-trust-boundary.json",
            validate_trust_boundary_report,
            TrustBoundaryError,
        ),
    )
    for relative_path, validator, error_type in validators:
        try:
            validator(_load_json(relative_path, "Cited recovery evidence"))
        except error_type as error:
            raise RecoveryPathError("cited recovery evidence is invalid") from error


def _validate_boundary_records(
    records: object, expected_ids: tuple[str, ...], label: str
) -> list[dict]:
    if not isinstance(records, list) or [
        item.get("id") if isinstance(item, dict) else None for item in records
    ] != list(expected_ids):
        raise RecoveryPathError(f"{label} membership or order is invalid")
    for item in records:
        record = _require_fields(item, _BOUNDARY_FIELDS, label)
        semantic = record["id"]
        status = record["status"]
        if status not in STATUSES:
            raise RecoveryPathError(f"{semantic} status is invalid")
        evidence = record["evidence"]
        if not isinstance(evidence, list) or len(evidence) > 8:
            raise RecoveryPathError(f"{semantic} evidence is invalid")
        support_levels = set()
        seen = set()
        for item in evidence:
            evidence_record = _require_fields(item, _EVIDENCE_FIELDS, "Recovery evidence")
            evidence_id = evidence_record["evidence_id"]
            registry = _EVIDENCE_REGISTRY.get(evidence_id)
            if registry is None or registry["semantic"] != semantic or evidence_id in seen:
                raise RecoveryPathError(f"{semantic} evidence identity is invalid")
            seen.add(evidence_id)
            if evidence_record != {
                "evidence_id": evidence_id,
                "source": registry["source"],
                "claim": registry["claim"],
            }:
                raise RecoveryPathError(f"{semantic} evidence record is invalid")
            support_levels.add(registry["support"])
        if status == "PARTIAL" and not support_levels.intersection(
            {"PARTIAL", "ESTABLISHED"}
        ):
            raise RecoveryPathError(f"{semantic} partial status lacks typed support")
        if status == "ESTABLISHED" and "ESTABLISHED" not in support_levels:
            raise RecoveryPathError(f"{semantic} established status lacks typed support")
        _require_text(
            record["blocker"],
            f"{semantic} blocker",
            allow_empty=status == "ESTABLISHED",
        )
    return records


def validate_recovery_report(document: dict) -> dict:
    """Validate the static restore boundary while keeping recovery false."""

    _reject_forbidden_material(document)
    report = _require_fields(document, _TOP_FIELDS, "Recovery path report")
    if type(report["schema_version"]) is not int or report["schema_version"] != 1:
        raise RecoveryPathError("recovery path schema version is invalid")
    if report["subject"] != "ILCE-6400 exact stock 2.00 external recovery boundary":
        raise RecoveryPathError("recovery path subject is invalid")
    if report["camera_policy"] != "physically-disconnected":
        raise RecoveryPathError("recovery path camera policy is invalid")
    for field in (
        "camera_connected",
        "camera_executed",
        "installable",
        "recovery_validated",
        "camera_test_eligible",
    ):
        if report[field] is not False:
            raise RecoveryPathError(f"{field} must remain false in static recovery work")

    stock, scenarios = _validated_dependencies()
    stock_reference = _require_fields(report["stock_bundle"], _STOCK_FIELDS, "Stock bundle")
    expected_stock = {
        "reference": _STOCK_REFERENCE,
        "source_key": stock["source_key"],
        "model_id": stock["model_id"],
        "region": stock["region"],
        "region_code": stock["region_code"],
        "version": stock["version"],
    }
    if type(stock_reference["region_code"]) is not int or stock_reference != expected_stock:
        raise RecoveryPathError("recovery stock bundle reference is invalid")

    scenario_reference = _require_fields(
        report["recovery_scenarios"],
        _SCENARIO_REFERENCE_FIELDS,
        "Recovery scenario reference",
    )
    recoverable_count = sum(
        item["status"] == "RECOVERABLE" for item in scenarios["scenarios"]
    )
    expected_scenarios = {
        "reference": _SCENARIO_REFERENCE,
        "scenario_count": len(scenarios["scenarios"]),
        "recoverable_count": recoverable_count,
    }
    if scenario_reference != expected_scenarios:
        raise RecoveryPathError("recovery scenario reference is invalid")

    normalized_export = normalize_restore_gate_export(report["static_gate_export"])
    if report["static_gate_export"] != normalized_export:
        raise RecoveryPathError("restore gate export is not canonical")

    _validate_cited_reports()
    gates = _validate_boundary_records(report["gates"], GATE_IDS, "Recovery gate")
    details = _validate_boundary_records(report["details"], DETAIL_IDS, "Recovery detail")
    gate_status = {item["id"]: item["status"] for item in gates}
    detail_status = {item["id"]: item["status"] for item in details}
    if gate_status != {
        "host_updater": "PARTIAL",
        "transport": "PARTIAL",
        "camera_updater": "PARTIAL",
        "boot_chain": "UNESTABLISHED",
        "runtime_integrity": "UNESTABLISHED",
    }:
        raise RecoveryPathError("recovery gate classifications are not fail-closed")
    if detail_status != {
        "signed_ranges": "UNESTABLISHED",
        "model_check": "PARTIAL",
        "version_check": "PARTIAL",
        "write_scope": "UNESTABLISHED",
        "write_order": "UNESTABLISHED",
        "post_write_verification": "UNESTABLISHED",
        "downgrade_or_reinstall": "UNESTABLISHED",
        "power_loss_behavior": "UNESTABLISHED",
    }:
        raise RecoveryPathError("recovery detail classifications are not fail-closed")

    expected_basis = {
        "authenticated_stock_bundle": True,
        "runtime_independent_entry_established": False,
        "write_scope_established": detail_status["write_scope"] == "ESTABLISHED",
        "write_order_established": detail_status["write_order"] == "ESTABLISHED",
        "post_write_verification_established": detail_status[
            "post_write_verification"
        ]
        == "ESTABLISHED",
        "scenario_overclaim_count": recoverable_count,
    }
    basis = _require_fields(report["readiness_basis"], _READINESS_FIELDS, "Readiness basis")
    for field in _READINESS_FIELDS - {"scenario_overclaim_count"}:
        if type(basis[field]) is not bool:
            raise RecoveryPathError(f"readiness basis {field} must be boolean")
    if type(basis["scenario_overclaim_count"]) is not int or basis != expected_basis:
        raise RecoveryPathError("recovery readiness basis is invalid")
    ready = (
        basis["authenticated_stock_bundle"]
        and basis["runtime_independent_entry_established"]
        and basis["write_scope_established"]
        and basis["write_order_established"]
        and basis["post_write_verification_established"]
        and basis["scenario_overclaim_count"] == 0
    )
    expected_readiness = (
        "READY_FOR_FUTURE_VALIDATION_DESIGN"
        if ready
        else "BLOCKED_STATIC_EVIDENCE"
    )
    if report["readiness"] != expected_readiness:
        raise RecoveryPathError("recovery readiness classification is invalid")
    if report["conclusion"] != _EXPECTED_CONCLUSION:
        raise RecoveryPathError("recovery path conclusion is invalid")
    return copy.deepcopy(report)
