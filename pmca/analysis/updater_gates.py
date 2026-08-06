"""Validate and render bounded evidence for the α6400 updater gates."""

import copy
import json
from pathlib import Path
import re


class UpdaterGateError(ValueError):
    """Raised when an updater-gate claim exceeds the offline evidence."""


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_RECOVERY_REPORT_PATH = _REPOSITORY_ROOT / "analysis" / "a6400-stock-200-recovery.json"
_RECOVERY_SCENARIOS_PATH = _REPOSITORY_ROOT / "analysis" / "a6400-recovery-scenarios.json"
_TOP_FIELDS = {
    "schema_version",
    "subject",
    "source_engine_sha256",
    "camera_policy",
    "camera_executed",
    "physical_transport_observed",
    "bypass_established",
    "installable",
    "gates",
    "feature_assessment",
    "conclusion",
}
_GATE_FIELDS = {
    "layer",
    "status",
    "summary",
    "evidence",
    "next_experiment",
    "feature_relevance",
}
_EVIDENCE_FIELDS = {"classification", "source", "claim"}
_FEATURE_FIELDS = {"feature", "status", "evidence_gap"}
_LAYERS = (
    "host-wrapper",
    "transport",
    "camera-updater",
    "boot",
    "runtime-integrity",
)
_STATUSES = (
    "PARTIAL",
    "PARTIAL",
    "PARTIAL",
    "INSUFFICIENT_EVIDENCE",
    "INSUFFICIENT_EVIDENCE",
)
_FEATURES = ("vertical-ui", "touch-ui", "creative-looks")
_CLASSIFICATIONS = {"OBSERVATION", "INFERENCE", "UNRESOLVED"}
_FORBIDDEN_KEYS = {
    "raw",
    "bytes",
    "payload",
    "base64",
    "hex_dump",
    "decrypted",
    "patch",
}


def _bounded_text(value: object, label: str, maximum: int = 1000) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or "\r" in value
        or "\n" in value
        or not value.isprintable()
    ):
        raise UpdaterGateError(f"{label} must be bounded single-line text")
    return value


def _reject_reconstructive_keys(value: object) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str) or key.casefold() in _FORBIDDEN_KEYS:
                raise UpdaterGateError("Gate map contains a forbidden field")
            _reject_reconstructive_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_reconstructive_keys(nested)


def validate_updater_gate_map(document: object) -> dict:
    """Validate a fail-closed map without converting static clues into a bypass."""
    if not isinstance(document, dict) or set(document) != _TOP_FIELDS:
        raise UpdaterGateError("Updater gate map fields are invalid")
    _reject_reconstructive_keys(document)
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise UpdaterGateError("Updater gate map schema is unsupported")
    if document["subject"] != "ILCE-6400 updater enforcement gate map":
        raise UpdaterGateError("Updater gate map subject is invalid")
    digest = document["source_engine_sha256"]
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise UpdaterGateError("Updater engine digest is invalid")
    if document["camera_policy"] != "physically-disconnected":
        raise UpdaterGateError("Updater camera policy is invalid")
    for field in (
        "camera_executed",
        "physical_transport_observed",
        "bypass_established",
        "installable",
    ):
        if document[field] is not False:
            raise UpdaterGateError(f"{field} must remain false")

    gates = document["gates"]
    if not isinstance(gates, list) or len(gates) != len(_LAYERS):
        raise UpdaterGateError("Updater gates are incomplete")
    if tuple(gate.get("layer") for gate in gates if isinstance(gate, dict)) != _LAYERS:
        raise UpdaterGateError("Updater gate layers are invalid or out of order")

    for gate, expected_status in zip(gates, _STATUSES):
        if set(gate) != _GATE_FIELDS:
            raise UpdaterGateError("Updater gate fields are invalid")
        if gate["status"] != expected_status:
            raise UpdaterGateError("Updater gate status exceeds the evidence")
        _bounded_text(gate["summary"], "Gate summary")
        _bounded_text(gate["next_experiment"], "Next experiment")
        _bounded_text(gate["feature_relevance"], "Feature relevance")
        evidence = gate["evidence"]
        if not isinstance(evidence, list) or not 2 <= len(evidence) <= 12:
            raise UpdaterGateError("Gate evidence is invalid")
        classifications = set()
        for item in evidence:
            if not isinstance(item, dict) or set(item) != _EVIDENCE_FIELDS:
                raise UpdaterGateError("Gate evidence fields are invalid")
            classification = item["classification"]
            if classification not in _CLASSIFICATIONS:
                raise UpdaterGateError("Gate evidence classification is invalid")
            classifications.add(classification)
            _bounded_text(item["source"], "Gate evidence source", 256)
            _bounded_text(item["claim"], "Gate evidence claim")
        if "UNRESOLVED" not in classifications or not classifications.intersection(
            {"OBSERVATION", "INFERENCE"}
        ):
            raise UpdaterGateError("Gate evidence does not preserve uncertainty")

    features = document["feature_assessment"]
    if not isinstance(features, list) or len(features) != len(_FEATURES):
        raise UpdaterGateError("Feature assessment is incomplete")
    for item, expected_feature in zip(features, _FEATURES):
        if not isinstance(item, dict) or set(item) != _FEATURE_FIELDS:
            raise UpdaterGateError("Feature assessment fields are invalid")
        if item["feature"] != expected_feature:
            raise UpdaterGateError("Feature assessment order is invalid")
        if item["status"] != "NATIVE_PORT_UNSUPPORTED":
            raise UpdaterGateError("Feature status exceeds the evidence")
        _bounded_text(item["evidence_gap"], "Feature evidence gap")

    _bounded_text(document["conclusion"], "Gate map conclusion")
    return copy.deepcopy(document)


def _validated_recovery_checkpoint(
    recovery_document: object | None,
    scenario_document: object | None,
) -> tuple[dict, dict]:
    """Load strict recovery state lazily to avoid the validator import cycle."""

    from .recovery_path import RecoveryPathError, validate_recovery_report
    from .recovery_scenarios import (
        RecoveryScenarioError,
        validate_recovery_scenarios,
    )

    try:
        if recovery_document is None:
            recovery_document = json.loads(
                _RECOVERY_REPORT_PATH.read_text(encoding="utf-8")
            )
        if scenario_document is None:
            scenario_document = json.loads(
                _RECOVERY_SCENARIOS_PATH.read_text(encoding="utf-8")
            )
        recovery = validate_recovery_report(recovery_document)
        scenarios = validate_recovery_scenarios(scenario_document)
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        RecoveryPathError,
        RecoveryScenarioError,
    ) as error:
        raise UpdaterGateError("Strict recovery checkpoint is unavailable") from error

    scenario_reference = recovery["recovery_scenarios"]
    recoverable_count = sum(
        item["status"] == "RECOVERABLE" for item in scenarios["scenarios"]
    )
    if scenario_reference != {
        "reference": "analysis/a6400-recovery-scenarios.json",
        "scenario_count": len(scenarios["scenarios"]),
        "recoverable_count": recoverable_count,
    }:
        raise UpdaterGateError("Recovery scenario checkpoint is inconsistent")
    return recovery, scenarios


def render_updater_gate_report(
    document: object,
    *,
    recovery_document: object | None = None,
    scenario_document: object | None = None,
) -> str:
    """Render a deterministic Markdown report from a validated gate map."""
    document = validate_updater_gate_map(document)
    recovery, scenarios = _validated_recovery_checkpoint(
        recovery_document, scenario_document
    )
    lines = [
        "# Sony α6400 Updater Enforcement Gate Report",
        "",
        "## Safety boundary",
        "",
        f"- Camera policy: `{document['camera_policy']}`",
        f"- Camera executed: `{str(document['camera_executed']).lower()}`",
        f"- Physical transport observed: `{str(document['physical_transport_observed']).lower()}`",
        f"- Bypass established: `{str(document['bypass_established']).lower()}`",
        f"- Installable output: `{str(document['installable']).lower()}`",
        f"- Signed updater engine SHA-256: `{document['source_engine_sha256']}`",
        "",
        "No physical camera transport command was observed. All command and status findings below are static observations from the signed updater engine unless explicitly labeled otherwise.",
        "",
    ]
    for gate in document["gates"]:
        lines.extend(
            [
                f"## {gate['layer']}",
                "",
                f"Status: `{gate['status']}`",
                "",
                gate["summary"],
                "",
                "Evidence:",
                "",
            ]
        )
        for item in gate["evidence"]:
            lines.append(
                f"- **{item['classification']}** — `{item['source']}`: {item['claim']}"
            )
        lines.extend(
            [
                "",
                f"Next offline experiment: {gate['next_experiment']}",
                "",
                f"Feature relevance: {gate['feature_relevance']}",
                "",
            ]
        )

    stock = recovery["stock_bundle"]
    lines.extend(
        [
            "## Exact stock-recovery checkpoint",
            "",
            f"The official {stock['region']}/region-{stock['region_code']} α6400 {stock['version']} updater and its embedded stock container are digest-pinned in `{stock['reference']}`. This authenticates the exact source needed for restoration; it does not establish same-version reinstall acceptance, complete write coverage, boot recovery, or safe interruption behavior.",
            "",
            f"The strict recovery status is `{recovery['readiness']}`, with `recovery_validated={str(recovery['recovery_validated']).lower()}`, `camera_test_eligible={str(recovery['camera_test_eligible']).lower()}`, and `installable={str(recovery['installable']).lower()}`.",
            "",
            "Candidate paths:",
            "",
        ]
    )
    for candidate in recovery["candidates"]:
        lines.append(f"- `{candidate['id']}` — `{candidate['status']}`")
    lines.extend(["", "Mandatory failure scenarios:", ""])
    for scenario in scenarios["scenarios"]:
        coverage = ", ".join(
            f"{item['id']}={item['status']}"
            for item in scenario["candidate_coverage"]
        )
        lines.append(
            f"- `{scenario['id']}` — `{scenario['status']}`; candidate coverage: {coverage}"
        )
    if recovery["readiness_basis"]["runtime_independent_entry_established"]:
        entry_sentence = (
            "A runtime-independent entry is established statically, but physical "
            "recovery and camera testing remain unvalidated."
        )
    else:
        entry_sentence = "No runtime-independent entry has been proven."
    lines.extend(
        [
            "",
            f"{entry_sentence} An in-camera settings reset would reset configuration only; it is not a route back to the exact stock firmware image.",
            "",
            "## Requested-feature assessment",
            "",
        ]
    )
    for item in document["feature_assessment"]:
        label = {
            "vertical-ui": "Vertical UI",
            "touch-ui": "Full touch UI",
            "creative-looks": "Creative Looks",
        }[item["feature"]]
        lines.append(
            f"- **{label} — `{item['status']}`.** {item['evidence_gap']}"
        )
    lines.extend(["", "## Current conclusion", "", document["conclusion"], ""])
    return "\n".join(lines)
