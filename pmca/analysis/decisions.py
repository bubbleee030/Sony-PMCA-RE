"""Validate and render evidence-bounded firmware feasibility decisions."""

from copy import deepcopy
from pathlib import PurePosixPath
from urllib.parse import urlsplit


SCHEMA_VERSION = 1
REQUIRED_CAPABILITIES = (
    "creative-look-discovery",
    "creative-look-emulation",
    "touch-menu",
    "vertical-ui",
    "signature-enforcement",
    "hardware-dependencies",
    "recovery",
)
_DOCUMENT_FIELDS = {"schema_version", "capabilities"}
_CAPABILITY_FIELDS = {"id", "status", "summary", "evidence", "next_action"}
_EVIDENCE_FIELDS = {"kind", "source", "claim"}
_STATUSES = {"FEASIBLE", "PARTIAL", "BLOCKED", "INSUFFICIENT_EVIDENCE"}
_KINDS = {"OBSERVATION", "INFERENCE"}
_OFFICIAL_HOSTS = {"www.sony.com.tw", "helpguide.sony.net"}


class DecisionError(ValueError):
    """Raised when feasibility evidence does not match the fixed schema."""


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DecisionError(f"{label} must be nonempty text")
    return value


def _is_approved_source(source: str) -> bool:
    try:
        parsed = urlsplit(source)
    except ValueError:
        return False
    if parsed.scheme or parsed.netloc:
        return (
            parsed.scheme == "https"
            and parsed.hostname in _OFFICIAL_HOSTS
            and parsed.username is None
            and parsed.password is None
            and bool(parsed.path and parsed.path != "/")
        )

    if "\\" in source:
        return False
    path = PurePosixPath(source)
    return (
        not path.is_absolute()
        and path.parts[:2] == ("analysis", "reports")
        and len(path.parts) == 3
        and path.suffix.casefold() == ".json"
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def _validate_evidence_item(item: object, capability_id: str) -> dict:
    if not isinstance(item, dict) or set(item) != _EVIDENCE_FIELDS:
        raise DecisionError(f"Evidence for {capability_id} does not match the schema")
    kind = item["kind"]
    if not isinstance(kind, str) or kind not in _KINDS:
        raise DecisionError(f"Evidence for {capability_id} has an unsupported kind")
    source = _require_text(item["source"], "Evidence source")
    if not _is_approved_source(source):
        raise DecisionError(
            f"Evidence for {capability_id} must cite an official URL or report"
        )
    _require_text(item["claim"], "Evidence claim")
    return item


def _validate_capability(item: object) -> dict:
    if not isinstance(item, dict) or set(item) != _CAPABILITY_FIELDS:
        raise DecisionError("Capability does not match the schema")
    capability_id = _require_text(item["id"], "Capability id")
    if capability_id not in REQUIRED_CAPABILITIES:
        raise DecisionError(f"Unknown capability: {capability_id}")
    if not isinstance(item["status"], str) or item["status"] not in _STATUSES:
        raise DecisionError(f"Unsupported status for {capability_id}")
    _require_text(item["summary"], f"Summary for {capability_id}")
    _require_text(item["next_action"], f"Next action for {capability_id}")

    evidence = item["evidence"]
    if not isinstance(evidence, list) or not evidence:
        raise DecisionError(f"Evidence for {capability_id} must be a nonempty list")
    for evidence_item in evidence:
        _validate_evidence_item(evidence_item, capability_id)
    kinds = {evidence_item["kind"] for evidence_item in evidence}
    if "INFERENCE" in kinds and "OBSERVATION" not in kinds:
        raise DecisionError(f"Inference for {capability_id} requires an observation")
    return item


def validate_evidence(document: dict) -> dict:
    """Return an isolated schema-validated copy in required capability order."""
    if not isinstance(document, dict) or set(document) != _DOCUMENT_FIELDS:
        raise DecisionError("Evidence document does not match schema version 1")
    if type(document["schema_version"]) is not int:
        raise DecisionError("Evidence schema version must be an integer")
    if document["schema_version"] != SCHEMA_VERSION:
        raise DecisionError("Unsupported evidence schema version")
    if not isinstance(document["capabilities"], list):
        raise DecisionError("Capabilities must be a list")

    normalized = deepcopy(document)
    by_id = {}
    for item in normalized["capabilities"]:
        _validate_capability(item)
        capability_id = item["id"]
        if capability_id in by_id:
            raise DecisionError(f"Duplicate capability: {capability_id}")
        by_id[capability_id] = item
    if set(by_id) != set(REQUIRED_CAPABILITIES):
        raise DecisionError("Evidence must contain exactly the required capabilities")
    normalized["capabilities"] = [
        by_id[capability_id] for capability_id in REQUIRED_CAPABILITIES
    ]
    return normalized


def render_markdown(document: dict) -> str:
    """Render only validated decision content in deterministic Markdown."""
    normalized = validate_evidence(document)
    lines = [
        "# Sony α6400 Firmware Feasibility Decisions",
        "",
        "Generation source: validated evidence document (schema version 1).",
    ]
    for capability in normalized["capabilities"]:
        lines.extend(
            [
                "",
                f"## {capability['id']}",
                "",
                f"Status: `{capability['status']}`",
                "",
                f"Summary: {capability['summary']}",
                "",
                "Evidence:",
            ]
        )
        for evidence in capability["evidence"]:
            lines.append(
                f"- **{evidence['kind']}** — `{evidence['source']}`: "
                f"{evidence['claim']}"
            )
        lines.extend(
            [
                "",
                f"Next permitted action: {capability['next_action']}",
            ]
        )
    return "\n".join(lines) + "\n"
