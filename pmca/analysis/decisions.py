"""Validate and render evidence-bounded firmware feasibility decisions."""

from copy import deepcopy
import unicodedata


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
_MAX_TEXT_CHARS = 2048
_MAX_RENDERED_BYTES = 64 * 1024
_APPROVED_SOURCES = frozenset(
    {
        "https://www.sony.com.tw/zh/electronics/support/"
        "e-mount-body-ilce-6000-series/ilce-6400/downloads/00016145",
        "https://www.sony.com.tw/zh/electronics/support/"
        "e-mount-body-ilce-6000-series/ilce-6700/software/00298440",
        "https://helpguide.sony.net/ilc/2320/v1/en/contents/"
        "0411B_creative_look.html",
        "https://helpguide.sony.net/ilc/2320/v1/en/contents/"
        "211h_touchpanel_settings.html",
        "https://helpguide.sony.net/ilc/2320/v1/en/contents/"
        "221h_touch_function_icon.html",
        "analysis/reports/a6400-tw-v2.00.json",
        "analysis/reports/a6700-tw-v2.00.json",
        "README.md",
    }
)


class DecisionError(ValueError):
    """Raised when feasibility evidence does not match the fixed schema."""


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DecisionError(f"{label} must be nonempty text")
    if len(value) > _MAX_TEXT_CHARS:
        raise DecisionError(f"{label} exceeds the text size limit")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise DecisionError(f"{label} contains a control character")
    return value


def _is_approved_source(source: str) -> bool:
    return source in _APPROVED_SOURCES


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
    markdown = "\n".join(lines) + "\n"
    if len(markdown.encode("utf-8")) > _MAX_RENDERED_BYTES:
        raise DecisionError("Rendered Markdown exceeds the output size limit")
    return markdown
