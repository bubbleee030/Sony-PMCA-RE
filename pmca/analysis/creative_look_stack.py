"""Fail-closed contract for first-class Creative Look research on ILCE-6400."""

from __future__ import annotations

import copy
import re
import unicodedata


LOOK_IDS = ("ST", "PT", "NT", "VV", "VV2", "FL", "IN", "SH", "BW", "SE")
AXIS_IDS = (
    "contrast",
    "highlights",
    "shadows",
    "fade",
    "saturation",
    "sharpness",
    "sharpness_range",
    "clarity",
)
LAYER_IDS = (
    "interface",
    "state",
    "base_looks",
    "adjustment_axes",
    "pipeline_binding",
)
WORKFLOW_IDS = (
    "menu_entry",
    "ten_preset_browser",
    "edit_screen",
    "reset_to_default",
    "copy_select",
    "range_display",
    "persistence",
    "mode_restrictions",
)
PIPELINE_OUTPUT_IDS = ("live_view", "still_jpeg", "movie")
STATUSES = {
    "TARGET_NATIVE",
    "TARGET_REIMPLEMENTABLE",
    "DONOR_COMPATIBLE",
    "APPROXIMATION_ONLY",
    "HARDWARE_BLOCKED",
    "UNESTABLISHED",
}
NATIVE_CAPABLE = {
    "TARGET_NATIVE",
    "TARGET_REIMPLEMENTABLE",
    "DONOR_COMPATIBLE",
}

_DOCUMENT_FIELDS = {
    "schema_version",
    "target",
    "reference",
    "looks",
    "axes",
    "layers",
    "workflow_records",
    "axis_records",
    "pipeline_outputs",
    "fallback",
    "native_creative_look_established",
}
_LAYER_FIELDS = {"status", "evidence", "blocker", "acceptance"}
_WORKFLOW_FIELDS = {"status", "evidence", "blocker"}
_AXIS_FIELDS = {"status", "ui", "state", "pipeline", "evidence", "blocker"}
_OUTPUT_FIELDS = {"status", "evidence", "blocker"}
_FALLBACK_FIELDS = {
    "creative_style_available",
    "status",
    "policy",
    "source",
    "native_claim_basis",
}
_EVIDENCE_FIELDS = {"source", "path_id", "semantic", "level", "claim"}
_NATIVE_EVIDENCE_SOURCES = {
    "analysis/a6400-creative-look-boundary.json",
    "analysis/a6400-ui-dispatch-boundary.json",
}
_EVIDENCE_LEVELS = {"CONFIRMED", "PARTIAL"}
_PATH_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,95}\Z")
_MAX_TEXT_CHARS = 2048


class CreativeLookStackError(ValueError):
    """Raised when the Creative Look stack contract is malformed or overclaimed."""


def _require_text(value: object, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise CreativeLookStackError(f"{label} must be text")
    if not allow_empty and not value.strip():
        raise CreativeLookStackError(f"{label} must be nonempty text")
    if len(value) > _MAX_TEXT_CHARS:
        raise CreativeLookStackError(f"{label} exceeds the text size limit")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise CreativeLookStackError(f"{label} contains a control character")
    return value


def _require_status(value: object, label: str) -> str:
    if not isinstance(value, str) or value not in STATUSES:
        raise CreativeLookStackError(f"{label} status is invalid")
    return value


def _validate_evidence(value: object, semantic: str, status: str) -> set[str]:
    if not isinstance(value, list):
        raise CreativeLookStackError(f"{semantic} evidence must be a list")

    levels: set[str] = set()
    path_ids: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != _EVIDENCE_FIELDS:
            raise CreativeLookStackError(f"{semantic} evidence fields are not exact")
        if item["source"] not in _NATIVE_EVIDENCE_SOURCES:
            raise CreativeLookStackError(
                f"{semantic} evidence is not a pinned native-path source"
            )
        if not isinstance(item["path_id"], str) or not _PATH_ID.fullmatch(
            item["path_id"]
        ):
            raise CreativeLookStackError(f"{semantic} evidence path id is invalid")
        if item["path_id"] in path_ids:
            raise CreativeLookStackError(f"{semantic} evidence path id is duplicated")
        path_ids.add(item["path_id"])
        if item["semantic"] != semantic:
            raise CreativeLookStackError(f"{semantic} evidence semantic is mismatched")
        if item["level"] not in _EVIDENCE_LEVELS:
            raise CreativeLookStackError(f"{semantic} evidence level is invalid")
        levels.add(item["level"])
        _require_text(item["claim"], f"{semantic} evidence claim")

    if status != "UNESTABLISHED" and not value:
        raise CreativeLookStackError(f"{semantic} status requires bounded evidence")
    if status in NATIVE_CAPABLE and "CONFIRMED" not in levels:
        raise CreativeLookStackError(
            f"{semantic} native-capable status requires confirmed evidence"
        )
    return levels


def _require_blocker(value: object, label: str, status: str) -> None:
    if status in {"UNESTABLISHED", "APPROXIMATION_ONLY", "HARDWARE_BLOCKED"}:
        _require_text(value, f"{label} blocker")
    else:
        _require_text(value, f"{label} blocker", allow_empty=True)


def _native_stack_complete(document: dict) -> bool:
    return (
        all(document["layers"][layer]["status"] in NATIVE_CAPABLE for layer in LAYER_IDS)
        and all(
            document["workflow_records"][workflow]["status"] in NATIVE_CAPABLE
            for workflow in WORKFLOW_IDS
        )
        and all(
            document["axis_records"][axis]["status"] in NATIVE_CAPABLE
            for axis in AXIS_IDS
        )
        and all(
            document["pipeline_outputs"][output]["status"] in NATIVE_CAPABLE
            for output in PIPELINE_OUTPUT_IDS
        )
    )


def validate_creative_look_stack(document: dict) -> dict:
    """Return an isolated validated copy of the fixed Creative Look contract."""

    if not isinstance(document, dict) or set(document) != _DOCUMENT_FIELDS:
        raise CreativeLookStackError("Creative Look stack fields are not exact")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise CreativeLookStackError("Creative Look stack schema version is invalid")
    if document["target"] != "ILCE-6400":
        raise CreativeLookStackError("Creative Look stack target is invalid")
    if document["reference"] != "ILCE-7M5-creative-look-behavior":
        raise CreativeLookStackError("Creative Look stack reference is invalid")
    if document["looks"] != list(LOOK_IDS):
        raise CreativeLookStackError("Creative Look membership or order is invalid")
    if document["axes"] != list(AXIS_IDS):
        raise CreativeLookStackError("Creative Look axis membership or order is invalid")

    layers = document["layers"]
    if not isinstance(layers, dict) or list(layers) != list(LAYER_IDS):
        raise CreativeLookStackError("Creative Look layer membership or order is invalid")
    for layer_id, record in layers.items():
        if not isinstance(record, dict) or set(record) != _LAYER_FIELDS:
            raise CreativeLookStackError(f"{layer_id} layer fields are not exact")
        status = _require_status(record["status"], layer_id)
        _validate_evidence(record["evidence"], layer_id, status)
        _require_blocker(record["blocker"], layer_id, status)
        _require_text(record["acceptance"], f"{layer_id} acceptance")

    workflow_records = document["workflow_records"]
    if not isinstance(workflow_records, dict) or list(workflow_records) != list(
        WORKFLOW_IDS
    ):
        raise CreativeLookStackError("Creative Look workflow records are not exact")
    for workflow_id, record in workflow_records.items():
        if not isinstance(record, dict) or set(record) != _WORKFLOW_FIELDS:
            raise CreativeLookStackError(
                f"{workflow_id} workflow fields are not exact"
            )
        status = _require_status(record["status"], workflow_id)
        _validate_evidence(record["evidence"], workflow_id, status)
        _require_blocker(record["blocker"], workflow_id, status)

    axis_records = document["axis_records"]
    if not isinstance(axis_records, dict) or list(axis_records) != list(AXIS_IDS):
        raise CreativeLookStackError("Creative Look axis records are not exact")
    for axis_id, record in axis_records.items():
        if not isinstance(record, dict) or set(record) != _AXIS_FIELDS:
            raise CreativeLookStackError(f"{axis_id} axis fields are not exact")
        status = _require_status(record["status"], axis_id)
        for boundary in ("ui", "state", "pipeline"):
            if type(record[boundary]) is not bool:
                raise CreativeLookStackError(
                    f"{axis_id} {boundary} boundary must be boolean"
                )
        if status == "UNESTABLISHED" and any(
            record[boundary] for boundary in ("ui", "state", "pipeline")
        ):
            raise CreativeLookStackError(
                f"{axis_id} unestablished status cannot promote a boundary"
            )
        if status in NATIVE_CAPABLE and not all(
            record[boundary] for boundary in ("ui", "state", "pipeline")
        ):
            raise CreativeLookStackError(
                f"{axis_id} native-capable status requires every boundary"
            )
        _validate_evidence(record["evidence"], axis_id, status)
        _require_blocker(record["blocker"], axis_id, status)

    pipeline_outputs = document["pipeline_outputs"]
    if not isinstance(pipeline_outputs, dict) or list(pipeline_outputs) != list(
        PIPELINE_OUTPUT_IDS
    ):
        raise CreativeLookStackError("Creative Look pipeline outputs are not exact")
    for output_id, record in pipeline_outputs.items():
        if not isinstance(record, dict) or set(record) != _OUTPUT_FIELDS:
            raise CreativeLookStackError(f"{output_id} output fields are not exact")
        status = _require_status(record["status"], output_id)
        _validate_evidence(record["evidence"], output_id, status)
        _require_blocker(record["blocker"], output_id, status)

    fallback = document["fallback"]
    if not isinstance(fallback, dict) or set(fallback) != _FALLBACK_FIELDS:
        raise CreativeLookStackError("Creative Style fallback fields are not exact")
    if type(fallback["creative_style_available"]) is not bool:
        raise CreativeLookStackError("Creative Style availability must be boolean")
    if fallback["status"] != "APPROXIMATION_ONLY":
        raise CreativeLookStackError("Creative Style fallback status is invalid")
    if fallback["policy"] != "LAST_RESORT_ONLY":
        raise CreativeLookStackError("Creative Style fallback policy is invalid")
    if fallback["source"] != "analysis/a6400-creative-look-guide.md":
        raise CreativeLookStackError("Creative Style fallback source is invalid")
    if fallback["native_claim_basis"] is not False:
        raise CreativeLookStackError("Creative Style cannot be native claim evidence")

    native_claim = document["native_creative_look_established"]
    if type(native_claim) is not bool:
        raise CreativeLookStackError("native Creative Look claim must be boolean")
    if native_claim and not _native_stack_complete(document):
        raise CreativeLookStackError("native Creative Look claim is not fully supported")

    return copy.deepcopy(document)
