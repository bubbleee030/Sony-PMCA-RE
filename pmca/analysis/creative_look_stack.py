"""Fail-closed α7 V Creative Look contract for offline ILCE-6400 research."""

from __future__ import annotations

import copy
import re
import unicodedata


BUILT_IN_LOOK_IDS = (
    "ST",
    "PT",
    "NT",
    "VV",
    "VV2",
    "FL",
    "FL2",
    "FL3",
    "IN",
    "SH",
    "BW",
    "SE",
)
CUSTOM_LOOK_IDS = tuple(f"Custom{index}" for index in range(1, 7))
AXIS_DEFINITIONS = {
    "contrast": (-9, 9),
    "highlights": (-9, 9),
    "shadows": (-9, 9),
    "fade": (0, 9),
    "saturation": (-9, 9),
    "sharpness": (0, 9),
    "sharpness_range": (1, 5),
    "clarity": (0, 9),
}
AXIS_IDS = tuple(AXIS_DEFINITIONS)
LAYER_IDS = (
    "interface",
    "state",
    "base_looks",
    "adjustment_axes",
    "pipeline_binding",
)
WORKFLOW_IDS = (
    "select_look",
    "edit_axes",
    "modified_marker",
    "reset_one_look",
    "select_custom_base",
)
RESTRICTION_IDS = (
    "intelligent_auto",
    "picture_profile_not_off",
    "flexible_iso_log",
    "bw_se_saturation",
    "movie_sharpness_range",
)
PIPELINE_OUTPUT_IDS = ("live_view", "still_jpeg", "movie")
REASON_CODES = frozenset(
    {
        "BASE_LOOK_REPRESENTATION_UNPROVEN",
        "CUSTOM_LOOK_STATE_UNPROVEN",
        "AXIS_UI_UNPROVEN",
        "AXIS_STATE_UNPROVEN",
        "AXIS_PIPELINE_UNPROVEN",
        "WORKFLOW_DISPATCH_UNPROVEN",
        "PERSISTENCE_UNPROVEN",
        "MODE_MATRIX_UNPROVEN",
        "LIVE_VIEW_BINDING_UNPROVEN",
        "STILL_JPEG_BINDING_UNPROVEN",
        "MOVIE_BINDING_UNPROVEN",
    }
)

# Compatibility alias for callers that consumed the schema-v1 constant.
LOOK_IDS = BUILT_IN_LOOK_IDS

REFERENCE_SOURCE = (
    "https://helpguide.sony.net/ilc/2540/v1/en/contents/"
    "0411B_creative_look.html"
)
REFERENCE_RESTRICTIONS = {
    "intelligent_auto": {
        "condition": "INTELLIGENT_AUTO",
        "scope": "creative_look",
        "effect": "UNAVAILABLE",
    },
    "picture_profile_not_off": {
        "condition": "PICTURE_PROFILE_NOT_OFF",
        "scope": "creative_look",
        "effect": "UNAVAILABLE",
    },
    "flexible_iso_log": {
        "condition": "FLEXIBLE_ISO_LOG",
        "scope": "creative_look",
        "effect": "UNAVAILABLE",
    },
    "bw_se_saturation": {
        "condition": "LOOK_IS_BW_OR_SE",
        "scope": "saturation",
        "effect": "UNAVAILABLE",
    },
    "movie_sharpness_range": {
        "condition": "MOVIE_MODE",
        "scope": "sharpness_range",
        "effect": "UNAVAILABLE",
    },
}

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
    "reference_catalog",
    "layers",
    "look_records",
    "custom_records",
    "workflow_records",
    "axis_records",
    "restriction_records",
    "pipeline_outputs",
    "presentation",
    "fallback",
    "safety",
    "native_creative_look_established",
}
_REFERENCE_FIELDS = {
    "source",
    "built_in_looks",
    "custom_slots",
    "axes",
    "workflow_actions",
    "restrictions",
}
_AXIS_DEFINITION_FIELDS = {"minimum", "maximum", "default"}
_RESTRICTION_DEFINITION_FIELDS = {"condition", "scope", "effect"}
_LAYER_FIELDS = {"status", "evidence", "blocker", "acceptance"}
_LOOK_FIELDS = {
    "status",
    "base_representation",
    "selectable_state",
    "output_bindings",
    "evidence",
    "blocker",
}
_CUSTOM_FIELDS = {
    "status",
    "base_selection",
    "slot_state",
    "adjustments",
    "reset",
    "persistence",
    "evidence",
    "blocker",
}
_WORKFLOW_FIELDS = {"status", "evidence", "blocker"}
_AXIS_FIELDS = {
    "status",
    "ui",
    "state",
    "range",
    "default",
    "pipeline",
    "evidence",
    "blocker",
}
_RESTRICTION_FIELDS = {"status", "implemented", "evidence", "blocker"}
_OUTPUT_FIELDS = {"status", "evidence", "blocker"}
_PRESENTATION_FIELDS = {"visibility", "availability", "reasons"}
_PRESENTATION_SECTIONS = {
    "looks": BUILT_IN_LOOK_IDS,
    "custom_slots": CUSTOM_LOOK_IDS,
    "axes": AXIS_IDS,
    "workflow_actions": WORKFLOW_IDS,
    "restriction_rules": RESTRICTION_IDS,
    "output_bindings": PIPELINE_OUTPUT_IDS,
}
_FALLBACK_FIELDS = {
    "creative_style_available",
    "status",
    "policy",
    "source",
    "represented_reference_looks",
    "unrepresented_reference_looks",
    "native_claim_basis",
}
_SAFETY_FIELDS = {
    "reference",
    "canonical_report_sha256",
    "readiness",
    "recovery_validated",
    "camera_test_eligible",
    "installable",
}
_EVIDENCE_FIELDS = {"source", "path_id", "semantic", "level", "claim"}
_NATIVE_EVIDENCE_SOURCES = {
    "analysis/a6400-creative-look-boundary.json",
    "analysis/a6400-ui-dispatch-boundary.json",
}
_EVIDENCE_LEVELS = {"CONFIRMED", "PARTIAL"}
_PATH_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,95}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_MAX_TEXT_CHARS = 2048


class CreativeLookStackError(ValueError):
    """Raised when the Creative Look contract is malformed or overclaimed."""


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


def _require_bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise CreativeLookStackError(f"{label} must be boolean")
    return value


def _require_members(value: object, identifiers: tuple[str, ...], label: str) -> dict:
    if not isinstance(value, dict) or list(value) != list(identifiers):
        raise CreativeLookStackError(f"{label} membership or order is invalid")
    return value


def _validate_evidence(value: object, semantic: str, status: str) -> None:
    if not isinstance(value, list):
        raise CreativeLookStackError(f"{semantic} evidence must be a list")
    path_ids: set[str] = set()
    levels: set[str] = set()
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


def _require_blocker(value: object, label: str, status: str) -> None:
    if status in {"UNESTABLISHED", "APPROXIMATION_ONLY", "HARDWARE_BLOCKED"}:
        _require_text(value, f"{label} blocker")
    else:
        _require_text(value, f"{label} blocker", allow_empty=True)


def _validate_record_base(record: dict, fields: set[str], semantic: str) -> str:
    if not isinstance(record, dict) or set(record) != fields:
        raise CreativeLookStackError(f"{semantic} fields are not exact")
    status = _require_status(record["status"], semantic)
    _validate_evidence(record["evidence"], semantic, status)
    _require_blocker(record["blocker"], semantic, status)
    return status


def _reference_catalog(document: dict) -> None:
    catalog = document["reference_catalog"]
    if not isinstance(catalog, dict) or set(catalog) != _REFERENCE_FIELDS:
        raise CreativeLookStackError("Creative Look reference catalog fields are invalid")
    if catalog["source"] != REFERENCE_SOURCE:
        raise CreativeLookStackError("Creative Look reference source is invalid")
    if catalog["built_in_looks"] != list(BUILT_IN_LOOK_IDS):
        raise CreativeLookStackError("Creative Look built-in membership is invalid")
    if catalog["custom_slots"] != list(CUSTOM_LOOK_IDS):
        raise CreativeLookStackError("Creative Look Custom membership is invalid")
    axes = _require_members(catalog["axes"], AXIS_IDS, "Creative Look axes")
    for axis_id, record in axes.items():
        if not isinstance(record, dict) or set(record) != _AXIS_DEFINITION_FIELDS:
            raise CreativeLookStackError(f"{axis_id} axis definition is invalid")
        minimum, maximum = AXIS_DEFINITIONS[axis_id]
        if record != {"minimum": minimum, "maximum": maximum, "default": None}:
            raise CreativeLookStackError(f"{axis_id} axis range or default is invalid")
    if catalog["workflow_actions"] != list(WORKFLOW_IDS):
        raise CreativeLookStackError("Creative Look workflow membership is invalid")
    restrictions = _require_members(
        catalog["restrictions"], RESTRICTION_IDS, "Creative Look restrictions"
    )
    for restriction_id, record in restrictions.items():
        if (
            not isinstance(record, dict)
            or set(record) != _RESTRICTION_DEFINITION_FIELDS
            or record != REFERENCE_RESTRICTIONS[restriction_id]
        ):
            raise CreativeLookStackError(
                f"{restriction_id} reference restriction is invalid"
            )


def _reasoned_record(reasons: list[str]) -> dict:
    return {
        "visibility": "VISIBLE",
        "availability": "DISABLED_UNPROVEN" if reasons else "ENABLED_OFFLINE",
        "reasons": reasons,
    }


def derive_presentation_availability(document: dict) -> dict:
    """Derive visible/offline availability without changing evidence records."""

    presentation = {section: {} for section in _PRESENTATION_SECTIONS}
    output_reasons = {
        "live_view": "LIVE_VIEW_BINDING_UNPROVEN",
        "still_jpeg": "STILL_JPEG_BINDING_UNPROVEN",
        "movie": "MOVIE_BINDING_UNPROVEN",
    }
    for look_id in BUILT_IN_LOOK_IDS:
        record = document["look_records"][look_id]
        reasons: list[str] = []
        if record["status"] not in NATIVE_CAPABLE or not record["base_representation"]:
            reasons.append("BASE_LOOK_REPRESENTATION_UNPROVEN")
        if not record["selectable_state"]:
            reasons.append("WORKFLOW_DISPATCH_UNPROVEN")
        for output_id in PIPELINE_OUTPUT_IDS:
            if not record["output_bindings"][output_id]:
                reasons.append(output_reasons[output_id])
        presentation["looks"][look_id] = _reasoned_record(reasons)

    for custom_id in CUSTOM_LOOK_IDS:
        record = document["custom_records"][custom_id]
        reasons = []
        if record["status"] not in NATIVE_CAPABLE or not all(
            record[field]
            for field in ("base_selection", "slot_state", "adjustments", "reset")
        ):
            reasons.append("CUSTOM_LOOK_STATE_UNPROVEN")
        if not record["persistence"]:
            reasons.append("PERSISTENCE_UNPROVEN")
        presentation["custom_slots"][custom_id] = _reasoned_record(reasons)

    for axis_id in AXIS_IDS:
        record = document["axis_records"][axis_id]
        reasons = []
        if not record["ui"]:
            reasons.append("AXIS_UI_UNPROVEN")
        if record["status"] not in NATIVE_CAPABLE or not all(
            record[field] for field in ("state", "range", "default")
        ):
            reasons.append("AXIS_STATE_UNPROVEN")
        if not record["pipeline"]:
            reasons.append("AXIS_PIPELINE_UNPROVEN")
        presentation["axes"][axis_id] = _reasoned_record(reasons)

    for workflow_id in WORKFLOW_IDS:
        record = document["workflow_records"][workflow_id]
        reasons = [] if record["status"] in NATIVE_CAPABLE else [
            "WORKFLOW_DISPATCH_UNPROVEN"
        ]
        presentation["workflow_actions"][workflow_id] = _reasoned_record(reasons)

    for restriction_id in RESTRICTION_IDS:
        record = document["restriction_records"][restriction_id]
        reasons = [] if (
            record["status"] in NATIVE_CAPABLE and record["implemented"]
        ) else ["MODE_MATRIX_UNPROVEN"]
        presentation["restriction_rules"][restriction_id] = _reasoned_record(reasons)

    for output_id in PIPELINE_OUTPUT_IDS:
        record = document["pipeline_outputs"][output_id]
        reasons = [] if record["status"] in NATIVE_CAPABLE else [
            output_reasons[output_id]
        ]
        presentation["output_bindings"][output_id] = _reasoned_record(reasons)
    return presentation


def _native_stack_complete(document: dict) -> bool:
    return (
        all(document["layers"][item]["status"] in NATIVE_CAPABLE for item in LAYER_IDS)
        and all(
            document["look_records"][item]["status"] in NATIVE_CAPABLE
            and document["look_records"][item]["base_representation"]
            and document["look_records"][item]["selectable_state"]
            and all(document["look_records"][item]["output_bindings"].values())
            for item in BUILT_IN_LOOK_IDS
        )
        and all(
            document["custom_records"][item]["status"] in NATIVE_CAPABLE
            and all(
                document["custom_records"][item][field]
                for field in (
                    "base_selection",
                    "slot_state",
                    "adjustments",
                    "reset",
                    "persistence",
                )
            )
            for item in CUSTOM_LOOK_IDS
        )
        and all(
            document["workflow_records"][item]["status"] in NATIVE_CAPABLE
            for item in WORKFLOW_IDS
        )
        and all(
            document["axis_records"][item]["status"] in NATIVE_CAPABLE
            and all(
                document["axis_records"][item][field]
                for field in ("ui", "state", "range", "default", "pipeline")
            )
            for item in AXIS_IDS
        )
        and all(
            document["restriction_records"][item]["status"] in NATIVE_CAPABLE
            and document["restriction_records"][item]["implemented"]
            for item in RESTRICTION_IDS
        )
        and all(
            document["pipeline_outputs"][item]["status"] in NATIVE_CAPABLE
            for item in PIPELINE_OUTPUT_IDS
        )
    )


def validate_creative_look_stack(document: dict) -> dict:
    """Return an isolated validated copy of the evidence-gated contract."""

    if not isinstance(document, dict) or set(document) != _DOCUMENT_FIELDS:
        raise CreativeLookStackError("Creative Look stack fields are not exact")
    if type(document["schema_version"]) is not int or document["schema_version"] != 2:
        raise CreativeLookStackError("Creative Look stack schema version is invalid")
    if document["target"] != "ILCE-6400":
        raise CreativeLookStackError("Creative Look stack target is invalid")
    if document["reference"] != "ILCE-7M5-creative-look-behavior":
        raise CreativeLookStackError("Creative Look stack reference is invalid")
    _reference_catalog(document)

    layers = _require_members(document["layers"], LAYER_IDS, "Creative Look layers")
    for layer_id, record in layers.items():
        _validate_record_base(record, _LAYER_FIELDS, layer_id)
        _require_text(record["acceptance"], f"{layer_id} acceptance")

    look_records = _require_members(
        document["look_records"], BUILT_IN_LOOK_IDS, "Creative Look records"
    )
    for look_id, record in look_records.items():
        status = _validate_record_base(record, _LOOK_FIELDS, look_id)
        flags = [
            _require_bool(record["base_representation"], f"{look_id} base representation"),
            _require_bool(record["selectable_state"], f"{look_id} selectable state"),
        ]
        outputs = _require_members(
            record["output_bindings"], PIPELINE_OUTPUT_IDS, f"{look_id} outputs"
        )
        flags.extend(
            _require_bool(value, f"{look_id} {output_id} binding")
            for output_id, value in outputs.items()
        )
        if status == "UNESTABLISHED" and any(flags):
            raise CreativeLookStackError(f"{look_id} unestablished boundaries are true")
        if status in NATIVE_CAPABLE and not all(flags):
            raise CreativeLookStackError(f"{look_id} native capability is incomplete")

    custom_records = _require_members(
        document["custom_records"], CUSTOM_LOOK_IDS, "Creative Look Custom records"
    )
    for custom_id, record in custom_records.items():
        status = _validate_record_base(record, _CUSTOM_FIELDS, custom_id)
        flags = [
            _require_bool(record[field], f"{custom_id} {field}")
            for field in ("base_selection", "slot_state", "adjustments", "reset", "persistence")
        ]
        if status == "UNESTABLISHED" and any(flags):
            raise CreativeLookStackError(f"{custom_id} unestablished boundaries are true")
        if status in NATIVE_CAPABLE and not all(flags):
            raise CreativeLookStackError(f"{custom_id} native capability is incomplete")

    workflows = _require_members(
        document["workflow_records"], WORKFLOW_IDS, "Creative Look workflows"
    )
    for workflow_id, record in workflows.items():
        _validate_record_base(record, _WORKFLOW_FIELDS, workflow_id)

    axes = _require_members(document["axis_records"], AXIS_IDS, "Creative Look axes")
    for axis_id, record in axes.items():
        status = _validate_record_base(record, _AXIS_FIELDS, axis_id)
        flags = [
            _require_bool(record[field], f"{axis_id} {field} boundary")
            for field in ("ui", "state", "range", "default", "pipeline")
        ]
        if status == "UNESTABLISHED" and any(flags):
            raise CreativeLookStackError(f"{axis_id} unestablished boundaries are true")
        if status in NATIVE_CAPABLE and not all(flags):
            raise CreativeLookStackError(f"{axis_id} native capability is incomplete")

    restrictions = _require_members(
        document["restriction_records"], RESTRICTION_IDS, "Creative Look restrictions"
    )
    for restriction_id, record in restrictions.items():
        status = _validate_record_base(record, _RESTRICTION_FIELDS, restriction_id)
        implemented = _require_bool(
            record["implemented"], f"{restriction_id} implementation"
        )
        if status == "UNESTABLISHED" and implemented:
            raise CreativeLookStackError(
                f"{restriction_id} unestablished implementation is true"
            )
        if status in NATIVE_CAPABLE and not implemented:
            raise CreativeLookStackError(
                f"{restriction_id} native implementation is false"
            )

    outputs = _require_members(
        document["pipeline_outputs"], PIPELINE_OUTPUT_IDS, "Creative Look outputs"
    )
    for output_id, record in outputs.items():
        _validate_record_base(record, _OUTPUT_FIELDS, output_id)

    fallback = document["fallback"]
    if not isinstance(fallback, dict) or set(fallback) != _FALLBACK_FIELDS:
        raise CreativeLookStackError("Creative Style fallback fields are not exact")
    _require_bool(fallback["creative_style_available"], "Creative Style availability")
    if fallback["status"] != "APPROXIMATION_ONLY":
        raise CreativeLookStackError("Creative Style fallback status is invalid")
    if fallback["policy"] != "LAST_RESORT_ONLY":
        raise CreativeLookStackError("Creative Style fallback policy is invalid")
    if fallback["source"] != "analysis/creative-look-recipes.json":
        raise CreativeLookStackError("Creative Style fallback source is invalid")
    represented = fallback["represented_reference_looks"]
    unrepresented = fallback["unrepresented_reference_looks"]
    expected_represented = [
        "ST", "PT", "NT", "VV", "VV2", "FL", "IN", "SH", "BW", "SE"
    ]
    if represented != expected_represented or unrepresented != ["FL2", "FL3"]:
        raise CreativeLookStackError("Creative Style fallback coverage is invalid")
    if set(represented) & set(unrepresented) or set(represented + unrepresented) != set(
        BUILT_IN_LOOK_IDS
    ):
        raise CreativeLookStackError("Creative Style fallback coverage overlaps or omits")
    if fallback["native_claim_basis"] is not False:
        raise CreativeLookStackError("Creative Style cannot be native claim evidence")

    safety = document["safety"]
    if not isinstance(safety, dict) or set(safety) != _SAFETY_FIELDS:
        raise CreativeLookStackError("Creative Look safety fields are not exact")
    if safety["reference"] != "analysis/a6400-stock-200-recovery.json":
        raise CreativeLookStackError("Creative Look recovery reference is invalid")
    if not isinstance(safety["canonical_report_sha256"], str) or not _DIGEST.fullmatch(
        safety["canonical_report_sha256"]
    ):
        raise CreativeLookStackError("Creative Look recovery digest is invalid")
    if safety["readiness"] != "BLOCKED_STATIC_EVIDENCE":
        raise CreativeLookStackError("Creative Look recovery readiness must stay blocked")
    for field in ("recovery_validated", "camera_test_eligible", "installable"):
        if safety[field] is not False:
            raise CreativeLookStackError(f"Creative Look safety {field} must stay false")

    presentation = document["presentation"]
    if not isinstance(presentation, dict) or list(presentation) != list(
        _PRESENTATION_SECTIONS
    ):
        raise CreativeLookStackError("Creative Look presentation sections are invalid")
    for section, identifiers in _PRESENTATION_SECTIONS.items():
        records = _require_members(
            presentation[section], identifiers, f"Creative Look presentation {section}"
        )
        for identifier, record in records.items():
            if not isinstance(record, dict) or set(record) != _PRESENTATION_FIELDS:
                raise CreativeLookStackError(
                    f"Creative Look presentation {section} {identifier} is invalid"
                )
            if record["visibility"] != "VISIBLE":
                raise CreativeLookStackError("Creative Look item visibility is invalid")
            if record["availability"] not in {"ENABLED_OFFLINE", "DISABLED_UNPROVEN"}:
                raise CreativeLookStackError("Creative Look item availability is invalid")
            if (
                not isinstance(record["reasons"], list)
                or len(record["reasons"]) != len(set(record["reasons"]))
                or any(reason not in REASON_CODES for reason in record["reasons"])
            ):
                raise CreativeLookStackError("Creative Look item reasons are invalid")
    if presentation != derive_presentation_availability(document):
        raise CreativeLookStackError("Creative Look presentation is not derived")

    native_claim = document["native_creative_look_established"]
    if type(native_claim) is not bool:
        raise CreativeLookStackError("native Creative Look claim must be boolean")
    if native_claim and not _native_stack_complete(document):
        raise CreativeLookStackError("native Creative Look claim is not fully supported")

    return copy.deepcopy(document)
