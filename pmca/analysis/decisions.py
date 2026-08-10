"""Validate and render evidence-bounded firmware feasibility decisions."""

from copy import deepcopy
import json
from pathlib import Path
import unicodedata

from .creative_look_stack import (
    CreativeLookStackError,
    validate_creative_look_stack,
)
from .creative_looks import CreativeLookError, validate_recipe_document
from .recovery_path import RecoveryPathError, validate_recovery_report


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
        "https://helpguide.sony.net/ilc/2540/v1/en/contents/"
        "0411B_creative_look.html",
        "https://helpguide.sony.net/ilc/2320/v1/en/contents/"
        "211h_touchpanel_settings.html",
        "https://helpguide.sony.net/ilc/2320/v1/en/contents/"
        "221h_touch_function_icon.html",
        "https://helpguide.sony.net/ilc/1810/v1/en/contents/"
        "TP0002264693.html",
        "https://helpguide.sony.net/ilc/1810/v1/en/contents/"
        "TP0002278024.html",
        "https://helpguide.sony.net/ilc/1810/v1/en/contents/"
        "TP0002241295.html",
        "https://helpguide.sony.net/ilc/1810/v1/en/contents/"
        "TP0002280339.html",
        "https://helpguide.sony.net/ilc/2540/v1/en/contents/"
        "251h_vertical_ui_display.html",
        "analysis/reports/a6400-tw-v2.00.json",
        "analysis/reports/a6700-tw-v2.00.json",
        "analysis/reports/a7v-tw-v2.00.json",
        "analysis/structures/a6400-tw-v2.00.json",
        "analysis/structures/a6700-tw-v2.00.json",
        "analysis/structures/a7v-tw-v2.00.json",
        "analysis/tool-baselines/ma1co-fwtool.json",
        "analysis/tool-baselines/joeording3-fwtool.json",
        "analysis/tool-baselines/ironpayne22-fwtool.json",
        "analysis/signature-experiments.json",
        "analysis/feature-compatibility.json",
        "analysis/creative-look-recipes.json",
        "analysis/a6400-creative-look-guide.md",
        "analysis/a6400-creative-look-boundary.json",
        "analysis/a6400-creative-look-stack.json",
        "analysis/firmware-manifest.json",
        "analysis/tool-provenance.json",
        "analysis/a6400-stock-200-bundle.json",
        "analysis/a6400-recovery-scenarios.json",
        "analysis/a6400-stock-200-recovery.json",
        "analysis/a6400a-updater-control-bootstrap.json",
        "README.md",
    }
)
_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_RECOVERY_REPORT_REFERENCE = "analysis/a6400-stock-200-recovery.json"
_CREATIVE_LOOK_STACK_REFERENCE = "analysis/a6400-creative-look-stack.json"
_CREATIVE_LOOK_RECIPES_REFERENCE = "analysis/creative-look-recipes.json"


class DecisionError(ValueError):
    """Raised when feasibility evidence does not match the fixed schema."""


def derive_creative_look_capabilities(
    stack_document: dict, recipes_document: dict
) -> tuple[dict, dict]:
    """Derive first-class and fallback decisions from their strict contracts."""

    try:
        stack = validate_creative_look_stack(stack_document)
        recipes = validate_recipe_document(recipes_document)
    except (CreativeLookStackError, CreativeLookError) as error:
        raise DecisionError("Creative Look contract evidence is unavailable") from error

    fallback = stack["fallback"]
    if (
        stack["reference_catalog"]["source"] != recipes["reference_source"]
        or fallback["source"] != _CREATIVE_LOOK_RECIPES_REFERENCE
        or fallback["represented_reference_looks"]
        != recipes["represented_reference_looks"]
        or fallback["unrepresented_reference_looks"]
        != recipes["unrepresented_reference_looks"]
        or fallback["native_claim_basis"] is not False
        or recipes["native_claim_basis"] is not False
    ):
        raise DecisionError("Creative Look fallback does not match the stack contract")

    discovery = {
        "id": "creative-look-discovery",
        "status": "INSUFFICIENT_EVIDENCE",
        "summary": "The authoritative α7 V contract records 12 built-in looks and six Custom slots; all 26 look, Custom, and axis items are visible in the offline contract but disabled because target UI, state, range/default, processing, and output joins remain unestablished.",
        "evidence": [
            {
                "kind": "OBSERVATION",
                "source": stack["reference_catalog"]["source"],
                "claim": "Sony documents 12 built-in Creative Looks, six Custom slots, eight adjustment axes, five workflows, and five mode-dependent restrictions for the α7 V reference behavior.",
            },
            {
                "kind": "OBSERVATION",
                "source": _CREATIVE_LOOK_STACK_REFERENCE,
                "claim": "The validated offline contract keeps every built-in look, Custom slot, axis, workflow, restriction, and output binding visible while marking each unavailable target path disabled or unestablished.",
            },
            {
                "kind": "OBSERVATION",
                "source": "analysis/a6400-creative-look-boundary.json",
                "claim": "Bounded target evidence does not establish a first-class Creative Look interface, state model, base-look table, adjustment pipeline, or live-view, still-JPEG, and movie output bindings.",
            },
            {
                "kind": "INFERENCE",
                "source": _CREATIVE_LOOK_STACK_REFERENCE,
                "claim": "A complete behavioral contract is suitable for continued offline research but cannot authorize implementation or camera testing while every required target chain remains disabled.",
            },
        ],
        "next_action": "Trace independent target UI, state, range/default, workflow, restriction, and live-view/still-JPEG/movie processing paths; keep every unsupported contract item visible and disabled.",
    }
    emulation = {
        "id": "creative-look-emulation",
        "status": "PARTIAL",
        "summary": "A separate Creative Style fallback represents 10 of the 12 reference looks as approximations; FL2 and FL3 have no fallback representation, and the catalog does not establish native Creative Look behavior.",
        "evidence": [
            {
                "kind": "OBSERVATION",
                "source": recipes["creative_style_source"],
                "claim": "ILCE-6400 Creative Style exposes the target-native styles, six Style Boxes, and three adjustment controls used by the fallback catalog.",
            },
            {
                "kind": "OBSERVATION",
                "source": _CREATIVE_LOOK_RECIPES_REFERENCE,
                "claim": "The schema-v2 fallback catalog represents ST, PT, NT, VV, VV2, FL, IN, SH, BW, and SE while explicitly leaving FL2 and FL3 unrepresented.",
            },
            {
                "kind": "OBSERVATION",
                "source": "analysis/a6400-creative-look-guide.md",
                "claim": "The deterministic guide labels every recipe APPROXIMATION_ONLY and LAST_RESORT_ONLY and rejects native, colorimetric, installation, recovery, and camera-test claims.",
            },
            {
                "kind": "INFERENCE",
                "source": _CREATIVE_LOOK_RECIPES_REFERENCE,
                "claim": "Creative Style remains a reversible fallback candidate rather than a first-class Creative Look implementation or proof of Sony-exact output.",
            },
        ],
        "next_action": "Retain the ten fallback recipes for offline comparison only; prioritize the separate first-class contract and do not fabricate FL2 or FL3 mappings.",
    }
    return discovery, emulation


def _load_creative_look_capabilities() -> tuple[dict, dict]:
    try:
        stack = json.loads(
            (_REPOSITORY_ROOT / _CREATIVE_LOOK_STACK_REFERENCE).read_text(
                encoding="utf-8"
            )
        )
        recipes = json.loads(
            (_REPOSITORY_ROOT / _CREATIVE_LOOK_RECIPES_REFERENCE).read_text(
                encoding="utf-8"
            )
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise DecisionError("Creative Look decision inputs are unavailable") from error
    return derive_creative_look_capabilities(stack, recipes)


def derive_recovery_capability(document: dict | None = None) -> dict:
    """Derive the repository recovery decision from the strict recovery report."""

    try:
        if document is None:
            document = json.loads(
                (_REPOSITORY_ROOT / _RECOVERY_REPORT_REFERENCE).read_text(
                    encoding="utf-8"
                )
            )
        recovery = validate_recovery_report(document)
    except (OSError, UnicodeError, json.JSONDecodeError, RecoveryPathError) as error:
        raise DecisionError("Strict recovery evidence is unavailable") from error

    if recovery["recovery_validated"] or recovery["camera_test_eligible"]:
        raise DecisionError("Static recovery evidence cannot authorize camera testing")
    readiness = recovery["readiness"]
    if readiness == "READY_FOR_FUTURE_VALIDATION_DESIGN":
        expected_basis = {
            "authenticated_stock_bundle": True,
            "runtime_independent_entry_established": True,
            "write_scope_established": True,
            "write_order_established": True,
            "post_write_verification_established": True,
            "scenario_overclaim_count": 0,
        }
        if recovery["readiness_basis"] != expected_basis:
            raise DecisionError("Future validation design readiness is inconsistent")
        return {
            "id": "recovery",
            "status": "BLOCKED",
            "summary": "Static evidence is sufficient only to design a future stock-recovery validation; recovery itself and camera testing remain unvalidated.",
            "evidence": [
                {
                    "kind": "OBSERVATION",
                    "source": "analysis/a6400-stock-200-bundle.json",
                    "claim": "The official Sony Taiwan updater and its embedded stock container remain digest-pinned to ILCE-6400 model 0x81030011, region code 0, and version 2.00.",
                },
                {
                    "kind": "OBSERVATION",
                    "source": _RECOVERY_REPORT_REFERENCE,
                    "claim": "The strict static report records READY_FOR_FUTURE_VALIDATION_DESIGN while recovery_validated and camera_test_eligible remain false.",
                },
                {
                    "kind": "INFERENCE",
                    "source": _RECOVERY_REPORT_REFERENCE,
                    "claim": "Static readiness can authorize a separately reviewed validation design but cannot establish physical recovery or authorize camera operations.",
                },
            ],
            "next_action": "Draft and separately review a non-operational stock-recovery validation design; keep the camera disconnected until fresh authorization is given for a later supervised phase.",
        }
    if readiness != "BLOCKED_STATIC_EVIDENCE":
        raise DecisionError("Recovery readiness is not recognized")
    if any(item["status"] != "UNESTABLISHED" for item in recovery["candidates"]):
        raise DecisionError("Blocked recovery candidate status is inconsistent")

    return {
        "id": "recovery",
        "status": "BLOCKED",
        "summary": "The exact Taiwan/region-0 α6400 2.00 stock source is authenticated, but all three external restore candidates and all six mandatory failure scenarios remain unestablished; recovery and camera testing are unvalidated.",
        "evidence": [
            {
                "kind": "OBSERVATION",
                "source": "analysis/a6400-stock-200-bundle.json",
                "claim": "The official Sony Taiwan updater and its embedded stock container are digest-pinned to ILCE-6400 model `0x81030011`, region code `0`, and version `2.00`.",
            },
            {
                "kind": "OBSERVATION",
                "source": "analysis/a6400-recovery-scenarios.json",
                "claim": "All six mandatory failure scenarios and every one of their three candidate coverage records remain `UNESTABLISHED`.",
            },
            {
                "kind": "OBSERVATION",
                "source": _RECOVERY_REPORT_REFERENCE,
                "claim": "The strict report records `BLOCKED_STATIC_EVIDENCE`, `recovery_validated=false`, `camera_test_eligible=false`, and no runtime-independent entry or complete write and verification path.",
            },
            {
                "kind": "OBSERVATION",
                "source": "analysis/a6400a-updater-control-bootstrap.json",
                "claim": "The different-model alpha 6400A 1.01 control resolves a bounded 37-function/71-call receiver graph with model/region/version guards and signature verification; target transfer, write orchestration, completion verification, and recovery support remain false.",
            },
            {
                "kind": "INFERENCE",
                "source": _RECOVERY_REPORT_REFERENCE,
                "claim": "Host-side updater mapping cannot establish camera-side reinstall acceptance, boot recovery, complete stock restoration, or safe interrupted-restore behavior.",
            },
        ],
        "next_action": "Continue static work on the missing pre-normal-runtime updater selector or authentic earlier installing receiver; do not draft camera steps until the strict report reaches a separately reviewed future-validation-design gate and fresh authorization exists.",
    }


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
    expected_creative = {
        item["id"]: item for item in _load_creative_look_capabilities()
    }
    for capability_id, expected in expected_creative.items():
        if by_id[capability_id] != expected:
            raise DecisionError(
                f"{capability_id} must be derived from strict Creative Look reports"
            )
    if by_id["recovery"] != derive_recovery_capability():
        raise DecisionError("Recovery capability must be derived from strict reports")
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
        "Generated decision section source: validated evidence document (schema version 1).",
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
