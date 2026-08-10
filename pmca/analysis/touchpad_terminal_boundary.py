"""Fail-closed evidence contract for the α6400 touchpad terminal boundary."""
from __future__ import annotations

import copy
import hashlib
import json
import re

VIEW_UNIFIED2_SHA256 = "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2"
VIEW_UNIFIED2_SIZE = 11530552
PRIOR_UI_GRAPH_SHA256 = "d19fc94fd52583f3d321535fd8b6a01aa03f4efc0c4dadde52adce3a9d246f22"
VERIFIED_PATH_EDGES = [
    {"owner": "0x22355e", "site": "0x223b36", "target": "0x21c644"},
    {"owner": "0x21c644", "site": "0x21c770", "target": "0x1626cc"},
]
OWNERS = [
    {"owner": "0x162608", "end": "0x162760"},
    {"owner": "0x41b244", "end": "0x41b290"},
    {"owner": "0x41add8", "end": "0x41ae68"},
    {"owner": "0x2b3f7c", "end": "0x2b3f98"},
]
INTERNAL_EDGES = [{"owner": "0x41b244", "site": "0x41b24e", "target": "0x2b3f7c"}]
PLT_BINDINGS = [
    {"relocation_index": 43, "got_address": "0x944758", "plt_address": "0x14e6c8", "symbol": "InputService::forceReleaseTp"},
    {"relocation_index": 154, "got_address": "0x944914", "plt_address": "0x14ecac", "symbol": "InputService::setTpEnableArea"},
    {"relocation_index": 1730, "got_address": "0x9461b4", "plt_address": "0x15404c", "symbol": "CmnViewTPAreaEnableUtil::setTouchPadEnableAreaToOff"},
    {"relocation_index": 2101, "got_address": "0x946780", "plt_address": "0x1553f4", "symbol": "CmnViewTPAreaEnableUtil::setTouchPadEnabAreaForEvfOn"},
]
CLAIMS = {
    "touch_configuration_found": False,
    "coordinate_transform_found": False,
    "hit_test_found": False,
    "gesture_found": False,
    "selection_dispatch_found": False,
    "object_ownership_found": False,
}
CONCLUSION = (
    "Only the first two touchpad-reconfiguration path edges are independently "
    "verified. The four terminal owners contain no dynamic typed identity, relocation, "
    "or direct call to the four bounded touch APIs; the one narrow internal edge has a "
    "callee with zero direct calls. The historical final two links are not independently "
    "proven, so no touch configuration or menu-touch behavior is established."
)
REPORT_ARTIFACT_SHA256 = "d4b9a5520d65b5243db55f84651cc19dbeca92a351196de37532eea886ec1d78"
_HEX = re.compile(r"0x[0-9a-f]+\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FORBIDDEN = ("raw", "byte", "disassembly", "instruction", "key", "device", "write", "usb", "flash", "package")


class TouchpadTerminalBoundaryError(ValueError):
    """Raised when terminal evidence is incomplete, unsafe, or promoted."""


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise TouchpadTerminalBoundaryError(label + " fields are invalid")
    return value


def _forbid(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if any(token in str(key).casefold() for token in _FORBIDDEN):
                raise TouchpadTerminalBoundaryError("unsafe or reconstructive evidence field")
            _forbid(item)
    elif isinstance(value, list):
        for item in value:
            _forbid(item)


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def normalize_touchpad_terminal_export(document):
    """Validate the exact, bounded static touchpad-terminal export."""
    _forbid(document)
    _exact(document, {
        "program", "sha256", "file_size", "analysis_mode", "program_changed", "prior_ui_graph_sha256",
        "verified_path_edges", "owners", "owner_dynamic_relocations", "owner_dynamic_symbols", "internal_edges",
        "callee_direct_call_count", "reverse_reference_scan", "plt_bindings", "owner_direct_plt_calls", "truncated",
    }, "raw export")
    if (document["program"], document["sha256"], document["file_size"]) != ("viewUnified2.so", VIEW_UNIFIED2_SHA256, VIEW_UNIFIED2_SIZE):
        raise TouchpadTerminalBoundaryError("source identity differs")
    if document["analysis_mode"] != {"read_only": True, "static_elf_metadata": True, "thumb_control_flow": True} or document["program_changed"] is not False or document["truncated"] is not False:
        raise TouchpadTerminalBoundaryError("source execution mode is unsafe")
    if document["prior_ui_graph_sha256"] != PRIOR_UI_GRAPH_SHA256 or document["verified_path_edges"] != VERIFIED_PATH_EDGES or document["owners"] != OWNERS or document["internal_edges"] != INTERNAL_EDGES:
        raise TouchpadTerminalBoundaryError("edge, range, or prior graph linkage differs")
    if document["owner_dynamic_relocations"] or document["owner_dynamic_symbols"] or document["owner_direct_plt_calls"] or document["callee_direct_call_count"] != 0:
        raise TouchpadTerminalBoundaryError("bounded owner result is not empty")
    if document["reverse_reference_scan"] != {"rel_dyn_count": 137966, "matching_relative_addends": []}:
        raise TouchpadTerminalBoundaryError("reverse relocation scan differs")
    if document["plt_bindings"] != PLT_BINDINGS:
        raise TouchpadTerminalBoundaryError("PLT bindings differ")
    return {"artifact_sha256": _digest(document), "owner_count": 4, "reverse_reference_count": 0, "claims": copy.deepcopy(CLAIMS)}


def validate_touchpad_terminal_report(document):
    _forbid(document)
    _exact(document, {"schema_version", "analysis_scope", "camera_policy", "camera_executed", "installable", "camera_test_eligible", "summary", "claims", "readiness", "conclusion"}, "report")
    if document["schema_version"] != 1 or document["analysis_scope"] != "offline-static-touchpad-terminal-boundary" or document["camera_policy"] != "physically-disconnected":
        raise TouchpadTerminalBoundaryError("report scope differs")
    if any(document[field] is not False for field in ("camera_executed", "installable", "camera_test_eligible")):
        raise TouchpadTerminalBoundaryError("report promotes camera activity")
    _exact(document["summary"], {"artifact_sha256", "owner_count", "reverse_reference_count"}, "summary")
    if _SHA.fullmatch(document["summary"]["artifact_sha256"] or "") is None or document["summary"]["owner_count"] != 4 or document["summary"]["reverse_reference_count"] != 0:
        raise TouchpadTerminalBoundaryError("report summary differs")
    if REPORT_ARTIFACT_SHA256 and document["summary"]["artifact_sha256"] != REPORT_ARTIFACT_SHA256:
        raise TouchpadTerminalBoundaryError("report digest differs")
    if document["claims"] != CLAIMS or document["readiness"] != "TERMINAL_BOUNDARY_UNRESOLVED" or document["conclusion"] != CONCLUSION:
        raise TouchpadTerminalBoundaryError("report promotes unsupported touch behavior")
    return copy.deepcopy(document)
