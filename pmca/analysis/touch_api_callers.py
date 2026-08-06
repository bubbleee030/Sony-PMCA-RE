"""Fail-closed contract for the α6400 bounded touch API caller inventory."""
from __future__ import annotations

import copy
import hashlib
import json
import re

VIEW_UNIFIED2_SHA256 = "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2"
VIEW_UNIFIED2_SIZE = 11530552
PRIOR_UI_GRAPH_SHA256 = "d19fc94fd52583f3d321535fd8b6a01aa03f4efc0c4dadde52adce3a9d246f22"
ANALYSIS_LOAD_BIAS = 0x10000
API_BINDINGS = [
    {"api": "force-release", "classification": "touch-configuration-or-release", "relocation_index": 43, "got_address": "0x944758", "plt_address": "0x14e6c8", "symbol": "InputService::forceReleaseTp"},
    {"api": "enable-area", "classification": "touch-configuration-or-release", "relocation_index": 154, "got_address": "0x944914", "plt_address": "0x14ecac", "symbol": "InputService::setTpEnableArea"},
    {"api": "focus-coordinate", "classification": "shooting-focus-coordinate", "relocation_index": 232, "got_address": "0x944a4c", "plt_address": "0x14f0c8", "symbol": "CmnViewFocus::getNewCoordinatesForFocusPointOnTouchPad"},
    {"api": "resource-settings", "classification": "touch-configuration-or-release", "relocation_index": 249, "got_address": "0x944a90", "plt_address": "0x14f1b4", "symbol": "InputService::setResourceTpSettings"},
    {"api": "disable-area", "classification": "touch-configuration-or-release", "relocation_index": 1730, "got_address": "0x9461b4", "plt_address": "0x15404c", "symbol": "CmnViewTPAreaEnableUtil::setTouchPadEnableAreaToOff"},
    {"api": "enable-evf-area", "classification": "touch-configuration-or-release", "relocation_index": 2101, "got_address": "0x946780", "plt_address": "0x1553f4", "symbol": "CmnViewTPAreaEnableUtil::setTouchPadEnabAreaForEvfOn"},
]
CALLERS = [
    {"api": "force-release", "classification": "touch-configuration-or-release", "owner": "0x1f48ac", "end": "0x1f4904", "site": "0x1f48da"},
    {"api": "force-release", "classification": "touch-configuration-or-release", "owner": "0x621980", "end": "0x6219b4", "site": "0x621998"},
    {"api": "force-release", "classification": "touch-configuration-or-release", "owner": "0x65c370", "end": "0x65c3a4", "site": "0x65c388"},
    {"api": "enable-area", "classification": "touch-configuration-or-release", "owner": "0x366314", "end": "0x3665c8", "site": "0x366564"},
    {"api": "enable-area", "classification": "touch-configuration-or-release", "owner": "0x3665c8", "end": "0x366608", "site": "0x3665d8"},
    {"api": "focus-coordinate", "classification": "shooting-focus-coordinate", "owner": "0x1c16ec", "end": "0x1c1a84", "site": "0x1c17f8"},
    {"api": "focus-coordinate", "classification": "shooting-focus-coordinate", "owner": "0x1c16ec", "end": "0x1c1a84", "site": "0x1c19c6"},
    {"api": "focus-coordinate", "classification": "shooting-focus-coordinate", "owner": "0x1c5200", "end": "0x1c537c", "site": "0x1c5304"},
    {"api": "focus-coordinate", "classification": "shooting-focus-coordinate", "owner": "0x1c63fc", "end": "0x1c6500", "site": "0x1c64de"},
    {"api": "focus-coordinate", "classification": "shooting-focus-coordinate", "owner": "0x61ecc8", "end": "0x61eec8", "site": "0x61edb6"},
    {"api": "focus-coordinate", "classification": "shooting-focus-coordinate", "owner": "0x61ecc8", "end": "0x61eec8", "site": "0x61eeb6"},
    {"api": "focus-coordinate", "classification": "shooting-focus-coordinate", "owner": "0x61f40c", "end": "0x61f4ec", "site": "0x61f4da"},
    {"api": "resource-settings", "classification": "touch-configuration-or-release", "owner": "0x240768", "end": "0x2407fc", "site": "0x2407d0"},
    {"api": "disable-area", "classification": "touch-configuration-or-release", "owner": "0x2038b4", "end": "0x2039e4", "site": "0x2038c8"},
    {"api": "disable-area", "classification": "touch-configuration-or-release", "owner": "0x621980", "end": "0x6219b4", "site": "0x621994"},
    {"api": "disable-area", "classification": "touch-configuration-or-release", "owner": "0x65c370", "end": "0x65c3a4", "site": "0x65c384"},
    {"api": "enable-evf-area", "classification": "touch-configuration-or-release", "owner": "0x2bfb44", "end": "0x2bfd18", "site": "0x2bfc48"},
    {"api": "enable-evf-area", "classification": "touch-configuration-or-release", "owner": "0x2c6778", "end": "0x2c6884", "site": "0x2c67d6"},
    {"api": "enable-evf-area", "classification": "touch-configuration-or-release", "owner": "0x2c69c4", "end": "0x2c6bd0", "site": "0x2c6a96"},
    {"api": "enable-evf-area", "classification": "touch-configuration-or-release", "owner": "0x2c69c4", "end": "0x2c6bd0", "site": "0x2c6b72"},
    {"api": "enable-evf-area", "classification": "touch-configuration-or-release", "owner": "0x2c6bd0", "end": "0x2c6de4", "site": "0x2c6d86"},
    {"api": "enable-evf-area", "classification": "touch-configuration-or-release", "owner": "0x621980", "end": "0x6219b4", "site": "0x62199e"},
    {"api": "enable-evf-area", "classification": "touch-configuration-or-release", "owner": "0x65c370", "end": "0x65c3a4", "site": "0x65c38e"},
]
ROOTS = ["ViewSettingMenuEventSwitch", "ViewStlrecOrientationRegistration", "ViewStlrecLayoutModeAttach", "ViewStlrecAfOrientationDispatch"]
CLAIMS = {"touch_configuration_or_release_api_found": True, "shooting_focus_coordinate_api_found": True, "menu_touch_coordinate_route_found": False, "widget_hit_test_found": False, "gesture_configuration_found": False, "selection_dispatch_found": False}
CONCLUSION = "Six bounded APIs have 23 direct calls from completely decoded owners. The shooting-focus coordinate API is present, but direct-only depth-32 searches from the menu and three ViewStlrec roots find no caller path; unresolved indirect and cross-module paths, coordinate transforms, menu hit tests, and selection dispatch remain unproven."
REPORT_ARTIFACT_SHA256 = "51715c6db751360960ee27db372b8c58b5e2f12c3c9a8393795d0f578ebd9688"
_HEX = re.compile(r"0x[0-9a-f]+\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FORBIDDEN = ("raw", "byte", "disassembly", "instruction", "key", "device", "usb", "flash", "package", "payload")


class TouchApiCallersError(ValueError):
    """Raised when bounded touch API caller evidence is unsafe or promoted."""


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise TouchApiCallersError(label + " fields are invalid")
    return value


def _forbid(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if any(token in str(key).casefold() for token in _FORBIDDEN):
                raise TouchApiCallersError("unsafe or reconstructive evidence field")
            _forbid(item)
    elif isinstance(value, list):
        for item in value: _forbid(item)


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def normalize_touch_api_callers_export(document):
    """Validate the exact static inventory, without accepting extrapolated behavior."""
    _forbid(document)
    _exact(document, {"program", "sha256", "file_size", "analysis_mode", "program_changed", "prior_ui_graph_sha256", "api_bindings", "callers", "owner_accounting", "root_paths", "prior_traversal", "truncated"}, "raw export")
    if (document["program"], document["sha256"], document["file_size"]) != ("viewUnified2.so", VIEW_UNIFIED2_SHA256, VIEW_UNIFIED2_SIZE): raise TouchApiCallersError("source identity differs")
    if document["analysis_mode"] != {"read_only": True, "static_elf_metadata": True, "thumb_control_flow": True} or document["program_changed"] is not False or document["truncated"] is not False: raise TouchApiCallersError("source execution mode is unsafe")
    if document["prior_ui_graph_sha256"] != PRIOR_UI_GRAPH_SHA256 or document["api_bindings"] != API_BINDINGS or document["callers"] != CALLERS: raise TouchApiCallersError("API binding or caller inventory differs")
    if document["owner_accounting"] != {"complete_owner_count": 28869, "incomplete_owner_count": 1593, "terminal_unbounded_owner_count": 1}: raise TouchApiCallersError("owner decode accounting differs")
    if document["root_paths"] != [{"root": root, "depth_cap": 32, "known_caller_count": 23, "paths": []} for root in ROOTS]: raise TouchApiCallersError("direct root path result differs")
    if document["prior_traversal"] != {"edge_count": 2046, "known_caller_owner_hits": []}: raise TouchApiCallersError("prior traversal cross-check differs")
    return {"artifact_sha256": _digest(document), "api_count": 6, "caller_count": 23, "claims": copy.deepcopy(CLAIMS)}


def validate_touch_api_callers_report(document):
    _forbid(document)
    _exact(document, {"schema_version", "analysis_scope", "camera_policy", "camera_executed", "installable", "camera_test_eligible", "summary", "claims", "readiness", "conclusion"}, "report")
    if document["schema_version"] != 1 or document["analysis_scope"] != "offline-static-touch-api-callers" or document["camera_policy"] != "physically-disconnected": raise TouchApiCallersError("report scope differs")
    if any(document[field] is not False for field in ("camera_executed", "installable", "camera_test_eligible")): raise TouchApiCallersError("report promotes camera activity")
    _exact(document["summary"], {"artifact_sha256", "api_count", "caller_count", "owner_accounting"}, "summary")
    if _SHA.fullmatch(document["summary"]["artifact_sha256"] or "") is None or document["summary"]["api_count"] != 6 or document["summary"]["caller_count"] != 23 or document["summary"]["owner_accounting"] != {"total_exidx_entry_count": 30463, "complete_owner_count": 28869, "decode_incomplete_owner_count": 1593, "terminal_without_successor_owner_count": 1}: raise TouchApiCallersError("report summary differs")
    if document["summary"]["artifact_sha256"] != REPORT_ARTIFACT_SHA256: raise TouchApiCallersError("report digest differs")
    if document["claims"] != CLAIMS or document["readiness"] != "DIRECT_CALLERS_ONLY" or document["conclusion"] != CONCLUSION: raise TouchApiCallersError("report promotes unsupported touch behavior")
    return copy.deepcopy(document)
