"""Fail-closed evidence contract for bounded α6400 generic slot-37 dispatches."""
from __future__ import annotations

import copy
import hashlib
import json
import re


VIEW_UNIFIED2_SIZE = 11_530_552
VIEW_UNIFIED2_SHA256 = "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2"
WIDGET_VTABLE_DIGEST = "3d88983377538b2fc98ddc1170bdb5848cebf4a28d319c35365a105075ca2035"
TOUCH_CALLERS_DIGEST = "51715c6db751360960ee27db372b8c58b5e2f12c3c9a8393795d0f578ebd9688"
ANALYSIS_LOAD_BIAS = 0x10000
SLOT_OFFSET = 0x94
PC_LITERAL_COUNT = 361
PC_LITERAL_DIGEST = "8abf600c2fbe5219989d71e72b5e4e091b4d803be9fcddd58a838ca682e5fb73"
ROOT_RECORDS = (
    {"name": "ViewSettingMenuEventSwitch", "role": "setting-menu-event-switch", "source_kind": "analysis-address", "source_offset": 0x22355E, "analysis_address": 0x22355E, "elf_address": 0x21355E},
    {"name": "ViewStlrecOrientationRegistration", "role": "orientation-registration", "source_kind": "elf-file-offset", "source_offset": 0x1AB41C, "analysis_address": 0x1BB41C, "elf_address": 0x1AB41C},
    {"name": "ViewStlrecLayoutModeAttach", "role": "layout-mode-attach", "source_kind": "elf-file-offset", "source_offset": 0x1AB2D2, "analysis_address": 0x1BB2D2, "elf_address": 0x1AB2D2},
    {"name": "ViewStlrecAfOrientationDispatch", "role": "af-orientation-dispatch", "source_kind": "elf-file-offset", "source_offset": 0x1B1E76, "analysis_address": 0x1C1E76, "elf_address": 0x1B1E76},
)
TOUCH_OWNER_RECORDS = (
    {"apis": ["focus-coordinate"], "analysis_address": 0x1C16EC, "elf_address": 0x1B16EC},
    {"apis": ["focus-coordinate"], "analysis_address": 0x1C5200, "elf_address": 0x1B5200},
    {"apis": ["focus-coordinate"], "analysis_address": 0x1C63FC, "elf_address": 0x1B63FC},
    {"apis": ["force-release"], "analysis_address": 0x1F48AC, "elf_address": 0x1E48AC},
    {"apis": ["disable-area"], "analysis_address": 0x2038B4, "elf_address": 0x1F38B4},
    {"apis": ["resource-settings"], "analysis_address": 0x240768, "elf_address": 0x230768},
    {"apis": ["enable-evf-area"], "analysis_address": 0x2BFB44, "elf_address": 0x2AFB44},
    {"apis": ["enable-evf-area"], "analysis_address": 0x2C6778, "elf_address": 0x2B6778},
    {"apis": ["enable-evf-area"], "analysis_address": 0x2C69C4, "elf_address": 0x2B69C4},
    {"apis": ["enable-evf-area"], "analysis_address": 0x2C6BD0, "elf_address": 0x2B6BD0},
    {"apis": ["enable-area"], "analysis_address": 0x366314, "elf_address": 0x356314},
    {"apis": ["enable-area"], "analysis_address": 0x3665C8, "elf_address": 0x3565C8},
    {"apis": ["focus-coordinate"], "analysis_address": 0x61ECC8, "elf_address": 0x60ECC8},
    {"apis": ["focus-coordinate"], "analysis_address": 0x61F40C, "elf_address": 0x60F40C},
    {"apis": ["force-release", "disable-area", "enable-evf-area"], "analysis_address": 0x621980, "elf_address": 0x611980},
    {"apis": ["force-release", "disable-area", "enable-evf-area"], "analysis_address": 0x65C370, "elf_address": 0x64C370},
)
ROOTS = tuple(record["elf_address"] for record in ROOT_RECORDS)
TOUCH_OWNERS = tuple(record["elf_address"] for record in TOUCH_OWNER_RECORDS)
_FORBIDDEN = ("raw", "byte", "disassembly", "instruction", "key", "device", "usb", "write", "flash", "package", "payload")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


class WidgetIsHitDispatchError(ValueError):
    """Raised when slot-37 evidence is unsafe or exceeds static proof."""


def _dispatch(owner, vptr, slot, call):
    return {"owner": owner, "receiver_vptr_load": vptr, "slot_load": slot, "indirect_call": call}


DISPATCHES = (
    _dispatch(0x310CD8, 0x310CFE, 0x310D02, 0x310D06),
    _dispatch(0x310CD8, 0x310D6C, 0x310D70, 0x310D74),
    _dispatch(0x310CD8, 0x310D9A, 0x310D9E, 0x310DA2),
    _dispatch(0x310CD8, 0x310DC8, 0x310DCC, 0x310DD0),
    _dispatch(0x35F66C, 0x35F674, 0x35F676, 0x35F67A),
    _dispatch(0x3E11D4, 0x3E1318, 0x3E1322, 0x3E1328),
    _dispatch(0x56CF24, 0x56CF86, 0x56CF8A, 0x56CFA4),
    _dispatch(0x56CF24, 0x56CFC6, 0x56CFCA, 0x56CFE8),
    _dispatch(0x5B7424, 0x5B7486, 0x5B748A, 0x5B74A4),
    _dispatch(0x5B7424, 0x5B74C6, 0x5B74CA, 0x5B74E8),
)


def _path_edge(owner, site, direct_target, resolved_target):
    return {"owner": owner, "site": site, "direct_target": direct_target, "resolved_target": resolved_target}


DEFINED_PLT_BINDING = {
    "symbol": "CmnWrpOrientationRegisterAF::getRecallRegisteredAfFrame()",
    "symbol_index": 1718,
    "defined_owner": 0x35F66C,
    "defined_size": 18,
    "relocation_index": 254,
    "got_address": 0x944AA4,
    "plt_address": 0x14F1FC,
    "direct_callsite_count": 15,
    "direct_caller_owner_count": 13,
    "direct_callsite_digest": "f513997145508f2955d32846568272e0aea973fa4f836a33dd59151bf1900e7b",
    "receiver_provenance": "helper-return-r0",
    "receiver_helper_owner": 0x35F424,
    "receiver_helper_call": 0x35F670,
    "slot_load": 0x35F676,
    "indirect_call": 0x35F67A,
}
_NAMED_DISPATCH = _dispatch(0x35F66C, 0x35F674, 0x35F676, 0x35F67A)
ROOT_PATHS = (
    {
        "root": "ViewSettingMenuEventSwitch",
        "start_owner": 0x21355E,
        "edges": [
            _path_edge(0x21355E, 0x2138A0, 0x210D94, 0x210D94),
            _path_edge(0x210D94, 0x210E3C, 0x20A9D4, 0x20A9D4),
            _path_edge(0x20A9D4, 0x20AAF2, 0x14F1FC, 0x35F66C),
        ],
        "dispatch": _NAMED_DISPATCH,
    },
    {
        "root": "ViewStlrecAfOrientationDispatch",
        "start_owner": 0x1B1E76,
        "edges": [_path_edge(0x1B1E76, 0x1B1EC2, 0x14F1FC, 0x35F66C)],
        "dispatch": _NAMED_DISPATCH,
    },
)
TOUCH_REVERSE_PATHS = (
    {
        "touch_api_caller_analysis_address": 0x1C16EC,
        "touch_api_caller_elf_owner": 0x1B16EC,
        "apis": ["focus-coordinate"],
        "edges": [
            _path_edge(0x1B16EC, 0x1B1816, 0x1683B0, 0x1683B0),
            _path_edge(0x1683B0, 0x1683C4, 0x4FFF62, 0x4FFF62),
            _path_edge(0x4FFF62, 0x4FFF7E, 0x4FFEF8, 0x4FFEF8),
            _path_edge(0x4FFEF8, 0x4FFF40, 0x4FFE84, 0x4FFE84),
            _path_edge(0x4FFE84, 0x4FFEC2, 0x4FF988, 0x4FF988),
            _path_edge(0x4FF988, 0x4FFA94, 0x4F7088, 0x4F7088),
            _path_edge(0x4F7088, 0x4F7092, 0x4F6E96, 0x4F6E96),
            _path_edge(0x4F6E96, 0x4F6EDE, 0x14F1FC, 0x35F66C),
        ],
        "dispatch": _NAMED_DISPATCH,
    },
    {
        "touch_api_caller_analysis_address": 0x1C63FC,
        "touch_api_caller_elf_owner": 0x1B63FC,
        "apis": ["focus-coordinate"],
        "edges": [
            _path_edge(0x1B63FC, 0x1B6470, 0x1683B0, 0x1683B0),
            _path_edge(0x1683B0, 0x1683C4, 0x4FFF62, 0x4FFF62),
            _path_edge(0x4FFF62, 0x4FFF7E, 0x4FFEF8, 0x4FFEF8),
            _path_edge(0x4FFEF8, 0x4FFF40, 0x4FFE84, 0x4FFE84),
            _path_edge(0x4FFE84, 0x4FFEC2, 0x4FF988, 0x4FF988),
            _path_edge(0x4FF988, 0x4FFA94, 0x4F7088, 0x4F7088),
            _path_edge(0x4F7088, 0x4F7092, 0x4F6E96, 0x4F6E96),
            _path_edge(0x4F6E96, 0x4F6EDE, 0x14F1FC, 0x35F66C),
        ],
        "dispatch": _NAMED_DISPATCH,
    },
)
STACK_CANDIDATES = (
    {"owner": 0x237648, "site": 0x237926}, {"owner": 0x239394, "site": 0x2397A4},
    {"owner": 0x2C0B98, "site": 0x2C0BB4}, {"owner": 0x2C2AA4, "site": 0x2C2C3E},
    {"owner": 0x4C3148, "site": 0x4C3450}, {"owner": 0x4C3148, "site": 0x4C3CD4},
    {"owner": 0x532574, "site": 0x53258A}, {"owner": 0x53323C, "site": 0x5333AC},
    {"owner": 0x54DB60, "site": 0x54DE94},
)
HIGHLIGHTED_STACK_SITES = (0x2C0BB4, 0x2C2C3E, 0x53258A, 0x5333AC, 0x54DE94)
CLAIMS = {
    "generic_slot37_dispatch_found": True,
    "ui_root_to_slot37_dispatch_found": True,
    "known_touch_caller_to_slot37_dispatch_found": True,
    "concrete_widget_identity_found": False,
    "menu_touch_hit_test_found": False,
    "menu_touch_selection_found": False,
    "touch_coordinate_transform_found": False,
    "gesture_found": False,
}
EXPECTED_RAW_EXPORT = {
    "schema_version": 1, "program": "viewUnified2.so", "sha256": VIEW_UNIFIED2_SHA256, "file_size": VIEW_UNIFIED2_SIZE,
    "analysis_mode": {"read_only": True, "static_elf_metadata": True, "thumb_structural": True, "source_unchanged": True},
    "prior_widget_vtables": {"analysis_contract": "widget_hit_test_vtables", "artifact_sha256": WIDGET_VTABLE_DIGEST},
    "prior_touch_api_callers": {"analysis_contract": "touch_api_callers", "artifact_sha256": TOUCH_CALLERS_DIGEST},
    "defined_plt_binding": DEFINED_PLT_BINDING,
    "slot_offset": SLOT_OFFSET, "dispatches": list(DISPATCHES),
    "coverage": {"total_exidx_entry_count": 30463, "complete_owner_count": 28869, "decode_incomplete_owner_count": 1593, "terminal_without_successor_owner_count": 1},
    "rejections": {"rule": "fully-decoded-direct-pc-relative-load", "pc_literal_count": PC_LITERAL_COUNT, "pc_literal_address_digest": PC_LITERAL_DIGEST, "stack_candidates": list(STACK_CANDIDATES), "highlighted_stack_sites": list(HIGHLIGHTED_STACK_SITES)},
    "path_summary": {"max_depth": 32, "analysis_load_bias": ANALYSIS_LOAD_BIAS, "roots": list(ROOT_RECORDS), "touch_api_caller_owners": list(TOUCH_OWNER_RECORDS), "root_paths": list(ROOT_PATHS), "touch_paths_forward": [], "touch_paths_reverse": list(TOUCH_REVERSE_PATHS)},
    "claims": CLAIMS, "truncated": False,
}


def _forbid(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if any(token in str(key).casefold() for token in _FORBIDDEN):
                raise WidgetIsHitDispatchError("unsafe or reconstructive evidence field")
            _forbid(child)
    elif isinstance(value, list):
        for child in value: _forbid(child)


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise WidgetIsHitDispatchError(label + " fields differ")
    return value


def _canonical(value):
    return hashlib.sha256((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest()


def normalize_widget_ishit_dispatch_export(document):
    """Accept only source-derived generic slot-37-shaped calls, never behavior."""
    _forbid(document)
    raw = _exact(document, set(EXPECTED_RAW_EXPORT), "slot-37 export")
    for key, expected in EXPECTED_RAW_EXPORT.items():
        if raw[key] != expected:
            raise WidgetIsHitDispatchError(key + " is not the pinned bounded result")
    return copy.deepcopy(raw)


def summarize_widget_ishit_dispatch_export(document):
    raw = normalize_widget_ishit_dispatch_export(document)
    return {"canonical_export_sha256": _canonical(raw), "accepted_count": len(DISPATCHES), "pc_literal_count": PC_LITERAL_COUNT, "stack_candidate_count": len(STACK_CANDIDATES)}


def validate_widget_ishit_dispatch_report(document):
    _forbid(document)
    report = _exact(document, {"schema_version", "analysis_scope", "camera_policy", "camera_executed", "installable", "camera_test_eligible", "source", "dispatch_summary", "prior_widget_vtables", "prior_touch_api_callers", "defined_plt_binding", "coverage", "path_summary", "claims", "readiness", "conclusion"}, "report")
    if report["schema_version"] != 1 or report["analysis_scope"] != "offline-static-slot37-dispatch" or report["camera_policy"] != "physically-disconnected":
        raise WidgetIsHitDispatchError("report scope differs")
    if any(report[key] is not False for key in ("camera_executed", "installable", "camera_test_eligible")):
        raise WidgetIsHitDispatchError("report promotes camera activity")
    expected = summarize_widget_ishit_dispatch_export(EXPECTED_RAW_EXPORT)
    if report["source"] != {"module": "lib/viewUnified2.so", "size": VIEW_UNIFIED2_SIZE, "sha256": VIEW_UNIFIED2_SHA256} or report["dispatch_summary"] != expected:
        raise WidgetIsHitDispatchError("report source or summary differs")
    if (report["prior_widget_vtables"] != EXPECTED_RAW_EXPORT["prior_widget_vtables"] or report["prior_touch_api_callers"] != EXPECTED_RAW_EXPORT["prior_touch_api_callers"] or report["defined_plt_binding"] != DEFINED_PLT_BINDING or report["coverage"] != EXPECTED_RAW_EXPORT["coverage"] or report["path_summary"] != EXPECTED_RAW_EXPORT["path_summary"] or report["claims"] != CLAIMS or report["readiness"] != "GENERIC_SLOT37_INTERFACE_UNRESOLVED" or report["conclusion"] != "Ten local generic slot-37-shaped virtual dispatches are established. Exact local PLT resolution links the setting-menu root, the AF-orientation root, and two known shooting-focus coordinate caller owners to a named orientation/AF wrapper method whose helper-returned object receives that virtual call; the concrete interface method, widget type, vtable identity, dataflow, gesture semantics, menu hit routing, and selection behavior remain unresolved."):
        raise WidgetIsHitDispatchError("report promotes unestablished behavior")
    return copy.deepcopy(report)
