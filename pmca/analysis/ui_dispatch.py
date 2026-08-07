"""Validate bounded static UI-dispatch evidence for the ILCE-6400."""

from __future__ import annotations

import copy
import re
import unicodedata

from pmca.analysis.modern_ui_contract import BEHAVIOR_IDS
from pmca.analysis.ui_factory_owner_registration import (
    REPORT_CANONICAL_EXPORT_SHA256 as OWNER_REGISTRATION_SHA256,
)
from pmca.analysis.vertical_layout_factory_trace import (
    CANONICAL_EXPORT_SHA256 as VERTICAL_FACTORY_SHA256,
)


VIEW_UNIFIED2_SIZE = 11_530_552
VIEW_UNIFIED2_SHA256 = (
    "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2"
)
VIEW_UNIFIED7_SHA256 = (
    "c48cde43ff22d808ad23c42019ddae516fff7da060004eb81ed2bb85012aa538"
)
_MODULES = [
    {
        "name": "lib/viewUnified2.so",
        "size": VIEW_UNIFIED2_SIZE,
        "sha256": VIEW_UNIFIED2_SHA256,
    },
    {
        "name": "lib/viewUnified7.so",
        "size": 541_024,
        "sha256": VIEW_UNIFIED7_SHA256,
    },
    {
        "name": "share/app/master_camera.uxc",
        "size": 101_720,
        "sha256": "5a0370408dff25dab43ed677c3b8e6c9be3b8bb8630d7ea15273d4f996cca7ec",
    },
    {
        "name": "share/app/viewStlrec.uxc",
        "size": 32_104,
        "sha256": "f5aaa2f70f9b262b515a529ee2d80bf21928f0898504643cc7f174efa405d4f5",
    },
]
_MODULE_BY_NAME = {item["name"]: item for item in _MODULES}
_EXECUTABLE_MODULES = {"lib/viewUnified2.so", "lib/viewUnified7.so"}
EDGE_KINDS = {
    "direct",
    "vtable-slot",
    "function-pointer-table",
    "uxc-reference-only",
    "unresolved-indirect",
}
CLAIM_KEYS = {
    "coordinate_consumer_found",
    "menu_selection_dispatch_found",
    "orientation_layout_selector_found",
}
_CLAIM_SEMANTICS = {
    "coordinate_consumer_found": "coordinate-consumer",
    "menu_selection_dispatch_found": "menu-selection-dispatch",
    "orientation_layout_selector_found": "orientation-layout-selection",
}
_PATH_SEMANTICS = {
    "status-read-not-coordinate-dispatch",
    "configuration-not-menu-selection",
    "coordinate-consumer",
    "menu-touch-hit-test",
    "menu-selection-dispatch",
    "orientation-layout-selection",
    "control-direction-transform",
    "touch-coordinate-transform",
    "layout-attach",
    "unresolved",
} | set(BEHAVIOR_IDS)
_EXECUTABLE_EDGE_KINDS = {"direct", "vtable-slot", "function-pointer-table"}
_TOP_FIELDS = {
    "schema_version",
    "analysis_scope",
    "modules",
    "roots",
    "bounded_export_summary",
    "invalid_offset_classifications",
    "vertical_factory_reference",
    "edges",
    "paths",
    "uxc_references",
    "negative_searches",
    "claims",
    "behavior_support",
}
_ROOT_FIELDS = {
    "name",
    "role",
    "module",
    "source_kind",
    "source_offset",
    "analysis_address",
    "function_address",
}
_EDGE_FIELDS = {
    "id",
    "caller_module",
    "caller",
    "site",
    "callee_module",
    "callee",
    "kind",
    "owner",
    "slot",
    "table_module",
    "table",
}
_PATH_FIELDS = {"id", "root", "offsets", "edge_ids", "semantic", "resolved"}
_PATH_OFFSET_FIELDS = {"module", "offset"}
_UXC_FIELDS = {"source", "kind", "value", "offset", "semantic"}
_BOUNDED_EXPORT_SUMMARY_FIELDS = {
    "root_count",
    "edge_count",
    "direct_edge_count",
    "unresolved_indirect_edge_count",
    "truncated",
    "depth_cap",
    "unresolved_indirect_terminal",
    "artifact_sha256",
}
_INVALID_OFFSET_FIELDS = {
    "module",
    "offset",
    "owner",
    "instruction_boundary",
    "classification",
    "callable_owner",
    "factory",
    "class_id_load",
}
_OWNER_RANGE_FIELDS = {"start", "end"}
_VERTICAL_FACTORY_REFERENCE_FIELDS = {
    "factory_report",
    "factory_report_sha256",
    "owner_registration_report",
    "owner_registration_report_sha256",
    "factory_owner",
    "wrapper_owner",
    "resource_reference_count",
    "total_constructor_arm_count",
    "vertical_constructor_arm_count",
    "wrapper_registration_count",
    "runtime_factory_invocation_proven",
    "view_unified2_to_factory_edge_found",
    "orientation_to_factory_join_proven",
}
_NEGATIVE_FIELDS = {
    "root_set",
    "requested_roots",
    "resolved_roots",
    "target_name",
    "target_module",
    "target_requested_offset",
    "target_function_offset",
    "search_method",
    "edge_kinds",
    "depth_cap",
    "path_found",
}
_FORBIDDEN_KEYS = {
    "raw",
    "bytes",
    "payload",
    "disassembly",
    "private_key",
    "hex_dump",
}
_ADDRESS = re.compile(r"0x(?:0|[1-9a-f][0-9a-f]*)\Z")
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
_MAX_TEXT_CHARS = 2048
_MAX_EDGES = 10_000
_MAX_PATHS = 2_000
_BOUNDED_EXPORT_SUMMARY = {
    "root_count": 4,
    "edge_count": 2_046,
    "direct_edge_count": 1_697,
    "unresolved_indirect_edge_count": 349,
    "truncated": False,
    "depth_cap": 32,
    "unresolved_indirect_terminal": True,
    "artifact_sha256": "d19fc94fd52583f3d321535fd8b6a01aa03f4efc0c4dadde52adce3a9d246f22",
}
_INVALID_OFFSET_CLASSIFICATIONS = [
    {
        "module": "lib/viewUnified2.so",
        "offset": offset,
        "owner": {"start": owner_start, "end": owner_end},
        "instruction_boundary": instruction_boundary,
        "classification": classification,
        "callable_owner": False,
        "factory": False,
        "class_id_load": False,
    }
    for offset, owner_start, owner_end, instruction_boundary, classification in (
        ("0x181f18", "0x1729e8", "0x184ac4", True, "internal-selector-branch"),
        ("0x24222c", "0x23a8c0", "0x2a3680", False, "thumb2-second-halfword"),
        ("0x3ba6dc", "0x3b6940", "0x3bbed8", False, "thumb2-second-halfword"),
        ("0x651684", "0x64da44", "0x6549e4", False, "thumb2-second-halfword"),
        ("0x37b614", "0x37b60c", "0x37b630", True, "constructor-vptr-material"),
        ("0x37aa18", "0x37aa10", "0x37aa34", True, "constructor-vptr-material"),
        ("0x37b5e0", "0x37b5d8", "0x37b5fc", True, "constructor-vptr-material"),
        ("0x37b648", "0x37b640", "0x37b664", True, "constructor-vptr-material"),
        ("0x37b578", "0x37b570", "0x37b594", True, "constructor-vptr-material"),
    )
]
_VERTICAL_FACTORY_REFERENCE = {
    "factory_report": "analysis/a6400-vertical-layout-factory.json",
    "factory_report_sha256": VERTICAL_FACTORY_SHA256,
    "owner_registration_report": "analysis/a6400-ui-factory-owner-registration.json",
    "owner_registration_report_sha256": OWNER_REGISTRATION_SHA256,
    "factory_owner": {"start": "0x52840", "end": "0x529b8"},
    "wrapper_owner": {"start": "0x529cc", "end": "0x529e8"},
    "resource_reference_count": 10,
    "total_constructor_arm_count": 12,
    "vertical_constructor_arm_count": 5,
    "wrapper_registration_count": 5,
    "runtime_factory_invocation_proven": False,
    "view_unified2_to_factory_edge_found": False,
    "orientation_to_factory_join_proven": False,
}
_RAW_EXPORT_FIELDS = {
    "program",
    "sha256",
    "image_size",
    "roots",
    "edges",
    "truncated",
}
_RAW_EDGE_FIELDS = {"caller", "site", "target", "kind", "slot", "table", "owner"}
_RAW_ROOT_FIELDS = {
    "name",
    "role",
    "source_kind",
    "source_offset",
    "analysis_address",
    "function_address",
}
_RAW_ROOT_SPECS = [
    (
        "ViewSettingMenuEventSwitch",
        "setting-menu-event-switch",
        "analysis-address",
        0x22355E,
        0x22355E,
    ),
    (
        "ViewStlrecOrientationRegistration",
        "orientation-registration",
        "elf-file-offset",
        0x1AB41C,
        0x1BB41C,
    ),
    (
        "ViewStlrecLayoutModeAttach",
        "layout-mode-attach",
        "elf-file-offset",
        0x1AB2D2,
        0x1BB2D2,
    ),
    (
        "ViewStlrecAfOrientationDispatch",
        "af-orientation-dispatch",
        "elf-file-offset",
        0x1B1E76,
        0x1C1E76,
    ),
]


class UiDispatchError(ValueError):
    """Raised when UI dispatch evidence is malformed or semantically promoted."""


def _reject_forbidden_keys(value: object) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if key in _FORBIDDEN_KEYS:
                raise UiDispatchError(f"forbidden reconstructive field: {key}")
            _reject_forbidden_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_forbidden_keys(nested)


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise UiDispatchError(f"{label} must be nonempty text")
    if len(value) > _MAX_TEXT_CHARS:
        raise UiDispatchError(f"{label} exceeds the text size limit")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise UiDispatchError(f"{label} contains a control character")
    return value


def _require_identifier(value: object, label: str) -> str:
    text = _require_text(value, label)
    if not _IDENTIFIER.fullmatch(text):
        raise UiDispatchError(f"{label} is invalid")
    return text


def _require_module(value: object, label: str, *, executable: bool = False) -> str:
    if not isinstance(value, str) or value not in _MODULE_BY_NAME:
        raise UiDispatchError(f"{label} is invalid")
    if executable and value not in _EXECUTABLE_MODULES:
        raise UiDispatchError(f"{label} is not executable")
    return value


def _require_address(value: object, label: str, module_name: str) -> str:
    if not isinstance(value, str) or not _ADDRESS.fullmatch(value):
        raise UiDispatchError(f"{label} is not a normalized address")
    offset = int(value, 16)
    if offset >= _MODULE_BY_NAME[module_name]["size"] or offset % 2:
        raise UiDispatchError(f"{label} is outside the module or not Thumb-normalized")
    return value


def _require_exact_fields(value: object, fields: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise UiDispatchError(f"{label} fields are not exact")
    return value


def _validate_edge(item: object) -> dict:
    edge = _require_exact_fields(item, _EDGE_FIELDS, "Edge")
    _require_identifier(edge["id"], "Edge id")
    caller_module = _require_module(
        edge["caller_module"], "Edge caller module", executable=True
    )
    _require_address(edge["caller"], "Edge caller", caller_module)
    _require_address(edge["site"], "Edge site", caller_module)
    _require_text(edge["owner"], "Edge owner")
    kind = edge["kind"]
    if not isinstance(kind, str) or kind not in EDGE_KINDS:
        raise UiDispatchError("Edge kind is invalid")

    if kind in _EXECUTABLE_EDGE_KINDS:
        callee_module = _require_module(
            edge["callee_module"], "Edge callee module", executable=True
        )
        _require_address(edge["callee"], "Edge callee", callee_module)
    elif edge["callee"] is not None or edge["callee_module"] is not None:
        raise UiDispatchError("Non-executable edge cannot have a callee identity")

    if kind in {"vtable-slot", "function-pointer-table"}:
        if type(edge["slot"]) is not int or not 0 <= edge["slot"] <= 1023:
            raise UiDispatchError("Table edge slot is invalid")
        table_module = _require_module(
            edge["table_module"], "Edge table module", executable=True
        )
        _require_address(edge["table"], "Edge table", table_module)
    elif (
        edge["slot"] is not None
        or edge["table"] is not None
        or edge["table_module"] is not None
    ):
        raise UiDispatchError("Non-table edge cannot have a slot or table identity")
    return edge


def _normalize_raw_address(
    value: object, label: str, module_name: str = "lib/viewUnified2.so"
) -> str:
    if type(value) is not int:
        raise UiDispatchError(f"{label} must be an integer")
    if value < 0 or value >= _MODULE_BY_NAME[module_name]["size"] or value % 2:
        raise UiDispatchError(f"{label} is outside the module or not Thumb-normalized")
    return f"0x{value:x}"


def normalize_ui_dispatch_export(raw: dict) -> dict:
    """Normalize a bounded Ghidra export without preserving raw program data."""

    document = _require_exact_fields(raw, _RAW_EXPORT_FIELDS, "Raw UI export")
    if document["program"] != "viewUnified2.so":
        raise UiDispatchError("Raw UI export program is invalid")
    if document["sha256"] != VIEW_UNIFIED2_SHA256:
        raise UiDispatchError("Raw UI export digest is invalid")
    if type(document["image_size"]) is not int or document["image_size"] != VIEW_UNIFIED2_SIZE:
        raise UiDispatchError("Raw UI export image size is invalid")
    if not isinstance(document["roots"], list) or len(document["roots"]) != len(
        _RAW_ROOT_SPECS
    ):
        raise UiDispatchError("Raw UI export roots are invalid")
    traversal_roots = []
    for item, expected in zip(document["roots"], _RAW_ROOT_SPECS):
        root = _require_exact_fields(item, _RAW_ROOT_FIELDS, "Raw traversal root")
        name, role, source_kind, source_offset, analysis_address = expected
        if (
            root["name"] != name
            or root["role"] != role
            or root["source_kind"] != source_kind
            or root["source_offset"] != source_offset
            or root["analysis_address"] != analysis_address
        ):
            raise UiDispatchError("Raw UI traversal root identity is invalid")
        traversal_roots.append(
            {
                "name": name,
                "role": role,
                "module": "lib/viewUnified2.so",
                "source_kind": source_kind,
                "source_offset": _normalize_raw_address(
                    root["source_offset"], "Traversal source offset"
                ),
                "analysis_address": _normalize_raw_address(
                    root["analysis_address"], "Traversal analysis address"
                ),
                "function_address": _normalize_raw_address(
                    root["function_address"], "Traversal function address"
                ),
            }
        )
    if document["truncated"] is not False:
        raise UiDispatchError("Raw UI export is truncated")
    if not isinstance(document["edges"], list) or len(document["edges"]) > _MAX_EDGES:
        raise UiDispatchError("Raw UI export edges are invalid or exceed the cap")

    sortable = []
    for item in document["edges"]:
        edge = _require_exact_fields(item, _RAW_EDGE_FIELDS, "Raw edge")
        kind = edge["kind"]
        if not isinstance(kind, str) or kind not in {
            "direct",
            "vtable-slot",
            "function-pointer-table",
            "unresolved-indirect",
        }:
            raise UiDispatchError("Raw edge kind is invalid")
        caller = _normalize_raw_address(edge["caller"], "Raw edge caller")
        site = _normalize_raw_address(edge["site"], "Raw edge site")
        callee = (
            None
            if edge["target"] is None
            else _normalize_raw_address(edge["target"], "Raw edge target")
        )
        table = (
            None
            if edge["table"] is None
            else _normalize_raw_address(edge["table"], "Raw edge table")
        )
        sortable.append(
            {
                "caller": caller,
                "caller_module": "lib/viewUnified2.so",
                "site": site,
                "callee": callee,
                "callee_module": None if callee is None else "lib/viewUnified2.so",
                "kind": kind,
                "owner": edge["owner"],
                "slot": edge["slot"],
                "table": table,
                "table_module": None if table is None else "lib/viewUnified2.so",
            }
        )

    sortable.sort(
        key=lambda item: (
            int(item["caller"], 16),
            int(item["site"], 16),
            item["kind"],
            -1 if item["callee"] is None else int(item["callee"], 16),
        )
    )
    normalized_edges = []
    for index, item in enumerate(sortable, 1):
        normalized = {"id": f"edge-{index:04d}", **item}
        _validate_edge(normalized)
        normalized_edges.append(normalized)
    sites = [item["site"] for item in normalized_edges]
    if len(set(sites)) != len(sites):
        raise UiDispatchError("Raw UI export contains duplicate call sites")

    return {
        "module": {
            "name": "lib/viewUnified2.so",
            "size": VIEW_UNIFIED2_SIZE,
            "sha256": VIEW_UNIFIED2_SHA256,
        },
        "roots": copy.deepcopy(traversal_roots),
        "traversal_roots": traversal_roots,
        "edges": normalized_edges,
    }


def _validate_path(
    item: object,
    roots: dict[str, tuple[str, str] | None],
    edges: dict[str, dict],
) -> dict:
    path = _require_exact_fields(item, _PATH_FIELDS, "Path")
    _require_identifier(path["id"], "Path id")
    if path["root"] not in roots:
        raise UiDispatchError("Path root is invalid")
    if not isinstance(path["offsets"], list) or not path["offsets"]:
        raise UiDispatchError("Path offsets must be a nonempty list")
    offsets = []
    for item_offset in path["offsets"]:
        path_offset = _require_exact_fields(item_offset, _PATH_OFFSET_FIELDS, "Path offset")
        module_name = _require_module(
            path_offset["module"], "Path offset module", executable=True
        )
        _require_address(path_offset["offset"], "Path offset", module_name)
        offsets.append((module_name, path_offset["offset"]))
    if not isinstance(path["edge_ids"], list):
        raise UiDispatchError("Path edge ids must be a list")
    if len(set(path["edge_ids"])) != len(path["edge_ids"]):
        raise UiDispatchError("Path edge ids must be unique")
    if any(edge_id not in edges for edge_id in path["edge_ids"]):
        raise UiDispatchError("Path references an unknown edge")
    if path["semantic"] not in _PATH_SEMANTICS:
        raise UiDispatchError("Path semantic is invalid")
    if type(path["resolved"]) is not bool:
        raise UiDispatchError("Path resolved flag must be boolean")
    if path["semantic"] == "unresolved" and path["resolved"] is not False:
        raise UiDispatchError("Unresolved path cannot be marked resolved")
    if path["resolved"] is True and path["edge_ids"]:
        root_identity = roots[path["root"]]
        if root_identity is None:
            raise UiDispatchError("Resolved path root has no discovered function")
        if offsets[0] != root_identity:
            raise UiDispatchError("Resolved path does not begin at its named root")
        if len(path["offsets"]) != len(path["edge_ids"]) + 1:
            raise UiDispatchError("Resolved path offsets and edges do not form a chain")
        for index, edge_id in enumerate(path["edge_ids"]):
            edge = edges[edge_id]
            if (
                (edge["caller_module"], edge["caller"]) != offsets[index]
                or (edge["callee_module"], edge["callee"]) != offsets[index + 1]
            ):
                raise UiDispatchError("Resolved path contains a disconnected edge")
    return path


def _validate_uxc_reference(item: object) -> dict:
    reference = _require_exact_fields(item, _UXC_FIELDS, "UXC reference")
    if reference["source"] not in {
        "share/app/master_camera.uxc",
        "share/app/viewStlrec.uxc",
    }:
        raise UiDispatchError("UXC source is invalid")
    if reference["kind"] not in {"name", "class-id"}:
        raise UiDispatchError("UXC reference kind is invalid")
    _require_text(reference["value"], "UXC reference value")
    if type(reference["offset"]) is not int or reference["offset"] < 0:
        raise UiDispatchError("UXC reference offset is invalid")
    if reference["offset"] >= _MODULE_BY_NAME[reference["source"]]["size"]:
        raise UiDispatchError("UXC reference offset is outside the pinned source")
    if reference["semantic"] != "reference-only":
        raise UiDispatchError("UXC reference cannot claim behavior")
    return reference


def _validate_negative_search(item: object) -> dict:
    if not isinstance(item, dict):
        raise UiDispatchError("Negative search fields are not exact")
    expected_fields = set(_NEGATIVE_FIELDS)
    if item.get("search_method") == "static-mixed-call-graph":
        expected_fields.add("terminal_edge_kinds")
    search = _require_exact_fields(item, expected_fields, "Negative search")
    _require_text(search["root_set"], "Negative search root set")
    _require_text(search["target_name"], "Negative search target")
    if type(search["requested_roots"]) is not int or search["requested_roots"] <= 0:
        raise UiDispatchError("Negative search requested_roots is invalid")
    if type(search["resolved_roots"]) is not int or search["resolved_roots"] < 0:
        raise UiDispatchError("Negative search resolved_roots is invalid")
    if search["resolved_roots"] > search["requested_roots"]:
        raise UiDispatchError("Negative search resolved roots exceed requested roots")
    target_module = _require_module(
        search["target_module"], "Negative search target module", executable=True
    )
    _require_address(
        search["target_requested_offset"], "Requested target offset", target_module
    )
    _require_address(
        search["target_function_offset"], "Target function offset", target_module
    )
    if search["search_method"] not in {
        "static-direct-call-graph",
        "static-mixed-call-graph",
    }:
        raise UiDispatchError("Negative search method is invalid")
    if (
        not isinstance(search["edge_kinds"], list)
        or not search["edge_kinds"]
        or len(set(search["edge_kinds"])) != len(search["edge_kinds"])
        or any(kind not in _EXECUTABLE_EDGE_KINDS for kind in search["edge_kinds"])
    ):
        raise UiDispatchError("Negative search edge kinds are invalid")
    terminal_edge_kinds = search.get("terminal_edge_kinds", [])
    if (
        not isinstance(terminal_edge_kinds, list)
        or len(set(terminal_edge_kinds)) != len(terminal_edge_kinds)
        or any(kind != "unresolved-indirect" for kind in terminal_edge_kinds)
    ):
        raise UiDispatchError("Negative search terminal edge kinds are invalid")
    depth_cap = search["depth_cap"]
    if depth_cap is not None and (type(depth_cap) is not int or depth_cap <= 0):
        raise UiDispatchError("Negative search depth cap is invalid")
    if search["search_method"] == "static-mixed-call-graph" and depth_cap is None:
        raise UiDispatchError("Mixed-call negative search requires a depth cap")
    if (
        search["search_method"] == "static-mixed-call-graph"
        and terminal_edge_kinds != ["unresolved-indirect"]
    ):
        raise UiDispatchError("Mixed-call negative search requires unresolved terminals")
    if (
        search["search_method"] == "static-direct-call-graph"
        and terminal_edge_kinds
    ):
        raise UiDispatchError("Direct-call negative search cannot have terminal kinds")
    if search["path_found"] is not False:
        raise UiDispatchError("Negative search cannot report a path")
    return search


def _claim_has_support(document: dict, claim: str) -> bool:
    return _semantic_has_support(document, _CLAIM_SEMANTICS[claim])


def _semantic_has_support(document: dict, required_semantic: str) -> bool:
    edges = {item["id"]: item for item in document["edges"]}
    for path in document["paths"]:
        if path["semantic"] != required_semantic or path["resolved"] is not True:
            continue
        if not path["edge_ids"]:
            continue
        if all(edges[edge_id]["kind"] in _EXECUTABLE_EDGE_KINDS for edge_id in path["edge_ids"]):
            return True
    return False


def build_ui_dispatch_report(source_document: dict) -> dict:
    """Migrate the pinned legacy report into the corrected fail-closed schema."""

    if not isinstance(source_document, dict):
        raise UiDispatchError("UI dispatch source report must be an object")
    _reject_forbidden_keys(source_document)
    source_fields = set(source_document)
    legacy_fields = (
        _TOP_FIELDS
        - {"invalid_offset_classifications", "vertical_factory_reference"}
    ) | {"uxc_owner_functions"}
    if source_fields not in (_TOP_FIELDS, legacy_fields):
        raise UiDispatchError("UI dispatch source report fields are not exact")

    report = copy.deepcopy(source_document)
    report.pop("uxc_owner_functions", None)
    report["invalid_offset_classifications"] = copy.deepcopy(
        _INVALID_OFFSET_CLASSIFICATIONS
    )
    report["vertical_factory_reference"] = copy.deepcopy(
        _VERTICAL_FACTORY_REFERENCE
    )
    searches = report.get("negative_searches")
    if not isinstance(searches, list):
        raise UiDispatchError("UI dispatch source negative searches must be a list")
    report["negative_searches"] = [
        item
        for item in searches
        if isinstance(item, dict)
        and item.get("target_name")
        in {"root_resource_call_owner", "sample_view_resource_setup_owner"}
    ]
    if len(report["negative_searches"]) != 4:
        raise UiDispatchError("Corrected UI dispatch report must retain four searches")
    return validate_ui_dispatch_report(report)


def validate_ui_dispatch_report(document: dict) -> dict:
    """Return an isolated copy of exact, fail-closed target UI evidence."""

    _reject_forbidden_keys(document)
    report = _require_exact_fields(document, _TOP_FIELDS, "UI dispatch report")
    if type(report["schema_version"]) is not int or report["schema_version"] != 1:
        raise UiDispatchError("UI dispatch schema version is invalid")
    if report["analysis_scope"] != "offline-static-target-filesystem":
        raise UiDispatchError("UI dispatch scope is invalid")

    if report["modules"] != _MODULES:
        raise UiDispatchError("UI dispatch module inventory is invalid")
    if not isinstance(report["roots"], list) or len(report["roots"]) != len(
        _RAW_ROOT_SPECS
    ):
        raise UiDispatchError("UI dispatch roots are invalid")
    roots = {}
    for item, expected in zip(report["roots"], _RAW_ROOT_SPECS):
        root = _require_exact_fields(item, _ROOT_FIELDS, "UI dispatch root")
        name, role, source_kind, source_offset, analysis_address = expected
        if (
            root["name"] != name
            or root["role"] != role
            or root["module"] != "lib/viewUnified2.so"
            or root["source_kind"] != source_kind
            or root["source_offset"] != f"0x{source_offset:x}"
            or root["analysis_address"] != f"0x{analysis_address:x}"
        ):
            raise UiDispatchError("UI dispatch root identity is invalid")
        function_address = root["function_address"]
        if function_address is not None:
            _require_address(
                function_address, "UI dispatch root function", root["module"]
            )
            roots[name] = (root["module"], function_address)
        else:
            roots[name] = None

    export_summary = _require_exact_fields(
        report["bounded_export_summary"],
        _BOUNDED_EXPORT_SUMMARY_FIELDS,
        "Bounded export summary",
    )
    if export_summary != _BOUNDED_EXPORT_SUMMARY:
        raise UiDispatchError("Bounded export summary is invalid")

    classifications = report["invalid_offset_classifications"]
    if not isinstance(classifications, list):
        raise UiDispatchError("Invalid-offset classifications must be a list")
    for classification in classifications:
        item = _require_exact_fields(
            classification, _INVALID_OFFSET_FIELDS, "Invalid-offset classification"
        )
        module_name = _require_module(
            item["module"], "Invalid-offset module", executable=True
        )
        _require_address(item["offset"], "Invalid-offset site", module_name)
        owner = _require_exact_fields(
            item["owner"], _OWNER_RANGE_FIELDS, "Invalid-offset owner"
        )
        _require_address(owner["start"], "Invalid-offset owner start", module_name)
        _require_address(owner["end"], "Invalid-offset owner end", module_name)
        if int(owner["start"], 16) >= int(owner["end"], 16):
            raise UiDispatchError("Invalid-offset owner range is empty")
        if type(item["instruction_boundary"]) is not bool:
            raise UiDispatchError("Invalid-offset boundary flag is invalid")
        if item["classification"] not in {
            "internal-selector-branch",
            "thumb2-second-halfword",
            "constructor-vptr-material",
        }:
            raise UiDispatchError("Invalid-offset classification is invalid")
        if any(item[field] is not False for field in ("callable_owner", "factory", "class_id_load")):
            raise UiDispatchError("Invalid offset was promoted to an owner, factory, or class-ID load")
    if classifications != _INVALID_OFFSET_CLASSIFICATIONS:
        raise UiDispatchError("Invalid-offset classifications differ")

    factory_reference = _require_exact_fields(
        report["vertical_factory_reference"],
        _VERTICAL_FACTORY_REFERENCE_FIELDS,
        "Vertical factory reference",
    )
    for field in ("factory_owner", "wrapper_owner"):
        owner = _require_exact_fields(
            factory_reference[field], _OWNER_RANGE_FIELDS, "Vertical factory owner"
        )
        for edge in ("start", "end"):
            _require_address(owner[edge], "Vertical factory owner address", "lib/viewUnified7.so")
    if factory_reference != _VERTICAL_FACTORY_REFERENCE:
        raise UiDispatchError("Vertical factory reference differs")

    if not isinstance(report["edges"], list) or len(report["edges"]) > _MAX_EDGES:
        raise UiDispatchError("UI dispatch edges are invalid or exceed the cap")
    edges = [_validate_edge(item) for item in report["edges"]]
    edge_ids = [item["id"] for item in edges]
    sites = [(item["caller_module"], item["site"]) for item in edges]
    if len(set(edge_ids)) != len(edge_ids) or len(set(sites)) != len(sites):
        raise UiDispatchError("UI dispatch edges contain duplicate ids or sites")
    by_edge_id = {item["id"]: item for item in edges}

    if not isinstance(report["paths"], list) or len(report["paths"]) > _MAX_PATHS:
        raise UiDispatchError("UI dispatch paths are invalid or exceed the cap")
    paths = [_validate_path(item, roots, by_edge_id) for item in report["paths"]]
    path_ids = [item["id"] for item in paths]
    if len(set(path_ids)) != len(path_ids):
        raise UiDispatchError("UI dispatch paths contain duplicate ids")

    if not isinstance(report["uxc_references"], list):
        raise UiDispatchError("UXC references must be a list")
    for item in report["uxc_references"]:
        _validate_uxc_reference(item)

    if not isinstance(report["negative_searches"], list):
        raise UiDispatchError("Negative searches must be a list")
    searches = [
        _validate_negative_search(item) for item in report["negative_searches"]
    ]
    search_keys = [
        (
            item["root_set"],
            item["target_name"],
            item["target_module"],
            item["target_requested_offset"],
            item["target_function_offset"],
            item["search_method"],
            tuple(item["edge_kinds"]),
            tuple(item.get("terminal_edge_kinds", [])),
            item["depth_cap"],
        )
        for item in searches
    ]
    if len(set(search_keys)) != len(search_keys):
        raise UiDispatchError("Negative searches contain duplicate scope")

    claims = _require_exact_fields(report["claims"], CLAIM_KEYS, "UI claims")
    for claim, value in claims.items():
        if type(value) is not bool:
            raise UiDispatchError("UI claim must be boolean")
        if value is not _claim_has_support(report, claim):
            raise UiDispatchError(f"UI claim does not match resolved evidence: {claim}")

    behavior_support = _require_exact_fields(
        report["behavior_support"], set(BEHAVIOR_IDS), "UI behavior support"
    )
    for behavior_id, value in behavior_support.items():
        if type(value) is not bool:
            raise UiDispatchError("UI behavior support must be boolean")
        if value is not _semantic_has_support(report, behavior_id):
            raise UiDispatchError(
                f"UI behavior support does not match resolved evidence: {behavior_id}"
            )

    return copy.deepcopy(report)
