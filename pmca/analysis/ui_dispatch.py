"""Validate bounded static UI-dispatch evidence for the ILCE-6400."""

from __future__ import annotations

import copy
import re
import unicodedata


VIEW_UNIFIED2_SIZE = 11_530_552
VIEW_UNIFIED2_SHA256 = (
    "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2"
)
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
}
_EXECUTABLE_EDGE_KINDS = {"direct", "vtable-slot", "function-pointer-table"}
_TOP_FIELDS = {
    "schema_version",
    "analysis_scope",
    "module",
    "roots",
    "edges",
    "paths",
    "uxc_references",
    "negative_searches",
    "claims",
}
_MODULE_FIELDS = {"name", "size", "sha256"}
_ROOT_FIELDS = {"name", "offset"}
_EDGE_FIELDS = {"id", "caller", "site", "callee", "kind", "owner", "slot", "table"}
_PATH_FIELDS = {"id", "root", "offsets", "edge_ids", "semantic", "resolved"}
_UXC_FIELDS = {"source", "kind", "value", "offset", "semantic"}
_NEGATIVE_FIELDS = {
    "root_set",
    "requested_roots",
    "resolved_roots",
    "target_name",
    "target_requested_offset",
    "target_function_offset",
    "search_method",
    "path_found",
}
_ROOTS = [
    {"name": "ViewSettingMenu", "offset": "0x22355e"},
    {"name": "ViewStlrec", "offset": "0x1ab41c"},
]
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


def _require_address(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ADDRESS.fullmatch(value):
        raise UiDispatchError(f"{label} is not a normalized address")
    offset = int(value, 16)
    if offset >= VIEW_UNIFIED2_SIZE or offset % 2:
        raise UiDispatchError(f"{label} is outside the module or not Thumb-normalized")
    return value


def _require_exact_fields(value: object, fields: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise UiDispatchError(f"{label} fields are not exact")
    return value


def _validate_edge(item: object) -> dict:
    edge = _require_exact_fields(item, _EDGE_FIELDS, "Edge")
    _require_identifier(edge["id"], "Edge id")
    _require_address(edge["caller"], "Edge caller")
    _require_address(edge["site"], "Edge site")
    _require_text(edge["owner"], "Edge owner")
    kind = edge["kind"]
    if not isinstance(kind, str) or kind not in EDGE_KINDS:
        raise UiDispatchError("Edge kind is invalid")

    if kind in _EXECUTABLE_EDGE_KINDS:
        _require_address(edge["callee"], "Edge callee")
    elif edge["callee"] is not None:
        raise UiDispatchError("Non-executable edge cannot have a callee")

    if kind in {"vtable-slot", "function-pointer-table"}:
        if type(edge["slot"]) is not int or not 0 <= edge["slot"] <= 1023:
            raise UiDispatchError("Table edge slot is invalid")
        _require_address(edge["table"], "Edge table")
    elif edge["slot"] is not None or edge["table"] is not None:
        raise UiDispatchError("Non-table edge cannot have a slot or table")
    return edge


def _validate_path(item: object, roots: set[str], edges: dict[str, dict]) -> dict:
    path = _require_exact_fields(item, _PATH_FIELDS, "Path")
    _require_identifier(path["id"], "Path id")
    if path["root"] not in roots:
        raise UiDispatchError("Path root is invalid")
    if not isinstance(path["offsets"], list) or not path["offsets"]:
        raise UiDispatchError("Path offsets must be a nonempty list")
    for offset in path["offsets"]:
        _require_address(offset, "Path offset")
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
    if reference["semantic"] != "reference-only":
        raise UiDispatchError("UXC reference cannot claim behavior")
    return reference


def _validate_negative_search(item: object) -> dict:
    search = _require_exact_fields(item, _NEGATIVE_FIELDS, "Negative search")
    _require_text(search["root_set"], "Negative search root set")
    _require_text(search["target_name"], "Negative search target")
    for field in ("requested_roots", "resolved_roots"):
        if type(search[field]) is not int or search[field] < 0:
            raise UiDispatchError(f"Negative search {field} is invalid")
    if search["resolved_roots"] > search["requested_roots"]:
        raise UiDispatchError("Negative search resolved roots exceed requested roots")
    _require_address(search["target_requested_offset"], "Requested target offset")
    _require_address(search["target_function_offset"], "Target function offset")
    if search["search_method"] != "static-direct-call-graph":
        raise UiDispatchError("Negative search method is invalid")
    if search["path_found"] is not False:
        raise UiDispatchError("Negative search cannot report a path")
    return search


def _claim_has_support(document: dict, claim: str) -> bool:
    required_semantic = _CLAIM_SEMANTICS[claim]
    edges = {item["id"]: item for item in document["edges"]}
    for path in document["paths"]:
        if path["semantic"] != required_semantic or path["resolved"] is not True:
            continue
        if not path["edge_ids"]:
            continue
        if all(edges[edge_id]["kind"] in _EXECUTABLE_EDGE_KINDS for edge_id in path["edge_ids"]):
            return True
    return False


def validate_ui_dispatch_report(document: dict) -> dict:
    """Return an isolated copy of exact, fail-closed target UI evidence."""

    _reject_forbidden_keys(document)
    report = _require_exact_fields(document, _TOP_FIELDS, "UI dispatch report")
    if type(report["schema_version"]) is not int or report["schema_version"] != 1:
        raise UiDispatchError("UI dispatch schema version is invalid")
    if report["analysis_scope"] != "offline-static-target-filesystem":
        raise UiDispatchError("UI dispatch scope is invalid")

    module = _require_exact_fields(report["module"], _MODULE_FIELDS, "Module")
    if module != {
        "name": "lib/viewUnified2.so",
        "size": VIEW_UNIFIED2_SIZE,
        "sha256": VIEW_UNIFIED2_SHA256,
    }:
        raise UiDispatchError("UI dispatch module identity is invalid")
    if report["roots"] != _ROOTS:
        raise UiDispatchError("UI dispatch roots are invalid")
    roots = {item["name"] for item in report["roots"]}

    if not isinstance(report["edges"], list) or len(report["edges"]) > _MAX_EDGES:
        raise UiDispatchError("UI dispatch edges are invalid or exceed the cap")
    edges = [_validate_edge(item) for item in report["edges"]]
    edge_ids = [item["id"] for item in edges]
    sites = [item["site"] for item in edges]
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
    for item in report["negative_searches"]:
        _validate_negative_search(item)

    claims = _require_exact_fields(report["claims"], CLAIM_KEYS, "UI claims")
    for claim, value in claims.items():
        if type(value) is not bool:
            raise UiDispatchError("UI claim must be boolean")
        if value is not _claim_has_support(report, claim):
            raise UiDispatchError(f"UI claim does not match resolved evidence: {claim}")

    return copy.deepcopy(report)
