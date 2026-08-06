"""Normalize and validate bounded static Creative Look boundary evidence."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import unicodedata


CAUTION_CONFIG_SHA256 = (
    "bfd1bd7bad0ab3478b894da5dbb51c15464b1bedc4201240ccb61cd743150ef7"
)
CAUTION_CONFIG_SIZE = 12_070_800
A6400A_CAUTION_CONFIG_SHA256 = (
    "5ff622c8a30595fe88195d3e492643ceeb5ad2da68e556076eed593851a4d3e9"
)
A6400A_CAUTION_CONFIG_SIZE = 12_070_832
ELF_LOAD_BIAS = 0x10000
A6400_CAUTION_CONFIG_MAX_SOURCE_ADDRESS = 0xC5B720
SELECTOR_SOURCE_OFFSET = 0x7DB958
SELECTOR_ANALYSIS_ADDRESS = SELECTOR_SOURCE_OFFSET + ELF_LOAD_BIAS
COMPILED_GRAPH_SOURCE_OFFSET = 0xB836CC
COMPILED_GRAPH_ANALYSIS_ADDRESS = COMPILED_GRAPH_SOURCE_OFFSET + ELF_LOAD_BIAS
DEPTH_CAP = 16

SEMANTICS = {
    "menu-graph-selection",
    "first-class-interface",
    "preset-state-read",
    "preset-state-write",
    "axis-range-validation",
    "base-look-table-load",
    "live-view-sink",
    "still-jpeg-sink",
    "movie-sink",
    "unresolved",
}
OUTPUT_IDS = ("live_view", "still_jpeg", "movie")
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
CLAIM_KEYS = {
    "native_creative_look_interface_found",
    "state_persistence_found",
    "base_look_processing_found",
    "pipeline_binding_found",
}

_EXPECTED_SOURCE_STATES = [
    {
        "id": "a6400-tw-v2.00",
        "state": "AUTHENTICATED_EXTRACTED",
        "executable_evidence_available": True,
    },
    {
        "id": "a6400a-eu-v1.01",
        "state": "AUTHENTICATED_EXTRACTED",
        "executable_evidence_available": True,
    },
    {
        "id": "a6700-tw-v2.00",
        "state": "AUTHENTICATED_OPAQUE",
        "executable_evidence_available": False,
    },
    {
        "id": "a7v-tw-v2.00",
        "state": "AUTHENTICATED_OPAQUE",
        "executable_evidence_available": False,
    },
]
_EXPECTED_MODULES = [
    {
        "source_id": "a6400-tw-v2.00",
        "name": "lib/CautionConfig.so",
        "size": CAUTION_CONFIG_SIZE,
        "sha256": CAUTION_CONFIG_SHA256,
    },
    {
        "source_id": "a6400a-eu-v1.01",
        "name": "lib/CautionConfig.so",
        "size": A6400A_CAUTION_CONFIG_SIZE,
        "sha256": A6400A_CAUTION_CONFIG_SHA256,
    },
]
_TOP_FIELDS = {
    "schema_version",
    "analysis_scope",
    "source_states",
    "modules",
    "bounded_export_summary",
    "roots",
    "paths",
    "negative_searches",
    "source_skips",
    "claims",
    "output_support",
}
_SUMMARY_FIELDS = {
    "root_count",
    "function_root_count",
    "data_root_count",
    "call_count",
    "direct_call_count",
    "unresolved_direct_call_count",
    "unresolved_indirect_call_count",
    "reference_count",
    "truncated",
    "depth_cap",
    "artifact_sha256",
}
_ROOT_FIELDS = {
    "id",
    "source_id",
    "module",
    "role",
    "kind",
    "source_kind",
    "source_offset",
    "analysis_address",
    "symbol",
}
_PATH_FIELDS = {
    "id",
    "source_id",
    "source_module",
    "source",
    "sink_module",
    "sink",
    "semantic",
    "resolved",
    "output_scope",
    "evidence_kind",
}
_NEGATIVE_FIELDS = {
    "id",
    "source_id",
    "module",
    "semantic",
    "root_count",
    "edge_kinds",
    "depth_cap",
    "path_found",
    "blocker",
}
_SKIP_FIELDS = {"source_id", "state", "reason"}
_RAW_FIELDS = {
    "program",
    "sha256",
    "file_size",
    "selector_source_offset",
    "selector_analysis_address",
    "selector_function",
    "compiled_graph_source_offset",
    "compiled_graph_analysis_address",
    "named_functions",
    "references",
    "calls",
    "truncated",
    "depth_cap",
}
_RAW_NAMED_FIELDS = {"address", "symbol"}
_RAW_REFERENCE_FIELDS = {"owner", "site", "target", "kind", "symbol"}
_RAW_CALL_FIELDS = {"caller", "site", "target", "kind", "owner"}
_FORBIDDEN_KEYS = {
    "raw",
    "raw_bytes",
    "bytes",
    "payload",
    "table_bytes",
    "table_contents",
    "disassembly",
    "decompiler_text",
    "instructions",
    "private_key",
    "key_material",
    "hex_dump",
}
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9-]{0,95}\Z")
_ADDRESS = re.compile(r"0x(?:0|[1-9a-f][0-9a-f]*)\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_MAX_TEXT = 2048
_MAX_ROOTS = 256
_MAX_PATHS = 512
_MAX_CALLS = 10_000
_MAX_REFERENCES = 2_048


class CreativeLookTraceError(ValueError):
    """Raised when Creative Look boundary evidence is unsafe or overclaimed."""


def _reject_forbidden_keys(value: object) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in _FORBIDDEN_KEYS:
                raise CreativeLookTraceError("reconstructive or secret field is forbidden")
            _reject_forbidden_keys(child)
    elif isinstance(value, list):
        for child in value:
            _reject_forbidden_keys(child)


def _require_fields(value: object, fields: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise CreativeLookTraceError(f"{label} fields are not exact")
    return value


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CreativeLookTraceError(f"{label} must be nonempty text")
    if len(value) > _MAX_TEXT:
        raise CreativeLookTraceError(f"{label} exceeds the text size limit")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise CreativeLookTraceError(f"{label} contains a control character")
    return value


def _require_identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise CreativeLookTraceError(f"{label} is invalid")
    return value


def _require_address(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ADDRESS.fullmatch(value):
        raise CreativeLookTraceError(f"{label} is invalid")
    if int(value, 16) >= 0x100000000 or int(value, 16) % 2:
        raise CreativeLookTraceError(f"{label} is outside the bounded address space")
    return value


def _normalize_address(value: object, label: str) -> str:
    if type(value) is not int or value < 0 or value >= 0x100000000 or value % 2:
        raise CreativeLookTraceError(f"{label} is invalid")
    return f"0x{value:x}"


def _normalize_module_address(value: object, label: str) -> str:
    address = _normalize_address(value, label)
    if not (
        ELF_LOAD_BIAS
        <= int(address, 16)
        < A6400_CAUTION_CONFIG_MAX_SOURCE_ADDRESS + ELF_LOAD_BIAS
    ):
        raise CreativeLookTraceError(f"{label} is outside the pinned ELF memory image")
    return address


def raw_export_sha256(document: dict) -> str:
    """Return the digest of the canonical raw-export bytes written by the exporter."""

    encoded = (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def normalize_creative_look_export(raw: dict) -> dict:
    """Normalize one bounded α6400 Ghidra export without retaining call dumps."""

    _reject_forbidden_keys(raw)
    document = _require_fields(raw, _RAW_FIELDS, "Raw Creative Look export")
    if document["program"] != "CautionConfig.so":
        raise CreativeLookTraceError("Raw Creative Look program is invalid")
    if document["sha256"] != CAUTION_CONFIG_SHA256:
        raise CreativeLookTraceError("Raw Creative Look digest is invalid")
    if type(document["file_size"]) is not int or document["file_size"] != CAUTION_CONFIG_SIZE:
        raise CreativeLookTraceError("Raw Creative Look file size is invalid")
    if document["selector_source_offset"] != SELECTOR_SOURCE_OFFSET:
        raise CreativeLookTraceError("Raw selector source offset is invalid")
    if document["selector_analysis_address"] != SELECTOR_ANALYSIS_ADDRESS:
        raise CreativeLookTraceError("Raw selector analysis address is invalid")
    if (
        document["selector_analysis_address"]
        - document["selector_source_offset"]
        != ELF_LOAD_BIAS
    ):
        raise CreativeLookTraceError("Raw selector load bias is invalid")
    selector_function = document["selector_function"]
    if (
        type(selector_function) is not int
        or selector_function != SELECTOR_ANALYSIS_ADDRESS
    ):
        raise CreativeLookTraceError("Raw selector function is invalid")
    if document["compiled_graph_source_offset"] != COMPILED_GRAPH_SOURCE_OFFSET:
        raise CreativeLookTraceError("Raw compiled graph source offset is invalid")
    if document["compiled_graph_analysis_address"] != COMPILED_GRAPH_ANALYSIS_ADDRESS:
        raise CreativeLookTraceError("Raw compiled graph analysis address is invalid")
    if (
        document["compiled_graph_analysis_address"]
        - document["compiled_graph_source_offset"]
        != ELF_LOAD_BIAS
    ):
        raise CreativeLookTraceError("Raw compiled graph load bias is invalid")
    if document["truncated"] is not False or document["depth_cap"] != DEPTH_CAP:
        raise CreativeLookTraceError("Raw Creative Look traversal is truncated or unbounded")

    named_functions = document["named_functions"]
    if not isinstance(named_functions, list) or len(named_functions) > _MAX_ROOTS:
        raise CreativeLookTraceError("Raw named functions are invalid or unbounded")
    normalized_functions = []
    function_addresses = set()
    for item in named_functions:
        function = _require_fields(item, _RAW_NAMED_FIELDS, "Raw named function")
        address = _normalize_module_address(
            function["address"], "Raw function address"
        )
        symbol = _require_text(function["symbol"], "Raw function symbol")
        if address in function_addresses:
            raise CreativeLookTraceError("Raw named function address is duplicated")
        function_addresses.add(address)
        normalized_functions.append((address, symbol))
    normalized_functions.sort(key=lambda item: int(item[0], 16))

    references = document["references"]
    if not isinstance(references, list) or len(references) > _MAX_REFERENCES:
        raise CreativeLookTraceError("Raw graph references are invalid or unbounded")
    normalized_references = []
    reference_sites = set()
    for item in references:
        reference = _require_fields(item, _RAW_REFERENCE_FIELDS, "Raw graph reference")
        owner = _normalize_module_address(reference["owner"], "Raw reference owner")
        site = _normalize_module_address(reference["site"], "Raw reference site")
        target = _normalize_module_address(reference["target"], "Raw reference target")
        if (
            reference["kind"] != "data-reference"
            or target != f"0x{COMPILED_GRAPH_ANALYSIS_ADDRESS:x}"
        ):
            raise CreativeLookTraceError("Raw graph reference kind or target is invalid")
        if site in reference_sites:
            raise CreativeLookTraceError("Raw graph reference site is duplicated")
        reference_sites.add(site)
        normalized_references.append(
            {
                "owner": owner,
                "site": site,
                "target": target,
                "symbol": _require_text(reference["symbol"], "Raw reference symbol"),
            }
        )
    normalized_references.sort(key=lambda item: int(item["site"], 16))

    calls = document["calls"]
    if not isinstance(calls, list) or len(calls) > _MAX_CALLS:
        raise CreativeLookTraceError("Raw calls are invalid or unbounded")
    direct_calls = 0
    unresolved_direct_calls = 0
    unresolved_calls = 0
    call_sites = set()
    for item in calls:
        call = _require_fields(item, _RAW_CALL_FIELDS, "Raw call")
        _normalize_module_address(call["caller"], "Raw call owner")
        site = _normalize_module_address(call["site"], "Raw call site")
        if site in call_sites:
            raise CreativeLookTraceError("Raw call site is duplicated")
        call_sites.add(site)
        _require_text(call["owner"], "Raw call symbol")
        if call["kind"] == "direct":
            _normalize_module_address(call["target"], "Raw call target")
            direct_calls += 1
        elif call["kind"] == "unresolved-direct":
            if call["target"] is not None:
                raise CreativeLookTraceError("Unresolved direct call cannot have a target")
            unresolved_direct_calls += 1
        elif call["kind"] == "unresolved-indirect":
            if call["target"] is not None:
                raise CreativeLookTraceError("Unresolved call cannot have a target")
            unresolved_calls += 1
        else:
            raise CreativeLookTraceError("Raw call kind is invalid")

    roots = [
        {
            "id": "selector-function",
            "source_id": "a6400-tw-v2.00",
            "module": "lib/CautionConfig.so",
            "role": "creative-style-selector",
            "kind": "function",
            "source_kind": "elf-virtual-address",
            "source_offset": f"0x{SELECTOR_SOURCE_OFFSET:x}",
            "analysis_address": f"0x{selector_function:x}",
            "symbol": "CmnViewSettingNodeCreativeStyle::_getSubNodeEv",
        },
        {
            "id": "compiled-default-graph",
            "source_id": "a6400-tw-v2.00",
            "module": "lib/CautionConfig.so",
            "role": "compiled-creative-style-graph",
            "kind": "data",
            "source_kind": "elf-virtual-address",
            "source_offset": f"0x{COMPILED_GRAPH_SOURCE_OFFSET:x}",
            "analysis_address": f"0x{COMPILED_GRAPH_ANALYSIS_ADDRESS:x}",
            "symbol": "Default",
        },
    ]
    seen_root_addresses = {item["analysis_address"] for item in roots}
    for index, (address, symbol) in enumerate(normalized_functions, 1):
        if address in seen_root_addresses:
            continue
        seen_root_addresses.add(address)
        roots.append(
            {
                "id": f"creative-style-function-{index:03d}",
                "source_id": "a6400-tw-v2.00",
                "module": "lib/CautionConfig.so",
                "role": "creative-style-named-function",
                "kind": "function",
                "source_kind": "elf-virtual-address",
                "source_offset": f"0x{int(address, 16) - ELF_LOAD_BIAS:x}",
                "analysis_address": address,
                "symbol": symbol,
            }
        )

    paths = []
    for index, reference in enumerate(normalized_references, 1):
        paths.append(
            {
                "id": f"selector-graph-reference-{index:03d}",
                "source_id": "a6400-tw-v2.00",
                "source_module": "lib/CautionConfig.so",
                "source": reference["owner"],
                "sink_module": "lib/CautionConfig.so",
                "sink": reference["target"],
                "semantic": "menu-graph-selection",
                "resolved": True,
                "output_scope": [],
                "evidence_kind": "compiled-graph-selector",
            }
        )

    return {
        "bounded_export_summary": {
            "root_count": len(roots),
            "function_root_count": sum(item["kind"] == "function" for item in roots),
            "data_root_count": sum(item["kind"] == "data" for item in roots),
            "call_count": len(calls),
            "direct_call_count": direct_calls,
            "unresolved_direct_call_count": unresolved_direct_calls,
            "unresolved_indirect_call_count": unresolved_calls,
            "reference_count": len(references),
            "truncated": False,
            "depth_cap": DEPTH_CAP,
            "artifact_sha256": raw_export_sha256(document),
        },
        "roots": roots,
        "paths": paths,
    }


def _semantic_supported(paths: list[dict], semantic: str) -> bool:
    return any(item["semantic"] == semantic and item["resolved"] is True for item in paths)


def validate_creative_look_boundary(document: dict) -> dict:
    """Return an isolated copy of fail-closed Creative Look boundary evidence."""

    _reject_forbidden_keys(document)
    report = _require_fields(document, _TOP_FIELDS, "Creative Look boundary")
    if type(report["schema_version"]) is not int or report["schema_version"] != 1:
        raise CreativeLookTraceError("Creative Look boundary schema version is invalid")
    if report["analysis_scope"] != "offline-static-creative-look-boundaries":
        raise CreativeLookTraceError("Creative Look boundary scope is invalid")
    if report["source_states"] != _EXPECTED_SOURCE_STATES:
        raise CreativeLookTraceError("Creative Look source states are invalid")
    if report["modules"] != _EXPECTED_MODULES:
        raise CreativeLookTraceError("Creative Look module identities are invalid")
    source_available = {
        item["id"]: item["executable_evidence_available"]
        for item in report["source_states"]
    }
    module_keys = {(item["source_id"], item["name"]) for item in report["modules"]}

    summary = _require_fields(
        report["bounded_export_summary"], _SUMMARY_FIELDS, "Bounded export summary"
    )
    count_fields = (
        "root_count",
        "function_root_count",
        "data_root_count",
        "call_count",
        "direct_call_count",
        "unresolved_direct_call_count",
        "unresolved_indirect_call_count",
        "reference_count",
    )
    if any(type(summary[field]) is not int or summary[field] < 0 for field in count_fields):
        raise CreativeLookTraceError("Bounded export counts are invalid")
    if summary["call_count"] != (
        summary["direct_call_count"]
        + summary["unresolved_direct_call_count"]
        + summary["unresolved_indirect_call_count"]
    ):
        raise CreativeLookTraceError("Bounded call counts do not balance")
    if summary["truncated"] is not False or summary["depth_cap"] != DEPTH_CAP:
        raise CreativeLookTraceError("Bounded export is truncated or has wrong depth")
    if not isinstance(summary["artifact_sha256"], str) or not _DIGEST.fullmatch(
        summary["artifact_sha256"]
    ):
        raise CreativeLookTraceError("Bounded export artifact digest is invalid")

    roots = report["roots"]
    if not isinstance(roots, list) or len(roots) > _MAX_ROOTS:
        raise CreativeLookTraceError("Creative Look roots are invalid or unbounded")
    root_ids = set()
    function_roots = 0
    data_roots = 0
    for item in roots:
        root = _require_fields(item, _ROOT_FIELDS, "Creative Look root")
        root_id = _require_identifier(root["id"], "Creative Look root id")
        if root_id in root_ids:
            raise CreativeLookTraceError("Creative Look root id is duplicated")
        root_ids.add(root_id)
        if not source_available.get(root["source_id"], False):
            raise CreativeLookTraceError("Opaque source cannot supply a root")
        if (root["source_id"], root["module"]) not in module_keys:
            raise CreativeLookTraceError("Creative Look root module is invalid")
        if root["kind"] not in {"function", "data"}:
            raise CreativeLookTraceError("Creative Look root kind is invalid")
        function_roots += root["kind"] == "function"
        data_roots += root["kind"] == "data"
        if root["source_id"] != "a6400-tw-v2.00":
            raise CreativeLookTraceError("Only the pinned target trace can supply roots")
        if root["source_kind"] != "elf-virtual-address":
            raise CreativeLookTraceError("Creative Look root source kind is invalid")
        source_offset = _require_address(
            root["source_offset"], "Creative Look root source offset"
        )
        analysis_address = _require_address(
            root["analysis_address"], "Creative Look root analysis address"
        )
        if int(analysis_address, 16) - int(source_offset, 16) != ELF_LOAD_BIAS:
            raise CreativeLookTraceError("Creative Look root load bias is invalid")
        if not 0 <= int(source_offset, 16) < A6400_CAUTION_CONFIG_MAX_SOURCE_ADDRESS:
            raise CreativeLookTraceError(
                "Creative Look root is outside the pinned ELF memory image"
            )
        _require_text(root["role"], "Creative Look root role")
        _require_text(root["symbol"], "Creative Look root symbol")
    if (
        summary["root_count"] != len(roots)
        or summary["function_root_count"] != function_roots
        or summary["data_root_count"] != data_roots
    ):
        raise CreativeLookTraceError("Creative Look root counts do not match roots")

    paths = report["paths"]
    if not isinstance(paths, list) or len(paths) > _MAX_PATHS:
        raise CreativeLookTraceError("Creative Look paths are invalid or unbounded")
    path_ids = set()
    for item in paths:
        path = _require_fields(item, _PATH_FIELDS, "Creative Look path")
        path_id = _require_identifier(path["id"], "Creative Look path id")
        if path_id in path_ids:
            raise CreativeLookTraceError("Creative Look path id is duplicated")
        path_ids.add(path_id)
        if not source_available.get(path["source_id"], False):
            raise CreativeLookTraceError("Opaque source cannot supply path offsets")
        if (path["source_id"], path["source_module"]) not in module_keys:
            raise CreativeLookTraceError("Creative Look path source module is invalid")
        _require_address(path["source"], "Creative Look path source")
        if path["semantic"] not in SEMANTICS:
            raise CreativeLookTraceError("Creative Look path semantic is invalid")
        if type(path["resolved"]) is not bool:
            raise CreativeLookTraceError("Creative Look path resolved state is invalid")
        if not isinstance(path["output_scope"], list) or len(set(path["output_scope"])) != len(
            path["output_scope"]
        ) or any(output not in OUTPUT_IDS for output in path["output_scope"]):
            raise CreativeLookTraceError("Creative Look output scope is invalid")
        _require_text(path["evidence_kind"], "Creative Look path evidence kind")
        if path["resolved"]:
            if path["sink"] is None or path["sink_module"] is None:
                raise CreativeLookTraceError("Resolved Creative Look path has no sink")
            if (path["source_id"], path["sink_module"]) not in module_keys:
                raise CreativeLookTraceError("Creative Look path sink module is invalid")
            _require_address(path["sink"], "Creative Look path sink")
        elif path["sink"] is not None or path["sink_module"] is not None or path["output_scope"]:
            raise CreativeLookTraceError("Unresolved Creative Look path has resolved fields")
        if path["semantic"] == "unresolved" and path["resolved"] is not False:
            raise CreativeLookTraceError("Unresolved semantic cannot be resolved")
        if path["semantic"] != "unresolved" and path["resolved"] is not True:
            raise CreativeLookTraceError("Non-unresolved semantic requires a resolved path")
        expected_scope = {
            "live-view-sink": ["live_view"],
            "still-jpeg-sink": ["still_jpeg"],
            "movie-sink": ["movie"],
        }.get(path["semantic"], [])
        if path["output_scope"] != expected_scope:
            raise CreativeLookTraceError("Creative Look semantic and output scope disagree")
        if (
            path["evidence_kind"] != "compiled-graph-selector"
            or path["semantic"] != "menu-graph-selection"
            or path["source_id"] != "a6400-tw-v2.00"
            or path["source_module"] != "lib/CautionConfig.so"
            or path["sink_module"] != "lib/CautionConfig.so"
            or path["source"] != f"0x{SELECTOR_ANALYSIS_ADDRESS:x}"
            or path["sink"] != f"0x{COMPILED_GRAPH_ANALYSIS_ADDRESS:x}"
        ):
            raise CreativeLookTraceError(
                "Only the normalized Creative Style selector path is accepted"
            )

    negatives = report["negative_searches"]
    if not isinstance(negatives, list) or len(negatives) > 128:
        raise CreativeLookTraceError("Creative Look negative searches are invalid")
    negative_ids = set()
    for item in negatives:
        search = _require_fields(item, _NEGATIVE_FIELDS, "Creative Look negative search")
        search_id = _require_identifier(search["id"], "Negative search id")
        if search_id in negative_ids:
            raise CreativeLookTraceError("Negative search id is duplicated")
        negative_ids.add(search_id)
        if not source_available.get(search["source_id"], False):
            raise CreativeLookTraceError("Opaque source cannot have executable negative search")
        if (search["source_id"], search["module"]) not in module_keys:
            raise CreativeLookTraceError("Negative search module is invalid")
        if search["semantic"] not in SEMANTICS - {"menu-graph-selection", "unresolved"}:
            raise CreativeLookTraceError("Negative search semantic is invalid")
        if type(search["root_count"]) is not int or search["root_count"] <= 0:
            raise CreativeLookTraceError("Negative search root count is invalid")
        expected_edge_kinds = ["direct"]
        if summary["unresolved_direct_call_count"]:
            expected_edge_kinds.append("unresolved-direct")
        if summary["unresolved_indirect_call_count"]:
            expected_edge_kinds.append("unresolved-indirect")
        if search["edge_kinds"] != expected_edge_kinds:
            raise CreativeLookTraceError("Negative search edge kinds are invalid")
        if search["depth_cap"] != DEPTH_CAP or search["path_found"] is not False:
            raise CreativeLookTraceError("Negative search bounds or result are invalid")
        _require_text(search["blocker"], "Negative search blocker")
    required_axis_negative_ids = {
        f"axis-{axis.replace('_', '-')}-boundaries-not-found" for axis in AXIS_IDS
    }
    if not required_axis_negative_ids.issubset(negative_ids):
        raise CreativeLookTraceError(
            "Each Creative Look axis requires an independent bounded negative search"
        )

    skips = report["source_skips"]
    expected_skips = [
        {
            "source_id": "a6700-tw-v2.00",
            "state": "AUTHENTICATED_OPAQUE",
            "reason": "source-not-extracted",
        },
        {
            "source_id": "a7v-tw-v2.00",
            "state": "AUTHENTICATED_OPAQUE",
            "reason": "source-not-extracted",
        },
    ]
    if not isinstance(skips, list):
        raise CreativeLookTraceError("Creative Look source skips must be a list")
    for item in skips:
        _require_fields(item, _SKIP_FIELDS, "Creative Look source skip")
    if skips != expected_skips:
        raise CreativeLookTraceError("Creative Look source skips are invalid")

    output_support = _require_fields(
        report["output_support"], set(OUTPUT_IDS), "Creative Look output support"
    )
    output_semantics = {
        "live_view": "live-view-sink",
        "still_jpeg": "still-jpeg-sink",
        "movie": "movie-sink",
    }
    for output_id, value in output_support.items():
        if type(value) is not bool or value is not _semantic_supported(
            paths, output_semantics[output_id]
        ):
            raise CreativeLookTraceError("Creative Look output support is overclaimed")

    claims = _require_fields(report["claims"], CLAIM_KEYS, "Creative Look claims")
    expected_claims = {
        "native_creative_look_interface_found": _semantic_supported(
            paths, "first-class-interface"
        ),
        "state_persistence_found": _semantic_supported(paths, "preset-state-read")
        and _semantic_supported(paths, "preset-state-write"),
        "base_look_processing_found": _semantic_supported(
            paths, "base-look-table-load"
        ),
        "pipeline_binding_found": any(output_support.values()),
    }
    for claim, value in claims.items():
        if type(value) is not bool or value is not expected_claims[claim]:
            raise CreativeLookTraceError(f"Creative Look claim is overclaimed: {claim}")

    return copy.deepcopy(report)
