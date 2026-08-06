"""Validate bounded α6400 Picture Profile reimplementation metadata."""

from __future__ import annotations

import copy
import hashlib
import json
import re


CAUTION_CONFIG_SHA256 = (
    "bfd1bd7bad0ab3478b894da5dbb51c15464b1bedc4201240ccb61cd743150ef7"
)
CAUTION_CONFIG_SIZE = 12_070_800
PICTURE_PROFILE_EXPORT_SHA256 = (
    "b69c884743e25d10fabdc6984d46ec4120755d4c9c8657f4773ae009d435ea32"
)
ELF_LOAD_BIAS = 0x10000
DEPTH_CAP = 16
MAX_DIRECT_CALLS = 512
MAX_DATA_REFERENCES = 512
MAX_UNRESOLVED_INDIRECT_EDGES = 128
_HEX = re.compile(r"0x[0-9a-f]+")


class PictureProfileTraceError(ValueError):
    """Raised when Picture Profile trace evidence is incomplete or unsafe."""


def _root(identifier, role, elf_thumb_offset, symbol):
    return {
        "id": identifier,
        "role": role,
        "elf_thumb_offset": f"0x{elf_thumb_offset:x}",
        "analysis_address": f"0x{((elf_thumb_offset & ~1) + ELF_LOAD_BIAS):x}",
        "analysis_address_int": (elf_thumb_offset & ~1) + ELF_LOAD_BIAS,
        "symbol": symbol,
    }


def _slot(identifier, elf_offset):
    return {
        "id": identifier,
        "elf_offset": f"0x{elf_offset:x}",
        "analysis_address": f"0x{(elf_offset + ELF_LOAD_BIAS):x}",
        "analysis_address_int": elf_offset + ELF_LOAD_BIAS,
        "symbol": f"cmnViewSettingNodePictureProfile{identifier}",
    }


PICTURE_PROFILE_ROOTS = (
    _root(
        "picture-profile-selector",
        "preset-selector",
        0x7DBC05,
        "CmnViewSettingNodePictureProfile::_getSubNode()",
    ),
    _root(
        "picture-profile-clone",
        "preset-clone",
        0x7DBBE1,
        "CmnViewSettingNodePictureProfile::clone()",
    ),
    _root(
        "picture-profile-copy",
        "copy-subnode",
        0x7DB825,
        "CmnViewSettingNodePictureProfileCopyPage1::_getSubNode()",
    ),
    _root(
        "picture-profile-gamma",
        "gamma-subnode",
        0x7DB6BD,
        "CmnViewSettingNodePictureProfileGamma::_getSubNode()",
    ),
    _root(
        "picture-profile-color-mode",
        "color-mode-subnode",
        0x7DDF5D,
        "CmnViewSettingNodePictureProfileColorMode::_getSubNode()",
    ),
)
PICTURE_PROFILE_SLOT_NODES = (
    _slot("PP1", 0xB9C208),
    _slot("PP2", 0xC4EE70),
    _slot("PP3", 0xC4EE98),
    _slot("PP4", 0xC4EEC0),
    _slot("PP5", 0xC4EEE8),
    _slot("PP6", 0xB9C240),
    _slot("PP7", 0xC4EF38),
    _slot("PP8", 0xC4EF60),
    _slot("PP9", 0xC4EF88),
)

_TOP_FIELDS = {
    "schema_version",
    "analysis_scope",
    "camera_policy",
    "camera_executed",
    "installable",
    "camera_test_eligible",
    "source",
    "roots",
    "slot_nodes",
    "bounded_export_summary",
    "direct_calls",
    "data_references",
    "unresolved_indirect_edges",
    "candidates",
    "claims",
    "readiness",
    "conclusion",
}
_SOURCE_FIELDS = {"source_id", "module", "size", "sha256"}
_ROOT_FIELDS = {"id", "role", "elf_thumb_offset", "analysis_address", "symbol"}
_SLOT_FIELDS = {"id", "elf_offset", "analysis_address", "symbol"}
_SUMMARY_FIELDS = {
    "direct_call_count",
    "data_reference_count",
    "unresolved_indirect_count",
    "truncated",
    "depth_cap",
    "artifact_sha256",
}
_CALL_FIELDS = {"caller", "site", "target", "owner"}
_REFERENCE_FIELDS = {"owner", "site", "target", "symbol"}
_INDIRECT_FIELDS = {"caller", "site", "owner"}
_CANDIDATE_FIELDS = {"named_slots", "copy_subnode", "uxc_reference"}
_CLAIM_FIELDS = {
    "reusable_target_interface_primitives",
    "reusable_target_state_primitives",
    "persistence_found",
    "base_look_processing",
    "live_view_binding",
    "still_jpeg_binding",
    "movie_binding",
}
_FORBIDDEN_KEY_PARTS = ("raw", "byte", "disassembly", "key", "device", "write")
_READINESS = "INFRASTRUCTURE_CANDIDATE_ONLY"
_CONCLUSION = (
    "Picture Profile exposes target-native preset, copy, gamma, color-mode, and "
    "PP1-PP9 node candidates, but no Creative Look state, persistence, processing, "
    "live-view, still-JPEG, or movie binding is established."
)


def _require_exact_fields(value, fields, label):
    if not isinstance(value, dict) or set(value) != fields:
        raise PictureProfileTraceError(f"{label} has invalid fields")
    return value


def _require_address(value, label):
    if not isinstance(value, str) or _HEX.fullmatch(value) is None:
        raise PictureProfileTraceError(f"{label} is invalid")
    return int(value, 16)


def _require_sha256(value, label):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise PictureProfileTraceError(f"{label} is invalid")
    return value


def _reject_forbidden_fields(value):
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = str(key).lower()
            if any(part in lowered for part in _FORBIDDEN_KEY_PARTS):
                raise PictureProfileTraceError("forbidden raw or device material")
            _reject_forbidden_fields(item)
    elif isinstance(value, list):
        for item in value:
            _reject_forbidden_fields(item)


def _expected_roots():
    return [
        {key: value for key, value in item.items() if key != "analysis_address_int"}
        for item in PICTURE_PROFILE_ROOTS
    ]


def _expected_slots():
    return [
        {key: value for key, value in item.items() if key != "analysis_address_int"}
        for item in PICTURE_PROFILE_SLOT_NODES
    ]


def _validate_roots(value):
    if not isinstance(value, list):
        raise PictureProfileTraceError("roots are invalid")
    normalized = []
    for root in value:
        root = _require_exact_fields(root, _ROOT_FIELDS, "root")
        if "CreativeStyle" in root["symbol"]:
            raise PictureProfileTraceError("Creative Style roots are excluded")
        _require_address(root["elf_thumb_offset"], "root ELF offset")
        address = _require_address(root["analysis_address"], "root analysis address")
        if address & 1:
            raise PictureProfileTraceError("root analysis address is not normalized")
        normalized.append(copy.deepcopy(root))
    if normalized != _expected_roots():
        raise PictureProfileTraceError("Picture Profile roots are not pinned")
    return normalized


def _validate_slots(value):
    if not isinstance(value, list):
        raise PictureProfileTraceError("slot nodes are invalid")
    normalized = []
    for slot in value:
        slot = _require_exact_fields(slot, _SLOT_FIELDS, "slot node")
        _require_address(slot["elf_offset"], "slot ELF offset")
        _require_address(slot["analysis_address"], "slot analysis address")
        normalized.append(copy.deepcopy(slot))
    if normalized != _expected_slots():
        raise PictureProfileTraceError("Picture Profile slot nodes are not pinned")
    return normalized


def _validate_edges(value, fields, label, limit):
    if not isinstance(value, list) or len(value) > limit:
        raise PictureProfileTraceError(f"{label} are invalid")
    result = []
    sites = set()
    for item in value:
        item = _require_exact_fields(item, fields, label)
        for key in fields:
            if key != "owner" and key != "symbol":
                _require_address(item[key], f"{label} {key}")
        site = item["site"]
        if site in sites:
            raise PictureProfileTraceError(f"{label} contain duplicate sites")
        sites.add(site)
        result.append(copy.deepcopy(item))
    return result


def _canonical_digest(document):
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def validate_picture_profile_boundary(document):
    """Return an independently owned, strict Picture Profile metadata summary."""

    _reject_forbidden_fields(document)
    document = _require_exact_fields(document, _TOP_FIELDS, "boundary document")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise PictureProfileTraceError("schema version is invalid")
    if document["analysis_scope"] != "offline-static-picture-profile-reimplementation-boundary":
        raise PictureProfileTraceError("analysis scope is invalid")
    if document["camera_policy"] != "physically-disconnected":
        raise PictureProfileTraceError("camera policy is invalid")
    for field in ("camera_executed", "installable", "camera_test_eligible"):
        if document[field] is not False:
            raise PictureProfileTraceError(f"{field} must remain false")

    source = _require_exact_fields(document["source"], _SOURCE_FIELDS, "source")
    if source != {
        "source_id": "a6400-tw-v2.00",
        "module": "lib/CautionConfig.so",
        "size": CAUTION_CONFIG_SIZE,
        "sha256": CAUTION_CONFIG_SHA256,
    }:
        raise PictureProfileTraceError("source identity is invalid")

    roots = _validate_roots(document["roots"])
    slots = _validate_slots(document["slot_nodes"])
    direct_calls = _validate_edges(
        document["direct_calls"], _CALL_FIELDS, "direct calls", MAX_DIRECT_CALLS
    )
    data_references = _validate_edges(
        document["data_references"], _REFERENCE_FIELDS, "data references", MAX_DATA_REFERENCES
    )
    unresolved = _validate_edges(
        document["unresolved_indirect_edges"],
        _INDIRECT_FIELDS,
        "unresolved indirect edges",
        MAX_UNRESOLVED_INDIRECT_EDGES,
    )
    summary = _require_exact_fields(
        document["bounded_export_summary"], _SUMMARY_FIELDS, "export summary"
    )
    if (
        summary["direct_call_count"] != len(direct_calls)
        or summary["data_reference_count"] != len(data_references)
        or summary["unresolved_indirect_count"] != len(unresolved)
        or summary["truncated"] is not False
        or summary["depth_cap"] != DEPTH_CAP
    ):
        raise PictureProfileTraceError("export summary is inconsistent")
    digest = _require_sha256(summary["artifact_sha256"], "export artifact digest")
    reconstructed_raw = {
        "program": "CautionConfig.so",
        "sha256": CAUTION_CONFIG_SHA256,
        "file_size": CAUTION_CONFIG_SIZE,
        "analysis_mode": {"read_only": True, "noanalysis": True},
        "roots": [
            {"address": item["analysis_address_int"], "symbol": item["symbol"]}
            for item in PICTURE_PROFILE_ROOTS
        ],
        "slot_nodes": [
            {"address": item["analysis_address_int"], "symbol": item["symbol"]}
            for item in PICTURE_PROFILE_SLOT_NODES
        ],
        "direct_calls": direct_calls,
        "data_references": data_references,
        "unresolved_indirect_edges": unresolved,
        "truncated": False,
        "depth_cap": DEPTH_CAP,
    }
    if digest != PICTURE_PROFILE_EXPORT_SHA256 or digest != _canonical_digest(
        reconstructed_raw
    ):
        raise PictureProfileTraceError("export artifact digest is not pinned to evidence")

    candidates = _require_exact_fields(document["candidates"], _CANDIDATE_FIELDS, "candidates")
    if candidates != {"named_slots": True, "copy_subnode": True, "uxc_reference": False}:
        raise PictureProfileTraceError("candidate status is invalid")
    claims = _require_exact_fields(document["claims"], _CLAIM_FIELDS, "claims")
    if any(value is not False for value in claims.values()):
        raise PictureProfileTraceError("unproven Picture Profile claim")
    if document["readiness"] != _READINESS or document["conclusion"] != _CONCLUSION:
        raise PictureProfileTraceError("Picture Profile conclusion is not fail-closed")

    return {
        "schema_version": 1,
        "analysis_scope": document["analysis_scope"],
        "camera_policy": "physically-disconnected",
        "camera_executed": False,
        "installable": False,
        "camera_test_eligible": False,
        "source": copy.deepcopy(source),
        "roots": roots,
        "slot_nodes": slots,
        "bounded_export_summary": copy.deepcopy(summary),
        "direct_calls": direct_calls,
        "data_references": data_references,
        "unresolved_indirect_edges": unresolved,
        "candidates": copy.deepcopy(candidates),
        "claims": copy.deepcopy(claims),
        "readiness": _READINESS,
        "conclusion": _CONCLUSION,
    }


def normalize_picture_profile_export(raw):
    """Normalize an ignored metadata-only exporter artifact into a safe summary."""

    _reject_forbidden_fields(raw)
    required = {
        "program",
        "sha256",
        "file_size",
        "analysis_mode",
        "roots",
        "slot_nodes",
        "direct_calls",
        "data_references",
        "unresolved_indirect_edges",
        "truncated",
        "depth_cap",
    }
    if not isinstance(raw, dict) or set(raw) != required:
        raise PictureProfileTraceError("raw exporter document has invalid fields")
    if (
        raw["program"] != "CautionConfig.so"
        or raw["sha256"] != CAUTION_CONFIG_SHA256
        or raw["file_size"] != CAUTION_CONFIG_SIZE
        or raw["analysis_mode"] != {"read_only": True, "noanalysis": True}
        or raw["truncated"] is not False
        or raw["depth_cap"] != DEPTH_CAP
    ):
        raise PictureProfileTraceError("raw exporter source identity is invalid")

    expected_roots = [
        {"address": item["analysis_address_int"], "symbol": item["symbol"]}
        for item in PICTURE_PROFILE_ROOTS
    ]
    expected_slots = [
        {"address": item["analysis_address_int"], "symbol": item["symbol"]}
        for item in PICTURE_PROFILE_SLOT_NODES
    ]
    if raw["roots"] != expected_roots or raw["slot_nodes"] != expected_slots:
        raise PictureProfileTraceError("raw exporter roots are not pinned")

    report = {
        "schema_version": 1,
        "analysis_scope": "offline-static-picture-profile-reimplementation-boundary",
        "camera_policy": "physically-disconnected",
        "camera_executed": False,
        "installable": False,
        "camera_test_eligible": False,
        "source": {
            "source_id": "a6400-tw-v2.00",
            "module": "lib/CautionConfig.so",
            "size": CAUTION_CONFIG_SIZE,
            "sha256": CAUTION_CONFIG_SHA256,
        },
        "roots": _expected_roots(),
        "slot_nodes": _expected_slots(),
        "bounded_export_summary": {
            "direct_call_count": len(raw["direct_calls"]),
            "data_reference_count": len(raw["data_references"]),
            "unresolved_indirect_count": len(raw["unresolved_indirect_edges"]),
            "truncated": False,
            "depth_cap": DEPTH_CAP,
            "artifact_sha256": _canonical_digest(raw),
        },
        "direct_calls": raw["direct_calls"],
        "data_references": raw["data_references"],
        "unresolved_indirect_edges": raw["unresolved_indirect_edges"],
        "candidates": {"named_slots": True, "copy_subnode": True, "uxc_reference": False},
        "claims": {key: False for key in _CLAIM_FIELDS},
        "readiness": _READINESS,
        "conclusion": _CONCLUSION,
    }
    return validate_picture_profile_boundary(report)
