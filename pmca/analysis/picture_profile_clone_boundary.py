"""Fail-closed metadata contract for the α6400 Picture Profile clone boundary."""
from __future__ import annotations

import copy
import hashlib
import json
import re

CAUTION_CONFIG_SHA256 = "bfd1bd7bad0ab3478b894da5dbb51c15464b1bedc4201240ccb61cd743150ef7"
CAUTION_CONFIG_SIZE = 12070800
CLONE_OWNER = {
    "address": "0x7ebbe0",
    "elf_address": "0x7dbbe0",
    "end": "0x7ebc04",
    "symbol": "CmnViewSettingNodePictureProfile::clone()",
}
CLONE_EDGES = [
    {"site": "0x7ebbe8", "target": "0x7c7528", "edge_type": "direct-call"},
    {"site": "0x7ebbf0", "target": "0x7c3540", "edge_type": "direct-call"},
]
COPY_CONSTRUCTOR_SYMBOL = "_ZN32CmnViewSettingNodePictureProfileC1ERKS_"
COPY_CONSTRUCTOR_VTABLE = "_ZTV32CmnViewSettingNodePictureProfile"
OTHER_IMPORT_SYMBOL = "_Znwj"
COPY_CONSTRUCTOR_RELOCATION = {
    "edge_site": "0x7ebbf0", "plt_address": "0x7c3540", "plt_elf_address": "0x7b3540",
    "relocation_index": 676, "got_address": "0xb0cc64", "intra_entry_offset": 0, "relocation_type": "R_ARM_JUMP_SLOT",
    "symbol": COPY_CONSTRUCTOR_SYMBOL,
}
OTHER_IMPORT = {
    "edge_site": "0x7ebbe8", "plt_address": "0x7c7528", "plt_elf_address": "0x7b7528",
    "relocation_index": 2038, "got_address": "0xb0e1ac", "intra_entry_offset": 0, "relocation_type": "R_ARM_JUMP_SLOT",
    "symbol": OTHER_IMPORT_SYMBOL, "semantic_classification": "allocation",
}
TYPED_VTABLE = {
    "address": "0xb11d20", "elf_address": "0xb01d20", "evidence_type": "dynamic-symbol",
    "symbol": COPY_CONSTRUCTOR_VTABLE, "elf_symbol_type": "STT_OBJECT", "size": 268,
}
CLAIMS = {
    "selected_slot_found": False,
    "persistence_found": False,
    "processing_found": False,
    "output_found": False,
    "interface_reuse_found": False,
    "state_reuse_found": False,
    "first_class_creative_look": False,
}
READINESS = "CLONE_CONSTRUCTOR_AND_TYPED_VTABLE_ONLY"
CONCLUSION = (
    "The Picture Profile clone's two direct calls are bounded, and the second call is "
    "mapped by an exact ELF PLT relocation to the Picture Profile copy constructor. "
    "A typed vtable symbol is metadata only; no selected-slot state, persistence, "
    "processing, output, interface reuse, state reuse, or first-class Creative Look "
    "behavior is established."
)
REPORT_ARTIFACT_SHA256 = "d95b525159e1ad291eab0a6b05dfede9cfedb49398ceb811db512ae8102690da"
_HEX = re.compile(r"0x[0-9a-f]+")
_SHA = re.compile(r"[0-9a-f]{64}")
_FORBIDDEN = ("raw", "byte", "disassembly", "key", "device", "write")


class PictureProfileCloneBoundaryError(ValueError):
    """Raised when clone-boundary evidence is incomplete or unsafe."""


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise PictureProfileCloneBoundaryError(label + " has invalid fields")
    return value


def _hex(value, label):
    if not isinstance(value, str) or _HEX.fullmatch(value) is None:
        raise PictureProfileCloneBoundaryError(label + " is invalid")
    return value


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _forbid(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if any(part in str(key).lower() for part in _FORBIDDEN):
                raise PictureProfileCloneBoundaryError("forbidden raw or device material")
            _forbid(item)
    elif isinstance(value, list):
        for item in value:
            _forbid(item)


def normalize_picture_profile_clone_boundary_export(document):
    """Validate an ignored static metadata export and return its safe summary."""
    _forbid(document)
    fields = {
        "program", "sha256", "file_size", "analysis_mode", "program_changed", "clone_owner", "plt_binding_scope",
        "clone_edges", "copy_constructor_relocation", "other_import", "typed_interface_registrations",
        "property_list_evidence", "selected_slot_paths", "persistence_paths", "processing_paths",
        "output_paths", "truncated",
    }
    _exact(document, fields, "raw export")
    if (document["program"], document["sha256"], document["file_size"]) != ("CautionConfig.so", CAUTION_CONFIG_SHA256, CAUTION_CONFIG_SIZE):
        raise PictureProfileCloneBoundaryError("source identity is not pinned")
    if document["analysis_mode"] != {"read_only": True, "static_elf_metadata": True} or document["program_changed"] is not False or document["truncated"] is not False:
        raise PictureProfileCloneBoundaryError("source mode or changed state is unsafe")
    if document["clone_owner"] != CLONE_OWNER or document["clone_edges"] != CLONE_EDGES:
        raise PictureProfileCloneBoundaryError("clone owner or exact direct edges differ")
    if document["plt_binding_scope"] != "targeted-exact":
        raise PictureProfileCloneBoundaryError("PLT mapping scope is not targeted exact")

    relocation = _exact(document["copy_constructor_relocation"], set(COPY_CONSTRUCTOR_RELOCATION), "copy constructor relocation")
    if relocation != COPY_CONSTRUCTOR_RELOCATION:
        raise PictureProfileCloneBoundaryError("copy constructor relocation is not exact")
    other = _exact(document["other_import"], set(OTHER_IMPORT), "other import")
    if other != OTHER_IMPORT:
        raise PictureProfileCloneBoundaryError("other import metadata is not exact")

    registrations = document["typed_interface_registrations"]
    if not isinstance(registrations, list) or len(registrations) > 16:
        raise PictureProfileCloneBoundaryError("typed interface evidence exceeds bound")
    if registrations != [TYPED_VTABLE]:
        raise PictureProfileCloneBoundaryError("typed vtable evidence is not exact")
    properties = _exact(document["property_list_evidence"], {"classification", "slots"}, "property-list evidence")
    if properties != {"classification": "construction-only", "slots": ["PP%d" % number for number in range(1, 10)]}:
        raise PictureProfileCloneBoundaryError("property lists are not construction-only")
    if any(document[field] for field in ("selected_slot_paths", "persistence_paths", "processing_paths", "output_paths")):
        raise PictureProfileCloneBoundaryError("unverified state or processing path was supplied")
    return {
        "artifact_sha256": _digest(document),
        "clone_edge_count": 2,
        "typed_interface_registration_count": 1,
        "claims": copy.deepcopy(CLAIMS),
        "readiness": READINESS,
    }


def validate_picture_profile_clone_boundary_report(document):
    _exact(document, {"schema_version", "analysis_scope", "camera_policy", "camera_executed", "installable", "camera_test_eligible", "summary", "claims", "readiness", "conclusion"}, "report")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1 or document["analysis_scope"] != "offline-static-picture-profile-clone-boundary" or document["camera_policy"] != "physically-disconnected":
        raise PictureProfileCloneBoundaryError("report scope or policy is unsafe")
    if any(document[field] is not False for field in ("camera_executed", "installable", "camera_test_eligible")):
        raise PictureProfileCloneBoundaryError("report promotes execution or installation")
    _exact(document["summary"], {"artifact_sha256", "clone_edge_count", "typed_interface_registration_count"}, "report summary")
    if _SHA.fullmatch(document["summary"]["artifact_sha256"] or "") is None or document["summary"]["clone_edge_count"] != 2 or type(document["summary"]["typed_interface_registration_count"]) is not int:
        raise PictureProfileCloneBoundaryError("report summary is invalid")
    if REPORT_ARTIFACT_SHA256 and document["summary"]["artifact_sha256"] != REPORT_ARTIFACT_SHA256:
        raise PictureProfileCloneBoundaryError("report digest is forged")
    if document["claims"] != CLAIMS or document["readiness"] != READINESS or document["conclusion"] != CONCLUSION:
        raise PictureProfileCloneBoundaryError("report promotes unsupported behavior")
    return copy.deepcopy(document)
