"""Fail-closed typed-interface contract for the α6400 Picture Profile vtable."""
from __future__ import annotations

import copy
import hashlib
import json
import re

CAUTION_CONFIG_SHA256 = "bfd1bd7bad0ab3478b894da5dbb51c15464b1bedc4201240ccb61cd743150ef7"
CAUTION_CONFIG_SIZE = 12070800
ANALYSIS_LOAD_BIAS = 0x10000
VTABLE = {
    "elf_address": "0xb01d20", "analysis_address": "0xb11d20",
    "symbol": "_ZTV32CmnViewSettingNodePictureProfile", "elf_symbol_type": "STT_OBJECT",
    "size": 268, "word_count": 67, "address_point": "0xb01d28", "typed_relocation_count": 66,
}
CLONE_SLOT = {
    "relocation_index": 86117, "relocation_type": "R_ARM_ABS32", "slot": 59,
    "offset": 236, "virtual_index": 57, "vtable_offset": "0xec",
    "symbol": "_ZN32CmnViewSettingNodePictureProfile5cloneEv", "elf_thumb_target": "0x7dbbe1",
    "elf_owner": "0x7dbbe0", "analysis_owner": "0x7ebbe0", "function_size": 34,
}
ADJACENT_SLOTS = [
    {"role": "update", "relocation_index": 71417, "relocation_type": "R_ARM_ABS32", "slot": 58, "offset": 232, "virtual_index": 56, "vtable_offset": "0xe8", "symbol": "_ZN18CmnViewSettingNode17updateSettingNodeEv", "elf_thumb_target": "0x7c72b9", "elf_owner": "0x7c72b8", "analysis_owner": "0x7d72b8", "function_size": 20},
    {"role": "init-before", "relocation_index": 72607, "relocation_type": "R_ARM_ABS32", "slot": 60, "offset": 240, "virtual_index": 58, "vtable_offset": "0xf0", "symbol": "_ZN18CmnViewSettingNode14userBeforeInitEv", "elf_thumb_target": "0x7c72eb", "elf_owner": "0x7c72ea", "analysis_owner": "0x7d72ea", "function_size": 8},
    {"role": "init-after", "relocation_index": 73796, "relocation_type": "R_ARM_ABS32", "slot": 61, "offset": 244, "virtual_index": 59, "vtable_offset": "0xf4", "symbol": "_ZN18CmnViewSettingNode13userAfterInitEv", "elf_thumb_target": "0x7c72f3", "elf_owner": "0x7c72f2", "analysis_owner": "0x7d72f2", "function_size": 8},
    {"role": "get-sub-node", "relocation_index": 74985, "relocation_type": "R_ARM_ABS32", "slot": 62, "offset": 248, "virtual_index": 60, "vtable_offset": "0xf8", "symbol": "_ZN18CmnViewSettingNode10getSubNodeEPPPS_Ri", "elf_thumb_target": "0x7c72cd", "elf_owner": "0x7c72cc", "analysis_owner": "0x7d72cc", "function_size": 30},
]
INHERITED_SLOT_GROUPS = {
    "selected-item": [
        {"slot": 12, "symbol": "_ZN18CmnViewSettingNode15getSelectedItemEPPS_"},
        {"slot": 13, "symbol": "_ZN18CmnViewSettingNode20getIndexSelectedItemERi"},
        {"slot": 14, "symbol": "_ZN18CmnViewSettingNode20getSRNumSelectedItemERi"},
        {"slot": 39, "symbol": "_ZN18CmnViewSettingNode14isItemSelectedEv"},
        {"slot": 40, "symbol": "_ZN18CmnViewSettingNode21isItemSelectedByIndexEi"},
        {"slot": 41, "symbol": "_ZN18CmnViewSettingNode21isItemSelectedBySRNumEi"},
    ],
    "state": [
        {"slot": 21, "symbol": "_ZN18CmnViewSettingNode8getStateERi"},
        {"slot": 22, "symbol": "_ZN18CmnViewSettingNode15getStateByIndexEiRi"},
        {"slot": 23, "symbol": "_ZN18CmnViewSettingNode15getStateBySRNumEiRi"},
    ],
    "set-selected": [
        {"slot": 48, "symbol": "_ZN18CmnViewSettingNode15setItemSelectedEv"},
        {"slot": 49, "symbol": "_ZN18CmnViewSettingNode22setItemSelectedByIndexEi"},
        {"slot": 50, "symbol": "_ZN18CmnViewSettingNode22setItemSelectedBySRNumEi"},
        {"slot": 51, "symbol": "_ZN18CmnViewSettingNode26setItemSelectedByDiffSRNumEi"},
        {"slot": 63, "symbol": "_ZN18CmnViewSettingNode17setItemUnselectedEv"},
    ],
}
VTABLE_GLOB_DAT = {
    "relocation_index": 100975, "got_address": "0xb17c40", "relocation_type": "R_ARM_GLOB_DAT",
    "symbol": "_ZTV32CmnViewSettingNodePictureProfile",
}
CONSTRUCTOR_ALIASES = [
    {"role": "constructor", "symbols": ["_ZN32CmnViewSettingNodePictureProfileC1EPP18CmnViewSettingNodeiPK24CmnViewSettingProperties", "_ZN32CmnViewSettingNodePictureProfileC2EPP18CmnViewSettingNodeiPK24CmnViewSettingProperties"], "elf_thumb_target": "0x7dbcbd", "elf_owner": "0x7dbcbc", "analysis_owner": "0x7ebcbc", "function_size": 52},
    {"role": "copy-constructor", "symbols": ["_ZN32CmnViewSettingNodePictureProfileC1ERKS_", "_ZN32CmnViewSettingNodePictureProfileC2ERKS_"], "elf_thumb_target": "0x7dbbbd", "elf_owner": "0x7dbbbc", "analysis_owner": "0x7ebbbc", "function_size": 36},
]
PRIOR_ARTIFACTS = {
    "clone_boundary_sha256": "d95b525159e1ad291eab0a6b05dfede9cfedb49398ceb811db512ae8102690da",
    "handoff_sha256": "c1c792b2aa28bbae168209329df4c0ce46dc5834f0d024f8d21cebb364aa74ff",
}
CLAIMS = {
    "picture_profile_typed_interface_found": True,
    "selected_slot_found": False,
    "persistence_found": False,
    "processing_found": False,
    "output_found": False,
    "interface_reuse_found": False,
    "state_reuse_found": False,
    "first_class_creative_look": False,
}
READINESS = "TYPED_INTERFACE_METADATA_ONLY"
CONCLUSION = (
    "The exact CmnViewSettingNodePictureProfile vtable, clone slot, adjacent lifecycle "
    "slots, inherited generic selection/state slots, vtable GLOB_DAT relocation, and "
    "constructor aliases are typed ELF metadata. No link from inherited generic methods "
    "to PP1-PP9, reusable Creative Look state, persistence, processing, output, or a "
    "first-class Creative Look interface is established."
)
REPORT_ARTIFACT_SHA256 = "e8772c3112c8eea444ab5778dfa8cd7b39bed1592b39dbe920e914f831368f59"
_HEX = re.compile(r"0x[0-9a-f]+")
_SHA = re.compile(r"[0-9a-f]{64}")
_FORBIDDEN = ("raw", "byte", "disassembly", "key", "device", "write")


class PictureProfileVtableInterfaceError(ValueError):
    """Raised when typed Picture Profile interface evidence is incomplete or unsafe."""


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise PictureProfileVtableInterfaceError(label + " has invalid fields")
    return value


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _coordinate_pair(record, label):
    for field in ("elf_thumb_target", "elf_owner", "analysis_owner"):
        if not isinstance(record.get(field), str) or _HEX.fullmatch(record[field]) is None:
            raise PictureProfileVtableInterfaceError(label + " has invalid coordinate fields")
    if int(record["elf_thumb_target"], 16) != int(record["elf_owner"], 16) + 1 or int(record["analysis_owner"], 16) != int(record["elf_owner"], 16) + ANALYSIS_LOAD_BIAS:
        raise PictureProfileVtableInterfaceError(label + " coordinate mapping differs")


def _forbid(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if any(part in str(key).lower() for part in _FORBIDDEN):
                raise PictureProfileVtableInterfaceError("forbidden raw or device material")
            _forbid(item)
    elif isinstance(value, list):
        for item in value:
            _forbid(item)


def normalize_picture_profile_vtable_interface_export(document):
    """Validate the isolated static typed-interface export and return its summary."""
    _forbid(document)
    _exact(document, {
        "program", "sha256", "file_size", "analysis_mode", "program_changed", "analysis_load_bias", "vtable", "clone_slot",
        "adjacent_slots", "inherited_slot_groups", "vtable_glob_dat", "constructor_aliases", "prior_artifacts",
        "pp1_pp9_bindings", "selected_slot_paths", "persistence_paths", "processing_paths", "output_paths", "truncated",
    }, "raw export")
    if (document["program"], document["sha256"], document["file_size"]) != ("CautionConfig.so", CAUTION_CONFIG_SHA256, CAUTION_CONFIG_SIZE):
        raise PictureProfileVtableInterfaceError("source identity is not pinned")
    if document["analysis_mode"] != {"read_only": True, "static_elf_metadata": True} or document["program_changed"] is not False or document["truncated"] is not False:
        raise PictureProfileVtableInterfaceError("source mode or changed state is unsafe")
    if document["analysis_load_bias"] != "0x10000":
        raise PictureProfileVtableInterfaceError("analysis coordinate bias is not pinned")
    if document["vtable"] != VTABLE or document["clone_slot"] != CLONE_SLOT or document["adjacent_slots"] != ADJACENT_SLOTS:
        raise PictureProfileVtableInterfaceError("vtable or clone lifecycle metadata is not exact")
    _coordinate_pair(document["clone_slot"], "clone slot")
    for item in document["adjacent_slots"]:
        _coordinate_pair(item, "adjacent slot")
    if document["inherited_slot_groups"] != INHERITED_SLOT_GROUPS or document["vtable_glob_dat"] != VTABLE_GLOB_DAT:
        raise PictureProfileVtableInterfaceError("inherited interface metadata is not exact")
    if document["constructor_aliases"] != CONSTRUCTOR_ALIASES or document["prior_artifacts"] != PRIOR_ARTIFACTS:
        raise PictureProfileVtableInterfaceError("constructor aliases or prior evidence is not pinned")
    for item in document["constructor_aliases"]:
        _coordinate_pair(item, "constructor alias")
    if any(document[field] for field in ("pp1_pp9_bindings", "selected_slot_paths", "persistence_paths", "processing_paths", "output_paths")):
        raise PictureProfileVtableInterfaceError("unverified profile or behavior path was supplied")
    return {
        "artifact_sha256": _digest(document), "typed_vtable_relocation_count": 66,
        "claims": copy.deepcopy(CLAIMS), "readiness": READINESS,
    }


def validate_picture_profile_vtable_interface_report(document):
    _exact(document, {"schema_version", "analysis_scope", "camera_policy", "camera_executed", "installable", "camera_test_eligible", "summary", "claims", "readiness", "conclusion"}, "report")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1 or document["analysis_scope"] != "offline-static-picture-profile-typed-vtable-interface" or document["camera_policy"] != "physically-disconnected":
        raise PictureProfileVtableInterfaceError("report scope or policy is unsafe")
    if any(document[field] is not False for field in ("camera_executed", "installable", "camera_test_eligible")):
        raise PictureProfileVtableInterfaceError("report promotes execution or installation")
    _exact(document["summary"], {"artifact_sha256", "typed_vtable_relocation_count"}, "report summary")
    if _SHA.fullmatch(document["summary"]["artifact_sha256"] or "") is None or document["summary"]["typed_vtable_relocation_count"] != 66:
        raise PictureProfileVtableInterfaceError("report summary is invalid")
    if REPORT_ARTIFACT_SHA256 and document["summary"]["artifact_sha256"] != REPORT_ARTIFACT_SHA256:
        raise PictureProfileVtableInterfaceError("report digest is forged")
    if document["claims"] != CLAIMS or document["readiness"] != READINESS or document["conclusion"] != CONCLUSION:
        raise PictureProfileVtableInterfaceError("report promotes unsupported behavior")
    return copy.deepcopy(document)
