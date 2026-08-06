"""Fail-closed evidence contract for α6400 Picture Profile generic consumers."""
from __future__ import annotations

import copy
import hashlib
import json
import re

CAUTION_CONFIG_SHA256 = "bfd1bd7bad0ab3478b894da5dbb51c15464b1bedc4201240ccb61cd743150ef7"
CAUTION_CONFIG_SIZE = 12070800
ANALYSIS_LOAD_BIAS = 0x10000
GENERIC_METHODS = [
    {"group": "selected-item", "slot": 12, "relocation_index": 16723, "relocation_type": "R_ARM_ABS32", "symbol": "_ZN18CmnViewSettingNode15getSelectedItemEPPS_", "elf_thumb_target": "0x7c6bd3", "elf_owner": "0x7c6bd2", "analysis_owner": "0x7d6bd2", "function_size": 68},
    {"group": "selected-item", "slot": 13, "relocation_index": 17912, "relocation_type": "R_ARM_ABS32", "symbol": "_ZN18CmnViewSettingNode20getIndexSelectedItemERi", "elf_thumb_target": "0x7c6c17", "elf_owner": "0x7c6c16", "analysis_owner": "0x7d6c16", "function_size": 20},
    {"group": "selected-item", "slot": 14, "relocation_index": 19101, "relocation_type": "R_ARM_ABS32", "symbol": "_ZN18CmnViewSettingNode20getSRNumSelectedItemERi", "elf_thumb_target": "0x7c6c2b", "elf_owner": "0x7c6c2a", "analysis_owner": "0x7d6c2a", "function_size": 36},
    {"group": "state", "slot": 21, "relocation_index": 27424, "relocation_type": "R_ARM_ABS32", "symbol": "_ZN18CmnViewSettingNode8getStateERi", "elf_thumb_target": "0x7c6d53", "elf_owner": "0x7c6d52", "analysis_owner": "0x7d6d52", "function_size": 12},
    {"group": "state", "slot": 22, "relocation_index": 28613, "relocation_type": "R_ARM_ABS32", "symbol": "_ZN18CmnViewSettingNode15getStateByIndexEiRi", "elf_thumb_target": "0x7c6d5f", "elf_owner": "0x7c6d5e", "analysis_owner": "0x7d6d5e", "function_size": 36},
    {"group": "state", "slot": 23, "relocation_index": 29802, "relocation_type": "R_ARM_ABS32", "symbol": "_ZN18CmnViewSettingNode15getStateBySRNumEiRi", "elf_thumb_target": "0x7c6d83", "elf_owner": "0x7c6d82", "analysis_owner": "0x7d6d82", "function_size": 36},
    {"group": "selected-item", "slot": 39, "relocation_index": 48826, "relocation_type": "R_ARM_ABS32", "symbol": "_ZN18CmnViewSettingNode14isItemSelectedEv", "elf_thumb_target": "0x7c6f27", "elf_owner": "0x7c6f26", "analysis_owner": "0x7d6f26", "function_size": 34},
    {"group": "selected-item", "slot": 40, "relocation_index": 50015, "relocation_type": "R_ARM_ABS32", "symbol": "_ZN18CmnViewSettingNode21isItemSelectedByIndexEi", "elf_thumb_target": "0x7c6f49", "elf_owner": "0x7c6f48", "analysis_owner": "0x7d6f48", "function_size": 34},
    {"group": "selected-item", "slot": 41, "relocation_index": 51204, "relocation_type": "R_ARM_ABS32", "symbol": "_ZN18CmnViewSettingNode21isItemSelectedBySRNumEi", "elf_thumb_target": "0x7c6f6b", "elf_owner": "0x7c6f6a", "analysis_owner": "0x7d6f6a", "function_size": 34},
    {"group": "set-selected", "slot": 48, "relocation_index": 59527, "relocation_type": "R_ARM_ABS32", "symbol": "_ZN18CmnViewSettingNode15setItemSelectedEv", "elf_thumb_target": "0x7c705b", "elf_owner": "0x7c705a", "analysis_owner": "0x7d705a", "function_size": 128},
    {"group": "set-selected", "slot": 49, "relocation_index": 60716, "relocation_type": "R_ARM_ABS32", "symbol": "_ZN18CmnViewSettingNode22setItemSelectedByIndexEi", "elf_thumb_target": "0x7c70db", "elf_owner": "0x7c70da", "analysis_owner": "0x7d70da", "function_size": 34},
    {"group": "set-selected", "slot": 50, "relocation_index": 61905, "relocation_type": "R_ARM_ABS32", "symbol": "_ZN18CmnViewSettingNode22setItemSelectedBySRNumEi", "elf_thumb_target": "0x7c70fd", "elf_owner": "0x7c70fc", "analysis_owner": "0x7d70fc", "function_size": 34},
    {"group": "set-selected", "slot": 51, "relocation_index": 63094, "relocation_type": "R_ARM_ABS32", "symbol": "_ZN18CmnViewSettingNode26setItemSelectedByDiffSRNumEi", "elf_thumb_target": "0x7c711f", "elf_owner": "0x7c711e", "analysis_owner": "0x7d711e", "function_size": 62},
    {"group": "set-selected", "slot": 63, "relocation_index": 76174, "relocation_type": "R_ARM_ABS32", "symbol": "_ZN18CmnViewSettingNode17setItemUnselectedEv", "elf_thumb_target": "0x7c72fb", "elf_owner": "0x7c72fa", "analysis_owner": "0x7d72fa", "function_size": 50},
]
CONSTRUCTOR_PLT_BINDINGS = [
    {"role": "copy-construction", "relocation_index": 676, "relocation_type": "R_ARM_JUMP_SLOT", "got_address": "0xb0cc64", "plt_elf_address": "0x7b3540", "plt_analysis_address": "0x7c3540", "symbol": "_ZN32CmnViewSettingNodePictureProfileC1ERKS_"},
    {"role": "construction", "relocation_index": 3601, "relocation_type": "R_ARM_JUMP_SLOT", "got_address": "0xb0fa18", "plt_elf_address": "0x7bbe70", "plt_analysis_address": "0x7cbe70", "symbol": "_ZN32CmnViewSettingNodePictureProfileC1EPP18CmnViewSettingNodeiPK24CmnViewSettingProperties"},
]
PRIOR_ARTIFACTS = {
    "handoff_sha256": "c1c792b2aa28bbae168209329df4c0ce46dc5834f0d024f8d21cebb364aa74ff",
    "clone_boundary_sha256": "d95b525159e1ad291eab0a6b05dfede9cfedb49398ceb811db512ae8102690da",
    "vtable_interface_sha256": "e8772c3112c8eea444ab5778dfa8cd7b39bed1592b39dbe920e914f831368f59",
}
CLAIMS = {
    "generic_base_interface_code_found": True,
    "selected_profile_state_found": False,
    "persistence_found": False,
    "processing_found": False,
    "output_found": False,
    "interface_reuse_found": False,
    "state_reuse_found": False,
    "first_class_creative_look": False,
}
READINESS = "GENERIC_BASE_INTERFACE_ONLY"
CONCLUSION = (
    "The fourteen inherited Picture Profile selection, state, and setter methods are "
    "bounded typed base-class interface code. Their bounded ranges contain no named "
    "direct-control-flow edge, dynamic typed relocation, or PP1-PP9 node/property "
    "reference; construction and copy-construction PLT bindings are distinct. No "
    "selected-profile state, persistence, processing, output, reusable Creative Look "
    "interface, or first-class Creative Look behavior is established."
)
REPORT_ARTIFACT_SHA256 = "b068bf450d0c27689fa44c4f3d1698dcebb60aab5771584752385d62b08340bf"
_HEX = re.compile(r"0x[0-9a-f]+")
_SHA = re.compile(r"[0-9a-f]{64}")
_FORBIDDEN = ("raw", "byte", "disassembly", "key", "device", "write", "usb", "flash", "package")


class PictureProfileGenericConsumerError(ValueError):
    """Raised when generic-consumer evidence is incomplete or unsafe."""


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise PictureProfileGenericConsumerError(label + " has invalid fields")
    return value


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _forbid(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if any(part in str(key).lower() for part in _FORBIDDEN):
                raise PictureProfileGenericConsumerError("forbidden raw or unsafe material")
            _forbid(item)
    elif isinstance(value, list):
        for item in value:
            _forbid(item)


def _coordinate_pair(record, label):
    for field in ("elf_thumb_target", "elf_owner", "analysis_owner"):
        if not isinstance(record.get(field), str) or _HEX.fullmatch(record[field]) is None:
            raise PictureProfileGenericConsumerError(label + " has invalid coordinate fields")
    if int(record["elf_thumb_target"], 16) != int(record["elf_owner"], 16) + 1 or int(record["analysis_owner"], 16) != int(record["elf_owner"], 16) + ANALYSIS_LOAD_BIAS:
        raise PictureProfileGenericConsumerError(label + " coordinate mapping differs")


def normalize_picture_profile_generic_consumer_export(document):
    """Validate a bounded static generic-consumer export and return its safe summary."""
    _forbid(document)
    _exact(document, {
        "program", "sha256", "file_size", "analysis_mode", "program_changed", "analysis_load_bias",
        "generic_methods", "named_direct_control_flow", "dynamic_typed_relocations", "pp1_pp9_references",
        "constructor_plt_bindings", "prior_artifacts", "selected_state_paths", "persistence_paths",
        "processing_paths", "output_paths", "reuse_paths", "truncated",
    }, "raw export")
    if (document["program"], document["sha256"], document["file_size"]) != ("CautionConfig.so", CAUTION_CONFIG_SHA256, CAUTION_CONFIG_SIZE):
        raise PictureProfileGenericConsumerError("source identity is not pinned")
    if document["analysis_mode"] != {"read_only": True, "static_elf_metadata": True, "thumb_control_flow": True} or document["program_changed"] is not False or document["truncated"] is not False or document["analysis_load_bias"] != "0x10000":
        raise PictureProfileGenericConsumerError("source mode or changed state is unsafe")
    if document["generic_methods"] != GENERIC_METHODS:
        raise PictureProfileGenericConsumerError("generic method metadata is not exact")
    for method in document["generic_methods"]:
        _coordinate_pair(method, "generic method")
    if any(document[field] for field in ("named_direct_control_flow", "dynamic_typed_relocations", "pp1_pp9_references", "selected_state_paths", "persistence_paths", "processing_paths", "output_paths", "reuse_paths")):
        raise PictureProfileGenericConsumerError("unverified behavior path or bounded result was supplied")
    if document["constructor_plt_bindings"] != CONSTRUCTOR_PLT_BINDINGS:
        raise PictureProfileGenericConsumerError("construction PLT bindings are not exact")
    if document["prior_artifacts"] != PRIOR_ARTIFACTS:
        raise PictureProfileGenericConsumerError("prior artifact digest linkage differs")
    return {
        "artifact_sha256": _digest(document), "generic_method_count": 14,
        "named_direct_control_flow_count": 0, "dynamic_typed_relocation_count": 0,
        "pp1_pp9_reference_count": 0, "claims": copy.deepcopy(CLAIMS), "readiness": READINESS,
    }


def validate_picture_profile_generic_consumer_report(document):
    _exact(document, {"schema_version", "analysis_scope", "camera_policy", "camera_executed", "installable", "camera_test_eligible", "summary", "claims", "readiness", "conclusion"}, "report")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1 or document["analysis_scope"] != "offline-static-picture-profile-generic-consumers" or document["camera_policy"] != "physically-disconnected":
        raise PictureProfileGenericConsumerError("report scope or policy is unsafe")
    if any(document[field] is not False for field in ("camera_executed", "installable", "camera_test_eligible")):
        raise PictureProfileGenericConsumerError("report promotes execution or installation")
    _exact(document["summary"], {"artifact_sha256", "generic_method_count", "named_direct_control_flow_count", "dynamic_typed_relocation_count", "pp1_pp9_reference_count"}, "report summary")
    summary = document["summary"]
    if _SHA.fullmatch(summary["artifact_sha256"] or "") is None or {key: summary[key] for key in summary if key != "artifact_sha256"} != {"generic_method_count": 14, "named_direct_control_flow_count": 0, "dynamic_typed_relocation_count": 0, "pp1_pp9_reference_count": 0}:
        raise PictureProfileGenericConsumerError("report summary is invalid")
    if REPORT_ARTIFACT_SHA256 and summary["artifact_sha256"] != REPORT_ARTIFACT_SHA256:
        raise PictureProfileGenericConsumerError("report digest is forged")
    if document["claims"] != CLAIMS or document["readiness"] != READINESS or document["conclusion"] != CONCLUSION:
        raise PictureProfileGenericConsumerError("report promotes unsupported behavior")
    return copy.deepcopy(document)
