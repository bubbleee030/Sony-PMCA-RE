"""Fail-closed static evidence contract for the α6400 Creative Style definition."""
from __future__ import annotations

import copy
import hashlib
import json
import re


CAUTION_CONFIG_SHA256 = "bfd1bd7bad0ab3478b894da5dbb51c15464b1bedc4201240ccb61cd743150ef7"
CAUTION_CONFIG_SIZE = 12070800
ANALYSIS_LOAD_BIAS = 0x10000
ROOT = {
    "symbol_index": 31507, "symbol": "cmnViewSettingNodeRootCreativeStyle",
    "elf_address": "0xc5ae38", "analysis_address": "0xc6ae38", "size": 40,
    "section": ".bss", "elf_symbol_type": "STT_OBJECT",
}
PROPERTY_ROOT = {
    "symbol_index": 59076, "symbol": "cmnViewSettingPropertiesCreativeStyleRoot",
    "elf_address": "0xc10a38", "analysis_address": "0xc20a38", "size": 8,
    "section": ".bss", "elf_symbol_type": "STT_OBJECT",
}
PROPERTY_LIST = {
    "symbol_index": 64985, "symbol": "cmnViewSettingPropertyListCreativeStyleRoot",
    "elf_address": "0xa54050", "analysis_address": "0xa64050", "size": 96,
    "section": ".rodata", "elf_symbol_type": "STT_OBJECT",
}
PUBLICATION = {
    "relocation_index": 87605, "relocation_type": "R_ARM_ABS32", "site": "0xb8a3bc",
    "container_symbol_index": 11778, "container_symbol": "cmnViewSettingNodesRootDefault",
    "container_address": "0xb8a380", "container_size": 1660, "container_section": ".data",
    "object_offset": "0x3c", "target_symbol_index": 31507,
}
GOT_BINDINGS = [
    {"role": "root", "relocation_index": 87604, "relocation_type": "R_ARM_GLOB_DAT", "site": "0xb1111c", "symbol_index": 31507},
    {"role": "properties", "relocation_index": 170252, "relocation_type": "R_ARM_GLOB_DAT", "site": "0xb3a864", "symbol_index": 59076},
    {"role": "property-list", "relocation_index": 175923, "relocation_type": "R_ARM_GLOB_DAT", "site": "0xb3d498", "symbol_index": 64985},
]
CONSTRUCTOR_ALIASES = {
    "symbols": [
        "_ZN31CmnViewSettingNodeCreativeStyleC1EPP18CmnViewSettingNodeiPK24CmnViewSettingProperties",
        "_ZN31CmnViewSettingNodeCreativeStyleC2EPP18CmnViewSettingNodeiPK24CmnViewSettingProperties",
    ],
    "elf_thumb_target": "0x7dba41", "elf_owner": "0x7dba40", "analysis_owner": "0x7eba40", "function_size": 52,
}
SELECTOR = {
    "symbol_index": 60476, "symbol": "_ZN31CmnViewSettingNodeCreativeStyle11_getSubNodeEv",
    "elf_thumb_target": "0x7db959", "elf_owner": "0x7db958", "analysis_owner": "0x7eb958", "function_size": 232,
}
PLT_BINDINGS = [
    {"role": "selector", "relocation_index": 2241, "relocation_type": "R_ARM_JUMP_SLOT", "got_address": "0xb0e4d8", "plt_address": "0x7b7eac", "symbol_index": 60476, "decoded_stub": True},
    {"role": "constructor-c1", "relocation_index": 4479, "relocation_type": "R_ARM_JUMP_SLOT", "got_address": "0xb107d0", "plt_address": "0x7be79c", "symbol_index": 34548, "decoded_stub": True},
]
VTABLE = {
    "symbol_index": 63566, "symbol": "_ZTV31CmnViewSettingNodeCreativeStyle",
    "elf_address": "0xac8900", "analysis_address": "0xad8900", "size": 268,
    "section": ".data.rel.ro", "elf_symbol_type": "STT_OBJECT", "address_point": "0xac8908", "word_count": 67, "typed_relocation_count": 66,
    "glob_dat": {"relocation_index": 134297, "relocation_type": "R_ARM_GLOB_DAT", "got_address": "0xb28a90"},
}
PARITY_SLOTS = {
    "selected": [12, 13, 14, 39, 40, 41],
    "state": [21, 22, 23],
    "set-selected": [48, 49, 50, 51, 63],
    "lifecycle": [58, 60, 61, 62],
    "clone": [59],
}
EXPECTED_SLOT_RECORDS = {
    12: (15901, "_ZN18CmnViewSettingNode15getSelectedItemEPPS_", 0x7C6BD3, 68),
    13: (17090, "_ZN18CmnViewSettingNode20getIndexSelectedItemERi", 0x7C6C17, 20),
    14: (18279, "_ZN18CmnViewSettingNode20getSRNumSelectedItemERi", 0x7C6C2B, 36),
    21: (26602, "_ZN18CmnViewSettingNode8getStateERi", 0x7C6D53, 12),
    22: (27791, "_ZN18CmnViewSettingNode15getStateByIndexEiRi", 0x7C6D5F, 36),
    23: (28980, "_ZN18CmnViewSettingNode15getStateBySRNumEiRi", 0x7C6D83, 36),
    39: (48004, "_ZN18CmnViewSettingNode14isItemSelectedEv", 0x7C6F27, 34),
    40: (49193, "_ZN18CmnViewSettingNode21isItemSelectedByIndexEi", 0x7C6F49, 34),
    41: (50382, "_ZN18CmnViewSettingNode21isItemSelectedBySRNumEi", 0x7C6F6B, 34),
    48: (58705, "_ZN18CmnViewSettingNode15setItemSelectedEv", 0x7C705B, 128),
    49: (59894, "_ZN18CmnViewSettingNode22setItemSelectedByIndexEi", 0x7C70DB, 34),
    50: (61083, "_ZN18CmnViewSettingNode22setItemSelectedBySRNumEi", 0x7C70FD, 34),
    51: (62272, "_ZN18CmnViewSettingNode26setItemSelectedByDiffSRNumEi", 0x7C711F, 62),
    58: (70595, "_ZN18CmnViewSettingNode17updateSettingNodeEv", 0x7C72B9, 20),
    59: (81185, "_ZN31CmnViewSettingNodeCreativeStyle5cloneEv", 0x7DB935, 34),
    60: (71785, "_ZN18CmnViewSettingNode14userBeforeInitEv", 0x7C72EB, 8),
    61: (72974, "_ZN18CmnViewSettingNode13userAfterInitEv", 0x7C72F3, 8),
    62: (74163, "_ZN18CmnViewSettingNode10getSubNodeEPPPS_Ri", 0x7C72CD, 30),
    63: (75352, "_ZN18CmnViewSettingNode17setItemUnselectedEv", 0x7C72FB, 50),
}
PRIOR_ARTIFACTS = {
    "picture_profile_vtable_interface_sha256": "e8772c3112c8eea444ab5778dfa8cd7b39bed1592b39dbe920e914f831368f59",
    "picture_profile_generic_consumers_sha256": "b068bf450d0c27689fa44c4f3d1698dcebb60aab5771584752385d62b08340bf",
    "picture_profile_initializer_registration_sha256": "585da9e3b3da99af9baeea003e749b75345b53e0eb322182e601ac7246eb986e",
}
INITIALIZER = {"array_index": 3, "array_site": "0xaa629c", "elf_thumb_target": "0x8251f9", "elf_owner": "0x8251f8", "analysis_owner": "0x8351f8"}
NEGATIVE_SCAN = {
    "name_fragments": ["creativestyle"],
    "verbs": ["save", "load", "write", "read", "store", "restore", "persist", "serialize"],
    "matches": [],
}
CLAIMS = {
    "creative_style_definition_found": True,
    "publication_data_graph_found": True,
    "typed_class_interface_found": True,
    "broad_loader_registration_found": True,
    "root_constructor_binding_found": False,
    "selected_state_found": False,
    "persistence_found": False,
    "processing_found": False,
    "output_found": False,
    "first_class_creative_look": False,
}
READINESS = "STATIC_DEFINITION_AND_REGISTRATION_ONLY"
CONCLUSION = (
    "The Creative Style root, properties, property list, default-root publication relocation, "
    "typed class interface, and broad initializer membership are exact static ELF metadata. "
    "They do not establish root constructor invocation, selected state, persistence, processing, "
    "output, or first-class Creative Look behavior."
)
REPORT_ARTIFACT_SHA256 = "783507c05654f172a03966c259635677430c78801c9a067f122e21752dda0d16"
_HEX = re.compile(r"0x[0-9a-f]+\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FORBIDDEN = ("raw", "byte", "disassembly", "instruction", "key", "device", "usb", "flash", "package")


class CreativeStyleDefinitionRegistrationError(ValueError):
    """Raised when bounded Creative Style evidence is incomplete or promoted."""


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise CreativeStyleDefinitionRegistrationError(label + " fields are invalid")
    return value


def _forbid(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if any(token in str(key).casefold() for token in _FORBIDDEN):
                raise CreativeStyleDefinitionRegistrationError("unsafe or reconstructive evidence field")
            _forbid(item)
    elif isinstance(value, list):
        for item in value:
            _forbid(item)


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _coordinate(record, label):
    for field in ("elf_thumb_target", "elf_owner", "analysis_owner"):
        if not isinstance(record.get(field), str) or _HEX.fullmatch(record[field]) is None:
            raise CreativeStyleDefinitionRegistrationError(label + " coordinate is invalid")
    if int(record["elf_thumb_target"], 16) != int(record["elf_owner"], 16) + 1 or int(record["analysis_owner"], 16) != int(record["elf_owner"], 16) + ANALYSIS_LOAD_BIAS:
        raise CreativeStyleDefinitionRegistrationError(label + " coordinate mapping differs")


def _slot_record(slot, index, symbol, thumb, size):
    return {"slot": slot, "relocation_index": index, "relocation_type": "R_ARM_ABS32", "symbol": symbol,
            "elf_thumb_target": hex(thumb), "elf_owner": hex(thumb & ~1), "analysis_owner": hex((thumb & ~1) + ANALYSIS_LOAD_BIAS), "function_size": size}


def _expected_slots():
    return {group: [_slot_record(slot, *EXPECTED_SLOT_RECORDS[slot]) for slot in slots] for group, slots in PARITY_SLOTS.items()}


EXPECTED_RAW_EXPORT = {
    "program": "CautionConfig.so", "sha256": CAUTION_CONFIG_SHA256, "file_size": CAUTION_CONFIG_SIZE,
    "analysis_mode": {"read_only": True, "static_elf_metadata": True, "plt_stub_decode": True}, "program_changed": False,
    "analysis_load_bias": "0x10000", "root": ROOT, "property_root": PROPERTY_ROOT, "property_list": PROPERTY_LIST,
    "publication": PUBLICATION, "got_bindings": GOT_BINDINGS, "constructor_aliases": CONSTRUCTOR_ALIASES,
    "selector": SELECTOR, "plt_bindings": PLT_BINDINGS, "vtable": VTABLE, "structural_parity_slots": _expected_slots(),
    "prior_artifacts": PRIOR_ARTIFACTS, "initializer": INITIALIZER, "negative_symbol_scan": NEGATIVE_SCAN,
    "root_constructor_bindings": [], "selected_state_paths": [], "persistence_paths": [], "processing_paths": [], "output_paths": [],
    "claims": CLAIMS, "truncated": False,
}


def normalize_creative_style_definition_registration_export(document):
    """Validate the exact bounded static Creative Style definition export."""
    _forbid(document)
    _exact(document, set(EXPECTED_RAW_EXPORT), "export")
    if document != EXPECTED_RAW_EXPORT:
        raise CreativeStyleDefinitionRegistrationError("static Creative Style evidence differs from the pinned contract")
    _coordinate(document["constructor_aliases"], "constructor aliases")
    _coordinate(document["selector"], "selector")
    _coordinate(document["initializer"], "initializer")
    for group in document["structural_parity_slots"].values():
        for slot in group:
            _coordinate(slot, "vtable slot")
    return {"artifact_sha256": _digest(document), "publication_relocation_index": 87605,
            "vtable_typed_relocation_count": 66, "claims": copy.deepcopy(CLAIMS), "readiness": READINESS}


def validate_creative_style_definition_registration_report(document):
    _forbid(document)
    _exact(document, {"schema_version", "analysis_scope", "camera_policy", "camera_executed", "installable", "camera_test_eligible", "summary", "claims", "readiness", "conclusion"}, "report")
    if document["schema_version"] != 1 or document["analysis_scope"] != "offline-static-creative-style-definition-registration" or document["camera_policy"] != "physically-disconnected":
        raise CreativeStyleDefinitionRegistrationError("report scope differs")
    if any(document[field] is not False for field in ("camera_executed", "installable", "camera_test_eligible")):
        raise CreativeStyleDefinitionRegistrationError("report promotes camera activity")
    _exact(document["summary"], {"artifact_sha256", "publication_relocation_index", "vtable_typed_relocation_count"}, "report summary")
    if _SHA.fullmatch(document["summary"]["artifact_sha256"] or "") is None or document["summary"]["publication_relocation_index"] != 87605 or document["summary"]["vtable_typed_relocation_count"] != 66:
        raise CreativeStyleDefinitionRegistrationError("report summary differs")
    if REPORT_ARTIFACT_SHA256 and document["summary"]["artifact_sha256"] != REPORT_ARTIFACT_SHA256:
        raise CreativeStyleDefinitionRegistrationError("report digest differs")
    if document["claims"] != CLAIMS or document["readiness"] != READINESS or document["conclusion"] != CONCLUSION:
        raise CreativeStyleDefinitionRegistrationError("report promotes unsupported Creative Style behavior")
    return copy.deepcopy(document)
