"""Fail-closed evidence contract for α6400 Picture Profile loader registration."""

from __future__ import annotations

import copy
import hashlib
import json
import re


CAUTION_CONFIG_SHA256 = "bfd1bd7bad0ab3478b894da5dbb51c15464b1bedc4201240ccb61cd743150ef7"
CAUTION_CONFIG_SIZE = 12_070_800
ANALYSIS_LOAD_BIAS = 0x10000
INIT_ARRAY_ADDRESS = "0xaa6290"
INIT_ARRAY_SIZE = 24
INIT_ARRAY_ENTRIES = [
    {"relocation_index": 0, "relocation_address": "0xaa6290", "relocation_type": "R_ARM_RELATIVE", "symbol_index": 0, "thumb_target": "0x7bf5e1", "elf_owner": "0x7bf5e0", "analysis_owner": "0x7cf5e0"},
    {"relocation_index": 1, "relocation_address": "0xaa6294", "relocation_type": "R_ARM_RELATIVE", "symbol_index": 0, "thumb_target": "0x7c7809", "elf_owner": "0x7c7808", "analysis_owner": "0x7d7808"},
    {"relocation_index": 2, "relocation_address": "0xaa6298", "relocation_type": "R_ARM_RELATIVE", "symbol_index": 0, "thumb_target": "0x7c792d", "elf_owner": "0x7c792c", "analysis_owner": "0x7d792c"},
    {"relocation_index": 3, "relocation_address": "0xaa629c", "relocation_type": "R_ARM_RELATIVE", "symbol_index": 0, "thumb_target": "0x8251f9", "elf_owner": "0x8251f8", "analysis_owner": "0x8351f8"},
    {"relocation_index": 4, "relocation_address": "0xaa62a0", "relocation_type": "R_ARM_RELATIVE", "symbol_index": 0, "thumb_target": "0x93aff5", "elf_owner": "0x93aff4", "analysis_owner": "0x94aff4"},
    {"relocation_index": 5, "relocation_address": "0xaa62a4", "relocation_type": "R_ARM_RELATIVE", "symbol_index": 0, "thumb_target": "0x93b075", "elf_owner": "0x93b074", "analysis_owner": "0x94b074"},
]
INITIALIZER_OWNER = {"elf_range_start": "0x8251f8", "elf_range_end": "0x93aff4", "analysis_range_start": "0x8351f8", "analysis_range_end": "0x94aff4", "evidence": "ARM.exidx-function"}
PRIOR_ARTIFACTS = {"handoff_sha256": "c1c792b2aa28bbae168209329df4c0ce46dc5834f0d024f8d21cebb364aa74ff", "generic_consumer_sha256": "b068bf450d0c27689fa44c4f3d1698dcebb60aab5771584752385d62b08340bf"}
ELF_INVENTORY = {"roots": ["lib", "bin", "sabin", "sbin"], "elf_file_count": 184, "canonical_inventory_sha256": "d5f4813f79834917315275747f19ed568d040c0dbbfde9b7f96b8dd8c89ccf50"}
NAME_FRAGMENTS = ["CmnViewSettingNodePictureProfile", "cmnViewSettingNodePictureProfile", "cmnViewSettingPropertyListPictureProfile"]
SYSTEM_DT_NEEDED = ["libpthread.so.0", "libstdc++.so.6", "libm.so.6", "libdl.so.2", "libgcc_s.so.1", "libc.so.6", "librt.so.1"]
CLAIMS = {
    "loader_registration_found": True,
    "selected_profile_state_found": False,
    "ui_dispatch_found": False,
    "persistence_found": False,
    "processing_found": False,
    "output_found": False,
    "first_class_creative_look": False,
}
READINESS = "STATIC_CONSTRUCTION_REGISTRATION_ONLY"
CONCLUSION = (
    "A typed loader registration entry establishes the broad PP1-PP9 construction batch only. "
    "It does not establish selected-profile state, UI dispatch, persistence, image processing, output, "
    "or a Creative Look path."
)
REPORT_ARTIFACT_SHA256 = "585da9e3b3da99af9baeea003e749b75345b53e0eb322182e601ac7246eb986e"
_HEX = re.compile(r"0x[0-9a-f]+\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FORBIDDEN = ("raw", "byte", "disassembly", "instruction", "key", "device", "usb", "write", "flash", "package")


class PictureProfileInitializerRegistrationError(ValueError):
    """Raised when initializer-registration evidence is malformed or over-promoted."""


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise PictureProfileInitializerRegistrationError(label + " has invalid fields")
    return value


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _forbid(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or any(part in key.casefold() for part in _FORBIDDEN):
                raise PictureProfileInitializerRegistrationError("forbidden unsafe or reconstructive material")
            _forbid(child)
    elif isinstance(value, list):
        for child in value:
            _forbid(child)


def _coordinates(record):
    for key in ("relocation_address", "thumb_target", "elf_owner", "analysis_owner"):
        if not isinstance(record[key], str) or _HEX.fullmatch(record[key]) is None:
            raise PictureProfileInitializerRegistrationError("initializer coordinate is invalid")
    if int(record["thumb_target"], 16) != int(record["elf_owner"], 16) + 1:
        raise PictureProfileInitializerRegistrationError("initializer Thumb target is not normalized")
    if int(record["analysis_owner"], 16) != int(record["elf_owner"], 16) + ANALYSIS_LOAD_BIAS:
        raise PictureProfileInitializerRegistrationError("initializer analysis coordinate differs")


def normalize_picture_profile_initializer_registration_export(document):
    """Validate a bounded, read-only loader-registration export."""

    _forbid(document)
    _exact(document, {
        "program", "sha256", "file_size", "analysis_mode", "program_changed", "init_array", "initializer_owner",
        "prior_artifacts", "pp1_pp9_construction", "bounded_elf_inventory", "named_symbol_scan", "dt_needed",
        "selected_state_paths", "ui_dispatch_paths", "persistence_paths", "processing_paths", "output_paths", "truncated",
    }, "raw export")
    if (document["program"], document["sha256"], document["file_size"]) != ("CautionConfig.so", CAUTION_CONFIG_SHA256, CAUTION_CONFIG_SIZE):
        raise PictureProfileInitializerRegistrationError("source identity is not pinned")
    if document["analysis_mode"] != {"read_only": True, "static_elf_metadata": True, "source_unchanged": True} or document["program_changed"] is not False or document["truncated"] is not False:
        raise PictureProfileInitializerRegistrationError("source mode is unsafe or incomplete")
    _exact(document["init_array"], {"elf_address", "size", "entries"}, "init array")
    if document["init_array"]["elf_address"] != INIT_ARRAY_ADDRESS or document["init_array"]["size"] != INIT_ARRAY_SIZE or document["init_array"]["entries"] != INIT_ARRAY_ENTRIES:
        raise PictureProfileInitializerRegistrationError("init-array relocations are not exact")
    for entry in document["init_array"]["entries"]:
        _coordinates(entry)
    if document["initializer_owner"] != INITIALIZER_OWNER:
        raise PictureProfileInitializerRegistrationError("initializer ARM.exidx owner is not exact")
    if document["prior_artifacts"] != PRIOR_ARTIFACTS:
        raise PictureProfileInitializerRegistrationError("prior artifact linkage differs")
    if document["pp1_pp9_construction"] != {"constructor_parameter_reference_count": 18, "analysis_owner": "0x8351f8"}:
        raise PictureProfileInitializerRegistrationError("PP1-PP9 construction linkage differs")
    if document["bounded_elf_inventory"] != ELF_INVENTORY:
        raise PictureProfileInitializerRegistrationError("bounded ELF inventory differs")
    _exact(document["named_symbol_scan"], {"exact_name_fragments", "defining_modules", "direct_named_cross_module_imports", "persistence_verb_symbols"}, "named symbol scan")
    if document["named_symbol_scan"] != {"exact_name_fragments": NAME_FRAGMENTS, "defining_modules": ["lib/CautionConfig.so"], "direct_named_cross_module_imports": [], "persistence_verb_symbols": []}:
        raise PictureProfileInitializerRegistrationError("named cross-module result differs")
    if document["dt_needed"] != SYSTEM_DT_NEEDED:
        raise PictureProfileInitializerRegistrationError("system dependency result differs")
    if any(document[key] for key in ("selected_state_paths", "ui_dispatch_paths", "persistence_paths", "processing_paths", "output_paths")):
        raise PictureProfileInitializerRegistrationError("unverified behavior path was supplied")
    return {
        "artifact_sha256": _digest(document),
        "initializer_entry_count": 6,
        "constructor_parameter_reference_count": 18,
        "bounded_elf_file_count": 184,
        "named_cross_module_import_count": 0,
        "claims": copy.deepcopy(CLAIMS),
        "readiness": READINESS,
    }


def validate_picture_profile_initializer_registration_report(document):
    """Validate the safe committed report for the static registration boundary."""

    _forbid(document)
    _exact(document, {"schema_version", "analysis_scope", "camera_policy", "camera_executed", "installable", "camera_test_eligible", "summary", "claims", "readiness", "conclusion"}, "report")
    if document["schema_version"] != 1 or document["analysis_scope"] != "offline-static-picture-profile-initializer-registration" or document["camera_policy"] != "physically-disconnected":
        raise PictureProfileInitializerRegistrationError("report scope is unsafe")
    if any(document[field] is not False for field in ("camera_executed", "installable", "camera_test_eligible")):
        raise PictureProfileInitializerRegistrationError("report promotes camera activity")
    _exact(document["summary"], {"artifact_sha256", "initializer_entry_count", "constructor_parameter_reference_count", "bounded_elf_file_count", "named_cross_module_import_count"}, "report summary")
    summary = document["summary"]
    if (_SHA.fullmatch(summary["artifact_sha256"] or "") is None or
            {key: summary[key] for key in summary if key != "artifact_sha256"} != {"initializer_entry_count": 6, "constructor_parameter_reference_count": 18, "bounded_elf_file_count": 184, "named_cross_module_import_count": 0}):
        raise PictureProfileInitializerRegistrationError("report summary is invalid")
    if REPORT_ARTIFACT_SHA256 and summary["artifact_sha256"] != REPORT_ARTIFACT_SHA256:
        raise PictureProfileInitializerRegistrationError("report digest is forged")
    if document["claims"] != CLAIMS or document["readiness"] != READINESS or document["conclusion"] != CONCLUSION:
        raise PictureProfileInitializerRegistrationError("report promotes unsupported behavior")
    return copy.deepcopy(document)
