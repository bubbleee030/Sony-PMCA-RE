"""Fail-closed α6400 Creative Style default-root registry evidence contract."""

from __future__ import annotations

import copy
import hashlib
import json
import re


FIRMWARE_REGULAR_FILE_COUNT = 799
FIRMWARE_ELF_FILE_COUNT = 324
FIRMWARE_SHARED_OBJECT_COUNT = 150
FIRMWARE_INVENTORY_SHA256 = "52ec5e8baf523878a417e3a61f9f16484634a9075d1c6afca2ca8c25940d827c"
REGISTRY_ENTRIES_SHA256 = "d728a6ad8d3a4a4bf7b07c47ee5249a131c3a73660ef116802be41cd5b77db42"
CONSUMER_RELOCATIONS_SHA256 = "29af26119aca899a9b45a6950be5dd5f3bee7181337caf13eb8c3c6865928c82"
CAUTION_CONFIG = {"module": "lib/CautionConfig.so", "size": 12_070_800, "sha256": "bfd1bd7bad0ab3478b894da5dbb51c15464b1bedc4201240ccb61cd743150ef7"}
VIEW_UNIFIED2 = {"module": "lib/viewUnified2.so", "size": 11_530_552, "sha256": "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2"}
VIEW_UNIFIED4 = {"module": "lib/viewUnified4.so", "size": 2_614_628, "sha256": "0fe8f852b0f028ac7d1d55c613726b3949879cf7fdd44074e525ae302a6f2e62"}
VIEW_UNIFIED7 = {"module": "lib/viewUnified7.so", "size": 541_024, "sha256": "c48cde43ff22d808ad23c42019ddae516fff7da060004eb81ed2bb85012aa538"}
MODULES = (CAUTION_CONFIG, VIEW_UNIFIED2, VIEW_UNIFIED4, VIEW_UNIFIED7)
REGISTRY = {
    "dynsym_index": 11778, "symbol": "cmnViewSettingNodesRootDefault", "elf_address": "0xb8a380",
    "size": 1660, "section": ".data", "symbol_type": "STT_OBJECT", "slot_count": 415,
}
CREATIVE_STYLE = {
    "slot": 15, "offset": "0x3c", "relocation_index": 87605, "site": "0xb8a3bc",
    "target_dynsym_index": 31507, "target_symbol": "cmnViewSettingNodeRootCreativeStyle",
}
PRIOR_ARTIFACTS = {
    "creative_style_definition_registration_sha256": "783507c05654f172a03966c259635677430c78801c9a067f122e21752dda0d16",
    "creative_style_root_consumers_sha256": "30982e2edb295595e6ec3d3c5bed05d6a6352055491014672f89b3a4c33b023c",
}
CLAIMS = {
    "typed_default_registry_found": True,
    "creative_style_registry_slot_found": True,
    "cross_module_data_publication_found": True,
    "indirect_data_consumers_found": False,
    "selected_state_found": False,
    "persistence_found": False,
    "creative_look_found": False,
}
READINESS = "STATIC_TYPED_REGISTRY_AND_DATA_PUBLICATION_ONLY"
CONCLUSION = (
    "The 415-entry typed default-root registry and its Creative Style slot are exact static ELF metadata. "
    "The three consumer modules publish imported data cells, but no provenance-backed indirect data consumer, "
    "selection state, persistence, or Creative Look behavior is established."
)
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_HEX = re.compile(r"0x[0-9a-f]+\Z")
_FORBIDDEN = {"raw", "bytes", "disassembly", "instruction", "key", "device", "usb", "write", "flash", "package", "install", "camera", "arbitrary_pointer_scan", "direct_caller"}


class CreativeStyleRegistryConsumersError(ValueError):
    """Raised when static registry evidence is incomplete or promoted."""


def _forbid(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or key.casefold().replace("-", "_") in _FORBIDDEN:
                raise CreativeStyleRegistryConsumersError("unsafe or reconstructive field")
            _forbid(child)
    elif isinstance(value, list):
        for child in value:
            _forbid(child)


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise CreativeStyleRegistryConsumersError(label + " fields are not exact")
    return value


def _digest(value):
    return hashlib.sha256((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")).hexdigest()


def normalize_creative_style_registry_consumers_export(document):
    """Accept only a complete, source-derived registry and publication inventory."""

    _forbid(document)
    raw = _exact(document, {
        "schema_version", "analysis_mode", "firmware_inventory", "modules", "registry", "registry_entries",
        "registry_entries_sha256", "creative_style", "reference_modules", "consumer_relocations",
        "data_cell_symbol_coverage", "plt_reference_modules", "prior_artifacts", "claims", "truncated",
    }, "registry export")
    if raw["schema_version"] != 1 or raw["analysis_mode"] != {"read_only": True, "static_elf_metadata": True, "source_unchanged": True} or raw["truncated"] is not False:
        raise CreativeStyleRegistryConsumersError("analysis mode is not complete and read-only")
    if raw["firmware_inventory"] != {"regular_file_count": FIRMWARE_REGULAR_FILE_COUNT, "elf_file_count": FIRMWARE_ELF_FILE_COUNT, "shared_object_count": FIRMWARE_SHARED_OBJECT_COUNT, "canonical_inventory_sha256": FIRMWARE_INVENTORY_SHA256}:
        raise CreativeStyleRegistryConsumersError("firmware inventory differs")
    if raw["modules"] != list(MODULES) or raw["registry"] != REGISTRY or raw["creative_style"] != CREATIVE_STYLE or raw["prior_artifacts"] != PRIOR_ARTIFACTS:
        raise CreativeStyleRegistryConsumersError("pinned source or prior evidence differs")
    entries = raw["registry_entries"]
    if not isinstance(entries, list) or len(entries) != 415 or raw["registry_entries_sha256"] != REGISTRY_ENTRIES_SHA256 or raw["registry_entries_sha256"] != _digest(entries):
        raise CreativeStyleRegistryConsumersError("registry entry digest differs")
    expected_sites = list(range(0xB8A380, 0xB8A380 + 1660, 4))
    if [entry.get("site") for entry in entries] != [hex(site) for site in expected_sites]:
        raise CreativeStyleRegistryConsumersError("registry sites do not cover every slot in address order")
    indices, targets = [], set()
    for slot, entry in enumerate(entries):
        _exact(entry, {"slot", "offset", "relocation_index", "site", "relocation_type", "target_dynsym_index", "target_symbol", "target_size", "target_section", "target_symbol_type", "target_binding", "target_defined"}, "registry entry")
        if entry["slot"] != slot or entry["offset"] != hex(slot * 4) or entry["relocation_type"] != "R_ARM_ABS32" or type(entry["relocation_index"]) is not int or entry["relocation_index"] < 0 or type(entry["target_dynsym_index"]) is not int or entry["target_dynsym_index"] < 0 or not entry["target_symbol"].startswith("cmnViewSettingNodeRoot") or entry["target_size"] != 40 or entry["target_symbol_type"] != "STT_OBJECT" or entry["target_binding"] != "STB_GLOBAL" or entry["target_defined"] is not True or not isinstance(entry["target_section"], str) or entry["target_section"] == "SHN_UNDEF":
            raise CreativeStyleRegistryConsumersError("registry entry is not a typed root object")
        indices.append(entry["relocation_index"])
        targets.add(entry["target_dynsym_index"])
    if len(set(indices)) != 415 or len(targets) != 415 or indices == list(range(min(indices), max(indices) + 1)):
        raise CreativeStyleRegistryConsumersError("registry relocation or target uniqueness differs")
    if entries[15] != {"slot": 15, "offset": "0x3c", "relocation_index": 87605, "site": "0xb8a3bc", "relocation_type": "R_ARM_ABS32", "target_dynsym_index": 31507, "target_symbol": "cmnViewSettingNodeRootCreativeStyle", "target_size": 40, "target_section": ".bss", "target_symbol_type": "STT_OBJECT", "target_binding": "STB_GLOBAL", "target_defined": True}:
        raise CreativeStyleRegistryConsumersError("Creative Style registry slot differs")
    if raw["reference_modules"] != [item["module"] for item in MODULES]:
        raise CreativeStyleRegistryConsumersError("global reference module scope differs")
    _validate_consumer_relocations(raw["consumer_relocations"])
    coverage = raw["data_cell_symbol_coverage"]
    expected_coverage = [
        {"module": "lib/viewUnified2.so", "cell_count": 51, "dynamic_exact": [], "dynamic_covering": [], "static_table_present": False, "static_exact": [], "static_covering": []},
        {"module": "lib/viewUnified4.so", "cell_count": 6, "dynamic_exact": [], "dynamic_covering": [], "static_table_present": False, "static_exact": [], "static_covering": []},
        {"module": "lib/viewUnified7.so", "cell_count": 1, "dynamic_exact": [], "dynamic_covering": [], "static_table_present": False, "static_exact": [], "static_covering": []},
    ]
    if coverage != expected_coverage:
        raise CreativeStyleRegistryConsumersError("consumer data-cell symbol coverage differs")
    if raw["plt_reference_modules"] != [] or raw["claims"] != CLAIMS:
        raise CreativeStyleRegistryConsumersError("PLT absence or negative claims were promoted")
    return copy.deepcopy(raw)


def _validate_consumer_relocations(value):
    _exact(value, {"lib/viewUnified2.so", "lib/viewUnified4.so", "lib/viewUnified7.so"}, "consumer relocations")
    if _digest(value) != CONSUMER_RELOCATIONS_SHA256:
        raise CreativeStyleRegistryConsumersError("consumer relocation inventory digest differs")
    expected = {
        "lib/viewUnified2.so": {"registry_dynsym_index": 392, "creative_style_dynsym_index": 901, "registry_glob_dat": {"relocation_index": 130801, "site": "0x948aa0"}, "creative_style_glob_dat": {"relocation_index": 130926, "site": "0x94b674"}, "creative_style_abs32_indices": list(range(130927, 130978))},
        "lib/viewUnified4.so": {"registry_dynsym_index": None, "creative_style_dynsym_index": 1113, "registry_glob_dat": None, "creative_style_glob_dat": None, "creative_style_abs32_indices": list(range(29687, 29693))},
        "lib/viewUnified7.so": {"registry_dynsym_index": None, "creative_style_dynsym_index": 544, "registry_glob_dat": None, "creative_style_glob_dat": {"relocation_index": 3858, "site": "0x72434"}, "creative_style_abs32_indices": [3859]},
    }
    for module, pinned in expected.items():
        item = _exact(value[module], {"registry_dynsym_index", "creative_style_dynsym_index", "registry_glob_dat", "creative_style_glob_dat", "creative_style_abs32"}, "consumer module")
        if item["registry_dynsym_index"] != pinned["registry_dynsym_index"] or item["creative_style_dynsym_index"] != pinned["creative_style_dynsym_index"]:
            raise CreativeStyleRegistryConsumersError("consumer dynamic symbol differs")
        for field in ("registry_glob_dat", "creative_style_glob_dat"):
            record = item[field]
            expected_record = pinned[field]
            if expected_record is None:
                if record is not None:
                    raise CreativeStyleRegistryConsumersError("unexpected consumer GOT publication")
            elif record != {**expected_record, "relocation_type": "R_ARM_GLOB_DAT", "section": ".got"}:
                raise CreativeStyleRegistryConsumersError("consumer GOT publication differs")
        records = item["creative_style_abs32"]
        if not isinstance(records, list) or [record.get("relocation_index") for record in records] != pinned["creative_style_abs32_indices"]:
            raise CreativeStyleRegistryConsumersError("Creative Style data publication index inventory differs")
        if any(set(record) != {"relocation_index", "site", "relocation_type", "section"} or record["relocation_type"] != "R_ARM_ABS32" or record["section"] != ".data" or _HEX.fullmatch(record["site"] or "") is None for record in records):
            raise CreativeStyleRegistryConsumersError("Creative Style data publication record differs")


def summarize_creative_style_registry_consumers_export(document):
    raw = normalize_creative_style_registry_consumers_export(document)
    return {
        "artifact_sha256": _digest(raw), "registry_slot_count": 415, "creative_style_slot": 15,
        "reference_module_count": 4, "consumer_data_cell_count": sum(item["cell_count"] for item in raw["data_cell_symbol_coverage"]),
        "plt_reference_module_count": 0,
    }


def validate_creative_style_registry_consumers_report(document):
    _forbid(document)
    report = _exact(document, {"schema_version", "analysis_scope", "camera_policy", "camera_executed", "installable", "camera_test_eligible", "summary", "claims", "readiness", "conclusion"}, "registry report")
    if report["schema_version"] != 1 or report["analysis_scope"] != "offline-static-creative-style-registry-consumers" or report["camera_policy"] != "physically-disconnected" or any(report[key] is not False for key in ("camera_executed", "installable", "camera_test_eligible")):
        raise CreativeStyleRegistryConsumersError("report scope is unsafe")
    _exact(report["summary"], {"artifact_sha256", "registry_slot_count", "creative_style_slot", "reference_module_count", "consumer_data_cell_count", "plt_reference_module_count"}, "report summary")
    if _SHA.fullmatch(report["summary"]["artifact_sha256"] or "") is None or {key: value for key, value in report["summary"].items() if key != "artifact_sha256"} != {"registry_slot_count": 415, "creative_style_slot": 15, "reference_module_count": 4, "consumer_data_cell_count": 58, "plt_reference_module_count": 0} or report["claims"] != CLAIMS or report["readiness"] != READINESS or report["conclusion"] != CONCLUSION:
        raise CreativeStyleRegistryConsumersError("report promotes unsupported registry consumers")
    return copy.deepcopy(report)
