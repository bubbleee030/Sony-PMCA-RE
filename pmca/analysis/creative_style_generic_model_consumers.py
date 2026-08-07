"""Fail-closed α6400 generic model-consumer/Creative Style ownership boundary."""
from __future__ import annotations

import copy
import hashlib
import json
import re


MODULES = [
    {
        "module": "lib/viewUnified4.so",
        "size": 2_614_628,
        "sha256": "0fe8f852b0f028ac7d1d55c613726b3949879cf7fdd44074e525ae302a6f2e62",
    },
    {
        "module": "lib/viewUnified7.so",
        "size": 541_024,
        "sha256": "c48cde43ff22d808ad23c42019ddae516fff7da060004eb81ed2bb85012aa538",
    },
]


def _binding(role, symbol, symbol_index, relocation_index, got, plt):
    return {
        "role": role,
        "symbol": symbol,
        "symbol_index": symbol_index,
        "symbol_defined": False,
        "relocation_index": relocation_index,
        "relocation_type": 22,
        "got": got,
        "plt": plt,
    }


BINDINGS = {
    "lib/viewUnified4.so": [
        _binding(
            "set-value-to-model",
            "_ZN18CmnSettingNodeUtil15setValueToModelEv",
            196,
            156,
            0x27E9D4,
            0x58480,
        ),
        _binding(
            "set-cursor-on-item-change",
            "_ZN18CmnSettingNodeUtil21setCursorOnItemChangeEv",
            306,
            247,
            0x27EB40,
            0x58900,
        ),
    ],
    "lib/viewUnified7.so": [
        _binding(
            "set-value-to-model",
            "_ZN18CmnSettingNodeUtil15setValueToModelEv",
            187,
            103,
            0x71CB4,
            0x141F0,
        ),
        _binding(
            "get-process-value",
            "_ZN18CmnSettingNodeUtil10getProcValEv",
            435,
            261,
            0x71F2C,
            0x14994,
        ),
        _binding(
            "set-cursor-on-item-change",
            "_ZN18CmnSettingNodeUtil21setCursorOnItemChangeEv",
            648,
            375,
            0x720F4,
            0x14F4C,
        ),
    ],
}


def _call(role, site, plt, symbol_index):
    return {
        "role": role,
        "site": site,
        "target": plt,
        "symbol_index": symbol_index,
        "transfer": "thumb-blx-direct",
    }


def _sequence(module, start, end, calls):
    return {
        "module": module,
        "owner": {
            "start": start,
            "end": end,
            "source": "arm-exidx",
            "nonzero_dynsym_owner": None,
        },
        "calls": calls,
        "call_order_exact": True,
        "creative_style_data_cell_inside_owner": False,
    }


GENERIC_MODEL_SEQUENCES = [
    _sequence(
        "lib/viewUnified4.so",
        0xCE0A8,
        0xCE244,
        [
            _call("set-cursor-on-item-change", 0xCE0C0, 0x58900, 306),
            _call("set-value-to-model", 0xCE0C8, 0x58480, 196),
        ],
    ),
    _sequence(
        "lib/viewUnified4.so",
        0x17A91C,
        0x17A9CE,
        [
            _call("set-cursor-on-item-change", 0x17A974, 0x58900, 306),
            _call("set-value-to-model", 0x17A97C, 0x58480, 196),
        ],
    ),
    _sequence(
        "lib/viewUnified7.so",
        0x2D284,
        0x2D2AE,
        [
            _call("set-cursor-on-item-change", 0x2D294, 0x14F4C, 648),
            _call("set-value-to-model", 0x2D29C, 0x141F0, 187),
            _call("get-process-value", 0x2D2A4, 0x14994, 435),
        ],
    ),
]


def _publication(module, symbol_index, records):
    return {
        "module": module,
        "symbol": "cmnViewSettingNodeRootCreativeStyle",
        "symbol_index": symbol_index,
        "symbol_defined": False,
        "relocations": records,
    }


def _relocation(index, site, relocation_type, section):
    return {
        "relocation_index": index,
        "site": site,
        "relocation_type": relocation_type,
        "section": section,
        "inside_any_sequence_owner": False,
    }


CREATIVE_STYLE_PUBLICATIONS = [
    _publication(
        "lib/viewUnified4.so",
        1113,
        [
            _relocation(29687, 0x282534, 2, ".data"),
            _relocation(29688, 0x282DBC, 2, ".data"),
            _relocation(29689, 0x282F1C, 2, ".data"),
            _relocation(29690, 0x284D74, 2, ".data"),
            _relocation(29691, 0x284ECC, 2, ".data"),
            _relocation(29692, 0x285034, 2, ".data"),
        ],
    ),
    _publication(
        "lib/viewUnified7.so",
        544,
        [
            _relocation(3858, 0x72434, 21, ".got"),
            _relocation(3859, 0x8056C, 2, ".data"),
        ],
    ),
]

OWNERSHIP_BOUNDARY = {
    "generic_sequences_found": True,
    "creative_root_co_contained": True,
    "creative_root_bound_to_sequence_owner": False,
    "sequence_owner_dynsym_names_resolved": False,
    "publication_cells_are_data_only": True,
    "path_sensitive_indirect_binding_proven": False,
}

CLAIMS = {
    "generic_cursor_to_model_sequence_found": True,
    "creative_style_root_publication_found": True,
    "creative_style_specific_model_sequence_found": False,
    "selected_model_value_storage_found": False,
    "final_model_setter_or_commit_found": False,
    "menu_event_binding_found": False,
    "renderer_binding_found": False,
    "touch_routing_found": False,
    "commit_or_persistence_found": False,
    "creative_look_equivalence_found": False,
    "runtime_execution_proven": False,
}


def canonical_digest(value):
    return hashlib.sha256(
        (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    ).hexdigest()


EXPECTED_EXPORT = {
    "schema_version": 1,
    "analysis_mode": {
        "read_only": True,
        "static_elf_metadata": True,
        "bounded_direct_thumb_calls": True,
        "source_unchanged": True,
    },
    "modules": MODULES,
    "bindings": BINDINGS,
    "generic_model_sequences": GENERIC_MODEL_SEQUENCES,
    "sequence_digest": canonical_digest(GENERIC_MODEL_SEQUENCES),
    "creative_style_publications": CREATIVE_STYLE_PUBLICATIONS,
    "publication_digest": canonical_digest(CREATIVE_STYLE_PUBLICATIONS),
    "ownership_boundary": OWNERSHIP_BOUNDARY,
    "claims": CLAIMS,
    "truncated": False,
}

READINESS = "GENERIC_MODEL_CONSUMER_SEQUENCES_ONLY"
CONCLUSION = (
    "Three exact anonymous owners call generic cursor-change and model-update helpers in order. "
    "Both modules separately publish Creative Style root data, but every publication cell is "
    "outside the executable owners and no typed ownership edge binds them. This is reusable "
    "generic UI/model control, not a proven Creative Style-specific commit path."
)

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FORBIDDEN_KEYS = ("payload", "key_material", "device_write", "usb_write", "flash_image", "package_bytes")


class CreativeStyleGenericModelConsumersError(ValueError):
    """Raised when generic consumer evidence is promoted into Creative Style ownership."""


def _forbid(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if any(token in str(key).casefold() for token in _FORBIDDEN_KEYS):
                raise CreativeStyleGenericModelConsumersError("unsafe or reconstructive evidence field")
            _forbid(child)
    elif isinstance(value, list):
        for child in value:
            _forbid(child)


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise CreativeStyleGenericModelConsumersError(label + " fields differ")
    return value


def normalize_creative_style_generic_model_consumers_export(document):
    _forbid(document)
    export = _exact(document, set(EXPECTED_EXPORT), "generic model-consumer export")
    if export != EXPECTED_EXPORT:
        differing = sorted(key for key in EXPECTED_EXPORT if export.get(key) != EXPECTED_EXPORT[key])
        raise CreativeStyleGenericModelConsumersError("generic model-consumer export differs in: " + ",".join(differing))
    if export["sequence_digest"] != canonical_digest(export["generic_model_sequences"]):
        raise CreativeStyleGenericModelConsumersError("sequence digest differs")
    if export["publication_digest"] != canonical_digest(export["creative_style_publications"]):
        raise CreativeStyleGenericModelConsumersError("publication digest differs")
    owners = [
        (item["module"], item["owner"]["start"], item["owner"]["end"])
        for item in export["generic_model_sequences"]
    ]
    for publication in export["creative_style_publications"]:
        for relocation in publication["relocations"]:
            inside = any(
                module == publication["module"] and start <= relocation["site"] < end
                for module, start, end in owners
            )
            if inside or relocation["inside_any_sequence_owner"] is not False:
                raise CreativeStyleGenericModelConsumersError("Creative Style data was promoted into an owner")
    if export["ownership_boundary"] != OWNERSHIP_BOUNDARY:
        raise CreativeStyleGenericModelConsumersError("ownership boundary differs")
    if any(export["claims"][key] for key in (
        "creative_style_specific_model_sequence_found", "selected_model_value_storage_found",
        "final_model_setter_or_commit_found", "menu_event_binding_found", "renderer_binding_found",
        "touch_routing_found", "commit_or_persistence_found", "creative_look_equivalence_found",
        "runtime_execution_proven",
    )):
        raise CreativeStyleGenericModelConsumersError("co-containment was promoted")
    return copy.deepcopy(export)


def summarize_creative_style_generic_model_consumers_export(document):
    export = normalize_creative_style_generic_model_consumers_export(document)
    return {
        "canonical_export_sha256": canonical_digest(export),
        "module_count": len(export["modules"]),
        "sequence_count": len(export["generic_model_sequences"]),
        "direct_call_count": sum(len(item["calls"]) for item in export["generic_model_sequences"]),
        "creative_publication_count": sum(len(item["relocations"]) for item in export["creative_style_publications"]),
    }


def validate_creative_style_generic_model_consumers_report(document):
    _forbid(document)
    fields = {
        "schema_version", "analysis_scope", "camera_policy", "camera_executed", "installable",
        "camera_test_eligible", "sources", "summary", "sequence_summary", "ownership_boundary",
        "claims", "readiness", "conclusion",
    }
    report = _exact(document, fields, "generic model-consumer report")
    if report["schema_version"] != 1 or report["analysis_scope"] != "offline-static-creative-style-generic-model-consumers" or report["camera_policy"] != "physically-disconnected":
        raise CreativeStyleGenericModelConsumersError("report scope differs")
    if any(report[key] is not False for key in ("camera_executed", "installable", "camera_test_eligible")):
        raise CreativeStyleGenericModelConsumersError("report promotes camera activity")
    expected_summary = summarize_creative_style_generic_model_consumers_export(EXPECTED_EXPORT)
    if report["sources"] != MODULES or report["summary"] != expected_summary or _SHA.fullmatch(report["summary"].get("canonical_export_sha256", "")) is None:
        raise CreativeStyleGenericModelConsumersError("report source or summary differs")
    expected_sequence_summary = {
        "owners": [item["owner"] for item in GENERIC_MODEL_SEQUENCES],
        "sequence_digest": EXPECTED_EXPORT["sequence_digest"],
        "publication_digest": EXPECTED_EXPORT["publication_digest"],
    }
    if report["sequence_summary"] != expected_sequence_summary or report["ownership_boundary"] != OWNERSHIP_BOUNDARY or report["claims"] != CLAIMS:
        raise CreativeStyleGenericModelConsumersError("report evidence differs")
    if report["readiness"] != READINESS or report["conclusion"] != CONCLUSION:
        raise CreativeStyleGenericModelConsumersError("report promotes Creative Style ownership")
    return copy.deepcopy(report)
