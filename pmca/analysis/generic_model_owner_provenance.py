"""Fail-closed provenance for anonymous α6400 generic model-sequence owners."""
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


def _relative(index, site, target):
    return {
        "relocation_index": index,
        "site": site,
        "relocation_type": 23,
        "section": ".data.rel.ro",
        "target": target,
    }


def _dispatch(owner_start, owner_end, site, target, table_branch, receiver_trace="linear"):
    return {
        "owner": {"start": owner_start, "end": owner_end, "source": "arm-exidx"},
        "site": site,
        "transfer": "thumb-b-wide-direct",
        "target": target,
        "selector_kind": "tbh",
        "table_branch": table_branch,
        "selector_case_value_rederived": True,
        "receiver_r0_preserved_linear_trace": receiver_trace == "linear",
        "receiver_r0_preserved_case_path": True,
        "receiver_type_proven": False,
        "path_sensitive_receiver_proof": False,
    }


VIEW_UNIFIED4 = {
    "module": "lib/viewUnified4.so",
    "targets": [
        {
            "exidx_interval": {"start": 0xCE0A8, "end": 0xCE244},
            "entry": 0xCE0A8,
            "entry_separated_by_prior_return": False,
            "prior_return_site": None,
            "exidx_interval_is_single_function": True,
            "inbound_dispatch": _dispatch(
                0xCF106,
                0xCF394,
                0xCF2CC,
                0xCE0A8,
                {
                    "site": 0xCF112,
                    "table_start": 0xCF116,
                    "entry_width": 2,
                    "selector_index": 0x29,
                    "entry_site": 0xCF168,
                    "entry_value": 0xD9,
                    "landing": 0xCF2C8,
                    "fallthrough_branch_site": 0xCF2CC,
                },
            ),
            "bounded_direct_inbound_count": 1,
            "direct_scan_scope": "canonical-prefixes-across-exidx-ranges",
            "direct_scan_complete": False,
            "direct_inventory_exhaustive": False,
            "utility_member_offset": 0x180,
            "guard_fields": [{"offset": 0x1D6, "width": 1}],
            "sequence_calls": [
                {"role": "set-cursor-on-item-change", "site": 0xCE0C0, "receiver": "entry-r0+0x180"},
                {"role": "set-value-to-model", "site": 0xCE0C8, "receiver": "entry-r0+0x180"},
            ],
            "dispatcher_address_taken": _relative(2812, 0x267930, 0xCF106),
            "entry_address_taken": None,
            "creative_style_pc_literal_reference_count": 0,
        },
        {
            "exidx_interval": {"start": 0x17A91C, "end": 0x17A9CE},
            "entry": 0x17A95A,
            "entry_separated_by_prior_return": True,
            "prior_return_site": 0x17A958,
            "exidx_interval_is_single_function": False,
            "inbound_dispatch": _dispatch(
                0x17AD50,
                0x17ADEC,
                0x17ADD4,
                0x17A95A,
                {
                    "site": 0x17AD58,
                    "table_start": 0x17AD5C,
                    "entry_width": 2,
                    "selector_index": 0x0B,
                    "entry_site": 0x17AD72,
                    "entry_value": 0x3A,
                    "landing": 0x17ADD0,
                    "fallthrough_branch_site": 0x17ADD4,
                },
            ),
            "bounded_direct_inbound_count": 1,
            "direct_scan_scope": "canonical-prefixes-across-exidx-ranges",
            "direct_scan_complete": False,
            "direct_inventory_exhaustive": False,
            "utility_member_offset": 0x188,
            "guard_fields": [{"offset": 0x178, "width": 1}, {"offset": 0x170, "width": 4}],
            "sequence_calls": [
                {"role": "set-cursor-on-item-change", "site": 0x17A974, "receiver": "entry-r0+0x188"},
                {"role": "set-value-to-model", "site": 0x17A97C, "receiver": "entry-r0+0x188"},
            ],
            "dispatcher_address_taken": _relative(8525, 0x273DE0, 0x17AD50),
            "entry_address_taken": None,
            "interval_first_entry_address_taken": _relative(8526, 0x273DE4, 0x17A91C),
            "creative_style_pc_literal_reference_count": 0,
        },
    ],
    "type_context": {
        "classification": "address-taken-data-rel-ro-table-context",
        "concrete_derived_type_found": False,
        "rtti_binding_found": False,
        "constructor_or_factory_found": False,
        "path_sensitive_receiver_type_proven": False,
    },
}


def _binding(role, site, symbol, symbol_index, relocation_index, got, plt):
    return {
        "role": role,
        "site": site,
        "symbol": symbol,
        "symbol_index": symbol_index,
        "symbol_defined": False,
        "relocation_index": relocation_index,
        "relocation_type": 22,
        "got": got,
        "plt": plt,
    }


INITIALIZER_CALLS = [
    _binding("allocate", 0x30894, "_Znwj", 644, 373, 0x720EC, 0x14F34),
    _binding("construct-utility", 0x3089A, "_ZN18CmnSettingNodeUtilC1Ev", 297, 172, 0x71DC8, 0x14540),
    _binding(
        "initialize-setting-node",
        0x308B2,
        "_ZN18CmnViewSettingNode15initSettingNodeEPPS_i",
        484,
        288,
        0x71F98,
        0x14AF8,
    ),
    _binding(
        "initialize-utility-data",
        0x308BE,
        "_ZN18CmnSettingNodeUtil19initSettingNodeDataEP18CmnViewSettingNode",
        133,
        74,
        0x71C40,
        0x14088,
    ),
]


VIEW_UNIFIED7 = {
    "module": "lib/viewUnified7.so",
    "target": {
        "range": {"start": 0x2D284, "end": 0x2D2AE},
        "decoded_instruction_count": 13,
        "utility_member_offset": 0x14C,
        "receiver_sites": [0x2D294, 0x2D29C, 0x2D2A4],
        "receiver_roles": ["set-cursor-on-item-change", "set-value-to-model", "get-process-value"],
        "inbound_dispatch": _dispatch(
            0x31040,
            0x3128C,
            0x31238,
            0x2D284,
            {
                "site": 0x3104C,
                "table_start": 0x31050,
                "entry_width": 2,
                "selector_index": 0x30,
                "entry_site": 0x310B0,
                "entry_value": 0xF2,
                "landing": 0x31234,
                "fallthrough_branch_site": 0x31238,
            },
            receiver_trace="bounded-case-path",
        ),
        "dispatcher_address_taken": _relative(850, 0x6FEF0, 0x31040),
        "static_inbound_inventory": {
            "bounded_direct_transfer_count": 1,
            "canonical_direct_scan_complete": False,
            "direct_inventory_exhaustive": False,
            "mapped_pointer_word_count": 0,
            "relocation_reference_count": 0,
            "dynsym_owner_count": 0,
            "address_taken_table_count": 0,
        },
        "creative_style_pc_literal_reference_count": 0,
        "dispatcher_creative_style_pc_literal_reference_count": 0,
        "blocker": "untyped-anonymous-table-dispatch",
    },
    "initializer_candidate": {
        "range": {"start": 0x30750, "end": 0x309A8},
        "dynsym_owner": None,
        "calls": INITIALIZER_CALLS,
        "utility_member_offset": 0x14C,
        "setting_node_member_offset": 0x148,
        "field_accesses": [
            {"site": 0x30876, "offset": 0x14C, "width": 4, "access": "write", "role": "previous-utility-pointer"},
            {"site": 0x308AA, "offset": 0x14C, "width": 4, "access": "write", "role": "constructed-utility-pointer"},
            {"site": 0x308AE, "offset": 0x148, "width": 4, "access": "write", "role": "setting-node-pointer"},
            {"site": 0x308B6, "offset": 0x148, "width": 4, "access": "read", "role": "utility-init-argument"},
            {"site": 0x308BA, "offset": 0x14C, "width": 4, "access": "read", "role": "utility-init-receiver"},
        ],
        "utility_store_site": 0x308AA,
        "utility_store_width": 4,
        "direct_path_to_target": False,
        "same_field_proves_same_class": False,
        "candidate_to_target_origin_proven": False,
        "creative_style_pc_literal_reference_found": False,
    },
}


CREATIVE_STYLE_BOUNDARY = {
    "view_unified4_publication_count": 6,
    "view_unified7_publication_count": 2,
    "target_or_dispatcher_pc_literal_reference_count": 0,
    "typed_owner_binding_found": False,
    "constructor_assignment_found": False,
    "path_sensitive_receiver_binding_found": False,
}

CLAIMS = {
    "generic_dispatcher_provenance_found": True,
    "generic_utility_member_lifecycle_found": True,
    "concrete_derived_type_found": False,
    "initializer_to_target_origin_found": False,
    "creative_style_owner_binding_found": False,
    "selected_model_value_storage_found": False,
    "final_model_setter_or_commit_found": False,
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
        "bounded_direct_and_table_dispatch": True,
        "source_unchanged": True,
    },
    "modules": MODULES,
    "view_unified4": VIEW_UNIFIED4,
    "view_unified7": VIEW_UNIFIED7,
    "creative_style_boundary": CREATIVE_STYLE_BOUNDARY,
    "evidence_digest": canonical_digest(
        {"view_unified4": VIEW_UNIFIED4, "view_unified7": VIEW_UNIFIED7, "creative_style_boundary": CREATIVE_STYLE_BOUNDARY}
    ),
    "claims": CLAIMS,
    "truncated": False,
}

READINESS = "GENERIC_OWNER_PROVENANCE_WITH_UNTYPED_BLOCKERS"
CONCLUSION = (
    "The VU4 model sequences are table-dispatch tails using utility members at offsets 0x180 "
    "and 0x188; VU7 has one direct table-dispatch predecessor that preserves entry r0 into a utility "
    "member at offset 0x14c, plus a separate initializer with the same field layout. Missing concrete "
    "RTTI/derived types, an initializer-to-target identity, and typed Creative Style references keep "
    "all three paths generic rather than Creative Style-owned."
)

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FORBIDDEN_KEYS = ("payload", "key_material", "device_write", "usb_write", "flash_image", "package_bytes")


class GenericModelOwnerProvenanceError(ValueError):
    """Raised when generic owner provenance is promoted beyond static evidence."""


def _forbid(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if any(token in str(key).casefold() for token in _FORBIDDEN_KEYS):
                raise GenericModelOwnerProvenanceError("unsafe or reconstructive evidence field")
            _forbid(child)
    elif isinstance(value, list):
        for child in value:
            _forbid(child)


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise GenericModelOwnerProvenanceError(label + " fields differ")
    return value


def normalize_generic_model_owner_provenance_export(document):
    _forbid(document)
    export = _exact(document, set(EXPECTED_EXPORT), "owner-provenance export")
    if export != EXPECTED_EXPORT:
        differing = sorted(key for key in EXPECTED_EXPORT if export.get(key) != EXPECTED_EXPORT[key])
        raise GenericModelOwnerProvenanceError("owner-provenance export differs in: " + ",".join(differing))
    evidence = {
        "view_unified4": export["view_unified4"],
        "view_unified7": export["view_unified7"],
        "creative_style_boundary": export["creative_style_boundary"],
    }
    if export["evidence_digest"] != canonical_digest(evidence):
        raise GenericModelOwnerProvenanceError("evidence digest differs")
    second = export["view_unified4"]["targets"][1]
    if second["exidx_interval_is_single_function"] or not second["entry_separated_by_prior_return"]:
        raise GenericModelOwnerProvenanceError("split EXIDX entry was promoted")
    candidate = export["view_unified7"]["initializer_candidate"]
    if candidate["same_field_proves_same_class"] or candidate["candidate_to_target_origin_proven"]:
        raise GenericModelOwnerProvenanceError("same-offset candidate was promoted")
    if any(export["claims"][key] for key in (
        "concrete_derived_type_found", "initializer_to_target_origin_found",
        "creative_style_owner_binding_found", "selected_model_value_storage_found",
        "final_model_setter_or_commit_found", "renderer_binding_found", "touch_routing_found",
        "commit_or_persistence_found", "creative_look_equivalence_found", "runtime_execution_proven",
    )):
        raise GenericModelOwnerProvenanceError("indirect generic owner was promoted")
    return copy.deepcopy(export)


def summarize_generic_model_owner_provenance_export(document):
    export = normalize_generic_model_owner_provenance_export(document)
    return {
        "canonical_export_sha256": canonical_digest(export),
        "vu4_target_count": len(export["view_unified4"]["targets"]),
        "vu7_target_count": 1,
        "initializer_candidate_count": 1,
        "creative_style_binding_count": 0,
    }


def validate_generic_model_owner_provenance_report(document):
    _forbid(document)
    fields = {
        "schema_version", "analysis_scope", "camera_policy", "camera_executed", "installable",
        "camera_test_eligible", "sources", "summary", "evidence_digest", "creative_style_boundary",
        "claims", "readiness", "conclusion",
    }
    report = _exact(document, fields, "owner-provenance report")
    if report["schema_version"] != 1 or report["analysis_scope"] != "offline-static-generic-model-owner-provenance" or report["camera_policy"] != "physically-disconnected":
        raise GenericModelOwnerProvenanceError("report scope differs")
    if any(report[key] is not False for key in ("camera_executed", "installable", "camera_test_eligible")):
        raise GenericModelOwnerProvenanceError("report promotes camera activity")
    expected_summary = summarize_generic_model_owner_provenance_export(EXPECTED_EXPORT)
    if report["sources"] != MODULES or report["summary"] != expected_summary or _SHA.fullmatch(report["summary"].get("canonical_export_sha256", "")) is None:
        raise GenericModelOwnerProvenanceError("report source or summary differs")
    if report["evidence_digest"] != EXPECTED_EXPORT["evidence_digest"] or report["creative_style_boundary"] != CREATIVE_STYLE_BOUNDARY or report["claims"] != CLAIMS:
        raise GenericModelOwnerProvenanceError("report evidence differs")
    if report["readiness"] != READINESS or report["conclusion"] != CONCLUSION:
        raise GenericModelOwnerProvenanceError("report promotes anonymous ownership")
    return copy.deepcopy(report)
