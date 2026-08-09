"""Fail-closed contract for the cross-ELF ProductAction delivery boundary."""
from __future__ import annotations

import copy
import hashlib
import json
import re


FIRMWARE_INVENTORY = {
    "regular_file_count": 799,
    "elf_file_count": 324,
    "shared_object_count": 150,
    "canonical_inventory_sha256": (
        "52ec5e8baf523878a417e3a61f9f16484634a9075d1c6afca2ca8c25940d827c"
    ),
}
DEPENDENCIES = {
    "selected_node_identity": {
        "report": "analysis/a6400-creative-style-selected-node-identity-boundary.json",
        "schema_version": 5,
        "canonical_export_sha256": (
            "dee95f6e6e33e48a0beb3aff1b0cbe33331b91ce6bb38002fc1b56bcb87aa7c6"
        ),
        "viewsettingmenu_productaction_10_delivery_proven": False,
    },
    "orientation_object_table": {
        "report": "analysis/a6400-orientation-object-table-boundary.json",
        "canonical_export_sha256": (
            "86daf8ed9640fac1825c1076a21b0252a59b2619024af031d036fe31816ddcd4"
        ),
        "af_address_point": 0x8E6228,
        "widget_address_point_match_count": 0,
    },
}
PRODUCTACTION_INTERFACE = {
    "module": "lib/viewUnified2.so",
    "module_size": 11_530_552,
    "module_sha256": (
        "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2"
    ),
    "viewsettingmenu_address_point": 0x8E2270,
    "viewsettingmenu_slot37_cell": 0x8E2304,
    "productaction_symbol_index": 2_323,
    "productaction_symbol": "_ZN15ViewBaseProduct13ProductActionEi",
    "productaction_entry": 0x2F1350,
    "productaction_end": 0x2F135E,
    "forwarded_slot": 64,
    "forwarded_slot_offset": 0x100,
    "required_selector": 10,
}
KNOWN_SELECTOR_CALLS = [
    {
        "module": "lib/libmpr.so",
        "owner_start": 0x736288,
        "owner_end": 0x7363A8,
        "vptr_load_site": 0x7362EA,
        "slot_load_site": 0x7362EC,
        "call_site": 0x7362F0,
        "selector": 0,
    },
    {
        "module": "lib/libmpr.so",
        "owner_start": 0x7C08E8,
        "owner_end": 0x7C0A04,
        "vptr_load_site": 0x7C0950,
        "slot_load_site": 0x7C0952,
        "call_site": 0x7C0956,
        "selector": 0,
    },
    {
        "module": "lib/libmpr.so",
        "owner_start": 0x7C08E8,
        "owner_end": 0x7C0A04,
        "vptr_load_site": 0x7C09DA,
        "slot_load_site": 0x7C09DC,
        "call_site": 0x7C09E0,
        "selector": 1,
    },
]
CALL_MODULES = [
    {
        "module": "bin/orb-server",
        "complete_owner_count": 15_952,
        "incomplete_owner_count": 333,
        "canonical_call_count": 51,
    },
    {
        "module": "lib/CautionConfig.so",
        "complete_owner_count": 6_469,
        "incomplete_owner_count": 741,
        "canonical_call_count": 3,
    },
    {
        "module": "lib/libBizFw.so",
        "complete_owner_count": 841,
        "incomplete_owner_count": 22,
        "canonical_call_count": 1,
    },
    {
        "module": "lib/libmpr.so",
        "complete_owner_count": 33_110,
        "incomplete_owner_count": 3_732,
        "canonical_call_count": 28,
    },
    {
        "module": "lib/libObj.so",
        "complete_owner_count": 56_271,
        "incomplete_owner_count": 3_343,
        "canonical_call_count": 22,
    },
    {
        "module": "lib/viewUnified2.so",
        "complete_owner_count": 28_869,
        "incomplete_owner_count": 1_594,
        "canonical_call_count": 6,
    },
]
CANONICAL_SLOT37_SCAN = {
    "scope": (
        "authenticated-inventory-elf-files-with-usable-arm-exidx-and-"
        "fully-decoded-thumb-owners-canonical-vptr-slot37-blx-shape"
    ),
    "exidx_scanned_file_count": 222,
    "excluded_file_count": 102,
    "excluded_reason_counts": {
        "kernel-module-without-usable-arm-exidx": 101,
        "shared-object-without-usable-arm-exidx": 1,
    },
    "excluded_records_sha256": (
        "d8b68f50d377b03b731b4150c1544780e6b5e0bde88b28111c1a2e96237deeef"
    ),
    "complete_owner_count": 195_837,
    "incomplete_owner_count": 13_885,
    "call_modules": CALL_MODULES,
    "canonical_call_count": 111,
    "known_selector_calls": KNOWN_SELECTOR_CALLS,
    "known_selector_calls_sha256": (
        "289eaac4a75dcaca96a5d86525af6f70a7dd907b6abf03598cc62bb8a838bb2f"
    ),
    "known_selector_histogram": {"0": 2, "1": 1},
    "unknown_selector_count": 108,
    "selector_10_call_count": 0,
    "noncanonical_dispatch_scanned": False,
    "incomplete_owner_dispatch_scanned": False,
    "runtime_indirect_dispatch_scanned": False,
    "whole_elf_universe_absence_proven": False,
}
VU2_DIRECT_CALLER_CLASSIFICATION = {
    "productaction_parent_owner": {
        "start": 0x310CD8,
        "end": 0x310E30,
        "defined_symbol_count": 0,
        "relative_address_taken_count": 0,
        "direct_inbound_calls": [
            {"site": 0x31107E, "owner_start": 0x310E30, "owner_end": 0x3110BC},
            {"site": 0x3112A0, "owner_start": 0x3110BC, "owner_end": 0x3112DC},
            {"site": 0x3114C6, "owner_start": 0x3112DC, "owner_end": 0x311514},
        ],
        "selector_origin": "call-clobbered-before-each-slot37-transfer",
    },
    "large_helpers": [
        {
            "start": 0x310E30,
            "end": 0x3110BC,
            "defined_symbol_count": 0,
            "relative_address_taken_count": 0,
            "decoded_direct_inbound_count": 0,
            "receiver_origin": "entry-r0",
            "viewsettingmenu_identity_proven": False,
        },
        {
            "start": 0x3110BC,
            "end": 0x3112DC,
            "defined_symbol_count": 0,
            "relative_address_taken_count": 0,
            "decoded_direct_inbound_count": 1,
            "receiver_origin": "af-slot36-route-entry-r0",
            "viewsettingmenu_identity_proven": False,
        },
        {
            "start": 0x3112DC,
            "end": 0x311514,
            "defined_symbol_count": 0,
            "relative_address_taken_count": 0,
            "decoded_direct_inbound_count": 1,
            "receiver_origin": "af-slot36-route-entry-r0",
            "viewsettingmenu_identity_proven": False,
        },
    ],
    "af_slot36_route": {
        "type_name": "AfImplForOrientationRegisterAF",
        "address_point": 0x8E6228,
        "viewsettingmenu_address_point": 0x8E2270,
        "address_points_equal": False,
        "slot": 36,
        "slot_offset": 0x90,
        "cell": 0x8E62B8,
        "relocation_index": 20_028,
        "relocation_type": 23,
        "target": 0x31286C,
        "owner": {"start": 0x31286C, "end": 0x31297C},
        "direct_tail_routes": [
            {"site": 0x3128CA, "target": 0x3112DC},
            {"site": 0x31293A, "target": 0x3110BC},
        ],
        "viewsettingmenu_receiver_proven": False,
    },
    "vu2_direct_inbound_scan_complete": False,
    "vu2_incomplete_owner_count": 1_594,
}
CLAIMS = {
    "canonical_cross_elf_productaction_inventory_found": True,
    "known_selector_10_call_found": False,
    "af_orientation_false_lead_identified": True,
    "viewsettingmenu_receiver_proven": False,
    "productaction_selector_10_delivery_proven": False,
    "whole_runtime_absence_proven": False,
    "runtime_creative_style_selection_proven": False,
    "process_id_42_activation_proven": False,
    "viewcreativestyle_factory_invocation_proven": False,
    "first_class_creative_look_proven": False,
    "processing_output_binding_proven": False,
}
FIRST_UNRESOLVED_BOUNDARY = (
    "noncanonical-or-incomplete-owner-or-runtime-indirect-viewsettingmenu-"
    "receiver-productaction-selector-10-delivery"
)
READINESS = "BOUNDED_CANONICAL_PRODUCTACTION_SELECTOR_10_NOT_FOUND"
CONCLUSION = (
    "Across the authenticated 324-ELF inventory, 222 files expose usable ARM EXIDX ownership. "
    "Their 195,837 fully decoded owners contain 111 canonical receiver-vptr to slot-37 register "
    "transfers; the only statically live immediate selectors are 0, 0, and 1 in libmpr owners, "
    "never selector 10. In viewUnified2, two direct helper routes are reached through "
    "slot 36 of the distinct AfImplForOrientationRegisterAF table, while the remaining helper "
    "has no decoded direct inbound or relocation-backed publication. This canonical bounded scan "
    "does not prove whole-runtime absence: 102 ELF files lack usable EXIDX ownership, 13,885 "
    "owners are incomplete, and noncanonical or runtime-indirect dispatch remains unresolved. "
    "A ViewSettingMenu receiver carrying ProductAction selector 10, runtime Creative Style "
    "selection, process-ID 42 activation, ViewCreativeStyle factory invocation, first-class "
    "Creative Look, processing/output binding, installation, recovery, and camera eligibility "
    "remain unproven."
)

EXPECTED_RAW_EXPORT = {
    "schema_version": 1,
    "analysis_mode": {
        "read_only": True,
        "static_elf_analysis": True,
        "source_unchanged": True,
    },
    "firmware_inventory": FIRMWARE_INVENTORY,
    "dependencies": DEPENDENCIES,
    "productaction_interface": PRODUCTACTION_INTERFACE,
    "canonical_slot37_scan": CANONICAL_SLOT37_SCAN,
    "vu2_direct_caller_classification": VU2_DIRECT_CALLER_CLASSIFICATION,
    "claims": CLAIMS,
    "first_unresolved_boundary": FIRST_UNRESOLVED_BOUNDARY,
    "truncated": False,
}

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class CreativeStyleProductActionDeliveryBoundaryError(ValueError):
    """Raised when the bounded ProductAction evidence is widened or changed."""


def _digest(value):
    return hashlib.sha256(
        (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )
    ).hexdigest()


def normalize_creative_style_productaction_delivery_boundary_export(document):
    """Accept only the complete pinned, fail-closed source-derived export."""

    if not isinstance(document, dict) or document != EXPECTED_RAW_EXPORT:
        raise CreativeStyleProductActionDeliveryBoundaryError(
            "ProductAction delivery export differs"
        )
    scan = document["canonical_slot37_scan"]
    if scan["known_selector_calls_sha256"] != _digest(
        scan["known_selector_calls"]
    ):
        raise CreativeStyleProductActionDeliveryBoundaryError(
            "known-selector inventory digest differs"
        )
    if (
        scan["exidx_scanned_file_count"] + scan["excluded_file_count"]
        != document["firmware_inventory"]["elf_file_count"]
        or sum(item["canonical_call_count"] for item in scan["call_modules"])
        != scan["canonical_call_count"]
        or sum(scan["known_selector_histogram"].values())
        + scan["unknown_selector_count"]
        != scan["canonical_call_count"]
    ):
        raise CreativeStyleProductActionDeliveryBoundaryError(
            "ProductAction delivery inventory is inconsistent"
        )
    return copy.deepcopy(document)


def build_creative_style_productaction_delivery_boundary_report(document):
    """Normalize a raw export into the checked report."""

    raw = normalize_creative_style_productaction_delivery_boundary_export(document)
    return {
        "schema_version": 1,
        "analysis_scope": "offline-static-creative-style-productaction-delivery-boundary",
        "camera_policy": "physically-disconnected",
        "camera_executed": False,
        "installable": False,
        "recovery_validated": False,
        "camera_test_eligible": False,
        "summary": {
            "canonical_export_sha256": _digest(raw),
            "elf_file_count": raw["firmware_inventory"]["elf_file_count"],
            "exidx_scanned_file_count": raw["canonical_slot37_scan"][
                "exidx_scanned_file_count"
            ],
            "canonical_call_count": raw["canonical_slot37_scan"][
                "canonical_call_count"
            ],
            "selector_10_call_count": raw["canonical_slot37_scan"][
                "selector_10_call_count"
            ],
        },
        "dependencies": copy.deepcopy(raw["dependencies"]),
        "productaction_interface": copy.deepcopy(raw["productaction_interface"]),
        "canonical_slot37_scan": copy.deepcopy(raw["canonical_slot37_scan"]),
        "vu2_direct_caller_classification": copy.deepcopy(
            raw["vu2_direct_caller_classification"]
        ),
        "claims": copy.deepcopy(raw["claims"]),
        "first_unresolved_boundary": raw["first_unresolved_boundary"],
        "readiness": READINESS,
        "conclusion": CONCLUSION,
    }


def validate_creative_style_productaction_delivery_boundary_report(report):
    """Validate the committed report without accepting promoted prose or claims."""

    expected = build_creative_style_productaction_delivery_boundary_report(
        EXPECTED_RAW_EXPORT
    )
    if not isinstance(report, dict) or report != expected:
        raise CreativeStyleProductActionDeliveryBoundaryError(
            "ProductAction delivery report differs"
        )
    if _SHA256.fullmatch(report["summary"]["canonical_export_sha256"]) is None:
        raise CreativeStyleProductActionDeliveryBoundaryError(
            "ProductAction delivery report digest differs"
        )
    return copy.deepcopy(report)
