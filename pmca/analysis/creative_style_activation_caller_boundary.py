"""Fail-closed α6400 Creative Style activation-caller evidence contract."""

from __future__ import annotations

import copy
import hashlib
import json


class CreativeStyleActivationCallerBoundaryError(ValueError):
    """Raised when activation-caller evidence exceeds the static boundary."""


SOURCE = {
    "module": "lib/viewUnified2.so",
    "size": 11_530_552,
    "sha256": "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2",
}

DEPENDENCY = {
    "report": "analysis/a6400-creative-style-view-lifecycle-boundary.json",
    "evidence_digest": "6d1f51bd05f0bd2ba203ddef1a807aa8e25f5b924f41319cb1ad1ebddb44a572",
    "typed_process_id_42_caller_proven": False,
    "runtime_factory_invocation_proven": False,
}

MANAGER_IDENTITY = {
    "type_name": "CmnViewProcessDataMgr",
    "instance_object": 0xB06BB0,
    "vtable_header": 0x905928,
    "vtable_address_point": 0x905930,
    "accessor": {
        "owner": {"start": 0x158350, "end": 0x1583AC, "complete": True},
        "pic_literal_site": 0x158398,
        "pic_base": 0x9446A0,
        "guard_got_cell": 0x94D228,
        "guard_relocation_index": 60668,
        "guard_storage": 0xB06BAC,
        "instance_got_cell": 0x94D990,
        "instance_relocation_index": 61126,
        "constructor_receiver_site": 0x158370,
        "constructor_call_site": 0x158372,
        "constructor_symbol": "_ZN21CmnViewProcessDataMgrC1Ev",
        "return_site": 0x15838A,
    },
    "constructor": {
        "owner": {"start": 0x43905C, "end": 0x4390BC, "complete": True},
        "bounded_body_end": 0x43907E,
        "pic_literal_site": 0x439080,
        "pic_base": 0x9446A0,
        "vtable_offset_literal_site": 0x439084,
        "vtable_got_cell": 0x94B104,
        "vtable_relocation_index": 58661,
        "vtable_header_target": 0x905928,
        "vtable_load_site": 0x43906E,
        "address_point_add_site": 0x439070,
        "vptr_store_site": 0x439072,
        "return_site": 0x43907A,
    },
    "bridge_slot": 20,
    "bridge_cell": 0x905980,
    "bridge_relocation_index": 37093,
    "bridge_target": 0x4390BC,
    "bridge_owner": {"start": 0x4390BC, "end": 0x4390D4, "complete": True},
    "bridge": {
        "condition_capture_site": 0x4390C0,
        "lookup_call_site": 0x4390C2,
        "lookup_target": 0x439088,
        "condition_forward_site": 0x4390CA,
        "typed_slot_load_site": 0x4390CC,
        "typed_slot_offset": 0x64,
        "typed_slot_call_site": 0x4390CE,
    },
}

TYPED_ACTIVATION_DEPENDENCY = {
    "element_type": "CmnViewProcessDataElementCustomCreativeStyle",
    "vtable_address_point": 0x90ED88,
    "slot": 25,
    "cell": 0x90EDEC,
    "relocation_index": 40033,
    "wrapper_target": 0x489218,
    "manager_bridge_target": 0x4390BC,
    "process_id": 42,
    "typed_process_id_42_caller_proven": False,
}


def _call(owner_start, owner_end, vptr_load, slot_load, call_site, receiver):
    return {
        "owner": {"start": owner_start, "end": owner_end, "complete": True},
        "vptr_load_site": vptr_load,
        "slot_load_site": slot_load,
        "call_site": call_site,
        "receiver_register": receiver,
        "manager_receiver_proven": False,
        "manager_vptr_proven": False,
        "process_id_42_proven": False,
        "condition_r2_proven": False,
        "accepted": False,
    }


CANONICAL_SLOT_20_CALLS = [
    _call(0x20C7C0, 0x20C8A4, 0x20C89C, 0x20C89E, 0x20C8A0, "r0"),
    _call(0x2A524C, 0x2A5294, 0x2A5254, 0x2A5256, 0x2A5258, "r0"),
    _call(0x2ABF6C, 0x2ABFDC, 0x2ABFAC, 0x2ABFAE, 0x2ABFB0, "r0"),
    _call(0x2AC550, 0x2AC590, 0x2AC56E, 0x2AC570, 0x2AC572, "r0"),
    _call(0x2F1094, 0x2F10C8, 0x2F10BA, 0x2F10BC, 0x2F10BE, "r0"),
    _call(0x35F8FE, 0x35F93E, 0x35F926, 0x35F928, 0x35F92A, "r0"),
    _call(0x43914C, 0x439164, 0x439158, 0x43915C, 0x43915E, "r0"),
    _call(0x43A5D0, 0x43A5F0, 0x43A5D8, 0x43A5DA, 0x43A5DC, "r0"),
    _call(0x45E114, 0x45E128, 0x45E120, 0x45E122, 0x45E124, "r0"),
    _call(0x46ADFC, 0x46AE10, 0x46AE08, 0x46AE0A, 0x46AE0C, "r0"),
    _call(0x50FBAC, 0x50FBDC, 0x50FBB4, 0x50FBB8, 0x50FBBA, "r1"),
    _call(0x50FBAC, 0x50FBDC, 0x50FBC0, 0x50FBC4, 0x50FBC6, "r4"),
    _call(0x578106, 0x578136, 0x57810E, 0x578112, 0x578114, "r1"),
    _call(0x578106, 0x578136, 0x57811A, 0x57811E, 0x578120, "r4"),
    _call(0x581144, 0x58131C, 0x581306, 0x581308, 0x58130A, "r0"),
    _call(0x5BC530, 0x5BC574, 0x5BC554, 0x5BC556, 0x5BC558, "r1"),
]

CALLER_SCAN = {
    "exidx_owner_count": 30_463,
    "fully_decoded_owner_count": 28_869,
    "incomplete_or_terminal_owner_count": 1_594,
    "canonical_slot_offset": 0x50,
    "canonical_slot_20_calls": CANONICAL_SLOT_20_CALLS,
    "accepted_candidates": [],
    "manager_bridge_direct_inbound": [],
    "typed_wrapper_direct_inbound": [],
    "direct_inbound_scan_complete": False,
    "whole_program_absence_proven": False,
    "unresolved_universes": [
        "decode-incomplete-or-terminal-exidx-owners",
        "noncanonical-virtual-dispatch",
        "indirect-callback-or-runtime-initialized-receiver",
        "cross-module-or-loader-mediated-delivery",
    ],
}

CLAIMS = {
    "concrete_process_manager_singleton_and_vptr_proven": True,
    "typed_manager_slot_20_bridge_proven": True,
    "bounded_canonical_slot_20_inventory_proven": True,
    "process_id_42_activation_caller_proven": False,
    "menu_root_activation_join_proven": False,
    "runtime_open_view_delivery_proven": False,
    "runtime_factory_invocation_proven": False,
    "returned_viewcreative_style_identity_proven": False,
    "first_class_creative_look_equivalence_proven": False,
    "processing_or_output_behavior_proven": False,
    "recovery_validated": False,
    "installable": False,
    "camera_test_eligible": False,
}

READINESS = "PROCESS_ID_42_ACTIVATION_CALLER_UNRESOLVED_IN_BOUNDED_STATIC_SCAN"
FIRST_UNRESOLVED_BOUNDARY = (
    "decode-incomplete-noncanonical-or-runtime-receiver-provenance-to-manager-slot-20"
)
CONCLUSION = (
    "The authenticated VU2 module constructs a concrete CmnViewProcessDataMgr "
    "singleton at 0xB06BB0 and installs vptr 0x905930. Manager slot 20 reaches "
    "the typed execProcWithCondition bridge, and the Creative Style element slot "
    "25 reaches the condition-preserving view/CREATIVE_STYLE openView wrapper. A "
    "function-aware scan covers 28,869 fully decoded exception-index owners and "
    "retains 1,594 incomplete or terminal owners outside the negative universe. "
    "It inventories 16 canonical slot-0x50 calls and accepts zero as a manager "
    "receiver with process ID 42 and condition provenance. This bounded result "
    "does not prove a process ID 42 activation caller, menu-root activation, "
    "runtime openView delivery, factory invocation, a returned ViewCreativeStyle "
    "object, first-class Creative Look equivalence, processing/output behavior, "
    "installability, recovery, or camera-test eligibility."
)

EXPECTED_EXPORT = {
    "schema_version": 1,
    "analysis_mode": "offline-static-creative-style-activation-caller-boundary",
    "source": SOURCE,
    "dependency": DEPENDENCY,
    "manager_identity": MANAGER_IDENTITY,
    "typed_activation_dependency": TYPED_ACTIVATION_DEPENDENCY,
    "caller_scan": CALLER_SCAN,
    "claims": CLAIMS,
    "readiness": READINESS,
    "first_unresolved_boundary": FIRST_UNRESOLVED_BOUNDARY,
}


def normalize_creative_style_activation_caller_boundary_export(raw):
    """Validate and copy the exact fail-closed static export."""
    if raw != EXPECTED_EXPORT:
        raise CreativeStyleActivationCallerBoundaryError(
            "Creative Style activation-caller export differs from the pinned boundary"
        )
    return copy.deepcopy(raw)


def canonical_digest(document):
    encoded = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def _report_from_export(export):
    scan = export["caller_scan"]
    report = {
        "schema_version": 1,
        "analysis_scope": "offline-static-creative-style-activation-caller-boundary",
        "camera_policy": "physically-disconnected",
        "camera_executed": False,
        "installable": False,
        "recovery_validated": False,
        "camera_test_eligible": False,
        "source": copy.deepcopy(export["source"]),
        "dependency": copy.deepcopy(export["dependency"]),
        "summary": {
            "canonical_export_sha256": canonical_digest(export),
            "manager_instance_object": export["manager_identity"]["instance_object"],
            "manager_vtable_address_point": export["manager_identity"][
                "vtable_address_point"
            ],
            "fully_decoded_owner_count": scan["fully_decoded_owner_count"],
            "incomplete_or_terminal_owner_count": scan[
                "incomplete_or_terminal_owner_count"
            ],
            "canonical_slot_20_call_count": len(scan["canonical_slot_20_calls"]),
            "accepted_candidate_count": len(scan["accepted_candidates"]),
            "whole_program_absence_proven": scan["whole_program_absence_proven"],
        },
        "evidence": {
            "manager_identity": copy.deepcopy(export["manager_identity"]),
            "typed_activation_dependency": copy.deepcopy(
                export["typed_activation_dependency"]
            ),
            "caller_scan": copy.deepcopy(scan),
        },
        "first_unresolved_boundary": export["first_unresolved_boundary"],
        "readiness": export["readiness"],
        "claims": copy.deepcopy(export["claims"]),
        "conclusion": CONCLUSION,
        "narrative_sha256": hashlib.sha256(CONCLUSION.encode("utf-8")).hexdigest(),
    }
    report["evidence_digest"] = canonical_digest(report["evidence"])
    return report


def build_creative_style_activation_caller_boundary_report(document):
    """Build the checked report from the exact validated raw export."""
    return _report_from_export(
        normalize_creative_style_activation_caller_boundary_export(document)
    )


def validate_creative_style_activation_caller_boundary_report(document):
    """Reject any report that promotes the bounded caller scan."""
    expected = _report_from_export(EXPECTED_EXPORT)
    if document != expected:
        raise CreativeStyleActivationCallerBoundaryError(
            "Creative Style activation-caller report differs from the pinned boundary"
        )
    return copy.deepcopy(document)
