"""Read-only exporter for the α6400 Creative Style activation-caller boundary."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pmca.analysis.creative_style_activation_caller_boundary import (
    ACTION_TO_MANAGER_ROUTE,
    CLAIMS,
    CREATIVE_STYLE_PROPERTY_14,
    DEPENDENCY,
    EXPECTED_EXPORT,
    FIRST_UNRESOLVED_BOUNDARY,
    MANAGER_IDENTITY,
    READINESS,
    SELECTED_NODE_IDENTITY_BOUNDARY,
    SOURCE,
    SUPPORTING_DEPENDENCY,
    SUPPORTING_SOURCE,
    TYPED_ACTIVATION_DEPENDENCY,
    VIEWSETTINGMENU_IDENTITY,
    build_creative_style_activation_caller_boundary_report,
    normalize_creative_style_activation_caller_boundary_export,
    validate_creative_style_activation_caller_boundary_report,
)
from pmca.analysis.creative_style_view_lifecycle_boundary import (
    validate_creative_style_view_lifecycle_boundary_report,
)
from pmca.analysis.creative_style_definition_registration import (
    validate_creative_style_definition_registration_report,
)
from tools.static.export_a6400_creative_style_view_lifecycle_boundary import (
    _dependencies,
)
from tools.static.export_a6400_creative_style_view_model_binding import (
    _at,
    _call_symbol,
    _decode,
    _direct_target,
    _instruction,
    _mappings,
    _owner,
    _plt_symbols,
    _relocations,
    _validate_relative,
    _word,
)
from tools.static.export_a6400_generic_model_owner_provenance import _exidx_ranges


SOURCE_PATH = (
    ROOT
    / ".artifacts"
    / "decrypted"
    / "a6400-tw-v2.00"
    / "ma1co"
    / "firmware.tar_unpacked"
    / "0700_part_image"
    / "dev"
    / "nflasha15_unpacked"
    / "lib"
    / "viewUnified2.so"
)
CAUTION_SOURCE_PATH = SOURCE_PATH.with_name("CautionConfig.so")
DEPENDENCY_PATH = ROOT / DEPENDENCY["report"]
SUPPORTING_DEPENDENCY_PATH = ROOT / SUPPORTING_DEPENDENCY["report"]
RAW_OUTPUT_PATH = (
    ROOT
    / ".artifacts"
    / "creative-style-activation-caller-boundary"
    / "a6400-v2.00"
    / "creative-style-activation-caller-boundary-export.json"
)
REPORT_PATH = ROOT / "analysis" / "a6400-creative-style-activation-caller-boundary.json"


def dependencies_available():
    try:
        _dependencies()
    except RuntimeError:
        return False
    return True


def sources_available():
    return (
        SOURCE_PATH.is_file()
        and not SOURCE_PATH.is_symlink()
        and CAUTION_SOURCE_PATH.is_file()
        and not CAUTION_SOURCE_PATH.is_symlink()
        and DEPENDENCY_PATH.is_file()
        and not DEPENDENCY_PATH.is_symlink()
        and SUPPORTING_DEPENDENCY_PATH.is_file()
        and not SUPPORTING_DEPENDENCY_PATH.is_symlink()
    )


def _sha256_bytes(blob):
    return hashlib.sha256(blob).hexdigest()


def _context(blob, deps):
    stream = io.BytesIO(blob)
    elf = deps["ELFFile"](stream)
    mappings = _mappings(elf)
    rels, by_site = _relocations(elf)
    return {
        "stream": stream,
        "elf": elf,
        "blob": blob,
        "mappings": mappings,
        "rels": rels,
        "by_site": by_site,
        "exidx": _exidx_ranges(elf, blob),
        "plt_symbols": _plt_symbols(elf, blob, mappings),
    }


def _validate_dependency():
    import json

    report = validate_creative_style_view_lifecycle_boundary_report(
        json.loads(DEPENDENCY_PATH.read_text(encoding="utf-8"))
    )
    if (
        report["evidence_digest"] != DEPENDENCY["evidence_digest"]
        or report["evidence"]["typed_activation"][
            "typed_process_id_42_caller_proven"
        ]
        != DEPENDENCY["typed_process_id_42_caller_proven"]
        or report["claims"]["runtime_factory_invocation_proven"]
        != DEPENDENCY["runtime_factory_invocation_proven"]
    ):
        raise RuntimeError("view-lifecycle dependency differs")
    supporting = validate_creative_style_definition_registration_report(
        json.loads(SUPPORTING_DEPENDENCY_PATH.read_text(encoding="utf-8"))
    )
    if (
        supporting["summary"]["artifact_sha256"]
        != SUPPORTING_DEPENDENCY["artifact_sha256"]
        or supporting["claims"]["root_constructor_binding_found"]
        != SUPPORTING_DEPENDENCY["root_constructor_binding_found"]
        or supporting["claims"]["root_constructor_runtime_provider_proven"]
        != SUPPORTING_DEPENDENCY["root_constructor_runtime_provider_proven"]
    ):
        raise RuntimeError("Creative Style definition dependency differs")


def _require_relative(
    context, *, index, site, target, label, encoded_target=None
):
    try:
        _validate_relative(
            context["rels"],
            context["by_site"],
            context["blob"],
            context["mappings"],
            index=index,
            site=site,
            target=target,
        )
    except (KeyError, RuntimeError, ValueError) as exc:
        raise RuntimeError(label + " relocation differs") from exc
    if encoded_target is not None and _word(
        context["blob"], context["mappings"], site
    ) != encoded_target:
        raise RuntimeError(label + " relocation addend differs")


def _require_symbol_relocation(
    context,
    *,
    index,
    site,
    relocation_type,
    symbol_index,
    symbol_name,
    symbol_value,
    symbol_size,
    label,
):
    try:
        actual_index, relocation = context["by_site"][site]
        symbol = context["elf"].get_section_by_name(".dynsym").get_symbol(
            relocation.entry["r_info_sym"]
        )
    except (AttributeError, KeyError, TypeError) as exc:
        raise RuntimeError(label + " relocation is missing") from exc
    if (
        actual_index != index
        or relocation.entry["r_offset"] != site
        or relocation.entry["r_info_type"] != relocation_type
        or relocation.entry["r_info_sym"] != symbol_index
        or symbol.name != symbol_name
        or symbol["st_value"] != symbol_value
        or symbol["st_size"] != symbol_size
        or symbol["st_info"]["bind"] != "STB_GLOBAL"
        or symbol["st_other"]["visibility"] != "STV_DEFAULT"
        or (relocation_type in (2, 21) and _word(context["blob"], context["mappings"], site) != 0)
    ):
        raise RuntimeError(label + " relocation/symbol differs")


def _require_mov(instruction, deps, destination, source, label):
    if (
        instruction.id != deps["mov"]
        or len(instruction.operands) != 2
        or instruction.operands[0].type != deps["reg"]
        or instruction.operands[0].reg != destination
        or instruction.operands[1].type != deps["reg"]
        or instruction.operands[1].reg != source
    ):
        raise RuntimeError(label + " register transfer differs")


def _require_mem(instruction, deps, kind, register, base, displacement, label):
    if (
        instruction.id != kind
        or len(instruction.operands) != 2
        or instruction.operands[0].type != deps["reg"]
        or instruction.operands[0].reg != register
        or instruction.operands[1].type != deps["mem"]
        or instruction.operands[1].mem.base != base
        or instruction.operands[1].mem.index != 0
        or instruction.operands[1].mem.disp != displacement
    ):
        raise RuntimeError(label + " memory operand differs")


def _require_immediate(instruction, deps, kind, destination, value, label):
    if (
        instruction.id != kind
        or len(instruction.operands) != 2
        or instruction.operands[0].type != deps["reg"]
        or instruction.operands[0].reg != destination
        or instruction.operands[1].type != deps["imm"]
        or instruction.operands[1].imm != value
    ):
        raise RuntimeError(label + " immediate operand differs")


def _literal_address(instruction, deps):
    if (
        instruction.id != deps["ldr"]
        or len(instruction.operands) != 2
        or instruction.operands[1].type != deps["mem"]
        or instruction.operands[1].mem.base != deps["pc"]
        or instruction.operands[1].mem.index != 0
    ):
        return None
    return ((instruction.address + 4) & ~3) + instruction.operands[1].mem.disp


def _halfword(blob, mappings, address):
    return int.from_bytes(_at(blob, mappings, address, 2), "little")


def _validate_manager_identity(context, deps):
    blob = context["blob"]
    mappings = context["mappings"]
    exidx = context["exidx"]
    manager = MANAGER_IDENTITY
    accessor = manager["accessor"]
    constructor = manager["constructor"]

    if _owner(exidx, accessor["owner"]["start"]) != (
        accessor["owner"]["start"],
        accessor["owner"]["end"],
    ):
        raise RuntimeError("process manager accessor owner differs")
    accessor_pic_base = _word(blob, mappings, accessor["pic_literal_site"]) + 0x15835C
    if accessor_pic_base != accessor["pic_base"]:
        raise RuntimeError("process manager accessor PIC base differs")
    guard_cell = accessor_pic_base + _word(blob, mappings, 0x15839C)
    instance_cell = accessor_pic_base + _word(blob, mappings, 0x1583A0)
    if guard_cell != accessor["guard_got_cell"] or instance_cell != accessor["instance_got_cell"]:
        raise RuntimeError("process manager accessor GOT cells differ")
    _require_relative(
        context,
        index=accessor["guard_relocation_index"],
        site=guard_cell,
        target=accessor["guard_storage"],
        label="process manager guard",
    )
    _require_relative(
        context,
        index=accessor["instance_relocation_index"],
        site=instance_cell,
        target=manager["instance_object"],
        label="process manager instance",
    )
    receiver = _instruction(blob, mappings, deps, accessor["constructor_receiver_site"])
    returned = _instruction(blob, mappings, deps, accessor["return_site"])
    instance_offset_load = _instruction(blob, mappings, deps, 0x158362)
    instance_offset_literal = (
        ((instance_offset_load.address + 4) & ~3)
        + instance_offset_load.operands[1].mem.disp
        if (
            instance_offset_load.id == deps["ldr"]
            and len(instance_offset_load.operands) == 2
            and instance_offset_load.operands[0].reg == deps["r3"]
            and instance_offset_load.operands[1].type == deps["mem"]
            and instance_offset_load.operands[1].mem.base == deps["pc"]
            and instance_offset_load.operands[1].mem.index == 0
        )
        else None
    )
    if (
        instance_offset_literal != 0x1583A0
        or receiver.id != deps["mov"]
        or receiver.operands[0].reg != deps["r0"]
        or receiver.operands[1].reg != deps["r5"]
        or _call_symbol(
            blob,
            mappings,
            deps,
            context["plt_symbols"],
            accessor["constructor_call_site"],
        )
        != accessor["constructor_symbol"]
        or returned.id != deps["mov"]
        or returned.operands[0].reg != deps["r0"]
        or returned.operands[1].reg != deps["r5"]
    ):
        raise RuntimeError("process manager accessor receiver/return differs")
    instance_load = _instruction(blob, mappings, deps, 0x158364)
    if (
        instance_load.id != deps["ldr"]
        or instance_load.operands[0].reg != deps["r5"]
        or instance_load.operands[1].mem.base != deps["r4"]
        or instance_load.operands[1].mem.index != deps["r3"]
    ):
        raise RuntimeError("process manager instance load differs")

    if _owner(exidx, constructor["owner"]["start"]) != (
        constructor["owner"]["start"],
        constructor["owner"]["end"],
    ):
        raise RuntimeError("process manager constructor owner differs")
    constructor_pic_base = _word(blob, mappings, constructor["pic_literal_site"]) + 0x43906E
    if constructor_pic_base != constructor["pic_base"]:
        raise RuntimeError("process manager constructor PIC base differs")
    vtable_cell = constructor_pic_base + _word(
        blob, mappings, constructor["vtable_offset_literal_site"]
    )
    if vtable_cell != constructor["vtable_got_cell"]:
        raise RuntimeError("process manager vtable GOT cell differs")
    _require_relative(
        context,
        index=constructor["vtable_relocation_index"],
        site=vtable_cell,
        target=constructor["vtable_header_target"],
        label="process manager vtable header",
    )
    vtable_load = _instruction(blob, mappings, deps, constructor["vtable_load_site"])
    address_point = _instruction(blob, mappings, deps, constructor["address_point_add_site"])
    vptr_store = _instruction(blob, mappings, deps, constructor["vptr_store_site"])
    constructor_return = _instruction(blob, mappings, deps, constructor["return_site"])
    if (
        vtable_load.id != deps["ldr"]
        or vtable_load.operands[0].reg != deps["r3"]
        or vtable_load.operands[1].mem.base != deps["r4"]
        or address_point.id != deps["add"]
        or address_point.operands[0].reg != deps["r3"]
        or address_point.operands[-1].imm != 8
        or vptr_store.id != deps["str"]
        or vptr_store.operands[0].reg != deps["r3"]
        or vptr_store.operands[1].mem.base != deps["r0"]
        or vptr_store.operands[1].mem.disp != 0
        or constructor_return.id != deps["mov"]
        or constructor_return.operands[0].reg != deps["r0"]
        or constructor_return.operands[1].reg != deps["r5"]
    ):
        raise RuntimeError("process manager constructor vptr store differs")
    _require_relative(
        context,
        index=manager["bridge_relocation_index"],
        site=manager["bridge_cell"],
        target=manager["bridge_target"],
        label="process manager slot 20",
    )
    if _owner(exidx, manager["bridge_target"]) != (
        manager["bridge_owner"]["start"],
        manager["bridge_owner"]["end"],
    ):
        raise RuntimeError("process manager bridge owner differs")
    bridge = manager["bridge"]
    condition_capture = _instruction(
        blob, mappings, deps, bridge["condition_capture_site"]
    )
    condition_forward = _instruction(
        blob, mappings, deps, bridge["condition_forward_site"]
    )
    typed_slot_load = _instruction(
        blob, mappings, deps, bridge["typed_slot_load_site"]
    )
    typed_slot_call = _instruction(
        blob, mappings, deps, bridge["typed_slot_call_site"]
    )
    if (
        condition_capture.id != deps["mov"]
        or condition_capture.operands[0].reg != deps["r4"]
        or condition_capture.operands[1].reg != deps["r2"]
        or _direct_target(
            _instruction(blob, mappings, deps, bridge["lookup_call_site"]), deps
        )
        != bridge["lookup_target"]
        or condition_forward.id != deps["mov"]
        or condition_forward.operands[0].reg != deps["r1"]
        or condition_forward.operands[1].reg != deps["r4"]
        or typed_slot_load.id != deps["ldr"]
        or typed_slot_load.operands[0].reg != deps["r3"]
        or typed_slot_load.operands[1].mem.base != deps["r3"]
        or typed_slot_load.operands[1].mem.disp != bridge["typed_slot_offset"]
        or typed_slot_call.id != deps["blx"]
        or typed_slot_call.operands[0].reg != deps["r3"]
    ):
        raise RuntimeError("process manager bridge condition/typed-slot flow differs")
    return copy.deepcopy(manager)


def _validate_typed_dependency(context):
    typed = TYPED_ACTIVATION_DEPENDENCY
    _require_relative(
        context,
        index=typed["relocation_index"],
        site=typed["cell"],
        target=typed["wrapper_target"],
        label="Creative Style typed slot 25",
    )
    if _owner(context["exidx"], typed["wrapper_target"]) != (0x4891D4, 0x489238):
        raise RuntimeError("Creative Style typed activation wrapper owner differs")
    return copy.deepcopy(typed)


def _validate_viewsettingmenu_route(context, deps):
    blob = context["blob"]
    mappings = context["mappings"]
    exidx = context["exidx"]
    menu = VIEWSETTINGMENU_IDENTITY
    route = ACTION_TO_MANAGER_ROUTE

    if _at(blob, mappings, menu["type_name_address"], 18) != b"15ViewSettingMenu\0":
        raise RuntimeError("ViewSettingMenu RTTI name differs")
    _require_relative(
        context,
        index=menu["typeinfo_relocation_index"],
        site=menu["typeinfo_cell"],
        target=menu["rtti"],
        label="ViewSettingMenu vtable typeinfo",
        encoded_target=menu["rtti"],
    )
    for role in ("slot_54", "slot_64", "slot_65"):
        slot = menu[role]
        _require_relative(
            context,
            index=slot["relocation_index"],
            site=slot["cell"],
            target=slot["target"],
            label="ViewSettingMenu " + role,
            encoded_target=slot["target"] | 1,
        )
        if _owner(exidx, slot["target"]) != (
            slot["owner"]["start"],
            slot["owner"]["end"],
        ):
            raise RuntimeError("ViewSettingMenu " + role + " owner differs")

    publication = menu["manager_publication"]
    _require_mov(
        _instruction(blob, mappings, deps, publication["receiver_capture_site"]),
        deps,
        deps["r5"],
        deps["r0"],
        "ViewSettingMenu receiver capture",
    )
    if (
        _direct_target(
            _instruction(
                blob, mappings, deps, publication["manager_accessor_call_site"]
            ),
            deps,
        )
        != publication["manager_accessor_target"]
    ):
        raise RuntimeError("ViewSettingMenu manager accessor call differs")
    _require_mem(
        _instruction(blob, mappings, deps, publication["store_site"]),
        deps,
        deps["str"],
        deps["r0"],
        deps["r5"],
        publication["field_offset"],
        "ViewSettingMenu manager publication",
    )
    publication_span = _decode(
        blob,
        mappings,
        deps,
        publication["receiver_capture_site"] + 2,
        publication["store_site"],
    )
    if any(deps["r5"] in _written_registers(item) for item in publication_span):
        raise RuntimeError("ViewSettingMenu receiver is not preserved to manager store")

    if _owner(exidx, route["dispatcher_owner"]["start"]) != (
        route["dispatcher_owner"]["start"],
        route["dispatcher_owner"]["end"],
    ):
        raise RuntimeError("ViewSettingMenu action dispatcher owner differs")
    _require_immediate(
        _instruction(blob, mappings, deps, route["selector_limit_site"]),
        deps,
        deps["cmp"],
        deps["r1"],
        route["selector_limit"],
        "ViewSettingMenu selector bound",
    )
    table_branch = _instruction(blob, mappings, deps, route["table_branch_site"])
    if table_branch.id != deps["tbh"] or table_branch.op_str != "[pc, r1, lsl #1]":
        raise RuntimeError("ViewSettingMenu TBH dispatch differs")
    if (
        route["action_table_entry_site"]
        != table_branch.address + 4 + route["action_selector"] * 2
        or _halfword(blob, mappings, route["action_table_entry_site"])
        != route["action_table_entry_halfword"]
        or table_branch.address
        + 4
        + route["action_table_entry_halfword"] * 2
        != route["action_landing"]
    ):
        raise RuntimeError("ViewSettingMenu selector-10 table entry differs")
    landing = _instruction(blob, mappings, deps, route["action_landing"])
    tail = _instruction(blob, mappings, deps, route["action_tail_site"])
    if (
        landing.id != deps["pop"]
        or tail.mnemonic != "b.w"
        or _direct_target(tail, deps) != route["action_target"]
    ):
        raise RuntimeError("ViewSettingMenu selector-10 tail differs")

    if _owner(exidx, route["action_target"]) != (
        route["action_owner"]["start"],
        route["action_owner"]["end"],
    ) or _owner(exidx, route["selected_node_property_helper"]) != (
        route["selected_node_property_helper_owner"]["start"],
        route["selected_node_property_helper_owner"]["end"],
    ):
        raise RuntimeError("ViewSettingMenu action/property helper owner differs")
    _require_mem(
        _instruction(blob, mappings, deps, route["state_field_load_site"]),
        deps,
        deps["ldr"],
        deps["r3"],
        deps["r0"],
        route["state_field_offset"],
        "ViewSettingMenu selected-node state field",
    )
    _require_mov(
        _instruction(blob, mappings, deps, route["receiver_capture_site"]),
        deps,
        deps["r4"],
        deps["r0"],
        "ViewSettingMenu action receiver capture",
    )
    for site, target, label in (
        (
            route["state_1_selected_node_call_site"],
            route["state_1_selected_node_target"],
            "ViewSettingMenu state-1 selected node",
        ),
        (
            route["state_3_probe_call_site"],
            route["state_3_probe_target"],
            "ViewSettingMenu state-3 probe",
        ),
        (
            route["state_3_nonzero_selected_node_call_site"],
            route["state_3_nonzero_selected_node_target"],
            "ViewSettingMenu state-3 nonzero selected node",
        ),
        (
            route["state_3_zero_selected_node_call_site"],
            route["state_3_zero_selected_node_target"],
            "ViewSettingMenu state-3 zero selected node",
        ),
    ):
        if _direct_target(_instruction(blob, mappings, deps, site), deps) != target:
            raise RuntimeError(label + " call differs")
    for site, label in (
        (
            route["state_3_nonzero_receiver_site"],
            "ViewSettingMenu state-3 nonzero receiver",
        ),
        (
            route["state_3_zero_receiver_site"],
            "ViewSettingMenu state-3 zero receiver",
        ),
    ):
        _require_mov(
            _instruction(blob, mappings, deps, site),
            deps,
            deps["r0"],
            deps["r4"],
            label,
        )
    _require_mov(
        _instruction(blob, mappings, deps, route["selected_node_move_site"]),
        deps,
        deps["r1"],
        deps["r0"],
        "ViewSettingMenu selected-node forwarding",
    )
    if (
        _direct_target(
            _instruction(
                blob, mappings, deps, route["selected_node_property_call_site"]
            ),
            deps,
        )
        != route["selected_node_property_helper"]
    ):
        raise RuntimeError("ViewSettingMenu selected-node property call differs")
    _require_mov(
        _instruction(blob, mappings, deps, route["property_result_capture_site"]),
        deps,
        deps["r5"],
        deps["r0"],
        "ViewSettingMenu property-result capture",
    )

    _require_immediate(
        _instruction(
            blob, mappings, deps, route["selected_node_property_key_site"]
        ),
        deps,
        deps["mov"],
        deps["r1"],
        route["selected_node_property_key"],
        "selected-node property key",
    )
    _require_mem(
        _instruction(
            blob, mappings, deps, route["selected_node_property_vptr_load_site"]
        ),
        deps,
        deps["ldr"],
        deps["r3"],
        deps["r1"],
        0,
        "selected-node property vptr",
    )
    _require_mem(
        _instruction(
            blob, mappings, deps, route["selected_node_property_slot_load_site"]
        ),
        deps,
        deps["ldr"],
        deps["r3"],
        deps["r3"],
        route["selected_node_property_slot_offset"],
        "selected-node property slot",
    )
    property_transfer = _instruction(
        blob, mappings, deps, route["selected_node_property_call_transfer_site"]
    )
    if (
        property_transfer.id != deps["blx"]
        or len(property_transfer.operands) != 1
        or property_transfer.operands[0].type != deps["reg"]
        or property_transfer.operands[0].reg != deps["r3"]
    ):
        raise RuntimeError("selected-node property virtual transfer differs")

    _require_relative(
        context,
        index=route["manager_slot_19_relocation_index"],
        site=route["manager_slot_19_cell"],
        target=route["manager_slot_19_target"],
        label="process manager slot 19",
        encoded_target=route["manager_slot_19_target"] | 1,
    )
    if _owner(exidx, route["manager_slot_19_target"]) != (0x4390D4, 0x4390E8):
        raise RuntimeError("process manager slot 19 owner differs")
    for site, register, displacement, label in (
        (route["manager_slot_19_receiver_site"], deps["r0"], 0x16C, "slot 19 receiver"),
        (route["manager_slot_20_receiver_site"], deps["r0"], 0x16C, "slot 20 receiver"),
        (route["condition_load_site"], deps["r2"], 0x174, "slot 20 condition"),
    ):
        _require_mem(
            _instruction(blob, mappings, deps, site),
            deps,
            deps["ldr"],
            register,
            deps["r4"],
            displacement,
            label,
        )
    for site, destination, source, label in (
        (route["manager_slot_19_id_site"], deps["r1"], deps["r5"], "slot 19 process ID"),
        (route["manager_slot_20_id_site"], deps["r1"], deps["r5"], "slot 20 process ID"),
    ):
        _require_mov(
            _instruction(blob, mappings, deps, site),
            deps,
            destination,
            source,
            label,
        )
    for site, base, displacement, label in (
        (route["manager_slot_19_vptr_site"], deps["r0"], 0, "slot 19 vptr"),
        (route["manager_slot_19_load_site"], deps["r3"], 0x4C, "slot 19 target"),
        (route["manager_slot_20_vptr_site"], deps["r0"], 0, "slot 20 vptr"),
        (route["manager_slot_20_load_site"], deps["r3"], 0x50, "slot 20 target"),
    ):
        _require_mem(
            _instruction(blob, mappings, deps, site),
            deps,
            deps["ldr"],
            deps["r3"],
            base,
            displacement,
            label,
        )
    for site, label in (
        (route["manager_slot_19_call_site"], "slot 19 call"),
        (route["manager_slot_20_call_site"], "slot 20 call"),
    ):
        call = _instruction(blob, mappings, deps, site)
        if (
            call.id != deps["blx"]
            or len(call.operands) != 1
            or call.operands[0].type != deps["reg"]
            or call.operands[0].reg != deps["r3"]
        ):
            raise RuntimeError(label + " differs")
    return copy.deepcopy(menu), copy.deepcopy(route)


def _validate_creative_style_property_14(context, deps):
    blob = context["blob"]
    mappings = context["mappings"]
    exidx = context["exidx"]
    evidence = CREATIVE_STYLE_PROPERTY_14

    if _owner(exidx, evidence["property_constructor_owner"]["start"]) != (
        evidence["property_constructor_owner"]["start"],
        evidence["property_constructor_owner"]["end"],
    ):
        raise RuntimeError("Creative Style property constructor owner differs")
    property_pic_base = _word(blob, mappings, 0x825F04) + 0x82520C
    if property_pic_base != evidence["property_pic_base"]:
        raise RuntimeError("Creative Style property PIC base differs")
    property_object_offset = _instruction(blob, mappings, deps, 0x83CCD2)
    property_list_offset = _instruction(blob, mappings, deps, 0x83CCDA)
    if (
        _literal_address(property_object_offset, deps) != 0x83D498
        or _literal_address(property_list_offset, deps) != 0x83D49C
        or property_pic_base + _word(blob, mappings, 0x83D498)
        != evidence["property_object_got_cell"]
        or property_pic_base + _word(blob, mappings, 0x83D49C)
        != evidence["property_list_got_cell"]
    ):
        raise RuntimeError("Creative Style property GOT materialization differs")
    property_object_load = _instruction(
        blob, mappings, deps, evidence["property_object_load_site"]
    )
    property_list_load = _instruction(
        blob, mappings, deps, evidence["property_list_load_site"]
    )
    if any(
        (
            item.id != deps["ldr"]
            or item.operands[0].reg != destination
            or item.operands[1].mem.base != deps["r4"]
            or item.operands[1].mem.index != deps["r3"]
            or item.operands[1].mem.disp != 0
        )
        for item, destination in (
            (property_object_load, deps["r0"]),
            (property_list_load, deps["r1"]),
        )
    ):
        raise RuntimeError("Creative Style property object/list load differs")
    _require_immediate(
        _instruction(blob, mappings, deps, evidence["property_count_site"]),
        deps,
        deps["mov"],
        deps["r2"],
        evidence["property_count"],
        "Creative Style property count",
    )
    if (
        _call_symbol(
            blob,
            mappings,
            deps,
            context["plt_symbols"],
            evidence["property_constructor_call_site"],
        )
        != evidence["property_constructor_symbol"]
    ):
        raise RuntimeError("Creative Style property constructor call differs")
    _require_symbol_relocation(
        context,
        index=evidence["property_object_relocation_index"],
        site=evidence["property_object_got_cell"],
        relocation_type=21,
        symbol_index=evidence["property_object_symbol_index"],
        symbol_name="cmnViewSettingPropertiesCreativeStyleRoot",
        symbol_value=evidence["properties_object"],
        symbol_size=8,
        label="Creative Style property object",
    )
    _require_symbol_relocation(
        context,
        index=evidence["property_list_relocation_index"],
        site=evidence["property_list_got_cell"],
        relocation_type=21,
        symbol_index=evidence["property_list_symbol_index"],
        symbol_name="cmnViewSettingPropertyListCreativeStyleRoot",
        symbol_value=evidence["property_list"],
        symbol_size=96,
        label="Creative Style property list",
    )
    words = tuple(
        _word(blob, mappings, evidence["record_address"] + offset)
        for offset in (0, 4, 8)
    )
    if words != (
        evidence["record"]["key"],
        evidence["record"]["type"],
        evidence["record"]["value"],
    ):
        raise RuntimeError("Creative Style property-14 record differs")

    if _owner(exidx, evidence["root_constructor_owner"]["start"]) != (
        evidence["root_constructor_owner"]["start"],
        evidence["root_constructor_owner"]["end"],
    ):
        raise RuntimeError("Creative Style root-construction owner differs")
    root_pic_base = _word(blob, mappings, 0x93B050) + 0x93B004
    if root_pic_base != evidence["property_pic_base"]:
        raise RuntimeError("Creative Style root-construction PIC base differs")
    root_offset = _instruction(blob, mappings, deps, 0x93B330)
    root_properties_offset = _instruction(blob, mappings, deps, 0x93B33C)
    if (
        _literal_address(root_offset, deps) != 0x93BD34
        or _literal_address(root_properties_offset, deps) != 0x93BD38
        or root_pic_base + _word(blob, mappings, 0x93BD34)
        != evidence["root_got_cell"]
        or root_pic_base + _word(blob, mappings, 0x93BD38)
        != evidence["property_object_got_cell"]
    ):
        raise RuntimeError("Creative Style root/property GOT materialization differs")
    root_load = _instruction(blob, mappings, deps, evidence["root_receiver_load_site"])
    root_properties_load = _instruction(
        blob, mappings, deps, evidence["root_properties_load_site"]
    )
    if (
        root_load.id != deps["ldr"]
        or root_load.operands[0].reg != deps["r8"]
        or root_load.operands[1].mem.base != deps["r4"]
        or root_load.operands[1].mem.index != deps["r3"]
        or root_properties_load.id != deps["ldr"]
        or root_properties_load.operands[0].reg != deps["r3"]
        or root_properties_load.operands[1].mem.base != deps["r4"]
        or root_properties_load.operands[1].mem.index != deps["r3"]
    ):
        raise RuntimeError("Creative Style root/property loads differ")
    _require_mov(
        _instruction(blob, mappings, deps, 0x93B340),
        deps,
        deps["r0"],
        deps["r8"],
        "Creative Style root constructor receiver",
    )
    if (
        _call_symbol(
            blob,
            mappings,
            deps,
            context["plt_symbols"],
            evidence["root_constructor_call_site"],
        )
        != evidence["root_constructor_symbol"]
    ):
        raise RuntimeError("Creative Style root constructor call differs")
    _require_symbol_relocation(
        context,
        index=evidence["root_relocation_index"],
        site=evidence["root_got_cell"],
        relocation_type=21,
        symbol_index=evidence["root_symbol_index"],
        symbol_name="cmnViewSettingNodeRootCreativeStyle",
        symbol_value=evidence["root_object"],
        symbol_size=40,
        label="Creative Style root object",
    )

    if _owner(exidx, evidence["derived_constructor_owner"]["start"]) != (
        evidence["derived_constructor_owner"]["start"],
        evidence["derived_constructor_owner"]["end"],
    ) or _owner(exidx, evidence["base_constructor_candidate_owner"]["start"]) != (
        evidence["base_constructor_candidate_owner"]["start"],
        evidence["base_constructor_candidate_owner"]["end"],
    ):
        raise RuntimeError("Creative Style derived/base constructor owner differs")
    if (
        _call_symbol(
            blob,
            mappings,
            deps,
            context["plt_symbols"],
            evidence["base_constructor_call_site"],
        )
        != evidence["base_constructor_symbol"]
    ):
        raise RuntimeError("Creative Style base constructor call differs")
    _require_mem(
        _instruction(
            blob,
            mappings,
            deps,
            evidence["base_constructor_properties_store_site"],
        ),
        deps,
        deps["str"],
        deps["r3"],
        deps["r0"],
        0xC,
        "Creative Style base properties store",
    )
    derived_pic_base = _word(blob, mappings, 0x7DBA6C) + 0x7DBA52
    derived_vtable_cell = derived_pic_base + _word(blob, mappings, 0x7DBA70)
    if (
        derived_pic_base != evidence["property_pic_base"]
        or derived_vtable_cell != evidence["derived_vtable_got_cell"]
    ):
        raise RuntimeError("Creative Style derived vtable materialization differs")
    _require_symbol_relocation(
        context,
        index=evidence["derived_vtable_relocation_index"],
        site=evidence["derived_vtable_got_cell"],
        relocation_type=21,
        symbol_index=evidence["derived_vtable_symbol_index"],
        symbol_name="_ZTV31CmnViewSettingNodeCreativeStyle",
        symbol_value=evidence["derived_vtable_header"],
        symbol_size=268,
        label="Creative Style derived vtable",
    )
    vptr_store = _instruction(blob, mappings, deps, evidence["derived_vptr_store_site"])
    if (
        vptr_store.id != deps["str"]
        or vptr_store.operands[0].reg != deps["r3"]
        or vptr_store.operands[1].mem.base != deps["r4"]
        or vptr_store.operands[1].mem.index != 0
        or vptr_store.operands[1].mem.disp != 0
    ):
        raise RuntimeError("Creative Style derived vptr store differs")
    _require_symbol_relocation(
        context,
        index=evidence["get_int_property_relocation_index"],
        site=evidence["get_int_property_cell"],
        relocation_type=2,
        symbol_index=evidence["get_int_property_symbol_index"],
        symbol_name="_ZN18CmnViewSettingNode14getIntPropertyEiRi",
        symbol_value=evidence["get_int_property_target"] | 1,
        symbol_size=18,
        label="Creative Style getIntProperty slot",
    )
    if _owner(exidx, evidence["get_int_property_target"]) != (0x7C74D0, 0x7C752C):
        raise RuntimeError("Creative Style getIntProperty owner differs")
    return copy.deepcopy(evidence)


def _written_registers(instruction):
    try:
        return set(instruction.regs_access()[1])
    except (AttributeError, ValueError):
        return set()


def _canonical_calls(context, deps):
    blob = context["blob"]
    mappings = context["mappings"]
    decoder = deps["Cs"](deps["arch"], deps["mode"])
    decoder.detail = True
    result = []
    complete_count = 0
    incomplete_count = 0
    direct_inbound = {
        MANAGER_IDENTITY["bridge_target"]: [],
        TYPED_ACTIVATION_DEPENDENCY["wrapper_target"]: [],
    }
    for start, end in context["exidx"]:
        items = list(decoder.disasm(_at(blob, mappings, start, end - start), start))
        complete = bool(
            items
            and items[0].address == start
            and items[-1].address + items[-1].size == end
        )
        for item in items:
            if not (item.group(deps["call_group"]) or item.group(deps["jump_group"])):
                continue
            target = _direct_target(item, deps)
            if target in direct_inbound:
                direct_inbound[target].append(
                    (item.address & ~1, start, end, item.mnemonic)
                )
        if not complete:
            incomplete_count += 1
            continue
        complete_count += 1
        for call_index, call in enumerate(items):
            if (
                call.id != deps["blx"]
                or len(call.operands) != 1
                or call.operands[0].type != deps["reg"]
            ):
                continue
            call_register = call.operands[0].reg
            slot_index = call_index - 1
            if slot_index < 0:
                continue
            slot = items[slot_index]
            if (
                slot.id != deps["ldr"]
                or len(slot.operands) != 2
                or slot.operands[0].type != deps["reg"]
                or slot.operands[0].reg != call_register
                or slot.operands[1].type != deps["mem"]
                or slot.operands[1].mem.index != 0
                or slot.operands[1].mem.disp != 0x50
            ):
                continue
            vptr_register = slot.operands[1].mem.base
            vptr_index = None
            for candidate_index in range(max(0, slot_index - 3), slot_index):
                candidate = items[candidate_index]
                if (
                    candidate.id == deps["ldr"]
                    and len(candidate.operands) == 2
                    and candidate.operands[0].type == deps["reg"]
                    and candidate.operands[0].reg == vptr_register
                    and candidate.operands[1].type == deps["mem"]
                    and candidate.operands[1].mem.index == 0
                    and candidate.operands[1].mem.disp == 0
                ):
                    between = items[candidate_index + 1 : slot_index]
                    if not any(vptr_register in _written_registers(item) for item in between):
                        vptr_index = candidate_index
            if vptr_index is None:
                continue
            receiver_register = items[vptr_index].operands[1].mem.base
            is_viewsettingmenu_route = (
                start == ACTION_TO_MANAGER_ROUTE["action_owner"]["start"]
                and end == ACTION_TO_MANAGER_ROUTE["action_owner"]["end"]
                and items[vptr_index].address
                == ACTION_TO_MANAGER_ROUTE["manager_slot_20_vptr_site"]
                and slot.address == ACTION_TO_MANAGER_ROUTE["manager_slot_20_load_site"]
                and call.address == ACTION_TO_MANAGER_ROUTE["manager_slot_20_call_site"]
                and receiver_register == deps["r0"]
            )
            result.append(
                {
                    "owner": {"start": start, "end": end, "complete": True},
                    "vptr_load_site": items[vptr_index].address,
                    "slot_load_site": slot.address,
                    "call_site": call.address,
                    "receiver_register": decoder.reg_name(receiver_register),
                    "manager_receiver_proven": is_viewsettingmenu_route,
                    "manager_vptr_proven": is_viewsettingmenu_route,
                    "process_id_source_proven": is_viewsettingmenu_route,
                    "process_id_42_proven": False,
                    "condition_r2_proven": is_viewsettingmenu_route,
                    "accepted": False,
                }
            )
    return (
        result,
        complete_count,
        incomplete_count,
        {
            target: list(dict.fromkeys(matches))
            for target, matches in direct_inbound.items()
        },
    )


def _caller_scan(context, deps):
    calls, complete_count, incomplete_count, direct_inbound = _canonical_calls(
        context, deps
    )
    return {
        "exidx_owner_count": len(context["exidx"]),
        "fully_decoded_owner_count": complete_count,
        "incomplete_or_terminal_owner_count": incomplete_count,
        "canonical_slot_offset": 0x50,
        "canonical_slot_20_calls": calls,
        "accepted_candidates": [item for item in calls if item["accepted"]],
        "manager_bridge_direct_inbound": direct_inbound[
            MANAGER_IDENTITY["bridge_target"]
        ],
        "typed_wrapper_direct_inbound": direct_inbound[
            TYPED_ACTIVATION_DEPENDENCY["wrapper_target"]
        ],
        "direct_inbound_scan_complete": incomplete_count == 0,
        "whole_program_absence_proven": False,
        "unresolved_universes": [
            "decode-incomplete-or-terminal-exidx-owners",
            "noncanonical-virtual-dispatch",
            "indirect-callback-or-runtime-initialized-receiver",
            "cross-module-or-loader-mediated-delivery",
        ],
    }


def _validate_caller_scan(context, deps):
    scan = _caller_scan(context, deps)
    if scan != EXPECTED_EXPORT["caller_scan"]:
        raise RuntimeError("bounded Creative Style activation caller inventory differs")
    return scan


def _build_raw_export_from_blob(blob, caution_blob, deps):
    if len(blob) != SOURCE["size"] or _sha256_bytes(blob) != SOURCE["sha256"]:
        raise RuntimeError("viewUnified2 source identity differs")
    if (
        len(caution_blob) != SUPPORTING_SOURCE["size"]
        or _sha256_bytes(caution_blob) != SUPPORTING_SOURCE["sha256"]
    ):
        raise RuntimeError("CautionConfig supporting source identity differs")
    context = _context(blob, deps)
    caution_context = _context(caution_blob, deps)
    viewsettingmenu, action_route = _validate_viewsettingmenu_route(context, deps)
    document = {
        "schema_version": 2,
        "analysis_mode": "offline-static-creative-style-activation-caller-boundary",
        "source": copy.deepcopy(SOURCE),
        "supporting_source": copy.deepcopy(SUPPORTING_SOURCE),
        "dependency": copy.deepcopy(DEPENDENCY),
        "supporting_dependency": copy.deepcopy(SUPPORTING_DEPENDENCY),
        "manager_identity": _validate_manager_identity(context, deps),
        "typed_activation_dependency": _validate_typed_dependency(context),
        "viewsettingmenu_identity": viewsettingmenu,
        "action_to_manager_route": action_route,
        "creative_style_property_14": _validate_creative_style_property_14(
            caution_context, deps
        ),
        "selected_node_identity_boundary": copy.deepcopy(
            SELECTED_NODE_IDENTITY_BOUNDARY
        ),
        "caller_scan": _validate_caller_scan(context, deps),
        "claims": copy.deepcopy(CLAIMS),
        "readiness": READINESS,
        "first_unresolved_boundary": FIRST_UNRESOLVED_BOUNDARY,
    }
    return normalize_creative_style_activation_caller_boundary_export(document)


def build_raw_export():
    _validate_dependency()
    return _build_raw_export_from_blob(
        SOURCE_PATH.read_bytes(), CAUTION_SOURCE_PATH.read_bytes(), _dependencies()
    )


def build_outputs():
    raw = normalize_creative_style_activation_caller_boundary_export(
        build_raw_export()
    )
    report = validate_creative_style_activation_caller_boundary_report(
        build_creative_style_activation_caller_boundary_report(raw)
    )
    return {RAW_OUTPUT_PATH: raw, REPORT_PATH: report}


def _encoded(document):
    return (
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def publish_outputs():
    outputs = build_outputs()
    temporary_paths = []
    try:
        for path, document in outputs.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temporary = tempfile.mkstemp(
                prefix=path.name + ".", suffix=".tmp", dir=path.parent
            )
            temporary_path = Path(temporary)
            temporary_paths.append(temporary_path)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(_encoded(document))
                stream.flush()
                os.fsync(stream.fileno())
        for temporary_path, path in zip(temporary_paths, outputs):
            os.replace(temporary_path, path)
        temporary_paths.clear()
    finally:
        for temporary_path in temporary_paths:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
    return outputs


def main():
    outputs = publish_outputs()
    print(
        "CREATIVE_STYLE_ACTIVATION_CALLER_BOUNDARY_EXPORT|"
        f"canonical_calls={len(outputs[RAW_OUTPUT_PATH]['caller_scan']['canonical_slot_20_calls'])}|"
        "accepted=0|runtime=0|installable=0|camera=0"
    )


if __name__ == "__main__":
    main()
