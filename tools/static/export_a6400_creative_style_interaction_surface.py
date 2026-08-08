"""Read-only exporter for the target-native Creative Style interaction surface."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pmca.analysis.creative_style_interaction_surface import (
    EXPECTED_EXPORT,
    SOURCE,
    build_creative_style_interaction_surface_report,
    normalize_creative_style_interaction_surface_export,
    validate_creative_style_interaction_surface_report,
)
from tools.static.export_a6400_creative_style_model_cursor_boundary import (
    _decoded_plt_addresses_exact,
)
from tools.static.export_a6400_creative_style_view_model_binding import (
    SOURCE_PATH,
    _call_symbol,
    _cstring,
    _decode,
    _dependencies,
    _direct_target,
    _instruction,
    _owner,
    _plt_symbols,
    _relocations,
    _sha256,
    _require_register_unchanged,
    _validate_relative,
    _validate_si_rtti,
    _word,
    dependencies_available,
    sources_available,
)
from tools.static.export_a6400_generic_model_owner_provenance import _at, _exidx_ranges, _mappings


ARTIFACT_BASE = ROOT / ".artifacts"
OUTPUT_ROOT = ARTIFACT_BASE / "creative-style-interaction-surface" / "a6400-v2.00"
OUTPUT_NAME = "creative-style-interaction-surface-export.json"
REPORT_PATH = ROOT / "analysis" / "a6400-creative-style-interaction-surface.json"
LIBOBJ_SOURCE_PATH = SOURCE_PATH.with_name("libObj.so")


def _require_mov_immediate(item, deps, register, value, label):
    if (
        item.id != deps["mov"] or len(item.operands) != 2
        or item.operands[0].type != deps["reg"] or item.operands[0].reg != register
        or item.operands[1].type != deps["imm"] or item.operands[1].imm != value
    ):
        raise RuntimeError(label + " differs")


def _literal_site(item, deps):
    if item.id != deps["ldr"] or item.operands[1].type != deps["mem"] or item.operands[1].mem.base != deps["pc"]:
        raise RuntimeError("PC-relative literal load differs")
    return ((item.address + 4) & ~3) + item.operands[1].mem.disp


def _validate_typed_vtable(blob, mappings, rels, by_site, *, address_point, rtti):
    header = address_point - 8
    if _word(blob, mappings, header, signed=True) != 0:
        raise RuntimeError("typed vtable offset-to-top differs")
    _index, relocation = by_site[header + 4]
    if (
        relocation["r_info_type"] != 23 or relocation["r_info_sym"] != 0
        or (_word(blob, mappings, header + 4) & ~1) != rtti
    ):
        raise RuntimeError("typed vtable/typeinfo join differs")


def _validate_dispatcher(blob, mappings, deps, rels, by_site, dynsym, exidx):
    expected = EXPECTED_EXPORT["view_dispatcher"]
    _validate_si_rtti(
        None, blob, mappings, rels, by_site, dynsym,
        rtti=expected["rtti"], encoding="17ViewCreativeStyle", base="_ZTI13ViewBaseForMR",
    )
    _validate_typed_vtable(
        blob, mappings, rels, by_site,
        address_point=expected["vtable_address_point"], rtti=expected["rtti"],
    )
    if expected["cell"] != expected["vtable_address_point"] + expected["slot"] * 4:
        raise RuntimeError("Creative Style dispatcher slot relation differs")
    _validate_relative(
        rels, by_site, blob, mappings, index=expected["relocation_index"],
        site=expected["cell"], target=expected["target"],
    )
    owner = expected["owner"]
    if not owner["complete"] or _owner(exidx, expected["target"]) != (owner["start"], owner["end"]):
        raise RuntimeError("Creative Style interaction dispatcher owner differs")
    compare = _instruction(blob, mappings, deps, expected["compare_site"])
    branch = _instruction(blob, mappings, deps, expected["branch_site"])
    table_branch = _instruction(blob, mappings, deps, expected["table_branch_site"])
    memory = table_branch.operands[0].mem
    if (
        compare.id != deps["cmp"] or compare.operands[0].reg != deps["r1"]
        or compare.operands[1].imm != expected["case_count"] - 1
        or branch.mnemonic != "bhi" or _direct_target(branch, deps) != expected["out_of_range_target"]
        or compare.address + compare.size != branch.address
        or branch.address + branch.size != table_branch.address
        or table_branch.id != deps["tbh"] or memory.base != deps["pc"]
        or memory.index != deps["r1"] or memory.lshift != 1
        or expected["table_start"] != table_branch.address + 4
        or expected["table_start"] + expected["case_count"] * 2 > owner["end"]
    ):
        raise RuntimeError("Creative Style interaction dispatcher guard/table differs")
    _require_register_unchanged(
        _decode(blob, mappings, deps, expected["target"], expected["compare_site"], complete=False),
        deps["r1"], label="Creative Style interaction selector preservation",
    )
    for index_text, target in expected["selected_cases"].items():
        index = int(index_text)
        entry = expected["table_start"] + index * 2
        # Read the 16-bit TBH entry without widening into the neighboring entry.
        landing = expected["table_start"] + 2 * int.from_bytes(_at(blob, mappings, entry, 2), "little")
        candidates = _decode(blob, mappings, deps, landing, min(landing + 10, owner["end"]), complete=False)
        transfers = [
            _direct_target(item, deps) for item in candidates[:3]
            if (item.group(deps["call_group"]) or item.group(deps["jump_group"]))
            and _direct_target(item, deps) is not None
        ]
        if not transfers or transfers[0] != target:
            raise RuntimeError("Creative Style selected dispatcher case differs")
    return copy.deepcopy(expected)


def _validate_layout(blob, mappings, deps, rels, by_site, dynsym, plt_symbols, exidx):
    expected = EXPECTED_EXPORT["creative_style_layout"]
    owner = expected["initializer_owner"]
    if not owner["complete"] or _owner(exidx, owner["start"]) != (owner["start"], owner["end"]):
        raise RuntimeError("Creative Style layout initializer owner differs")
    dispatcher = EXPECTED_EXPORT["view_dispatcher"]
    if expected["initializer_cell"] != dispatcher["vtable_address_point"] + expected["initializer_slot"] * 4:
        raise RuntimeError("Creative Style layout initializer slot relation differs")
    _validate_relative(
        rels, by_site, blob, mappings, index=expected["initializer_relocation_index"],
        site=expected["initializer_cell"], target=owner["start"],
    )
    if _call_symbol(blob, mappings, deps, plt_symbols, expected["layout_call_site"]) != expected["layout_call_symbol"]:
        raise RuntimeError("Creative Style layout-management call differs")
    key_load = _instruction(blob, mappings, deps, expected["layout_key_load_site"])
    if (
        _literal_site(key_load, deps) != expected["layout_key_literal_site"]
        or key_load.operands[0].reg != deps["r1"]
        or _word(blob, mappings, expected["layout_key_literal_site"]) != expected["layout_key"]
    ):
        raise RuntimeError("Creative Style layout key differs")

    callback = expected["callback_got"]
    base_load = _instruction(blob, mappings, deps, callback["base_literal_load_site"])
    index_load = _instruction(blob, mappings, deps, callback["index_literal_load_site"])
    base_add = _instruction(blob, mappings, deps, callback["base_add_site"])
    got_load = _instruction(blob, mappings, deps, callback["load_site"])
    if (
        _literal_site(base_load, deps) != callback["base_literal_site"]
        or base_load.operands[0].reg != deps["r3"]
        or _literal_site(index_load, deps) != callback["index_literal_site"]
        or index_load.operands[0].reg != deps["r2"]
        or base_add.id != deps["add"] or base_add.operands[0].reg != deps["r3"] or base_add.operands[1].reg != deps["pc"]
        or got_load.id != deps["ldr"] or got_load.operands[0].reg != deps["r2"]
        or got_load.operands[1].mem.base != deps["r3"] or got_load.operands[1].mem.index != deps["r2"]
    ):
        raise RuntimeError("Creative Style layout callback GOT dataflow differs")
    calculated_got = (
        callback["base_add_site"] + 4
        + _word(blob, mappings, callback["base_literal_site"])
        + _word(blob, mappings, callback["index_literal_site"])
    ) & 0xFFFFFFFF
    if calculated_got != callback["got_cell"]:
        raise RuntimeError("Creative Style layout callback GOT cell differs")
    _validate_relative(
        rels, by_site, blob, mappings, index=callback["relocation_index"],
        site=callback["got_cell"], target=expected["layout_callback"],
    )
    callback_owner = expected["layout_callback_owner"]
    if not callback_owner["complete"] or _owner(exidx, expected["layout_callback"]) != (callback_owner["start"], callback_owner["end"]):
        raise RuntimeError("Creative Style layout callback owner differs")
    callback_symbols = [
        symbol for symbol in dynsym.iter_symbols()
        if symbol["st_shndx"] != "SHN_UNDEF"
        and (int(symbol["st_value"]) & ~1) == expected["layout_callback"]
    ]
    if bool(callback_symbols) != expected["layout_callback_symbol_found"]:
        raise RuntimeError("Creative Style layout callback symbol classification differs")

    this_capture = _instruction(blob, mappings, deps, 0x5CCFB2)
    if this_capture.id != deps["mov"] or this_capture.operands[0].reg != deps["r4"] or this_capture.operands[1].reg != deps["r0"]:
        raise RuntimeError("Creative Style layout receiver capture differs")

    for helper in expected["helpers"]:
        size_item = _instruction(blob, mappings, deps, helper["size_site"])
        _require_mov_immediate(size_item, deps, deps["r0"], helper["size"], "Creative Style helper allocation size")
        if _call_symbol(blob, mappings, deps, plt_symbols, helper["allocation_site"]) != "_Znwj":
            raise RuntimeError("Creative Style helper allocation call differs")
        capture = _instruction(blob, mappings, deps, helper["result_capture_site"])
        store = _instruction(blob, mappings, deps, helper["store_site"])
        if (
            capture.id != deps["mov"] or capture.operands[0].reg != deps["r5"] or capture.operands[1].reg != deps["r0"]
            or _call_symbol(blob, mappings, deps, plt_symbols, helper["constructor_site"]) != helper["constructor_symbol"]
            or store.id != deps["str"] or store.operands[0].reg != deps["r5"]
            or store.operands[1].mem.base != deps["r4"] or store.operands[1].mem.disp != helper["object_offset"]
        ):
            raise RuntimeError("Creative Style helper construction/store differs")
    return copy.deepcopy(expected)


def _validate_menu_table(blob, mappings, deps, plt_symbols, exidx):
    expected = EXPECTED_EXPORT["menu_table"]
    if EXPECTED_EXPORT["view_dispatcher"]["selected_cases"][str(expected["case_index"])] != expected["target"]:
        raise RuntimeError("Creative Style menu-table case differs")
    owner = expected["owner"]
    if not owner["complete"] or _owner(exidx, expected["target"]) != (owner["start"], owner["end"]):
        raise RuntimeError("Creative Style menu-table owner differs")
    if _call_symbol(blob, mappings, deps, plt_symbols, expected["init_call_site"]) != expected["init_symbol"]:
        raise RuntimeError("Creative Style menu-table initializer differs")
    receiver = _instruction(blob, mappings, deps, expected["receiver_load_site"])
    menu_data = _instruction(blob, mappings, deps, expected["menu_data_address_site"])
    table_load = _instruction(blob, mappings, deps, expected["table_literal_load_site"])
    table_add = _instruction(blob, mappings, deps, expected["table_address_add_site"])
    this_capture = _instruction(blob, mappings, deps, 0x5CF39E)
    if (
        this_capture.id != deps["mov"] or this_capture.operands[0].reg != deps["r4"] or this_capture.operands[1].reg != deps["r0"]
        or receiver.id != deps["ldr"] or receiver.operands[0].reg != deps["r0"]
        or receiver.operands[1].mem.base != deps["r0"] or receiver.operands[1].mem.disp != expected["receiver_offset"]
        or menu_data.id != deps["add"] or menu_data.operands[0].reg != deps["r1"]
        or menu_data.operands[1].reg != deps["r4"] or menu_data.operands[2].imm != expected["menu_data_offset"]
        or _literal_site(table_load, deps) != expected["table_literal_site"] or table_load.operands[0].reg != deps["r2"]
        or table_add.id != deps["add"] or table_add.operands[0].reg != deps["r2"] or table_add.operands[1].reg != deps["pc"]
    ):
        raise RuntimeError("Creative Style menu-table argument dataflow differs")

    loop = expected["index_loop"]
    init = _instruction(blob, mappings, deps, loop["init_site"])
    index = _instruction(blob, mappings, deps, loop["body_start"])
    increment = _instruction(blob, mappings, deps, 0x5CF3B8)
    compare = _instruction(blob, mappings, deps, loop["compare_site"])
    backedge = _instruction(blob, mappings, deps, loop["backedge_site"])
    _require_mov_immediate(init, deps, deps["r5"], loop["first"], "Creative Style menu index initialization")
    if (
        index.id != deps["mov"] or index.operands[0].reg != deps["r1"] or index.operands[1].reg != deps["r5"]
        or increment.id != deps["add"] or increment.operands[0].reg != deps["r5"] or increment.operands[1].imm != 1
        or _instruction(blob, mappings, deps, loop["helper_call_site"]).id != deps["bl"]
        or _direct_target(_instruction(blob, mappings, deps, loop["helper_call_site"]), deps) != loop["helper"]
        or compare.id != deps["cmp"] or compare.operands[0].reg != deps["r5"]
        or compare.operands[1].imm != loop["iteration_count"]
        or compare.address + compare.size != backedge.address
        or backedge.mnemonic != "bne" or not backedge.group(deps["jump_group"])
        or _direct_target(backedge, deps) != loop["body_start"]
        or loop["last"] != loop["first"] + loop["iteration_count"] - 1
    ):
        raise RuntimeError("Creative Style menu index-loop differs")
    _require_register_unchanged(
        _decode(blob, mappings, deps, increment.address + increment.size, compare.address, complete=False),
        deps["r5"], label="Creative Style menu loop counter preservation",
    )
    for site in expected["set_greyout_call_sites"]:
        if _call_symbol(blob, mappings, deps, plt_symbols, site) != expected["set_greyout_symbol"]:
            raise RuntimeError("Creative Style greyout call inventory differs")
    return copy.deepcopy(expected)


def _validate_belt_cursor(blob, mappings, deps, plt_symbols, exidx):
    expected = EXPECTED_EXPORT["belt_cursor"]
    if EXPECTED_EXPORT["view_dispatcher"]["selected_cases"][str(expected["case_index"])] != expected["target"]:
        raise RuntimeError("Creative Style belt case differs")
    owner = expected["owner"]
    if not owner["complete"] or _owner(exidx, expected["target"]) != (owner["start"], owner["end"]):
        raise RuntimeError("Creative Style belt owner differs")
    belt = _instruction(blob, mappings, deps, expected["belt_load_site"])
    null_test = _instruction(blob, mappings, deps, expected["null_test_site"])
    null_branch = _instruction(blob, mappings, deps, expected["null_branch_site"])
    menu = _instruction(blob, mappings, deps, expected["menu_util_load_site"])
    flag_1 = _instruction(blob, mappings, deps, expected["flag_1_site"])
    flag_2 = _instruction(blob, mappings, deps, expected["flag_2_site"])
    if (
        belt.id != deps["ldr"] or belt.operands[0].reg != deps["r1"]
        or belt.operands[1].mem.base != deps["r0"] or belt.operands[1].mem.disp != expected["belt_object_offset"]
        or null_test.id != deps["cmp"] or null_test.operands[0].reg != deps["r1"] or null_test.operands[1].imm != 0
        or null_test.address + null_test.size != null_branch.address
        or null_branch.mnemonic != "beq" or _direct_target(null_branch, deps) != 0x5CE170
        or menu.id != deps["ldr"] or menu.operands[0].reg != deps["r0"]
        or menu.operands[1].mem.base != deps["r0"] or menu.operands[1].mem.disp != expected["menu_util_offset"]
        or _call_symbol(blob, mappings, deps, plt_symbols, expected["update_call_site"]) != expected["update_symbol"]
        or _call_symbol(blob, mappings, deps, plt_symbols, expected["get_menu_id_call_site"]) != expected["get_menu_id_symbol"]
        or _call_symbol(blob, mappings, deps, plt_symbols, expected["widget_lookup_call_site"]) != expected["widget_lookup_symbol"]
        or _direct_target(_instruction(blob, mappings, deps, expected["post_lookup_local_call_site"]), deps) != expected["post_lookup_local_target"]
    ):
        raise RuntimeError("Creative Style belt/widget call boundary differs")
    _require_register_unchanged(
        _decode(blob, mappings, deps, belt.address + belt.size, expected["update_call_site"], complete=False),
        deps["r1"], label="Creative Style belt pointer preservation",
    )
    _require_mov_immediate(flag_1, deps, deps["r2"], int(expected["flag_1"]), "Creative Style belt flag one")
    _require_mov_immediate(flag_2, deps, deps["r3"], int(expected["flag_2"]), "Creative Style belt flag two")
    for name in ("positive_widget_id", "nonpositive_widget_id"):
        record = expected[name]
        item = _instruction(blob, mappings, deps, record["load_site"])
        if (
            _literal_site(item, deps) != record["literal_site"] or item.operands[0].reg != deps["r1"]
            or _word(blob, mappings, record["literal_site"]) != record["value"]
        ):
            raise RuntimeError("Creative Style branch-selected widget ID differs")
    selector = expected["widget_selector"]
    value_load = _instruction(blob, mappings, deps, selector["value_load_site"])
    compare = _instruction(blob, mappings, deps, selector["compare_site"])
    it = _instruction(blob, mappings, deps, selector["it_site"])
    positive = _instruction(blob, mappings, deps, expected["positive_widget_id"]["load_site"])
    nonpositive = _instruction(blob, mappings, deps, expected["nonpositive_widget_id"]["load_site"])
    if (
        value_load.id != deps["ldr"] or value_load.operands[0].reg != deps["r3"]
        or value_load.operands[1].mem.base != deps["r7"] or value_load.operands[1].mem.disp != selector["value_offset"]
        or compare.id != deps["cmp"] or compare.operands[0].reg != deps["r3"] or compare.operands[1].imm != 0
        or compare.address + compare.size != it.address or it.mnemonic != "ite" or it.op_str != "gt"
        or positive.id != deps["ldr"] or nonpositive.id != deps["ldr"]
        or nonpositive.address + nonpositive.size != expected["widget_lookup_call_site"]
        or expected["widget_lookup_call_site"] + _instruction(blob, mappings, deps, expected["widget_lookup_call_site"]).size
        != expected["post_lookup_local_call_site"]
    ):
        raise RuntimeError("Creative Style branch-selected widget dataflow differs")
    return copy.deepcopy(expected)


def _validate_post_lookup_widget_cast(blob, mappings, deps, elf, plt_symbols, exidx):
    """Bound the post-lookup thunk as a generic PAS_BtnCombo cast only."""
    expected = EXPECTED_EXPORT["post_lookup_widget_cast"]
    call = _instruction(blob, mappings, deps, expected["call"]["site"])
    tail = _instruction(blob, mappings, deps, expected["tail"]["site"])
    gate = _instruction(blob, mappings, deps, expected["interworking_gate"])
    if (
        not call.group(deps["call_group"])
        or _direct_target(call, deps) != expected["call"]["target"]
        or _owner(exidx, expected["call"]["target"])
        != (expected["thunk_owner"]["start"], expected["thunk_owner"]["end"])
        or not tail.group(deps["jump_group"])
        or tail.group(deps["call_group"])
        or _direct_target(tail, deps) != expected["tail"]["target"]
        or expected["interworking_veneer"] != expected["interworking_gate"] + 4
        or gate.id != deps["bx"]
        or len(gate.operands) != 1
        or gate.operands[0].type != deps["reg"]
        or gate.operands[0].reg != deps["pc"]
    ):
        raise RuntimeError("Creative Style post-lookup cast thunk differs")

    got_to_veneer = _decoded_plt_addresses_exact(elf, blob, mappings)
    relplt = list(elf.get_section_by_name(".rel.plt").iter_relocations())
    dynsym = elf.get_section_by_name(".dynsym")
    relocation = relplt[expected["rel_plt_index"]]
    symbol_entry = dynsym.get_symbol(relocation["r_info_sym"])
    symbol = symbol_entry.name
    owner = expected["cast_owner"]
    if (
        got_to_veneer.get(expected["got"]) != expected["interworking_veneer"]
        or relocation["r_offset"] != expected["got"]
        or relocation["r_info_type"] != 22
        or symbol != expected["symbol"]
        or symbol_entry["st_shndx"] == "SHN_UNDEF"
        or (symbol_entry["st_value"] & ~1) != owner["start"]
        or symbol_entry["st_size"] != owner["end"] - owner["start"]
        or plt_symbols.get(expected["interworking_veneer"]) != expected["symbol"]
    ):
        raise RuntimeError("Creative Style post-lookup cast PLT binding differs")

    if _owner(exidx, owner["start"]) != (owner["start"], owner["end"]):
        raise RuntimeError("PAS_BtnCombo cast owner differs")
    capture = _instruction(blob, mappings, deps, expected["original_widget_capture_site"])
    null_input = _instruction(blob, mappings, deps, expected["null_input_branch_site"])
    vptr = _instruction(blob, mappings, deps, expected["vptr_load_site"])
    slot = _instruction(blob, mappings, deps, expected["virtual_type_slot_load_site"])
    virtual_call = _instruction(blob, mappings, deps, expected["virtual_type_call_site"])
    comparison = _instruction(blob, mappings, deps, expected["type_compare_site"])
    conditional_items = {
        item.address: item for item in _decode(
            blob, mappings, deps,
            expected["result_select_site"], expected["null_result_site"] + 2,
        )
    }
    try:
        selection = conditional_items[expected["result_select_site"]]
        original_result = conditional_items[expected["original_widget_return_site"]]
        null_result = conditional_items[expected["null_result_site"]]
    except KeyError as error:
        raise RuntimeError("PAS_BtnCombo conditional result sequence differs") from error
    null_input_return = _instruction(blob, mappings, deps, expected["null_input_return_site"])
    if (
        capture.id != deps["mov"]
        or [operand.type for operand in capture.operands] != [deps["reg"], deps["reg"]]
        or capture.operands[0].reg != deps["r5"]
        or capture.operands[1].reg != deps["r0"]
        or null_input.mnemonic != "cbz"
        or len(null_input.operands) != 2
        or null_input.operands[0].type != deps["reg"]
        or null_input.operands[0].reg != deps["r0"]
        or _direct_target(null_input, deps) != expected["null_input_return_site"]
        or vptr.id != deps["ldr"]
        or len(vptr.operands) != 2
        or vptr.operands[0].type != deps["reg"]
        or vptr.operands[0].reg != deps["r3"]
        or vptr.operands[1].type != deps["mem"]
        or vptr.operands[1].mem.base != deps["r0"]
        or vptr.operands[1].mem.index != 0
        or vptr.operands[1].mem.disp != 0
        or slot.id != deps["ldr"]
        or len(slot.operands) != 2
        or slot.operands[0].type != deps["reg"]
        or slot.operands[0].reg != deps["r3"]
        or slot.operands[1].type != deps["mem"]
        or slot.operands[1].mem.base != deps["r3"]
        or slot.operands[1].mem.index != 0
        or slot.operands[1].mem.disp != expected["virtual_type_slot"]
        or virtual_call.id != deps["blx"]
        or not virtual_call.group(deps["call_group"])
        or len(virtual_call.operands) != 1
        or virtual_call.operands[0].type != deps["reg"]
        or virtual_call.operands[0].reg != deps["r3"]
        or comparison.id != deps["cmp"]
        or [operand.type for operand in comparison.operands] != [deps["reg"], deps["reg"]]
        or comparison.operands[0].reg != deps["r3"]
        or comparison.operands[1].reg != deps["r0"]
        or selection.mnemonic != "ite"
        or selection.cc != original_result.cc
        or original_result.mnemonic != "moveq"
        or original_result.id != deps["mov"]
        or [operand.type for operand in original_result.operands] != [deps["reg"], deps["reg"]]
        or original_result.operands[0].reg != deps["r0"]
        or original_result.operands[1].reg != deps["r5"]
        or null_result.mnemonic != "movne"
        or null_result.cc == original_result.cc
        or null_result.id != deps["mov"]
        or [operand.type for operand in null_result.operands] != [deps["reg"], deps["imm"]]
        or null_result.operands[0].reg != deps["r0"]
        or null_result.operands[1].imm != 0
        or null_input_return.id != deps["pop"]
        or not null_input_return.operands
        or null_input_return.operands[-1].type != deps["reg"]
        or null_input_return.operands[-1].reg != deps["pc"]
    ):
        raise RuntimeError("PAS_BtnCombo cast type filter or result differs")
    _require_register_unchanged(
        _decode(
            blob, mappings, deps,
            expected["original_widget_capture_site"] + capture.size,
            expected["original_widget_return_site"],
            complete=False,
        ),
        deps["r5"], label="PAS_BtnCombo original widget preservation",
    )
    _require_register_unchanged(
        _decode(
            blob, mappings, deps,
            expected["null_input_branch_site"] + null_input.size,
            expected["virtual_type_call_site"],
            complete=False,
        ),
        deps["r0"], label="PAS_BtnCombo virtual receiver preservation",
    )
    return copy.deepcopy(expected)


def _validate_field_0x14c_constructor_boundary(blob, mappings, deps, plt_symbols, exidx):
    """Ensure a bounded constructor scan does not promote the belt member type."""
    expected = EXPECTED_EXPORT["field_0x14c_constructor_boundary"]
    owner = expected["derived_constructor_owner"]
    owners = (
        ("ViewCreativeStyle derived constructor", owner),
        ("ViewBaseForMR default constructor", expected["default_base_constructor_owner"]),
        ("ViewBaseProduct default constructor", expected["default_product_constructor_owner"]),
    )
    for label, candidate in owners:
        if _owner(exidx, candidate["start"]) != (candidate["start"], candidate["end"]):
            raise RuntimeError(label + " owner differs")
    base = expected["derived_base_constructor_call"]
    if _call_symbol(blob, mappings, deps, plt_symbols, base["site"]) != base["symbol"]:
        raise RuntimeError("ViewCreativeStyle base constructor boundary differs")
    for label, candidate in owners:
        for item in _decode(blob, mappings, deps, candidate["start"], candidate["end"]):
            if (
                item.id == deps["str"]
                and len(item.operands) == 2
                and item.operands[1].type == deps["mem"]
                and item.operands[1].mem.disp == 0x14C
            ):
                raise RuntimeError(label + " unexpectedly stores +0x14c")
    # The inherited ViewBase constructor below this external boundary is not
    # joined to this concrete view in the bounded static slice.
    external = expected["external_viewbase_constructor_boundary"]
    if (
        _call_symbol(blob, mappings, deps, plt_symbols, external["site"])
        != external["symbol"]
        or external["resolved"] is not False
    ):
        raise RuntimeError("ViewBase external constructor boundary differs")
    return copy.deepcopy(expected)


def _needed_libraries(elf):
    dynamic = elf.get_section_by_name(".dynamic")
    if dynamic is None:
        raise RuntimeError("dynamic dependency table is unavailable")
    return [tag.needed for tag in dynamic.iter_tags() if tag.entry.d_tag == "DT_NEEDED"]


def _validate_viewbase_constructor_candidate(
    view_blob, view_mappings, view_elf, view_plt_symbols,
    candidate_blob, candidate_mappings, candidate_elf, deps,
):
    """Pin an unbound libObj candidate without inferring Creative Style ownership."""
    expected = EXPECTED_EXPORT["field_0x14c_constructor_boundary"]
    imported = expected["viewbase_constructor_import"]
    if (
        imported["module"] != SOURCE["module"]
        or _call_symbol(view_blob, view_mappings, deps, view_plt_symbols, imported["call_site"])
        != imported["symbol"]
        or _direct_target(_instruction(view_blob, view_mappings, deps, imported["call_site"]), deps)
        != imported["branch_target"]
        or _needed_libraries(view_elf) != imported["declared_dependencies"]
        or imported["candidate_module_declared_dependency"] is not False
        or imported["binding_proven"] is not False
    ):
        raise RuntimeError("ViewBase constructor import boundary differs")
    view_dynsym = view_elf.get_section_by_name(".dynsym")
    view_symbol = view_dynsym.get_symbol(imported["dynsym_index"])
    view_relplt = list(view_elf.get_section_by_name(".rel.plt").iter_relocations())
    view_relocation = view_relplt[imported["rel_plt_index"]]
    if (
        view_symbol.name != imported["symbol"]
        or view_symbol["st_shndx"] != "SHN_UNDEF"
        or imported["symbol_undefined"] is not True
        or view_relocation["r_info_sym"] != imported["dynsym_index"]
        or view_relocation["r_offset"] != imported["got"]
        or view_relocation["r_info_type"] != imported["relocation_type"]
    ):
        raise RuntimeError("ViewBase constructor import relocation differs")

    candidate = expected["libobj_candidate"]
    source = candidate["source"]
    if (
        source["module"] != "lib/libObj.so"
        or LIBOBJ_SOURCE_PATH.stat().st_size != source["size"]
        or _sha256(LIBOBJ_SOURCE_PATH) != source["sha256"]
    ):
        raise RuntimeError("libObj candidate source identity differs")
    candidate_dynsym = candidate_elf.get_section_by_name(".dynsym")
    candidate_symbol = candidate_dynsym.get_symbol(candidate["dynsym_index"])
    owner = candidate["owner"]
    if (
        candidate_symbol.name != candidate["symbol"]
        or candidate_symbol["st_shndx"] == "SHN_UNDEF"
        or candidate_symbol["st_value"] != candidate["symbol_entry"]
        or candidate_symbol["st_size"] != owner["end"] - owner["start"]
        or candidate["symbol_entry"] & ~1 != owner["start"]
    ):
        raise RuntimeError("libObj ViewBase constructor symbol differs")
    items = _decode(candidate_blob, candidate_mappings, deps, owner["start"], owner["end"])
    transfer = _instruction(candidate_blob, candidate_mappings, deps, candidate["receiver_transfer_site"])
    if (
        len(items) != owner["instruction_count"]
        or transfer.id != deps["mov"]
        or len(transfer.operands) != 2
        or transfer.operands[0].type != deps["reg"]
        or transfer.operands[0].reg != deps["r4"]
        or transfer.operands[1].type != deps["reg"]
        or transfer.operands[1].reg != deps["r0"]
    ):
        raise RuntimeError("libObj ViewBase constructor receiver transfer differs")
    stores = {
        f"0x{item.address:x}": operand.mem.disp
        for item in items
        if item.id in (deps["str"], deps["strb"])
        for operand in item.operands
        if operand.type == deps["mem"] and operand.mem.base == deps["r4"]
    }
    if (
        stores != candidate["receiver_store_offsets"]
        or candidate["direct_0x14c_store_found"] is not False
        or 0x14C in stores.values()
    ):
        raise RuntimeError("libObj ViewBase constructor belt-store boundary differs")
    first = candidate["first_plt_boundary"]
    call = _instruction(candidate_blob, candidate_mappings, deps, first["call_site"])
    candidate_relplt = list(candidate_elf.get_section_by_name(".rel.plt").iter_relocations())
    relocation = candidate_relplt[first["rel_plt_index"]]
    called_symbol = candidate_dynsym.get_symbol(relocation["r_info_sym"])
    same_module = candidate_dynsym.get_symbol(first["dynsym_index"])
    if (
        not call.group(deps["call_group"])
        or _direct_target(call, deps) != first["plt_target"]
        or relocation["r_offset"] != first["got"]
        or relocation["r_info_type"] != first["relocation_type"]
        or relocation["r_info_sym"] != first["dynsym_index"]
        or called_symbol.name != first["symbol"]
        or same_module.name != first["symbol"]
        or same_module["st_value"] != first["same_module_definition"]["entry"]
        or same_module["st_size"] != first["same_module_definition"]["size"]
        or first["binding_proven"] is not False
    ):
        raise RuntimeError("libObj ViewBase constructor PLT boundary differs")
    return copy.deepcopy(expected)


def _resolve_pc_string(blob, mappings, deps, record):
    load = _instruction(blob, mappings, deps, record["load_site"])
    add = _instruction(blob, mappings, deps, record["add_site"])
    if (
        _literal_site(load, deps) != record["literal_site"] or load.operands[0].reg != deps["r1"]
        or add.id != deps["add"] or add.operands[0].reg != deps["r1"] or add.operands[1].reg != deps["pc"]
    ):
        raise RuntimeError("Creative Style navigation string dataflow differs")
    return _cstring(blob, mappings, record["add_site"] + 4 + _word(blob, mappings, record["literal_site"]))


def _validate_navigation(blob, mappings, deps, plt_symbols, exidx):
    expected = EXPECTED_EXPORT["navigation"]
    if EXPECTED_EXPORT["view_dispatcher"]["selected_cases"][str(expected["case_index"])] != expected["target"]:
        raise RuntimeError("Creative Style navigation case differs")
    owner = expected["owner"]
    if not owner["complete"] or _owner(exidx, expected["target"]) != (owner["start"], owner["end"]):
        raise RuntimeError("Creative Style navigation owner differs")
    this_capture = _instruction(blob, mappings, deps, 0x5CFD1E)
    field = _instruction(blob, mappings, deps, expected["field_load_site"])
    compare_3 = _instruction(blob, mappings, deps, expected["compare_3_site"])
    branch_not_3 = _instruction(blob, mappings, deps, expected["branch_not_3_site"])
    route_3_join = _instruction(blob, mappings, deps, expected["route_3_join_site"])
    compare_2 = _instruction(blob, mappings, deps, expected["compare_2_site"])
    branch_not_2 = _instruction(blob, mappings, deps, expected["branch_not_2_site"])
    open_r2 = _instruction(blob, mappings, deps, expected["open_argument_sites"]["r2"])
    open_r3 = _instruction(blob, mappings, deps, expected["open_argument_sites"]["r3"])
    if (
        this_capture.id != deps["mov"] or this_capture.operands[0].reg != deps["r4"] or this_capture.operands[1].reg != deps["r0"]
        or field.id != deps["ldr"] or field.operands[0].reg != deps["r3"]
        or field.operands[1].mem.base != deps["r4"] or field.operands[1].mem.disp != expected["field_offset"]
        or compare_3.id != deps["cmp"] or compare_3.operands[0].reg != deps["r3"] or compare_3.operands[1].imm != 3
        or compare_3.address + compare_3.size != branch_not_3.address
        or branch_not_3.mnemonic != "bne" or _direct_target(branch_not_3, deps) != expected["branch_not_3_target"]
        or route_3_join.mnemonic != "b" or _direct_target(route_3_join, deps) != expected["route_3_join_target"]
        or compare_2.id != deps["cmp"] or compare_2.operands[0].reg != deps["r3"] or compare_2.operands[1].imm != 2
        or compare_2.address + compare_2.size != branch_not_2.address
        or branch_not_2.mnemonic != "bne" or _direct_target(branch_not_2, deps) != expected["branch_not_2_target"]
        or _call_symbol(blob, mappings, deps, plt_symbols, expected["open_call_site"]) != expected["open_symbol"]
        or _call_symbol(blob, mappings, deps, plt_symbols, expected["close_call_site"]) != expected["close_symbol"]
    ):
        raise RuntimeError("Creative Style navigation selector differs")
    _require_mov_immediate(open_r2, deps, deps["r2"], 0, "Creative Style openView r2 argument")
    if open_r3.id != deps["mov"] or open_r3.operands[0].reg != deps["r3"] or open_r3.operands[1].reg != deps["r2"]:
        raise RuntimeError("Creative Style openView r3 argument dataflow differs")
    for key, route in expected["routes"].items():
        if _resolve_pc_string(blob, mappings, deps, expected["route_evidence"][key]) != route["name"]:
            raise RuntimeError("Creative Style navigation route string differs")
        receiver = _instruction(blob, mappings, deps, expected["route_evidence"][key]["receiver_site"])
        if receiver.id != deps["mov"] or receiver.operands[0].reg != deps["r0"] or receiver.operands[1].reg != deps["r4"]:
            raise RuntimeError("Creative Style navigation view receiver differs")
    if (
        expected["route_evidence"]["3"]["add_site"] + _instruction(blob, mappings, deps, expected["route_evidence"]["3"]["add_site"]).size
        != expected["route_3_join_site"]
        or expected["route_evidence"]["2"]["add_site"] + _instruction(blob, mappings, deps, expected["route_evidence"]["2"]["add_site"]).size
        != expected["open_argument_sites"]["r2"]
        or expected["route_evidence"]["other"]["add_site"] + _instruction(blob, mappings, deps, expected["route_evidence"]["other"]["add_site"]).size
        != expected["close_call_site"]
    ):
        raise RuntimeError("Creative Style navigation string/call join differs")
    return copy.deepcopy(expected)


def _validate_touchability(blob, mappings, deps, rels, by_site, dynsym, plt_symbols, exidx):
    expected = EXPECTED_EXPORT["touchability_candidate"]
    movie = expected["movie_view"]
    _validate_si_rtti(
        None, blob, mappings, rels, by_site, dynsym,
        rtti=movie["rtti"], encoding="17ViewMovieRecPatch", base="_ZTI13ViewBaseForMR",
    )
    _validate_typed_vtable(
        blob, mappings, rels, by_site,
        address_point=movie["vtable_address_point"], rtti=movie["rtti"],
    )
    _validate_relative(
        rels, by_site, blob, mappings, index=movie["relocation_index"],
        site=movie["cell"], target=movie["slot_target"],
    )
    if (
        movie["cell"] != movie["vtable_address_point"] + movie["slot"] * 4
        or not movie["slot_owner"]["complete"]
        or _owner(exidx, movie["slot_target"]) != (movie["slot_owner"]["start"], movie["slot_owner"]["end"])
        or _direct_target(_instruction(blob, mappings, deps, movie["branch_site"]), deps) != movie["branch_target"]
        or not movie["branch_target_owner"]["complete"]
        or _owner(exidx, movie["branch_target"]) != (movie["branch_target_owner"]["start"], movie["branch_target_owner"]["end"])
        or _call_symbol(blob, mappings, deps, plt_symbols, movie["get_widget_call_site"]) != "_ZN8ViewBase9getWidgetEj"
        or _call_symbol(blob, mappings, deps, plt_symbols, movie["check_widget_call_site"]) != movie["check_widget_symbol"]
        or _call_symbol(blob, mappings, deps, plt_symbols, movie["set_touchable_call_site"]) != movie["set_touchable_symbol"]
    ):
        raise RuntimeError("Movie Rec touchability candidate differs")
    movie_value = _instruction(blob, mappings, deps, movie["set_touchable_value_site"])
    _require_mov_immediate(movie_value, deps, deps["r1"], int(movie["set_touchable_value"]), "Movie Rec touchability value")
    get_widget = _instruction(blob, mappings, deps, movie["get_widget_call_site"])
    check_widget = _instruction(blob, mappings, deps, movie["check_widget_call_site"])
    set_touchable = _instruction(blob, mappings, deps, movie["set_touchable_call_site"])
    if (
        get_widget.address + get_widget.size != check_widget.address
        or movie_value.address + movie_value.size != set_touchable.address
    ):
        raise RuntimeError("Movie Rec widget/check/touchability call join differs")
    _require_register_unchanged(
        _decode(blob, mappings, deps, check_widget.address + check_widget.size, set_touchable.address, complete=False),
        deps["r0"], label="Movie Rec checked BarCtrlDial receiver preservation",
    )

    converter = expected["converter"]
    _validate_si_rtti(
        None, blob, mappings, rels, by_site, dynsym,
        rtti=converter["rtti"], encoding="24PAS_BarCtrlDialConverter",
        base="_ZTIN2ux6wgtlay15WidgetConverterE",
    )
    _validate_typed_vtable(
        blob, mappings, rels, by_site,
        address_point=converter["vtable_address_point"], rtti=converter["rtti"],
    )
    _validate_relative(
        rels, by_site, blob, mappings, index=converter["relocation_index"],
        site=converter["cell"], target=converter["target"],
    )
    forwarded = _instruction(blob, mappings, deps, converter["forward_to_boolean_site"])
    receiver = _instruction(blob, mappings, deps, converter["widget_receiver_site"])
    if (
        converter["cell"] != converter["vtable_address_point"] + converter["slot"] * 4
        or not converter["owner"]["complete"]
        or _owner(exidx, converter["target"]) != (converter["owner"]["start"], converter["owner"]["end"])
        or forwarded.id != deps["mov"] or forwarded.operands[0].reg != deps["r1"] or forwarded.operands[1].reg != deps["r0"]
        or receiver.id != deps["mov"] or receiver.operands[0].reg != deps["r0"] or receiver.operands[1].reg != deps["r4"]
        or _call_symbol(blob, mappings, deps, plt_symbols, converter["set_touchable_call_site"]) != movie["set_touchable_symbol"]
    ):
        raise RuntimeError("Bar-control converter touchability forwarding differs")
    return copy.deepcopy(expected)


def _register_name(item, register):
    return item.reg_name(register)


def _require_register_operand(item, deps, operand_index, name, label):
    if (
        len(item.operands) <= operand_index
        or item.operands[operand_index].type != deps["reg"]
        or _register_name(item, item.operands[operand_index].reg) != name
    ):
        raise RuntimeError(label + " differs")


def _require_memory_instruction(item, deps, instruction_id, source_or_dest, base, displacement, label):
    instruction_matches = (
        item.mnemonic.split(".", 1)[0] == instruction_id
        if isinstance(instruction_id, str) else item.id == instruction_id
    )
    if not instruction_matches or len(item.operands) != 2:
        raise RuntimeError(label + " differs")
    _require_register_operand(item, deps, 0, source_or_dest, label)
    memory = item.operands[1]
    if (
        memory.type != deps["mem"]
        or _register_name(item, memory.mem.base) != base
        or memory.mem.index != 0
        or memory.mem.disp != displacement
    ):
        raise RuntimeError(label + " differs")


def _require_add_immediate(item, deps, destination, source, immediate, label):
    if item.id != deps["add"] or len(item.operands) != 3:
        raise RuntimeError(label + " differs")
    _require_register_operand(item, deps, 0, destination, label)
    _require_register_operand(item, deps, 1, source, label)
    if item.operands[2].type != deps["imm"] or item.operands[2].imm != immediate:
        raise RuntimeError(label + " differs")


def _require_add_in_place(item, deps, register, immediate, label):
    if item.id != deps["add"] or len(item.operands) != 2:
        raise RuntimeError(label + " differs")
    _require_register_operand(item, deps, 0, register, label)
    if item.operands[1].type != deps["imm"] or item.operands[1].imm != immediate:
        raise RuntimeError(label + " differs")


def _require_move_register(item, deps, destination, source, label):
    if item.id != deps["mov"] or len(item.operands) != 2:
        raise RuntimeError(label + " differs")
    _require_register_operand(item, deps, 0, destination, label)
    _require_register_operand(item, deps, 1, source, label)


def _require_indexed_memory_instruction(item, deps, instruction_id, destination, base, index, label):
    if item.id != instruction_id or len(item.operands) != 2:
        raise RuntimeError(label + " differs")
    _require_register_operand(item, deps, 0, destination, label)
    memory = item.operands[1]
    if (
        memory.type != deps["mem"]
        or _register_name(item, memory.mem.base) != base
        or _register_name(item, memory.mem.index) != index
        or memory.mem.disp != 0
    ):
        raise RuntimeError(label + " differs")


def _require_indirect_call(item, deps, register, label):
    if item.id != deps["blx"] or not item.group(deps["call_group"]):
        raise RuntimeError(label + " differs")
    _require_register_operand(item, deps, 0, register, label)


def _require_direct_call(item, deps, target, label):
    if not item.group(deps["call_group"]) or _direct_target(item, deps) != target:
        raise RuntimeError(label + " differs")


def _validate_candidate_widget_system_delivery(
    expected, view_blob, view_mappings, view_elf, deps, view_rels, view_by_site,
    view_dynsym, view_plt_symbols, view_exidx, candidate_blob, candidate_mappings,
    candidate_elf, candidate_rels, candidate_by_site, candidate_dynsym,
    candidate_plt_symbols, candidate_exidx,
):
    delivery = expected["candidate_widget_system_delivery"]
    view_chain = delivery["view_constructor_chain"]
    provider = delivery["candidate_provider"]
    layer = delivery["layer_attachment"]
    parent = delivery["parent_chain"]
    hit = delivery["hit_delivery"]

    _require_direct_call(
        _instruction(view_blob, view_mappings, deps, view_chain["pas_base_call_site"]),
        deps, view_chain["pas_base_call_target"], "PAS base-constructor call",
    )
    _require_direct_call(
        _instruction(view_blob, view_mappings, deps, view_chain["layoutable_base_import_call_site"]),
        deps, view_chain["layoutable_base_import_plt"], "layoutable-base import call",
    )
    if (
        _call_symbol(
            view_blob, view_mappings, deps, view_plt_symbols,
            view_chain["layoutable_base_import_call_site"],
        ) != view_chain["layoutable_base_symbol"]
        or ("libObj.so" in _needed_libraries(view_elf)) != view_chain["view_needed_libobj"]
    ):
        raise RuntimeError("layoutable-base provider boundary differs")
    view_relplt = list(view_elf.get_section_by_name(".rel.plt").iter_relocations())
    view_relocation = view_relplt[view_chain["layoutable_base_rel_plt_index"]]
    view_symbol = view_dynsym.get_symbol(view_relocation["r_info_sym"])
    if (
        view_relocation["r_offset"] != view_chain["layoutable_base_got"]
        or view_relocation["r_info_type"] != 22
        or view_relocation["r_info_sym"] != view_chain["layoutable_base_dynsym_index"]
        or view_symbol.name != view_chain["layoutable_base_symbol"]
        or view_symbol["st_shndx"] != "SHN_UNDEF"
    ):
        raise RuntimeError("layoutable-base relocation differs")

    layoutable_symbol = candidate_dynsym.get_symbol(provider["layoutable_constructor_dynsym_index"])
    if (
        layoutable_symbol.name != view_chain["layoutable_base_symbol"]
        or layoutable_symbol["st_shndx"] == "SHN_UNDEF"
        or layoutable_symbol["st_value"] != provider["layoutable_constructor_entry"]
        or layoutable_symbol["st_size"] != provider["layoutable_constructor_size"]
        or _owner(candidate_exidx, provider["layoutable_constructor_owner"]["start"])
        != (provider["layoutable_constructor_owner"]["start"], provider["layoutable_constructor_owner"]["end"])
    ):
        raise RuntimeError("layoutable-base candidate provider differs")
    _require_move_register(
        _instruction(candidate_blob, candidate_mappings, deps, 0x41328A),
        deps, "r4", "r0", "layoutable receiver capture",
    )
    _require_direct_call(
        _instruction(candidate_blob, candidate_mappings, deps, provider["layoutable_to_abstract_call_site"]),
        deps, provider["layoutable_to_abstract_target"], "layoutable-to-abstract constructor call",
    )
    if _owner(candidate_exidx, provider["abstract_constructor_owner"]["start"]) != (
        provider["abstract_constructor_owner"]["start"], provider["abstract_constructor_owner"]["end"]
    ):
        raise RuntimeError("abstract widget candidate owner differs")
    _require_move_register(
        _instruction(candidate_blob, candidate_mappings, deps, 0x3FECCE),
        deps, "r4", "r0", "abstract widget receiver capture",
    )
    _require_direct_call(
        _instruction(candidate_blob, candidate_mappings, deps, provider["abstract_to_widget_bridge_call_site"]),
        deps, provider["abstract_to_widget_bridge_target"], "abstract-to-widget bridge call",
    )
    if _owner(candidate_exidx, provider["widget_bridge_owner"]["start"]) != (
        provider["widget_bridge_owner"]["start"], provider["widget_bridge_owner"]["end"]
    ):
        raise RuntimeError("widget constructor bridge owner differs")
    _require_move_register(
        _instruction(
            candidate_blob,
            candidate_mappings,
            deps,
            provider["widget_bridge_receiver_capture_site"],
        ),
        deps, "r5", "r0", "widget bridge receiver capture",
    )
    _require_direct_call(
        _instruction(candidate_blob, candidate_mappings, deps, provider["widget_constructor_call_site"]),
        deps, provider["widget_constructor_target"], "widget constructor call",
    )
    if (
        _owner(candidate_exidx, provider["widget_constructor_target"])
        != (provider["widget_constructor_owner"]["start"], provider["widget_constructor_owner"]["end"])
        or provider["same_receiver_preserved"] is not True
    ):
        raise RuntimeError("widget constructor owner/receiver claim differs")
    _require_move_register(
        _instruction(candidate_blob, candidate_mappings, deps, 0x5ED6DA),
        deps, "r4", "r0", "widget receiver capture",
    )
    _require_move_register(
        _instruction(candidate_blob, candidate_mappings, deps, 0x5ED760),
        deps, "r0", "r4", "set-layer receiver forwarding",
    )

    _validate_relative(
        candidate_rels, candidate_by_site, candidate_blob, candidate_mappings,
        index=layer["default_layer_relocation_index"], site=layer["default_layer_got_cell"],
        target=layer["default_layer_object"],
    )
    _require_indexed_memory_instruction(
        _instruction(candidate_blob, candidate_mappings, deps, layer["default_layer_load_site"]),
        deps, deps["ldr"], "r1", "r8", "r3", "default layer-ID load",
    )
    _require_direct_call(
        _instruction(candidate_blob, candidate_mappings, deps, layer["set_layer_call_site"]),
        deps, layer["set_layer_plt"], "widget set-layer call",
    )
    if _call_symbol(
        candidate_blob, candidate_mappings, deps, candidate_plt_symbols,
        layer["set_layer_call_site"],
    ) != layer["set_layer_symbol"]:
        raise RuntimeError("widget set-layer symbol differs")
    candidate_relplt = list(candidate_elf.get_section_by_name(".rel.plt").iter_relocations())
    set_layer_relocation = candidate_relplt[layer["set_layer_rel_plt_index"]]
    set_layer_symbol = candidate_dynsym.get_symbol(set_layer_relocation["r_info_sym"])
    if (
        set_layer_relocation["r_offset"] != layer["set_layer_got"]
        or set_layer_relocation["r_info_type"] != 22
        or set_layer_relocation["r_info_sym"] != layer["set_layer_dynsym_index"]
        or set_layer_symbol.name != layer["set_layer_symbol"]
        or _owner(candidate_exidx, layer["set_layer_owner"]["start"])
        != (layer["set_layer_owner"]["start"], layer["set_layer_owner"]["end"])
    ):
        raise RuntimeError("widget set-layer provider differs")
    if _call_symbol(
        candidate_blob, candidate_mappings, deps, candidate_plt_symbols,
        layer["get_layer_call_site"],
    ) != layer["get_layer_symbol"]:
        raise RuntimeError("WidgetSystem layer lookup differs")
    _require_direct_call(
        _instruction(candidate_blob, candidate_mappings, deps, layer["get_layer_call_site"]),
        deps, layer["get_layer_plt"], "WidgetSystem layer lookup call",
    )
    _require_add_immediate(
        _instruction(candidate_blob, candidate_mappings, deps, layer["widget_node_address_site"]),
        deps, "r1", "r5", layer["widget_node_offset"], "widget layer-node address",
    )
    _require_add_immediate(
        _instruction(candidate_blob, candidate_mappings, deps, layer["layer_widget_list_address_site"]),
        deps, "r0", "r0", layer["layer_widget_list_offset"], "layer widget-list address",
    )
    _require_direct_call(
        _instruction(candidate_blob, candidate_mappings, deps, layer["insert_call_site"]),
        deps, layer["insert_target"], "layer widget-list insertion",
    )

    set_parent_symbol = candidate_dynsym.get_symbol(parent["set_parent_dynsym_index"])
    if (
        set_parent_symbol.name != "_ZN2ux6wgtsys6Widget9setParentERNS0_10WidgetBaseE"
        or set_parent_symbol["st_value"] != parent["set_parent_entry"]
        or set_parent_symbol["st_size"] != parent["set_parent_size"]
        or set_parent_symbol["st_shndx"] == "SHN_UNDEF"
        or _owner(candidate_exidx, parent["set_parent_owner"]["start"])
        != (parent["set_parent_owner"]["start"], parent["set_parent_owner"]["end"])
    ):
        raise RuntimeError("set-parent candidate provider differs")
    _require_add_immediate(
        _instruction(candidate_blob, candidate_mappings, deps, parent["child_node_address_site"]),
        deps, "r1", "r5", parent["node_offset"], "child node address",
    )
    _require_add_immediate(
        _instruction(candidate_blob, candidate_mappings, deps, parent["parent_node_address_site"]),
        deps, "r0", "r4", parent["node_offset"], "parent child-list address",
    )
    _require_direct_call(
        _instruction(candidate_blob, candidate_mappings, deps, parent["insert_call_site"]),
        deps, parent["insert_target"], "parent child-list insertion",
    )
    for site in (parent["pas_to_base_call_site"], parent["base_to_grid_call_site"]):
        if _call_symbol(view_blob, view_mappings, deps, view_plt_symbols, site) != set_parent_symbol.name:
            raise RuntimeError("PAS embedded parent chain differs")

    child_cells = (
        (expected["pas_belt"]["vtable_address_point"], parent["pas_child_slot_relocation_index"]),
        (expected["embedded_grid"]["base_vtable_address_point"], parent["base_child_slot_relocation_index"]),
    )
    for address_point, relocation_index in child_cells:
        cell = address_point + parent["child_slot"] * 4
        index, relocation = view_by_site[cell]
        symbol = view_dynsym.get_symbol(relocation["r_info_sym"])
        if (
            index != relocation_index or relocation["r_info_type"] != 2
            or symbol.name != parent["view_child_symbol"]
        ):
            raise RuntimeError("PAS/base child traversal slot differs")
    candidate_grid_cell = (
        expected["embedded_grid"]["candidate_vtable_address_point"]
        + parent["child_slot"] * 4
    )
    index, relocation = candidate_by_site[candidate_grid_cell]
    child_symbol = candidate_dynsym.get_symbol(parent["candidate_child_symbol_dynsym_index"])
    if (
        index != parent["candidate_grid_child_slot_relocation_index"]
        or relocation["r_info_type"] != 2
        or relocation["r_info_sym"] != parent["candidate_child_symbol_dynsym_index"]
        or child_symbol.name != parent["view_child_symbol"]
        or child_symbol["st_value"] != parent["candidate_child_entry"]
        or child_symbol["st_size"] != parent["candidate_child_size"]
    ):
        raise RuntimeError("GEN_GridList child traversal slot differs")
    child_tail = _instruction(
        candidate_blob, candidate_mappings, deps, parent["candidate_child_tail_site"]
    )
    if (
        child_tail.group(deps["call_group"])
        or not child_tail.group(deps["jump_group"])
        or _direct_target(child_tail, deps) != parent["candidate_child_tail_target"]
    ):
        raise RuntimeError("candidate child traversal tail differs")
    _require_add_in_place(
        _instruction(candidate_blob, candidate_mappings, deps, parent["candidate_child_container_address_site"]),
        deps, "r0", parent["candidate_child_container_offset"], "candidate child-list address",
    )

    for owner_name in ("layer_hit_owner", "recursive_hit_owner", "per_mouse_owner", "mouse_dispatch_owner"):
        owner = hit[owner_name]
        if _owner(candidate_exidx, owner["start"]) != (owner["start"], owner["end"]):
            raise RuntimeError(owner_name.replace("_", " ") + " differs")
    _require_direct_call(
        _instruction(candidate_blob, candidate_mappings, deps, hit["layer_first_widget_call_site"]),
        deps, hit["layer_first_widget_target"], "layer first-widget lookup",
    )
    _require_add_in_place(
        _instruction(candidate_blob, candidate_mappings, deps, hit["layer_widget_list_offset_site"]),
        deps, "r0", hit["layer_widget_list_offset"], "layer first-widget list address",
    )
    _require_direct_call(
        _instruction(candidate_blob, candidate_mappings, deps, hit["recursive_hit_call_site"]),
        deps, hit["recursive_hit_target"], "recursive widget hit walk",
    )
    _require_memory_instruction(
        _instruction(candidate_blob, candidate_mappings, deps, hit["recursive_child_slot_load_site"]),
        deps, deps["ldr"], "r3", "r3", parent["child_slot"] * 4,
        "recursive child-slot load",
    )
    _require_indirect_call(
        _instruction(candidate_blob, candidate_mappings, deps, hit["recursive_child_slot_call_site"]),
        deps, "r3", "recursive child-slot call",
    )
    _require_direct_call(
        _instruction(candidate_blob, candidate_mappings, deps, hit["recursive_next_child_call_site"]),
        deps, hit["recursive_next_child_target"], "recursive next-child lookup",
    )
    _require_direct_call(
        _instruction(candidate_blob, candidate_mappings, deps, hit["hit_walk_call_site"]),
        deps, hit["hit_walk_target"], "per-mouse hit walk",
    )
    for site in (hit["old_receiver_dispatch_call_site"], hit["new_receiver_dispatch_call_site"]):
        _require_direct_call(
            _instruction(candidate_blob, candidate_mappings, deps, site),
            deps, hit["mouse_dispatch_target"], "per-mouse receiver dispatch",
        )
    if (
        hit["hook_dispatch_offset"] != hit["hook_dispatch_slot"] * 4
        or hit["fallback_dispatch_offset"] != hit["fallback_dispatch_slot"] * 4
    ):
        raise RuntimeError("mouse dispatch slot relation differs")
    for load_site, call_site, offset in (
        (hit["hook_dispatch_load_site"], hit["hook_dispatch_call_site"], hit["hook_dispatch_offset"]),
        (hit["fallback_dispatch_load_site"], hit["fallback_dispatch_call_site"], hit["fallback_dispatch_offset"]),
    ):
        _require_memory_instruction(
            _instruction(candidate_blob, candidate_mappings, deps, load_site),
            deps, deps["ldr"], "r3", "r3", offset, "mouse dispatch slot load",
        )
        _require_indirect_call(
            _instruction(candidate_blob, candidate_mappings, deps, call_site),
            deps, "r3", "mouse receiver dispatch",
        )


def _validate_generic_belt_input_chain(
    view_blob, view_mappings, view_elf, view_deps, view_rels, view_by_site,
    view_dynsym, view_plt_symbols, view_exidx,
    candidate_blob, candidate_mappings, candidate_elf, candidate_rels,
    candidate_by_site, candidate_dynsym, candidate_plt_symbols, candidate_exidx,
):
    """Pin a conditional PAS belt path without promoting Creative Style touch."""
    expected = EXPECTED_EXPORT["generic_belt_input_chain"]
    pas = expected["pas_belt"]
    grid = expected["embedded_grid"]
    path = expected["path"]

    _validate_si_rtti(
        None, view_blob, view_mappings, view_rels, view_by_site, view_dynsym,
        rtti=pas["rtti"], encoding="22PAS_MenuDataSelectBelt",
    )
    _validate_typed_vtable(
        view_blob, view_mappings, view_rels, view_by_site,
        address_point=pas["vtable_address_point"], rtti=pas["rtti"],
    )
    _validate_relative(
        view_rels, view_by_site, view_blob, view_mappings,
        index=pas["vtable_type_relocation_index"],
        site=pas["vtable_address_point"] - 4, target=pas["rtti"],
    )
    _validate_relative(
        view_rels, view_by_site, view_blob, view_mappings,
        index=pas["vtable_got_relocation_index"], site=pas["vtable_got_cell"],
        target=pas["vtable_address_point"] - 8,
    )
    if _owner(view_exidx, pas["constructor_owner"]["start"]) != (
        pas["constructor_owner"]["start"], pas["constructor_owner"]["end"]
    ):
        raise RuntimeError("PAS belt constructor owner differs")
    _require_memory_instruction(
        _instruction(view_blob, view_mappings, view_deps, pas["vptr_store_site"]),
        view_deps, view_deps["str"], "r3", "r5", 0, "PAS belt vptr store",
    )
    _require_direct_call(
        _instruction(view_blob, view_mappings, view_deps, pas["embedded_base_constructor_call_site"]),
        view_deps, pas["embedded_base_constructor_target"], "PAS belt embedded-base constructor",
    )
    if _call_symbol(
        view_blob, view_mappings, view_deps, view_plt_symbols,
        pas["embedded_base_parent_call_site"],
    ) != "_ZN2ux6wgtsys6Widget9setParentERNS0_10WidgetBaseE":
        raise RuntimeError("PAS belt embedded-base parent link differs")

    _validate_si_rtti(
        None, view_blob, view_mappings, view_rels, view_by_site, view_dynsym,
        rtti=grid["base_rtti"], encoding="26PAS_MenuDataSelectBeltBase",
    )
    _validate_typed_vtable(
        view_blob, view_mappings, view_rels, view_by_site,
        address_point=grid["base_vtable_address_point"], rtti=grid["base_rtti"],
    )
    _validate_relative(
        view_rels, view_by_site, view_blob, view_mappings,
        index=grid["base_vtable_type_relocation_index"],
        site=grid["base_vtable_address_point"] - 4, target=grid["base_rtti"],
    )
    _require_add_immediate(
        _instruction(view_blob, view_mappings, view_deps, 0x59DD42),
        view_deps, "r6", "r5", grid["object_offset"], "embedded grid address",
    )
    if _call_symbol(
        view_blob, view_mappings, view_deps, view_plt_symbols, grid["constructor_call_site"]
    ) != grid["constructor_symbol"]:
        raise RuntimeError("embedded grid constructor import differs")
    view_relplt = list(view_elf.get_section_by_name(".rel.plt").iter_relocations())
    constructor_relocation = view_relplt[grid["constructor_rel_plt_index"]]
    constructor_import = view_dynsym.get_symbol(constructor_relocation["r_info_sym"])
    if (
        constructor_relocation["r_offset"] != grid["constructor_got"]
        or constructor_relocation["r_info_type"] != 22
        or constructor_relocation["r_info_sym"] != grid["constructor_dynsym_index"]
        or constructor_import.name != grid["constructor_symbol"]
        or constructor_import["st_shndx"] != "SHN_UNDEF"
    ):
        raise RuntimeError("embedded grid constructor relocation differs")
    if "libObj.so" in _needed_libraries(view_elf) or grid["runtime_provider_binding_proven"] is not False:
        raise RuntimeError("embedded grid provider boundary differs")
    if (
        _call_symbol(view_blob, view_mappings, view_deps, view_plt_symbols, grid["parent_call_site"])
        != "_ZN2ux6wgtsys6Widget9setParentERNS0_10WidgetBaseE"
        or _call_symbol(view_blob, view_mappings, view_deps, view_plt_symbols, grid["mouse_hook_call_site"])
        != "_ZN2ux6wgtsys10WidgetBase17setMouseEventHookEb"
    ):
        raise RuntimeError("embedded grid parent/hook setup differs")

    _validate_si_rtti(
        None, candidate_blob, candidate_mappings, candidate_rels, candidate_by_site,
        candidate_dynsym, rtti=grid["candidate_rtti"], encoding="12GEN_GridList",
    )
    candidate_constructor = candidate_dynsym.get_symbol(grid["candidate_constructor_dynsym_index"])
    if (
        candidate_constructor.name != grid["constructor_symbol"]
        or candidate_constructor["st_shndx"] == "SHN_UNDEF"
        or candidate_constructor["st_value"] != grid["candidate_constructor_entry"]
        or candidate_constructor["st_size"] != grid["candidate_constructor_size"]
    ):
        raise RuntimeError("GEN_GridList candidate constructor symbol differs")
    _validate_typed_vtable(
        candidate_blob, candidate_mappings, candidate_rels, candidate_by_site,
        address_point=grid["candidate_vtable_address_point"], rtti=grid["candidate_rtti"],
    )
    _validate_relative(
        candidate_rels, candidate_by_site, candidate_blob, candidate_mappings,
        index=grid["candidate_vtable_type_relocation_index"],
        site=grid["candidate_vtable_address_point"] - 4, target=grid["candidate_rtti"],
    )
    _validate_relative(
        candidate_rels, candidate_by_site, candidate_blob, candidate_mappings,
        index=grid["candidate_vtable_got_relocation_index"],
        site=grid["candidate_vtable_got_cell"], target=grid["candidate_vtable_address_point"] - 8,
    )
    if _owner(candidate_exidx, grid["candidate_constructor_owner"]["start"]) != (
        grid["candidate_constructor_owner"]["start"], grid["candidate_constructor_owner"]["end"]
    ):
        raise RuntimeError("GEN_GridList candidate constructor owner differs")
    _require_memory_instruction(
        _instruction(candidate_blob, candidate_mappings, view_deps, grid["candidate_vptr_store_site"]),
        view_deps, view_deps["str"], "r3", "r4", 0, "GEN_GridList candidate vptr store",
    )
    for slot in grid["candidate_slots"].values():
        site = grid["candidate_vtable_address_point"] + slot["slot"] * 4
        _validate_relative(
            candidate_rels, candidate_by_site, candidate_blob, candidate_mappings,
            index=slot["relocation_index"], site=site, target=slot["target"],
        )

    registration_cell = grid["base_vtable_address_point"] + grid["registration_slot"] * 4
    _validate_relative(
        view_rels, view_by_site, view_blob, view_mappings,
        index=grid["registration_relocation_index"], site=registration_cell,
        target=grid["registration_target"],
    )
    _require_direct_call(
        _instruction(view_blob, view_mappings, view_deps, grid["registration_call_site"]),
        view_deps, 0x567B5C, "grid callback registration helper",
    )
    _validate_relative(
        view_rels, view_by_site, view_blob, view_mappings,
        index=grid["registration_callback_relocation_index"],
        site=grid["registration_callback_got_cell"], target=grid["callback"],
    )
    _require_memory_instruction(
        _instruction(view_blob, view_mappings, view_deps, 0x567B60),
        view_deps, view_deps["str"], "r1", "r0", grid["callback_callee_offset"],
        "grid callback callee store",
    )
    _require_memory_instruction(
        _instruction(view_blob, view_mappings, view_deps, 0x567B64),
        view_deps, view_deps["str"], "r2", "r0", grid["callback_function_offset"],
        "grid callback function store",
    )

    # The event-type-4 handler loads slot 126 into r6 and calls it with the
    # same grid receiver.  It later loads slot 121 and enters selection update.
    handler_owner = path["mouse_handler_owner"]
    if _owner(candidate_exidx, handler_owner["start"]) != (handler_owner["start"], handler_owner["end"]):
        raise RuntimeError("GEN_GridList mouse-handler owner differs")
    _require_direct_call(
        _instruction(candidate_blob, candidate_mappings, view_deps, path["event_type_call_site"]),
        view_deps, path["event_type_call_plt"], "grid event-type call",
    )
    if _call_symbol(
        candidate_blob, candidate_mappings, view_deps, candidate_plt_symbols,
        path["event_type_call_site"],
    ) != path["event_type_symbol"]:
        raise RuntimeError("grid event-type symbol differs")
    bias = _instruction(candidate_blob, candidate_mappings, view_deps, path["event_type_bias_site"])
    if (
        not bias.mnemonic.startswith("sub") or len(bias.operands) != 2
        or bias.operands[1].type != view_deps["imm"]
        or bias.operands[1].imm != path["event_type_bias"]
    ):
        raise RuntimeError("grid event-type bias differs")
    _require_register_operand(bias, view_deps, 0, "r0", "grid event-type bias")
    guard = _instruction(candidate_blob, candidate_mappings, view_deps, path["event_type_guard_site"])
    branch = _instruction(candidate_blob, candidate_mappings, view_deps, path["event_type_guard_branch_site"])
    table = _instruction(candidate_blob, candidate_mappings, view_deps, path["event_type_table_branch_site"])
    if (
        guard.id != view_deps["cmp"] or len(guard.operands) != 2
        or guard.operands[1].type != view_deps["imm"]
        or guard.operands[1].imm != path["event_type_guard_max_index"]
        or branch.mnemonic != "bhi.w"
        or _direct_target(branch, view_deps) != path["event_type_guard_target"]
        or table.id != view_deps["tbh"]
        or table.operands[0].mem.base != view_deps["pc"]
        or _register_name(table, table.operands[0].mem.index) != "r0"
        or table.operands[0].mem.lshift != 1
        or table.address + 4 != path["event_type_table_start"]
    ):
        raise RuntimeError("grid event-type dispatch differs")
    _require_register_operand(guard, view_deps, 0, "r0", "grid event-type guard")
    entry = int.from_bytes(
        _at(candidate_blob, candidate_mappings, path["event_type_table_start"], 2), "little"
    )
    if path["event_type_table_start"] + 2 * entry != path["event_type_case_landing"]:
        raise RuntimeError("grid event-type-4 landing differs")
    handler_items = _decode(
        candidate_blob, candidate_mappings, view_deps,
        handler_owner["start"], handler_owner["end"], complete=True,
    )
    absent_offsets = set(expected["findings"]["bounded_absent_vtable_offsets"])
    if any(
        operand.type == view_deps["mem"] and operand.mem.disp in absent_offsets
        for item in handler_items for operand in item.operands
    ):
        raise RuntimeError("grid handler unexpectedly uses inherited hit-test slots")
    absent_targets = set(expected["findings"]["bounded_absent_direct_targets"])
    absent_symbols = set(expected["findings"]["bounded_absent_plt_symbols"])
    for item in handler_items:
        if not item.group(view_deps["call_group"]):
            continue
        target = _direct_target(item, view_deps)
        if target in absent_targets or candidate_plt_symbols.get(target) in absent_symbols:
            raise RuntimeError("grid handler unexpectedly calls inherited hit testing")
    _require_memory_instruction(
        _instruction(candidate_blob, candidate_mappings, view_deps, 0x3E9F30),
        view_deps, view_deps["ldr"], "r6", "r3", 0x1F8, "custom region slot load",
    )
    _require_indirect_call(
        _instruction(candidate_blob, candidate_mappings, view_deps, path["custom_region_call_site"]),
        view_deps, "r6", "custom region call",
    )
    custom_zero = _instruction(
        candidate_blob, candidate_mappings, view_deps, path["custom_region_zero_branch_site"]
    )
    zero_tail = _instruction(
        candidate_blob, candidate_mappings, view_deps, path["custom_region_zero_tail_call_site"]
    )
    if (
        custom_zero.mnemonic != "cbz"
        or _direct_target(custom_zero, view_deps) != path["custom_region_zero_target"]
        or not zero_tail.group(view_deps["call_group"])
        or zero_tail.address + zero_tail.size != path["custom_region_zero_path_join"]
    ):
        raise RuntimeError("custom region conditional continuation differs")
    _require_register_operand(custom_zero, view_deps, 0, "r0", "custom region zero branch")
    _require_memory_instruction(
        _instruction(candidate_blob, candidate_mappings, view_deps, 0x3E9FF6),
        view_deps, view_deps["ldr"], "r6", "r3", 0x1E4, "selection-update slot load",
    )
    _require_indirect_call(
        _instruction(candidate_blob, candidate_mappings, view_deps, path["selection_update_call_site"]),
        view_deps, "r6", "selection-update call",
    )

    _require_mov_immediate(
        _instruction(candidate_blob, candidate_mappings, view_deps, path["callback_enable_zero_source_site"]),
        view_deps, _instruction(candidate_blob, candidate_mappings, view_deps, path["callback_enable_zero_source_site"]).operands[0].reg,
        path["callback_enable_initial_value"], "selection callback initial value",
    )
    zero_source = _instruction(candidate_blob, candidate_mappings, view_deps, path["callback_enable_zero_source_site"])
    _require_register_operand(zero_source, view_deps, 0, "r6", "selection callback zero source")
    _require_memory_instruction(
        _instruction(candidate_blob, candidate_mappings, view_deps, path["callback_enable_initialization_site"]),
        view_deps, view_deps["strb"], "r6", "r4", path["callback_enable_offset"],
        "selection callback initial store",
    )
    _require_memory_instruction(
        _instruction(candidate_blob, candidate_mappings, view_deps, path["callback_enable_test_site"]),
        view_deps, "ldrb", "r3", "r4", path["callback_enable_offset"],
        "selection callback enable test",
    )
    _require_direct_call(
        _instruction(candidate_blob, candidate_mappings, view_deps, path["enabled_callback_entry_call_site"]),
        view_deps, 0x3E977C, "enabled selection callback entry",
    )
    _require_memory_instruction(
        _instruction(candidate_blob, candidate_mappings, view_deps, 0x3E97FC),
        view_deps, view_deps["ldr"], "r3", "r3", 0x160, "grid action-callback slot load",
    )
    _require_indirect_call(
        _instruction(candidate_blob, candidate_mappings, view_deps, path["action_callback_call_site"]),
        view_deps, "r3", "grid action-callback call",
    )
    _require_direct_call(
        _instruction(candidate_blob, candidate_mappings, view_deps, path["action_dispatch_call_site"]),
        view_deps, path["action_dispatch_target"], "grid action dispatch",
    )
    _require_memory_instruction(
        _instruction(candidate_blob, candidate_mappings, view_deps, 0x3E8C60),
        view_deps, view_deps["ldr"], "r1", "r6", grid["callback_callee_offset"],
        "registered callback callee load",
    )
    _require_memory_instruction(
        _instruction(candidate_blob, candidate_mappings, view_deps, 0x3E8C68),
        view_deps, view_deps["ldr"], "r3", "r6", grid["callback_function_offset"],
        "registered callback function load",
    )
    _require_indirect_call(
        _instruction(candidate_blob, candidate_mappings, view_deps, path["registered_callback_call_site"]),
        view_deps, "r3", "registered callback call",
    )

    callback_tail = _instruction(view_blob, view_mappings, view_deps, path["callback_tail_site"])
    if not callback_tail.group(view_deps["jump_group"]) or _direct_target(callback_tail, view_deps) != path["callback_tail_target"]:
        raise RuntimeError("PAS belt callback continuation differs")
    _require_direct_call(
        _instruction(view_blob, view_mappings, view_deps, path["selection_helper_call_site"]),
        view_deps, path["selection_helper_target"], "PAS belt selection helper",
    )
    _require_add_immediate(
        _instruction(view_blob, view_mappings, view_deps, path["selection_grid_address_site"]),
        view_deps, "r5", "r0", grid["object_offset"], "PAS belt selection grid address",
    )
    set_item_receiver = _instruction(view_blob, view_mappings, view_deps, 0x59E842)
    if set_item_receiver.id != view_deps["mov"]:
        raise RuntimeError("PAS belt set-item receiver differs")
    _require_register_operand(set_item_receiver, view_deps, 0, "r0", "PAS belt set-item receiver")
    _require_register_operand(set_item_receiver, view_deps, 1, "r5", "PAS belt set-item receiver")
    _require_direct_call(
        _instruction(view_blob, view_mappings, view_deps, path["set_item_select_call_site"]),
        view_deps, path["set_item_select_plt"], "PAS belt set-item-selection call",
    )
    _require_direct_call(
        _instruction(view_blob, view_mappings, view_deps, path["belt_check_call_site"]),
        view_deps, path["belt_check_plt"], "PAS belt type-check call",
    )
    if (
        _call_symbol(view_blob, view_mappings, view_deps, view_plt_symbols, path["set_item_select_call_site"])
        != path["set_item_select_symbol"]
        or _call_symbol(view_blob, view_mappings, view_deps, view_plt_symbols, path["belt_check_call_site"])
        != path["belt_check_symbol"]
    ):
        raise RuntimeError("PAS belt selection/check boundary differs")

    _require_direct_call(
        _instruction(view_blob, view_mappings, view_deps, path["event_helper_call_site"]),
        view_deps, path["event_helper_target"], "PAS belt event helper call",
    )
    _require_add_immediate(
        _instruction(view_blob, view_mappings, view_deps, path["event_id_base_site"]),
        view_deps, "r3", "r0", path["event_id_base_offset"], "PAS belt event-id base",
    )
    _require_memory_instruction(
        _instruction(view_blob, view_mappings, view_deps, path["event_id_load_site"]),
        view_deps, view_deps["ldr"], "r1", "r3", path["event_id_offset"],
        "PAS belt event-id load",
    )

    event_tail = _instruction(view_blob, view_mappings, view_deps, path["event_push_tail_site"])
    if (
        event_tail.group(view_deps["call_group"])
        or not event_tail.group(view_deps["jump_group"])
        or _direct_target(event_tail, view_deps) != path["event_push_gate"]
    ):
        raise RuntimeError("PAS belt event-push tail differs")
    relocation = view_relplt[path["event_push_rel_plt_index"]]
    symbol = view_dynsym.get_symbol(relocation["r_info_sym"])
    decoded = _decoded_plt_addresses_exact(view_elf, view_blob, view_mappings)
    if (
        relocation["r_offset"] != path["event_push_got"]
        or relocation["r_info_type"] != 22
        or symbol.name != path["event_push_symbol"]
        or decoded.get(path["event_push_got"]) != path["event_push_veneer"]
    ):
        raise RuntimeError("PAS belt event-push binding boundary differs")

    _validate_candidate_widget_system_delivery(
        expected,
        view_blob,
        view_mappings,
        view_elf,
        view_deps,
        view_rels,
        view_by_site,
        view_dynsym,
        view_plt_symbols,
        view_exidx,
        candidate_blob,
        candidate_mappings,
        candidate_elf,
        candidate_rels,
        candidate_by_site,
        candidate_dynsym,
        candidate_plt_symbols,
        candidate_exidx,
    )

    if expected["findings"] != {
        "slot27_to_custom_region_test_proven": True,
        "slot27_to_selection_update_proven": True,
        "slot27_to_registered_callback_proven": False,
        "selection_callback_enable_state_proven": False,
        "selection_callback_constructor_initial_value": 0,
        "enabled_callback_to_grid_selection_proven": True,
        "enabled_callback_to_typed_pas_belt_event_push_boundary_proven": True,
        "widget_is_hit_used_by_this_path": False,
        "candidate_provider_layer_attachment_path_proven": True,
        "candidate_provider_parent_chain_to_embedded_grid_proven": True,
        "candidate_provider_widget_system_hit_delivery_path_proven": True,
        "bounded_absent_vtable_offsets": [0x8C, 0x90],
        "bounded_absent_direct_targets": [0x606676, 0x5ED0F8],
        "bounded_absent_plt_symbols": [
            "_ZN2ux6wgtsys10WidgetBase9sys_isHitERKNS_4core7Vector2E",
            "_ZN2ux6wgtsys6Widget5isHitERKNS_4core7Vector2E",
        ],
    } or any(expected["preconditions"].values()):
        raise RuntimeError("generic belt claim boundary differs")
    return copy.deepcopy(expected)


class ElfAdapter:
    def metadata(self):
        if not sources_available():
            raise RuntimeError("pinned viewUnified2 source is unavailable")
        if not LIBOBJ_SOURCE_PATH.is_file() or LIBOBJ_SOURCE_PATH.is_symlink():
            raise RuntimeError("pinned libObj candidate source is unavailable")
        before = _sha256(SOURCE_PATH)
        candidate_before = _sha256(LIBOBJ_SOURCE_PATH)
        if SOURCE_PATH.stat().st_size != SOURCE["size"] or before != SOURCE["sha256"]:
            raise RuntimeError("pinned viewUnified2 source identity differs")
        blob = SOURCE_PATH.read_bytes()
        candidate_blob = LIBOBJ_SOURCE_PATH.read_bytes()
        deps = _dependencies()
        with SOURCE_PATH.open("rb") as handle, LIBOBJ_SOURCE_PATH.open("rb") as candidate_handle:
            elf = deps["ELFFile"](handle)
            candidate_elf = deps["ELFFile"](candidate_handle)
            mappings = _mappings(elf)
            candidate_mappings = _mappings(candidate_elf)
            rels, by_site = _relocations(elf)
            candidate_rels, candidate_by_site = _relocations(candidate_elf)
            dynsym = elf.get_section_by_name(".dynsym")
            candidate_dynsym = candidate_elf.get_section_by_name(".dynsym")
            plt_symbols = _plt_symbols(elf, blob, mappings)
            candidate_plt_symbols = _plt_symbols(candidate_elf, candidate_blob, candidate_mappings)
            exidx = _exidx_ranges(elf, blob)
            candidate_exidx = _exidx_ranges(candidate_elf, candidate_blob)
            dispatcher = _validate_dispatcher(blob, mappings, deps, rels, by_site, dynsym, exidx)
            layout = _validate_layout(blob, mappings, deps, rels, by_site, dynsym, plt_symbols, exidx)
            menu = _validate_menu_table(blob, mappings, deps, plt_symbols, exidx)
            belt = _validate_belt_cursor(blob, mappings, deps, plt_symbols, exidx)
            widget_cast = _validate_post_lookup_widget_cast(
                blob, mappings, deps, elf, plt_symbols, exidx
            )
            constructor_boundary = _validate_field_0x14c_constructor_boundary(
                blob, mappings, deps, plt_symbols, exidx
            )
            constructor_boundary = _validate_viewbase_constructor_candidate(
                blob, mappings, elf, plt_symbols,
                candidate_blob, candidate_mappings, candidate_elf, deps,
            )
            navigation = _validate_navigation(blob, mappings, deps, plt_symbols, exidx)
            touchability = _validate_touchability(blob, mappings, deps, rels, by_site, dynsym, plt_symbols, exidx)
            generic_belt = _validate_generic_belt_input_chain(
                blob, mappings, elf, deps, rels, by_site, dynsym, plt_symbols, exidx,
                candidate_blob, candidate_mappings, candidate_elf, candidate_rels,
                candidate_by_site, candidate_dynsym, candidate_plt_symbols, candidate_exidx,
            )
        if _sha256(SOURCE_PATH) != before or _sha256(LIBOBJ_SOURCE_PATH) != candidate_before:
            raise RuntimeError("pinned interaction source changed during export")
        document = copy.deepcopy(EXPECTED_EXPORT)
        document.update({
            "view_dispatcher": dispatcher,
            "creative_style_layout": layout,
            "menu_table": menu,
            "belt_cursor": belt,
            "post_lookup_widget_cast": widget_cast,
            "field_0x14c_constructor_boundary": constructor_boundary,
            "navigation": navigation,
            "touchability_candidate": touchability,
            "generic_belt_input_chain": generic_belt,
        })
        return document


def build_raw_export(adapter=None):
    return normalize_creative_style_interaction_surface_export((adapter or ElfAdapter()).metadata())


def write_export(document, output_root=OUTPUT_ROOT):
    normalized = normalize_creative_style_interaction_surface_export(document)
    root = Path(output_root).resolve()
    if root != OUTPUT_ROOT.resolve() or ARTIFACT_BASE.resolve() not in root.parents:
        raise RuntimeError("output root is outside the approved artifact path")
    root.mkdir(parents=True, exist_ok=True)
    target = root / OUTPUT_NAME
    if target.exists() and (target.is_symlink() or not target.is_file()):
        raise RuntimeError("output target is not a regular file")
    descriptor, temporary = tempfile.mkstemp(prefix=OUTPUT_NAME + ".", suffix=".tmp", dir=str(root))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(normalized, indent=2, sort_keys=True) + "\n")
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return target


def write_checked_report(document, path=REPORT_PATH):
    """Atomically replace only the validator-built interaction report."""
    report = build_creative_style_interaction_surface_report(document)
    validate_creative_style_interaction_surface_report(report)
    path = Path(path)
    if path != REPORT_PATH or path.is_symlink() or (path.exists() and not path.is_file()):
        raise RuntimeError("checked interaction report path differs")
    descriptor, temporary = tempfile.mkstemp(
        prefix=".creative-style-interaction-report-", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    document = build_raw_export()
    output = write_export(document)
    write_checked_report(document)
    print("CREATIVE_STYLE_INTERACTION_SURFACE_EXPORT|layout=1|belt=1|widget_filter=1|touch_route=0|installable=0")
    print(output)


if __name__ == "__main__":
    main()
