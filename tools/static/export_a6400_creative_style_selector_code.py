"""Read-only exporter for typed Creative Style selector-code evidence."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pmca.analysis.creative_style_selector_code import (
    EXPECTED_EXPORT,
    SOURCE,
    normalize_creative_style_selector_code_export,
)
from tools.static.export_a6400_creative_style_view_model_binding import (
    _at,
    _call_symbol,
    _cstring,
    _decode,
    _dependencies as _binding_dependencies,
    _direct_target,
    _exidx_ranges,
    _instruction,
    _mappings,
    _owner,
    _plt_symbols,
    _relocations,
    _require_mov_immediate,
    _require_register_unchanged,
    _validate_relative,
    _validate_si_rtti,
    _word,
)


SOURCE_PATH = (
    ROOT / ".artifacts" / "decrypted" / "a6400-tw-v2.00" / "ma1co"
    / "firmware.tar_unpacked" / "0700_part_image" / "dev" / "nflasha15_unpacked"
    / "lib" / "viewUnified2.so"
)
ARTIFACT_BASE = ROOT / ".artifacts"
OUTPUT_ROOT = ARTIFACT_BASE / "creative-style-selector-code" / "a6400-v2.00"
OUTPUT_NAME = "creative-style-selector-code-export.json"


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _dependencies():
    deps = _binding_dependencies()
    try:
        from capstone.arm import (
            ARM_CC_AL,
            ARM_CC_EQ,
            ARM_CC_GT,
            ARM_INS_IT,
            ARM_INS_LDM,
            ARM_INS_LSL,
            ARM_INS_MVN,
            ARM_INS_STM,
            ARM_INS_SUB,
            ARM_REG_IP,
            ARM_REG_R6,
        )
    except (ImportError, AttributeError) as exc:
        raise RuntimeError("local Capstone and pyelftools are required") from exc
    deps.update({
        "al": ARM_CC_AL, "eq": ARM_CC_EQ, "gt": ARM_CC_GT, "it": ARM_INS_IT,
        "ldm": ARM_INS_LDM, "lsl": ARM_INS_LSL, "mvn": ARM_INS_MVN,
        "stm": ARM_INS_STM, "sub": ARM_INS_SUB, "ip": ARM_REG_IP, "r6": ARM_REG_R6,
    })
    return deps


def dependencies_available():
    try:
        _dependencies()
    except RuntimeError:
        return False
    return True


def sources_available():
    return SOURCE_PATH.is_file() and not SOURCE_PATH.is_symlink()


def _require_reg_to_reg(item, deps, instruction_id, destination, source, label):
    if (
        item.id != instruction_id
        or len(item.operands) != 2
        or item.operands[0].type != deps["reg"]
        or item.operands[0].reg != destination
        or item.operands[1].type != deps["reg"]
        or item.operands[1].reg != source
    ):
        raise RuntimeError(label + " differs")


def _require_memory(item, deps, instruction_id, source_or_destination, base, displacement, label):
    if (
        item.id != instruction_id
        or len(item.operands) < 2
        or item.operands[0].type != deps["reg"]
        or item.operands[0].reg != source_or_destination
        or item.operands[1].type != deps["mem"]
        or item.operands[1].mem.base != base
        or item.operands[1].mem.disp != displacement
    ):
        raise RuntimeError(label + " differs")


def _require_add_immediate(item, deps, destination, source, value, label):
    operands = item.operands
    valid = (
        item.id == deps["add"]
        and len(operands) == 3
        and operands[0].type == deps["reg"]
        and operands[0].reg == destination
        and operands[1].type == deps["reg"]
        and operands[1].reg == source
        and operands[2].type == deps["imm"]
        and operands[2].imm == value
    )
    if not valid:
        raise RuntimeError(label + " differs")


def _require_call_target(blob, mappings, deps, site, target, label):
    item = _instruction(blob, mappings, deps, site)
    if not item.group(deps["call_group"]) or _direct_target(item, deps) != target:
        raise RuntimeError(label + " differs")


def _validate_typed_element(elf, blob, mappings, deps, rels, by_site, dynsym, exidx):
    expected = EXPECTED_EXPORT["typed_element"]
    _validate_si_rtti(
        elf,
        blob,
        mappings,
        rels,
        by_site,
        dynsym,
        rtti=expected["rtti"],
        encoding=expected["type_name_encoding"],
    )
    header = expected["vtable_header"]
    if _word(blob, mappings, header, signed=True) != 0:
        raise RuntimeError("typed-element vtable offset-to-top differs")
    _validate_relative(
        rels,
        by_site,
        blob,
        mappings,
        index=40019,
        site=header + 4,
        target=expected["rtti"],
    )
    for prefix in ("setter", "getter"):
        if expected[prefix + "_cell"] != expected["vtable_address_point"] + expected[prefix + "_slot"] * 4:
            raise RuntimeError("typed-element " + prefix + " slot geometry differs")
        _validate_relative(
            rels,
            by_site,
            blob,
            mappings,
            index=expected[prefix + "_relocation_index"],
            site=expected[prefix + "_cell"],
            target=expected[prefix],
        )
        owner = _owner(exidx, expected[prefix])
        owner_expected = expected[prefix + "_owner"]
        if owner != (owner_expected["start"], owner_expected["end"]):
            raise RuntimeError("typed-element " + prefix + " owner differs")
        base_cell = expected[prefix + "_base_cell"]
        if base_cell != expected["base_vtable_address_point"] + expected[prefix + "_slot"] * 4:
            raise RuntimeError("typed-element base " + prefix + " slot geometry differs")
        _base_index, base_relocation = by_site[base_cell]
        if (
            base_relocation["r_info_type"] != 2
            or dynsym.get_symbol(base_relocation["r_info_sym"]).name != expected[prefix + "_base_symbol"]
        ):
            raise RuntimeError("typed-element base " + prefix + " signature differs")
    return copy.deepcopy(expected)


def _validate_selector_cases(blob, mappings, deps, plt_symbols):
    expected = EXPECTED_EXPORT["setter_selector"]
    capture = _instruction(blob, mappings, deps, expected["capture_site"])
    if (
        capture.id != deps["mov"]
        or capture.operands[1].type != deps["reg"]
        or capture.operands[1].reg != deps["r1"]
    ):
        raise RuntimeError("setter selector capture differs")
    selector_register = capture.operands[0].reg
    compare = _instruction(blob, mappings, deps, expected["guard_compare_site"])
    branch = _instruction(blob, mappings, deps, expected["guard_branch_site"])
    table = _instruction(blob, mappings, deps, expected["table_branch_site"])
    memory = table.operands[0].mem
    if (
        compare.id != deps["cmp"]
        or compare.operands[0].reg != selector_register
        or compare.operands[1].imm != expected["input_max"]
        or branch.cc != deps["hi"]
        or _direct_target(branch, deps) != expected["out_of_range_target"]
        or table.id != deps["tbh"]
        or not table.group(deps["jump_group"])
        or memory.base != deps["pc"]
        or memory.index != selector_register
        or memory.lshift != 1
        or expected["table_start"] != expected["table_branch_site"] + table.size
    ):
        raise RuntimeError("setter selector guard/table differs")
    _require_register_unchanged(
        _decode(
            blob,
            mappings,
            deps,
            expected["capture_site"] + capture.size,
            expected["guard_compare_site"],
            complete=False,
        ),
        selector_register,
        label="setter selector preservation",
    )

    actual_map = {}
    for case in expected["cases"]:
        entry = expected["table_start"] + case["selector"] * 2
        landing = expected["table_start"] + 2 * int.from_bytes(_at(blob, mappings, entry, 2), "little")
        if landing != case["landing"]:
            raise RuntimeError("setter selector table target differs")
        if case.get("rejected"):
            if landing != expected["out_of_range_target"]:
                raise RuntimeError("setter rejected selector target differs")
            continue
        size = _instruction(blob, mappings, deps, case["landing"])
        _require_mov_immediate(size, deps, deps["r0"], 0x14, "selector holder size")
        if _call_symbol(blob, mappings, deps, plt_symbols, case["allocation_site"]) != "_Znwj":
            raise RuntimeError("selector holder allocation differs")
        capture_holder = _instruction(blob, mappings, deps, case["capture_site"])
        _require_reg_to_reg(capture_holder, deps, deps["mov"], deps["r4"], deps["r0"], "selector holder capture")
        code = _instruction(blob, mappings, deps, case["code_site"])
        _require_mov_immediate(code, deps, deps["r1"], case["persisted_code"], "selector persisted code")
        if case["join_branch_site"] is not None:
            join = _instruction(blob, mappings, deps, case["join_branch_site"])
            if not join.group(deps["jump_group"]) or _direct_target(join, deps) != case["constructor_call_site"]:
                raise RuntimeError("selector constructor join differs")
        path_end = case["join_branch_site"] if case["join_branch_site"] is not None else case["constructor_call_site"]
        _require_register_unchanged(
            _decode(
                blob,
                mappings,
                deps,
                case["code_site"] + code.size,
                path_end,
                complete=False,
            ),
            deps["r0"],
            label="selector holder receiver preservation",
        )
        _require_register_unchanged(
            _decode(
                blob,
                mappings,
                deps,
                case["code_site"] + code.size,
                path_end,
                complete=False,
            ),
            deps["r1"],
            label="selector code preservation",
        )
        _require_call_target(
            blob,
            mappings,
            deps,
            case["constructor_call_site"],
            EXPECTED_EXPORT["selector_record"]["holder_constructor"],
            "selector holder constructor",
        )
        actual_map[str(case["selector"])] = case["persisted_code"]
    if actual_map != expected["selector_to_persisted_code"]:
        raise RuntimeError("selector-to-code map differs")
    return copy.deepcopy(expected)


def _validate_holder(blob, mappings, deps, plt_symbols, exidx):
    expected = EXPECTED_EXPORT["selector_record"]
    constructor_owner = _owner(exidx, expected["holder_constructor"])
    accessor_owner = _owner(exidx, expected["holder_accessor"])
    if constructor_owner != (expected["holder_constructor_owner"]["start"], expected["holder_constructor_owner"]["end"]):
        raise RuntimeError("selector holder constructor owner differs")
    if accessor_owner != (expected["holder_accessor_owner"]["start"], expected["holder_accessor_owner"]["end"]):
        raise RuntimeError("selector holder accessor owner differs")
    capture = _instruction(blob, mappings, deps, expected["holder_input_capture_site"])
    if capture.id != deps["mov"] or capture.operands[1].reg != deps["r1"]:
        raise RuntimeError("selector holder input capture differs")
    value_register = capture.operands[0].reg
    if _call_symbol(blob, mappings, deps, plt_symbols, expected["param_base_constructor_call_site"]) != expected["param_base_constructor_symbol"]:
        raise RuntimeError("selector ParamBase construction differs")
    store = _instruction(blob, mappings, deps, expected["holder_value_store_site"])
    if (
        store.id != deps["str"]
        or store.operands[0].reg != value_register
        or store.operands[1].type != deps["mem"]
        or store.operands[1].mem.disp != expected["holder_value_offset"]
    ):
        raise RuntimeError("selector holder value store differs")
    object_register = store.operands[1].mem.base
    constructor_prefix = _decode(
        blob, mappings, deps, expected["holder_constructor"], expected["param_base_constructor_call_site"], complete=False,
    )
    if not any(
        item.id == deps["mov"]
        and len(item.operands) == 2
        and item.operands[0].type == deps["reg"]
        and item.operands[0].reg == object_register
        and item.operands[1].type == deps["reg"]
        and item.operands[1].reg == deps["r0"]
        for item in constructor_prefix
    ):
        raise RuntimeError("selector holder object capture differs")
    load = _instruction(blob, mappings, deps, expected["holder_value_load_site"])
    _require_memory(load, deps, deps["ldr"], deps["r0"], deps["r0"], expected["holder_value_offset"], "selector holder value load")
    return copy.deepcopy(expected)


def _validate_persistence(blob, mappings, deps, plt_symbols):
    selector = EXPECTED_EXPORT["selector_record"]
    argument_2 = EXPECTED_EXPORT["argument_2_record"]

    accepted_constructor_sites = {
        case["constructor_call_site"]
        for case in EXPECTED_EXPORT["setter_selector"]["cases"]
        if not case.get("rejected")
    }
    preservation_constructor_sites = {
        path["constructor_call_site"] for path in selector["holder_preservation_paths"]
    }
    if accepted_constructor_sites != preservation_constructor_sites:
        raise RuntimeError("selector holder path coverage differs")
    for path in selector["holder_preservation_paths"]:
        constructor = _instruction(blob, mappings, deps, path["constructor_call_site"])
        if path["segments"][0][0] != constructor.address + constructor.size:
            raise RuntimeError("selector holder path start differs")
        if path["segments"][-1][1] != EXPECTED_EXPORT["request_boundary"]["param_key_sites"][-1] + 4:
            raise RuntimeError("selector holder path endpoint differs")
        if not any(
            start <= selector["setter_holder_receiver_site"] < end
            for start, end in path["segments"]
        ):
            raise RuntimeError("selector holder accessor path coverage differs")
        if path["join_branch_site"] is not None:
            join = _instruction(blob, mappings, deps, path["join_branch_site"])
            if (
                path["segments"][0][1] != path["join_branch_site"]
                or path["segments"][1][0] != path["join_target"]
                or not join.group(deps["jump_group"])
                or _direct_target(join, deps) != path["join_target"]
            ):
                raise RuntimeError("selector holder path join differs")
        for start, end in path["segments"]:
            _require_register_unchanged(
                _decode(blob, mappings, deps, start, end, complete=False),
                deps["r4"],
                label="selector holder preservation",
            )

    receiver = _instruction(blob, mappings, deps, selector["setter_holder_receiver_site"])
    _require_reg_to_reg(receiver, deps, deps["mov"], deps["r0"], deps["r4"], "selector accessor receiver")
    _require_register_unchanged(
        _decode(blob, mappings, deps, receiver.address + receiver.size, selector["setter_holder_accessor_call_site"], complete=False),
        deps["r0"],
        label="selector accessor receiver preservation",
    )
    _require_call_target(
        blob,
        mappings,
        deps,
        selector["setter_holder_accessor_call_site"],
        selector["holder_accessor"],
        "selector holder accessor",
    )
    selector_store = _instruction(blob, mappings, deps, selector["code_byte_store_site"])
    _require_memory(selector_store, deps, deps["strb"], deps["r0"], deps["r7"], selector["code_byte_local_offset"], "selector code byte store")
    accessor_call = _instruction(blob, mappings, deps, selector["setter_holder_accessor_call_site"])
    _require_register_unchanged(
        _decode(blob, mappings, deps, accessor_call.address + accessor_call.size, selector_store.address, complete=False),
        deps["r0"],
        label="selector accessor result preservation",
    )

    arg2_capture = _instruction(blob, mappings, deps, argument_2["argument_capture_site"])
    if arg2_capture.id != deps["mov"] or arg2_capture.operands[1].reg != deps["r2"]:
        raise RuntimeError("argument 2 capture differs")
    arg2_register = arg2_capture.operands[0].reg
    default = _instruction(blob, mappings, deps, argument_2["default_minus_one_site"])
    default_is_minus_one = (
        default.id == deps["mov"]
        and default.operands[0].reg == deps["r3"]
        and (default.operands[1].imm & 0xFF) == 0xFF
    ) or (
        default.id == deps["mvn"]
        and default.operands[0].reg == deps["r3"]
        and default.operands[1].imm == 0
    )
    if not default_is_minus_one:
        raise RuntimeError("argument 2 default differs")
    compare = _instruction(blob, mappings, deps, argument_2["encode_compare_site"])
    if compare.id != deps["cmp"] or compare.operands[0].reg != arg2_register or compare.operands[1].imm != 0:
        raise RuntimeError("argument 2 encode compare differs")
    default_store = _instruction(blob, mappings, deps, argument_2["default_byte_store_site"])
    positive_store = _instruction(blob, mappings, deps, argument_2["positive_byte_store_site"])
    _require_memory(default_store, deps, deps["strb"], deps["r3"], deps["r7"], argument_2["byte_local_offset"], "argument 2 default store")
    decrement = _instruction(blob, mappings, deps, argument_2["positive_decrement_site"])
    decrement_is_exact = (
        decrement.operands[0].reg == deps["r3"]
        and decrement.operands[1].reg == arg2_register
        and (
            (decrement.id == deps["sub"] and decrement.operands[2].imm == 1)
            or (
                decrement.id == deps["add"]
                and (decrement.operands[2].imm & 0xFFFFFFFF) == 0xFFFFFFFF
            )
        )
    )
    if not decrement_is_exact:
        raise RuntimeError("argument 2 positive encoding differs")
    _require_memory(positive_store, deps, deps["strb"], deps["r3"], deps["r7"], argument_2["byte_local_offset"], "argument 2 positive store")
    predicate_items = {
        item.address: item
        for item in _decode(
            blob, mappings, deps, argument_2["positive_it_site"],
            argument_2["positive_byte_store_site"] + positive_store.size,
        )
    }
    positive_it = predicate_items[argument_2["positive_it_site"]]
    predicated_decrement = predicate_items[argument_2["positive_decrement_site"]]
    predicated_store = predicate_items[argument_2["positive_byte_store_site"]]
    if (
        default_store.cc != deps["al"]
        or positive_it.id != deps["it"]
        or positive_it.cc != deps["gt"]
        or predicated_decrement.cc != deps["gt"]
        or predicated_store.cc != deps["gt"]
    ):
        raise RuntimeError("argument 2 positive predicate differs")
    first_pointer = _instruction(blob, mappings, deps, argument_2["byte_pointer_sites"][0])
    second_pointer = _instruction(blob, mappings, deps, argument_2["byte_pointer_sites"][1])
    _require_add_immediate(first_pointer, deps, deps["r1"], deps["r7"], 0x11C, "argument 2 pointer base")
    if not (
        second_pointer.id == deps["add"]
        and second_pointer.operands[0].reg == deps["r1"]
        and second_pointer.operands[-1].type == deps["imm"]
        and second_pointer.operands[-1].imm == 3
    ):
        raise RuntimeError("argument 2 pointer increment differs")
    fixed_id = _instruction(blob, mappings, deps, argument_2["backup_id_load_site"])
    if (
        fixed_id.id != deps["ldr"]
        or fixed_id.operands[0].reg != deps["r0"]
        or fixed_id.operands[1].mem.base != deps["pc"]
        or ((fixed_id.address + 4) & ~3) + fixed_id.operands[1].mem.disp != argument_2["backup_id_literal_site"]
        or _word(blob, mappings, argument_2["backup_id_literal_site"]) != argument_2["backup_id"]
        or _call_symbol(blob, mappings, deps, plt_symbols, argument_2["backup_write_call_site"]) != argument_2["backup_write_symbol"]
    ):
        raise RuntimeError("argument 2 fixed backup record differs")
    _require_register_unchanged(
        _decode(blob, mappings, deps, second_pointer.address + second_pointer.size, argument_2["backup_write_call_site"], complete=False),
        deps["r1"],
        label="argument 2 backup pointer preservation",
    )

    nonzero_compare = _instruction(blob, mappings, deps, selector["argument_2_nonzero_compare_site"])
    skip = _instruction(blob, mappings, deps, selector["argument_2_zero_skip_branch_site"])
    if (
        nonzero_compare.id != deps["cmp"]
        or nonzero_compare.operands[0].reg != arg2_register
        or nonzero_compare.operands[1].imm != 0
        or skip.cc != deps["eq"]
        or _direct_target(skip, deps) != selector["argument_2_zero_skip_target"]
    ):
        raise RuntimeError("selector conditional persistence differs")
    _require_register_unchanged(
        _decode(
            blob, mappings, deps, arg2_capture.address + arg2_capture.size,
            selector["argument_2_nonzero_compare_site"], complete=False,
        ),
        arg2_register,
        label="setter argument 2 preservation",
    )
    pointer = _instruction(blob, mappings, deps, selector["code_byte_pointer_site"])
    _require_add_immediate(pointer, deps, deps["r1"], deps["r7"], selector["code_byte_local_offset"], "selector code pointer")
    table_base = _instruction(blob, mappings, deps, selector["dynamic_record_id_table_base_site"])
    table_index = _instruction(blob, mappings, deps, selector["dynamic_record_id_index_site"])
    table_load = _instruction(blob, mappings, deps, selector["dynamic_record_id_load_site"])
    if (
        table_base.id != deps["add"]
        or table_base.operands[0].reg != deps["r2"]
        or table_base.operands[1].reg != deps["r7"]
        or table_base.operands[2].imm != 0x120
        or table_index.id != deps["add"]
        or table_index.operands[0].reg != deps["r3"]
        or table_index.operands[1].reg != deps["r2"]
        or table_index.operands[2].reg != arg2_register
        or table_index.operands[2].shift.value != 2
        or table_load.id != deps["ldr"]
        or table_load.operands[0].reg != deps["r0"]
        or table_load.operands[1].mem.base != deps["r3"]
        or table_load.operands[1].mem.disp != -40
    ):
        raise RuntimeError("selector dynamic record lookup differs")
    if _call_symbol(blob, mappings, deps, plt_symbols, selector["backup_write_call_site"]) != selector["backup_write_symbol"]:
        raise RuntimeError("selector dynamic backup call differs")
    _require_register_unchanged(
        _decode(blob, mappings, deps, pointer.address + pointer.size, selector["backup_write_call_site"], complete=False),
        deps["r1"],
        label="selector backup pointer preservation",
    )
    return copy.deepcopy(selector), copy.deepcopy(argument_2)


def _validate_request(blob, mappings, deps, plt_symbols):
    expected = EXPECTED_EXPORT["request_boundary"]
    arg3_capture = _instruction(blob, mappings, deps, expected["argument_3_capture_site"])
    _require_memory(arg3_capture, deps, deps["str"], deps["r3"], deps["r7"], expected["argument_3_local_offset"], "argument 3 capture")
    for load_site, call_site in zip(expected["argument_3_value_load_sites"], expected["argument_3_constructor_call_sites"]):
        load = _instruction(blob, mappings, deps, load_site)
        _require_memory(load, deps, deps["ldr"], deps["r1"], deps["r7"], expected["argument_3_local_offset"], "argument 3 holder input")
        _require_call_target(blob, mappings, deps, call_site, EXPECTED_EXPORT["selector_record"]["holder_constructor"], "argument 3 holder constructor")
        _require_register_unchanged(
            _decode(blob, mappings, deps, load.address + load.size, call_site, complete=False),
            deps["r1"],
            label="argument 3 holder input preservation",
        )
    argument_4_load = _instruction(blob, mappings, deps, expected["argument_4_value_sources"]["normal_stack_load_site"])
    _require_memory(argument_4_load, deps, deps["ldr"], deps["r1"], deps["r7"], expected["argument_4_stack_offset"], "argument 4 normal input")
    argument_4_join = _instruction(blob, mappings, deps, expected["argument_4_normal_join_branch_site"])
    if not argument_4_join.group(deps["jump_group"]) or _direct_target(argument_4_join, deps) != expected["argument_4_constructor_call_site"]:
        raise RuntimeError("argument 4 normal constructor join differs")
    argument_4_default = _instruction(blob, mappings, deps, expected["argument_4_value_sources"]["special_default_zero_site"])
    _require_mov_immediate(argument_4_default, deps, deps["r1"], 0, "argument 4 special default")
    _require_call_target(
        blob, mappings, deps, expected["argument_4_constructor_call_site"],
        EXPECTED_EXPORT["selector_record"]["holder_constructor"], "argument 4 holder constructor",
    )
    argument_5_load = _instruction(blob, mappings, deps, expected["argument_5_value_load_site"])
    _require_memory(argument_5_load, deps, deps["ldr"], deps["r1"], deps["r7"], expected["argument_5_stack_offset"], "argument 5 input")
    _require_call_target(
        blob, mappings, deps, expected["argument_5_constructor_call_site"],
        EXPECTED_EXPORT["selector_record"]["holder_constructor"], "argument 5 holder constructor",
    )
    _require_register_unchanged(
        _decode(blob, mappings, deps, argument_5_load.address + argument_5_load.size, expected["argument_5_constructor_call_site"], complete=False),
        deps["r1"],
        label="argument 5 holder input preservation",
    )
    for construction in expected["holder_constructions"]:
        size = _instruction(blob, mappings, deps, construction["allocation_size_site"])
        _require_mov_immediate(size, deps, deps["r0"], 0x14, "request holder allocation size")
        if _call_symbol(blob, mappings, deps, plt_symbols, construction["allocation_call_site"]) != "_Znwj":
            raise RuntimeError("request holder allocation differs")
        capture = _instruction(blob, mappings, deps, construction["holder_capture_site"])
        if (
            capture.id != deps["mov"]
            or capture.operands[1].type != deps["reg"]
            or capture.operands[1].reg != deps["r0"]
            or capture.reg_name(capture.operands[0].reg) != construction["holder_register"]
        ):
            raise RuntimeError("request holder capture differs")
        holder_register = capture.operands[0].reg
        value_source = _instruction(blob, mappings, deps, construction["value_source_site"])
        if not (
            len(value_source.operands) >= 1
            and value_source.operands[0].type == deps["reg"]
            and value_source.operands[0].reg == deps["r1"]
        ):
            raise RuntimeError("request holder value source differs")
        _require_call_target(
            blob, mappings, deps, construction["constructor_call_site"],
            EXPECTED_EXPORT["selector_record"]["holder_constructor"], "request holder constructor",
        )
        for start, end in construction["receiver_preservation_segments"]:
            _require_register_unchanged(
                _decode(blob, mappings, deps, start, end, complete=False),
                deps["r0"],
                label="request holder receiver preservation",
            )
        for start, end in construction["value_preservation_segments"]:
            _require_register_unchanged(
                _decode(blob, mappings, deps, start, end, complete=False),
                deps["r1"],
                label="request holder value preservation",
            )
        for start, end in construction["preservation_segments"]:
            _require_register_unchanged(
                _decode(blob, mappings, deps, start, end, complete=False),
                holder_register,
                label="request holder result preservation",
            )

    param_list = expected["param_list"]
    param_size = _instruction(blob, mappings, deps, param_list["allocation_size_site"])
    _require_mov_immediate(param_size, deps, deps["r0"], 0x14, "ParamList allocation size")
    if _call_symbol(blob, mappings, deps, plt_symbols, param_list["allocation_call_site"]) != "_Znwj":
        raise RuntimeError("ParamList allocation differs")
    constructor_argument = _instruction(blob, mappings, deps, param_list["constructor_argument_site"])
    _require_mov_immediate(constructor_argument, deps, deps["r1"], 0, "ParamList constructor argument")
    param_capture = _instruction(blob, mappings, deps, param_list["capture_site"])
    if (
        param_capture.id != deps["mov"]
        or param_capture.operands[1].reg != deps["r0"]
        or param_capture.reg_name(param_capture.operands[0].reg) != param_list["capture_register"]
        or _call_symbol(blob, mappings, deps, plt_symbols, param_list["constructor_call_site"]) != param_list["constructor_symbol"]
    ):
        raise RuntimeError("ParamList construction differs")
    param_register = param_capture.operands[0].reg
    allocation_call = _instruction(blob, mappings, deps, param_list["allocation_call_site"])
    _require_register_unchanged(
        _decode(blob, mappings, deps, allocation_call.address + allocation_call.size, param_list["constructor_call_site"], complete=False),
        deps["r0"],
        label="ParamList constructor receiver preservation",
    )
    _require_register_unchanged(
        _decode(blob, mappings, deps, param_capture.address + param_capture.size, expected["request_param_list_site"], complete=False),
        param_register,
        label="ParamList result preservation",
    )
    for receiver_site, key_site, call_site, key, holder_name in zip(
        expected["param_receiver_sites"],
        expected["param_key_sites"],
        expected["param_add_call_sites"],
        expected["param_keys"],
        expected["param_holder_registers"],
    ):
        receiver_item = _instruction(blob, mappings, deps, receiver_site)
        _require_reg_to_reg(receiver_item, deps, deps["mov"], deps["r0"], param_register, "request parameter receiver")
        key_item = _instruction(blob, mappings, deps, key_site)
        holder_item = _instruction(blob, mappings, deps, key_site + key_item.size)
        _require_mov_immediate(key_item, deps, deps["r1"], key, "request parameter key")
        if (
            holder_item.id != deps["mov"]
            or holder_item.operands[0].reg != deps["r2"]
            or holder_item.reg_name(holder_item.operands[1].reg) != holder_name
            or _call_symbol(blob, mappings, deps, plt_symbols, call_site) != expected["param_add_symbol"]
        ):
            raise RuntimeError("request parameter holder differs")
        _require_register_unchanged(
            _decode(blob, mappings, deps, receiver_item.address + receiver_item.size, call_site, complete=False),
            deps["r0"],
            label="request parameter receiver preservation",
        )
        _require_register_unchanged(
            _decode(blob, mappings, deps, holder_item.address + holder_item.size, call_site, complete=False),
            deps["r1"],
            label="request parameter key preservation",
        )
        _require_register_unchanged(
            _decode(blob, mappings, deps, holder_item.address + holder_item.size, call_site, complete=False),
            deps["r2"],
            label="request parameter holder preservation",
        )
    if _call_symbol(blob, mappings, deps, plt_symbols, expected["request_call_site"]) != expected["request_symbol"]:
        raise RuntimeError("Creative Style request call differs")
    model_load = _instruction(blob, mappings, deps, expected["request_model_literal_load_site"])
    model_add = _instruction(blob, mappings, deps, expected["request_model_add_site"])
    code = _instruction(blob, mappings, deps, expected["request_code_site"])
    param_argument = _instruction(blob, mappings, deps, expected["request_param_list_site"])
    if (
        model_load.id != deps["ldr"]
        or len(model_load.operands) != 2
        or model_load.operands[0].type != deps["reg"]
        or model_load.operands[0].reg != deps["r0"]
        or model_load.operands[1].type != deps["mem"]
        or model_load.operands[1].mem.base != deps["pc"]
        or ((model_load.address + 4) & ~3) + model_load.operands[1].mem.disp != expected["request_model_literal_site"]
        or model_add.id != deps["add"]
        or len(model_add.operands) != 2
        or model_add.operands[0].type != deps["reg"]
        or model_add.operands[0].reg != deps["r0"]
        or model_add.operands[1].type != deps["reg"]
        or model_add.operands[1].reg != deps["pc"]
    ):
        raise RuntimeError("Creative Style request model argument differs")
    _require_mov_immediate(code, deps, deps["r1"], expected["request_code"], "Creative Style request code")
    _require_reg_to_reg(param_argument, deps, deps["mov"], deps["r2"], param_register, "Creative Style request ParamList")
    for register, start in (
        (deps["r0"], model_add.address + model_add.size),
        (deps["r1"], code.address + code.size),
        (deps["r2"], param_argument.address + param_argument.size),
    ):
        _require_register_unchanged(
            _decode(blob, mappings, deps, start, expected["request_call_site"], complete=False),
            register,
            label="Creative Style request argument preservation",
        )
    model = model_add.address + 4 + _word(blob, mappings, expected["request_model_literal_site"])
    if _cstring(blob, mappings, model) != expected["request_model"]:
        raise RuntimeError("Creative Style request model differs")
    return copy.deepcopy(expected)


def _validate_getter(blob, mappings, deps, plt_symbols):
    expected = EXPECTED_EXPORT["getter_boundary"]
    capture = _instruction(blob, mappings, deps, expected["direct_output_capture_site"])
    if capture.id != deps["mov"] or capture.operands[1].reg != deps["r2"] or capture.reg_name(capture.operands[0].reg) != "r8":
        raise RuntimeError("getter argument 2 output capture differs")
    output_register = capture.operands[0].reg
    buffer_base = _instruction(blob, mappings, deps, expected["read_buffer_base_site"])
    buffer_initial_value = _instruction(blob, mappings, deps, expected["read_buffer_initial_value_site"])
    buffer_adjust = _instruction(blob, mappings, deps, expected["read_buffer_pointer_adjust_site"])
    _require_add_immediate(buffer_base, deps, deps["r1"], deps["r7"], expected["read_buffer_local_offset"] + 3, "getter read-buffer base")
    if (
        buffer_initial_value.id != deps["mov"]
        or buffer_initial_value.operands[0].reg != deps["r3"]
        or (buffer_initial_value.operands[1].imm & 0xFF) != 0xFF
        or buffer_adjust.id != deps["strb"]
        or buffer_adjust.operands[0].reg != deps["r3"]
        or buffer_adjust.operands[1].mem.base != deps["r1"]
        or buffer_adjust.operands[1].mem.disp != -3
        or not buffer_adjust.writeback
        or buffer_adjust.post_index
    ):
        raise RuntimeError("getter read-buffer pointer adjustment differs")
    _require_register_unchanged(
        _decode(blob, mappings, deps, buffer_adjust.address + buffer_adjust.size, expected["fixed_backup_read_call_site"], complete=False),
        deps["r1"],
        label="getter read-buffer pointer preservation",
    )
    fixed_id = _instruction(blob, mappings, deps, expected["fixed_backup_id_load_site"])
    if (
        fixed_id.id != deps["ldr"]
        or fixed_id.operands[0].reg != deps["r0"]
        or ((fixed_id.address + 4) & ~3) + fixed_id.operands[1].mem.disp != expected["fixed_backup_id_literal_site"]
        or _word(blob, mappings, expected["fixed_backup_id_literal_site"]) != EXPECTED_EXPORT["argument_2_record"]["backup_id"]
        or _call_symbol(blob, mappings, deps, plt_symbols, expected["fixed_backup_read_call_site"]) != expected["backup_read_symbol"]
    ):
        raise RuntimeError("getter fixed backup record differs")
    signed_load = _instruction(blob, mappings, deps, expected["signed_byte_load_site"])
    if (
        signed_load.id != deps["ldrsb"]
        or signed_load.operands[1].mem.base != deps["r7"]
        or signed_load.operands[1].mem.disp != expected["read_buffer_local_offset"]
    ):
        raise RuntimeError("getter signed byte decode differs")
    value_register = signed_load.operands[0].reg
    zero_source = _instruction(blob, mappings, deps, expected["output_zero_source_site"])
    if (
        zero_source.id != deps["mov"]
        or zero_source.operands[1].type != deps["imm"]
        or zero_source.operands[1].imm != 0
    ):
        raise RuntimeError("getter argument 2 zero source differs")
    zero_register = zero_source.operands[0].reg
    zero_initialization = _instruction(blob, mappings, deps, expected["output_zero_initialization_site"])
    _require_memory(
        zero_initialization, deps, deps["str"], zero_register, output_register, 0,
        "getter argument 2 zero initialization",
    )
    _require_register_unchanged(
        _decode(
            blob, mappings, deps, zero_source.address + zero_source.size,
            zero_initialization.address, complete=False,
        ),
        zero_register,
        label="getter argument 2 zero-source preservation",
    )
    _require_register_unchanged(
        _decode(
            blob, mappings, deps, capture.address + capture.size,
            expected["output_store_site"], complete=False,
        ),
        output_register,
        label="getter argument 2 output-reference preservation",
    )
    for item in _decode(
        blob, mappings, deps, zero_initialization.address + zero_initialization.size,
        expected["signed_byte_load_site"], complete=False,
    ):
        if (
            item.id == deps["str"]
            and len(item.operands) >= 2
            and item.operands[1].type == deps["mem"]
            and item.operands[1].mem.base == output_register
            and item.operands[1].mem.disp == 0
        ):
            raise RuntimeError("getter argument 2 zero initialization is overwritten")
    compare = _instruction(blob, mappings, deps, expected["decode_compare_site"])
    skip_branch = _instruction(blob, mappings, deps, expected["minus_one_skip_branch_site"])
    increment = _instruction(blob, mappings, deps, expected["positive_increment_site"])
    join = _instruction(blob, mappings, deps, expected["decode_join_branch_site"])
    output = _instruction(blob, mappings, deps, expected["output_store_site"])
    if (
        compare.id != deps["cmp"]
        or compare.operands[0].reg != value_register
        or compare.operands[1].imm != -1
        or not skip_branch.group(deps["jump_group"])
        or skip_branch.cc != deps["eq"]
        or _direct_target(skip_branch, deps) != expected["minus_one_skip_target"]
        or increment.id != deps["add"]
        or increment.operands[0].reg != value_register
        or increment.operands[-1].imm != 1
        or not join.group(deps["jump_group"])
        or _direct_target(join, deps) != expected["output_store_site"]
        or
        output.id != deps["str"]
        or output.operands[0].reg != value_register
        or output.operands[1].mem.base != output_register
        or output.operands[1].mem.disp != 0
    ):
        raise RuntimeError("getter argument 2 output differs")
    if [item["call_site"] for item in expected["branch_dependent_reads"]] != expected["branch_dependent_backup_read_sites"]:
        raise RuntimeError("getter branch-dependent read inventory differs")
    for record in expected["branch_dependent_reads"]:
        base = _instruction(blob, mappings, deps, record["buffer_base_site"])
        _require_add_immediate(
            base, deps, deps["r1"], deps["r7"], record["buffer_base_offset"],
            "getter branch-dependent buffer base",
        )
        pointer_definition = base
        if record["buffer_adjust_site"] is not None:
            adjust = _instruction(blob, mappings, deps, record["buffer_adjust_site"])
            if not (
                adjust.id == deps["add"]
                and len(adjust.operands) in (2, 3)
                and adjust.operands[0].type == deps["reg"]
                and adjust.operands[0].reg == deps["r1"]
                and adjust.operands[-1].type == deps["imm"]
                and adjust.operands[-1].imm == record["buffer_adjustment"]
                and (
                    len(adjust.operands) == 2
                    or (
                        adjust.operands[1].type == deps["reg"]
                        and adjust.operands[1].reg == deps["r1"]
                    )
                )
            ):
                raise RuntimeError("getter branch-dependent buffer adjustment differs")
            pointer_definition = adjust
        if record["buffer_base_offset"] + record["buffer_adjustment"] != record["buffer_local_offset"]:
            raise RuntimeError("getter branch-dependent buffer formula differs")
        _require_register_unchanged(
            _decode(
                blob, mappings, deps, pointer_definition.address + pointer_definition.size,
                record["call_site"], complete=False,
            ),
            deps["r1"],
            label="getter branch-dependent buffer pointer preservation",
        )
        if _call_symbol(blob, mappings, deps, plt_symbols, record["call_site"]) != expected["backup_read_symbol"]:
            raise RuntimeError("getter branch-dependent backup read differs")
    return copy.deepcopy(expected)


def _validate_dynamic_records(blob, mappings, deps, plt_symbols):
    expected = EXPECTED_EXPORT["dynamic_records"]
    if expected["other_backup_write_count"] != len(expected["other_backup_write_call_sites"]):
        raise RuntimeError("other dynamic backup-write count differs")
    if EXPECTED_EXPORT["selector_record"]["backup_write_call_site"] in expected["other_backup_write_call_sites"]:
        raise RuntimeError("selector dynamic backup write is double counted")
    if [item["backup_write_call_site"] for item in expected["writes"][1:]] != expected["other_backup_write_call_sites"]:
        raise RuntimeError("dynamic backup-write inventory differs")
    arg2_capture = _instruction(blob, mappings, deps, EXPECTED_EXPORT["argument_2_record"]["argument_capture_site"])
    arg2_register = arg2_capture.operands[0].reg
    plus_13 = _instruction(blob, mappings, deps, expected["argument_2_plus_13_site"])
    incoming_start, incoming_end = expected["incoming_argument_2_preservation_segment"]
    if incoming_start != arg2_capture.address + arg2_capture.size or incoming_end != plus_13.address:
        raise RuntimeError("dynamic record incoming argument-2 preservation range differs")
    _require_register_unchanged(
        _decode(blob, mappings, deps, incoming_start, incoming_end, complete=False),
        arg2_register,
        label="dynamic record incoming argument-2 preservation",
    )
    if (
        plus_13.id != deps["add"]
        or len(plus_13.operands) != 3
        or plus_13.operands[1].reg != arg2_register
        or plus_13.operands[2].imm != 13
    ):
        raise RuntimeError("dynamic record argument-2-plus-13 transform differs")
    plus_13_register = plus_13.operands[0].reg
    scaled = _instruction(blob, mappings, deps, expected["argument_2_plus_13_scaled_site"])
    if (
        scaled.id != deps["lsl"]
        or len(scaled.operands) != 3
        or scaled.operands[0].reg != arg2_register
        or scaled.operands[1].reg != plus_13_register
        or scaled.operands[2].imm != 2
    ):
        raise RuntimeError("dynamic record scaled argument-2 transform differs")
    argument_3_index_site = expected["writes"][1]["id_index_site"]
    argument_4_index_site = expected["writes"][2]["id_index_site"]
    argument_5_load_site = expected["writes"][3]["id_load_site"]
    scaled_segments = expected["scaled_argument_2_preservation_segments"]
    if scaled_segments != [
        [scaled.address + scaled.size, argument_3_index_site],
        [argument_3_index_site + _instruction(blob, mappings, deps, argument_3_index_site).size, argument_4_index_site],
    ]:
        raise RuntimeError("dynamic record scaled argument-2 preservation ranges differ")
    for start, end in scaled_segments:
        _require_register_unchanged(
            _decode(blob, mappings, deps, start, end, complete=False),
            arg2_register,
            label="dynamic record scaled argument-2 preservation",
        )
    plus_13_segment = expected["argument_2_plus_13_preservation_segment"]
    if plus_13_segment != [plus_13.address + plus_13.size, argument_5_load_site]:
        raise RuntimeError("dynamic record argument-2-plus-13 preservation range differs")
    _require_register_unchanged(
        _decode(blob, mappings, deps, *plus_13_segment, complete=False),
        plus_13_register,
        label="dynamic record argument-2-plus-13 preservation",
    )

    for record in expected["writes"]:
        base = _instruction(blob, mappings, deps, record["id_base_site"])
        pointer = _instruction(blob, mappings, deps, record["value_pointer_site"])
        load = _instruction(blob, mappings, deps, record["id_load_site"])
        _require_add_immediate(
            pointer, deps, deps["r1"], deps["r7"], record["value_local_offset"],
            "dynamic backup payload pointer",
        )
        if record["role"] == "selector-code":
            _require_add_immediate(base, deps, deps["r2"], deps["r7"], record["id_base_offset"], "selector record ID base")
            index = _instruction(blob, mappings, deps, record["id_index_site"])
            if not (
                index.id == deps["add"]
                and index.operands[0].reg == deps["r3"]
                and index.operands[1].reg == deps["r2"]
                and index.operands[2].reg == arg2_register
                and index.operands[2].shift.value == 2
            ):
                raise RuntimeError("selector record ID index differs")
            calculated_offset = record["id_base_offset"] + record["id_load_displacement"]
        elif record["role"] in ("argument-3", "argument-4"):
            _require_add_immediate(base, deps, deps["r2"], deps["r7"], record["id_base_offset"], "argument record ID base")
            index = _instruction(blob, mappings, deps, record["id_index_site"])
            if not (
                index.id == deps["add"]
                and index.operands[0].reg == deps["r3"]
                and index.operands[1].reg == deps["r2"]
                and index.operands[2].reg == arg2_register
                and index.operands[2].shift.value == 0
            ):
                raise RuntimeError("argument record ID index differs")
            calculated_offset = record["id_base_offset"] + 4 * 13 + record["id_load_displacement"]
        elif record["role"] == "argument-5":
            _require_add_immediate(base, deps, deps["r3"], deps["r7"], record["id_base_offset"], "argument-5 record ID base")
            memory = load.operands[1].mem
            if (
                memory.base != deps["r3"]
                or memory.index != plus_13_register
                or load.operands[1].shift.value != 2
            ):
                raise RuntimeError("argument-5 record ID index differs")
            calculated_offset = record["id_base_offset"] + 4 * 13 + record["id_load_displacement"]
        else:
            raise RuntimeError("dynamic backup role differs")
        if (
            load.id != deps["ldr"]
            or load.operands[0].reg != deps["r0"]
            or load.operands[1].mem.base != deps["r3"]
            or load.operands[1].mem.disp != record["id_load_displacement"]
            or calculated_offset != record["record_id_effective_byte_offset"]
            or record["record_id_argument_2_scale"] != 4
        ):
            raise RuntimeError("dynamic backup record ID formula differs")
        _require_register_unchanged(
            _decode(blob, mappings, deps, pointer.address + pointer.size, record["backup_write_call_site"], complete=False),
            deps["r1"],
            label="dynamic backup payload pointer preservation",
        )
        if _call_symbol(blob, mappings, deps, plt_symbols, record["backup_write_call_site"]) != EXPECTED_EXPORT["selector_record"]["backup_write_symbol"]:
            raise RuntimeError("dynamic backup write boundary differs")
    for site in expected["other_backup_write_call_sites"]:
        if _call_symbol(blob, mappings, deps, plt_symbols, site) != EXPECTED_EXPORT["selector_record"]["backup_write_symbol"]:
            raise RuntimeError("dynamic backup write boundary differs")
    return copy.deepcopy(expected)


def _validate_record_id_tables(elf, blob, mappings, deps, plt_symbols):
    expected = EXPECTED_EXPORT["record_id_tables"]
    rodata = elf.get_section_by_name(".rodata")
    rodata_range = expected["rodata_range"]
    if (
        rodata is None
        or rodata["sh_addr"] != rodata_range["start"]
        or rodata["sh_addr"] + rodata["sh_size"] != rodata_range["end"]
    ):
        raise RuntimeError("record ID table read-only range differs")
    if sum(item["row_count"] for item in expected["families"]) != expected["total_row_count"]:
        raise RuntimeError("record ID table row count differs")

    def require_source(side):
        source_load = _instruction(blob, mappings, deps, side["source_site"])
        memory = source_load.operands[1].mem
        if (
            source_load.id != deps["ldr"]
            or len(source_load.operands) != 2
            or source_load.operands[0].type != deps["reg"]
            or source_load.operands[1].type != deps["mem"]
            or memory.base != deps["pc"]
            or memory.index != 0
        ):
            raise RuntimeError("record ID table source load differs")
        source_register = source_load.operands[0].reg
        source_add = _instruction(blob, mappings, deps, side["source_add_site"])
        if (
            source_add.id != deps["add"]
            or len(source_add.operands) != 2
            or source_add.operands[0].type != deps["reg"]
            or source_add.operands[0].reg != source_register
            or source_add.operands[1].type != deps["reg"]
            or source_add.operands[1].reg != deps["pc"]
        ):
            raise RuntimeError("record ID table source add differs")
        literal = ((source_load.address + 4) & ~3) + memory.disp
        resolved = source_add.address + 4 + _word(blob, mappings, literal, signed=True)
        if resolved != side["source"]:
            raise RuntimeError("record ID table source address differs")
        return source_register

    def require_inline_copy(side, destination_register, load_sites, store_sites):
        source_register = require_source(side)
        destination = _instruction(
            blob, mappings, deps, side["destination_site"]
        )
        _require_add_immediate(
            destination,
            deps,
            destination_register,
            deps["r7"],
            side["destination_offset"],
            "record ID table inline destination",
        )
        expected_registers = ([deps["r0"], deps["r1"], deps["r2"], deps["r3"]], [deps["r0"], deps["r1"], deps["r2"]])
        for index, (load_site, store_site) in enumerate(zip(load_sites, store_sites)):
            load = _instruction(blob, mappings, deps, load_site)
            store = _instruction(blob, mappings, deps, store_site)
            registers = expected_registers[index]
            if (
                load.id != deps["ldm"]
                or store.id != deps["stm"]
                or load.operands[0].reg != source_register
                or store.operands[0].reg != destination_register
                or [item.reg for item in load.operands[1:]] != registers
                or [item.reg for item in store.operands[1:]] != registers
                or load.writeback != (index == 0)
                or store.writeback != (index == 0)
            ):
                raise RuntimeError("record ID table inline copy differs")

    first = expected["families"][0]
    require_inline_copy(
        first["setter"], deps["r4"], (0x4893C2, 0x4893C6), (0x4893C4, 0x4893CA)
    )
    require_inline_copy(
        first["getter"], deps["ip"], (0x48B916, 0x48B91E), (0x48B91A, 0x48B922)
    )

    for family in expected["families"]:
        count = family["row_count"]
        expected_values = family["record_ids"]
        if len(expected_values) != count:
            raise RuntimeError("record ID table family length differs")
        observed = []
        for side in ("setter", "getter"):
            source = family[side]["source"]
            if not rodata_range["start"] <= source <= rodata_range["end"] - count * 4:
                raise RuntimeError("record ID table source is outside read-only storage")
            values = [_word(blob, mappings, source + index * 4) for index in range(count)]
            if values != expected_values:
                raise RuntimeError("record ID table values differ")
            observed.append(values)
        if observed[0] != observed[1] or family["setter_getter_values_equal"] is not True:
            raise RuntimeError("record ID table setter/getter equality differs")
        if family["row_count"] == 20:
            for side_name in ("setter", "getter"):
                side = family[side_name]
                require_source(side)
                _require_mov_immediate(
                    _instruction(blob, mappings, deps, side["size_site"]),
                    deps,
                    deps["r2"],
                    80,
                    "record ID table copy size",
                )
                _require_add_immediate(
                    _instruction(blob, mappings, deps, side["destination_site"]),
                    deps,
                    deps["r0"],
                    deps["r7"],
                    side["destination_offset"],
                    "record ID table copy destination",
                )
                if _call_symbol(
                    blob, mappings, deps, plt_symbols, side["copy_call_site"]
                ) != "memcpy":
                    raise RuntimeError("record ID table memcpy boundary differs")
    return copy.deepcopy(expected)


class ElfAdapter:
    def metadata(self):
        if not sources_available():
            raise RuntimeError("pinned viewUnified2 source is unavailable")
        before = _sha256(SOURCE_PATH)
        if SOURCE_PATH.stat().st_size != SOURCE["size"] or before != SOURCE["sha256"]:
            raise RuntimeError("pinned viewUnified2 source identity differs")
        blob = SOURCE_PATH.read_bytes()
        deps = _dependencies()
        with SOURCE_PATH.open("rb") as handle:
            elf = deps["ELFFile"](handle)
            mappings = _mappings(elf)
            rels, by_site = _relocations(elf)
            dynsym = elf.get_section_by_name(".dynsym")
            plt_symbols = _plt_symbols(elf, blob, mappings)
            exidx = _exidx_ranges(elf, blob)
            typed = _validate_typed_element(elf, blob, mappings, deps, rels, by_site, dynsym, exidx)
            selector_map = _validate_selector_cases(blob, mappings, deps, plt_symbols)
            _validate_holder(blob, mappings, deps, plt_symbols, exidx)
            selector_record, argument_2_record = _validate_persistence(blob, mappings, deps, plt_symbols)
            request = _validate_request(blob, mappings, deps, plt_symbols)
            getter = _validate_getter(blob, mappings, deps, plt_symbols)
            record_id_tables = _validate_record_id_tables(
                elf, blob, mappings, deps, plt_symbols
            )
            dynamic = _validate_dynamic_records(blob, mappings, deps, plt_symbols)
        if _sha256(SOURCE_PATH) != before:
            raise RuntimeError("pinned viewUnified2 source changed during export")
        document = copy.deepcopy(EXPECTED_EXPORT)
        document.update({
            "typed_element": typed,
            "setter_selector": selector_map,
            "selector_record": selector_record,
            "argument_2_record": argument_2_record,
            "request_boundary": request,
            "getter_boundary": getter,
            "record_id_tables": record_id_tables,
            "dynamic_records": dynamic,
        })
        return document


def build_raw_export(adapter=None):
    document = (adapter or ElfAdapter()).metadata()
    return normalize_creative_style_selector_code_export(document)


def write_export(document, output_root=OUTPUT_ROOT):
    normalized = normalize_creative_style_selector_code_export(document)
    root = Path(output_root).resolve()
    approved = OUTPUT_ROOT.resolve()
    if root != approved or ARTIFACT_BASE.resolve() not in root.parents:
        raise RuntimeError("output root is outside the approved artifact path")
    root.mkdir(parents=True, exist_ok=True)
    target = root / OUTPUT_NAME
    if target.exists() and (target.is_symlink() or not target.is_file()):
        raise RuntimeError("output target is not a regular file")
    payload = json.dumps(normalized, indent=2, sort_keys=True) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=OUTPUT_NAME + ".", suffix=".tmp", dir=str(root))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return target


def main():
    output = write_export(build_raw_export())
    print("CREATIVE_STYLE_SELECTOR_CODE_EXPORT|selectors=13|rejected=1|fixed_arg2=1|touch=0|installable=0")
    print(output)


if __name__ == "__main__":
    main()
