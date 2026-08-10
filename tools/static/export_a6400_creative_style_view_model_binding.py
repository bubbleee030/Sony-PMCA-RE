"""Read-only exporter for the target Creative Style view/model binding."""
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

from pmca.analysis.creative_style_view_model_binding import (
    CASE_TARGETS,
    EXPECTED_EXPORT,
    SOURCE,
    normalize_creative_style_view_model_binding_export,
)
from tools.static.export_a6400_creative_style_model_cursor_boundary import _decoded_plt_addresses_exact
from tools.static.export_a6400_generic_model_owner_provenance import (
    _at,
    _exidx_ranges,
    _global_direct_inbound,
    _mappings,
    _section_name,
)


SOURCE_PATH = (
    ROOT / ".artifacts" / "decrypted" / "a6400-tw-v2.00" / "ma1co"
    / "firmware.tar_unpacked" / "0700_part_image" / "dev" / "nflasha15_unpacked"
    / "lib" / "viewUnified2.so"
)
ARTIFACT_BASE = ROOT / ".artifacts"
OUTPUT_ROOT = ARTIFACT_BASE / "creative-style-view-model-binding" / "a6400-v2.00"
OUTPUT_NAME = "creative-style-view-model-binding-export.json"


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _dependencies():
    try:
        from capstone import (
            Cs, CS_ARCH_ARM, CS_GRP_CALL, CS_GRP_JUMP, CS_MODE_THUMB, CS_OP_IMM,
        )
        from capstone.arm import (
            ARM_CC_HI,
            ARM_INS_ADD, ARM_INS_ADR, ARM_INS_BL, ARM_INS_BLX, ARM_INS_BX,
            ARM_INS_CMP, ARM_INS_LDR,
            ARM_INS_LDRSB, ARM_INS_MOV, ARM_INS_POP, ARM_INS_STR, ARM_INS_STRB,
            ARM_INS_TBH,
            ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC, ARM_REG_R0, ARM_REG_R1,
            ARM_REG_R2, ARM_REG_R3, ARM_REG_R4, ARM_REG_R5, ARM_REG_R7,
        )
        from elftools.elf.elffile import ELFFile
    except (ImportError, AttributeError) as exc:
        raise RuntimeError("local Capstone and pyelftools are required") from exc
    return {
        "Cs": Cs, "arch": CS_ARCH_ARM, "mode": CS_MODE_THUMB,
        "call_group": CS_GRP_CALL, "jump_group": CS_GRP_JUMP, "imm": CS_OP_IMM,
        "add": ARM_INS_ADD, "adr": ARM_INS_ADR, "bl": ARM_INS_BL,
        "blx": ARM_INS_BLX, "bx": ARM_INS_BX,
        "cmp": ARM_INS_CMP, "ldr": ARM_INS_LDR, "ldrsb": ARM_INS_LDRSB,
        "mov": ARM_INS_MOV,
        "pop": ARM_INS_POP, "str": ARM_INS_STR, "strb": ARM_INS_STRB,
        "tbh": ARM_INS_TBH, "hi": ARM_CC_HI, "mem": ARM_OP_MEM, "reg": ARM_OP_REG,
        "pc": ARM_REG_PC, "r0": ARM_REG_R0, "r1": ARM_REG_R1,
        "r2": ARM_REG_R2, "r3": ARM_REG_R3, "r4": ARM_REG_R4,
        "r5": ARM_REG_R5,
        "r7": ARM_REG_R7,
        "ELFFile": ELFFile,
    }


def dependencies_available():
    try:
        _dependencies()
    except RuntimeError:
        return False
    return True


def sources_available():
    return SOURCE_PATH.is_file() and not SOURCE_PATH.is_symlink()


def _word(blob, mappings, address, *, signed=False):
    return int.from_bytes(_at(blob, mappings, address, 4), "little", signed=signed)


def _cstring(blob, mappings, address, limit=128):
    value = bytearray()
    for offset in range(limit):
        byte = _at(blob, mappings, address + offset, 1)[0]
        if byte == 0:
            try:
                return value.decode("ascii")
            except UnicodeDecodeError as exc:
                raise RuntimeError("bounded string is not ASCII") from exc
        value.append(byte)
    raise RuntimeError("bounded string is unterminated")


def _decoder(deps):
    decoder = deps["Cs"](deps["arch"], deps["mode"])
    decoder.detail = True
    return decoder


def _decode(blob, mappings, deps, start, end, *, complete=True):
    items = list(_decoder(deps).disasm(_at(blob, mappings, start, end - start), start))
    if complete and (not items or items[0].address != start or items[-1].address + items[-1].size != end):
        raise RuntimeError("bounded Thumb range is incomplete")
    return items


def _instruction(blob, mappings, deps, site):
    items = _decode(blob, mappings, deps, site, site + 4, complete=False)
    if not items or items[0].address != site:
        raise RuntimeError("instruction site does not decode")
    return items[0]


def _direct_target(item, deps):
    targets = [operand.imm & ~1 for operand in item.operands if operand.type == deps["imm"]]
    return targets[0] if len(targets) == 1 else None


def _require_mov_immediate(item, deps, register, value, label):
    if (
        item.id != deps["mov"]
        or len(item.operands) != 2
        or item.operands[0].type != deps["reg"]
        or item.operands[0].reg != register
        or item.operands[1].type != deps["imm"]
        or item.operands[1].imm != value
    ):
        raise RuntimeError(label + " differs")


def _require_register_unchanged(items, register, *, label):
    for item in items:
        _reads, writes = item.regs_access()
        if register in writes:
            raise RuntimeError(label + " differs")


def _count_targets_in_range(targets, start, end):
    if not isinstance(start, int) or not isinstance(end, int) or start >= end:
        raise RuntimeError("invalid target range")
    return sum(start <= target < end for target in targets)


def _relocations(elf):
    rels = list(elf.get_section_by_name(".rel.dyn").iter_relocations())
    return rels, {relocation["r_offset"]: (index, relocation) for index, relocation in enumerate(rels)}


def _plt_symbols(elf, blob, mappings):
    dynsym = elf.get_section_by_name(".dynsym")
    got_to_plt = _decoded_plt_addresses_exact(elf, blob, mappings)
    return {
        got_to_plt[relocation["r_offset"]] & ~1: dynsym.get_symbol(relocation["r_info_sym"]).name
        for relocation in elf.get_section_by_name(".rel.plt").iter_relocations()
        if relocation["r_offset"] in got_to_plt
    }


def _call_symbol(blob, mappings, deps, plt_symbols, site):
    item = _instruction(blob, mappings, deps, site)
    target = _direct_target(item, deps)
    if not item.group(deps["call_group"]) or target not in plt_symbols:
        raise RuntimeError("named call binding differs")
    return plt_symbols[target]


def _owner(exidx, target):
    matches = [(start, end) for start, end in exidx if start <= target < end]
    if len(matches) != 1:
        raise RuntimeError("exception-index owner differs")
    return matches[0]


def _validate_relative(rels, by_site, blob, mappings, *, index, site, target):
    actual_index, relocation = by_site[site]
    if (
        actual_index != index
        or relocation["r_info_type"] != 23
        or relocation["r_info_sym"] != 0
        or (_word(blob, mappings, site) & ~1) != target
    ):
        raise RuntimeError("relative relocation differs")


def _validate_si_rtti(elf, blob, mappings, rels, by_site, dynsym, *, rtti, encoding, base=None):
    abi_index, abi = by_site[rtti]
    name_index, name = by_site[rtti + 4]
    if (
        abi["r_info_type"] != 2
        or dynsym.get_symbol(abi["r_info_sym"]).name != "_ZTVN10__cxxabiv120__si_class_type_infoE"
        or name["r_info_type"] != 23
        or name["r_info_sym"] != 0
        or _cstring(blob, mappings, _word(blob, mappings, rtti + 4)) != encoding
    ):
        raise RuntimeError("SI RTTI identity differs")
    if base is not None:
        _base_index, base_rel = by_site[rtti + 8]
        if base_rel["r_info_type"] != 2 or dynsym.get_symbol(base_rel["r_info_sym"]).name != base:
            raise RuntimeError("SI RTTI base differs")
    return abi_index, name_index


def _validate_view(elf, blob, mappings, deps, rels, by_site, dynsym, plt_symbols, exidx):
    expected = EXPECTED_EXPORT["view"]
    _validate_si_rtti(
        elf, blob, mappings, rels, by_site, dynsym,
        rtti=expected["rtti"], encoding=expected["type_name_encoding"],
        base=expected["base_rtti_symbol"],
    )
    primary = expected["primary_vtable"]
    if _word(blob, mappings, primary["header"], signed=True) != 0:
        raise RuntimeError("ViewCreativeStyle primary offset-to-top differs")
    _validate_relative(rels, by_site, blob, mappings, index=51782, site=primary["header"] + 4, target=expected["rtti"])
    shape = {"dynamic_symbol": 0, "local_relative": 0}
    for cell in range(primary["address_point"], primary["end"], 4):
        if cell not in by_site:
            raise RuntimeError("ViewCreativeStyle primary slot lacks relocation")
        _index, relocation = by_site[cell]
        if relocation["r_info_type"] == 2:
            shape["dynamic_symbol"] += 1
        elif relocation["r_info_type"] == 23 and relocation["r_info_sym"] == 0:
            shape["local_relative"] += 1
        else:
            raise RuntimeError("ViewCreativeStyle primary relocation kind differs")
    if shape != expected["primary_relocation_shape"] or (primary["end"] - primary["address_point"]) // 4 != 94:
        raise RuntimeError("ViewCreativeStyle primary vtable shape differs")
    secondary = expected["secondary_vtable"]
    if _word(blob, mappings, secondary["header"], signed=True) != -0x28:
        raise RuntimeError("ViewCreativeStyle secondary offset-to-top differs")
    _validate_relative(rels, by_site, blob, mappings, index=51808, site=secondary["typeinfo_cell"], target=expected["rtti"])
    for cell in (secondary["address_point"], secondary["address_point"] + 4):
        if cell not in by_site or by_site[cell][1]["r_info_type"] != 23:
            raise RuntimeError("ViewCreativeStyle secondary slots differ")

    factory = expected["factory_entry"]
    symbol = dynsym.get_symbol(factory["symbol_index"])
    if (
        symbol.name != factory["symbol"]
        or symbol["st_shndx"] == "SHN_UNDEF"
        or (symbol["st_value"] & ~1) != factory["range"]["start"]
        or symbol["st_size"] != factory["range"]["end"] - factory["range"]["start"]
    ):
        raise RuntimeError("ViewCreativeStyle factory entry differs")
    factory_items = _decode(blob, mappings, deps, factory["range"]["start"], factory["range"]["end"])
    if _direct_target(next(item for item in factory_items if item.address == 0x5CD8A0), deps) != 0x5CD664:
        raise RuntimeError("ViewCreativeStyle factory constructor edge differs")
    allocation = _instruction(blob, mappings, deps, 0x5CD890)
    if allocation.id != deps["mov"] or allocation.operands[1].imm != 0x194:
        raise RuntimeError("ViewCreativeStyle allocation size differs")

    constructor = expected["constructor"]
    if _owner(exidx, constructor["helper"]["start"]) != (constructor["helper"]["start"], constructor["helper"]["end"]):
        raise RuntimeError("ViewCreativeStyle constructor owner differs")
    if _call_symbol(blob, mappings, deps, plt_symbols, 0x5CD66C) != constructor["base_constructor_call"]["symbol"]:
        raise RuntimeError("ViewCreativeStyle base constructor differs")
    if _call_symbol(blob, mappings, deps, plt_symbols, 0x5CD686) != constructor["set_model_request_call"]["symbol"]:
        raise RuntimeError("ViewCreativeStyle model-request flag call differs")
    _validate_relative(
        rels, by_site, blob, mappings,
        index=constructor["vtable_got_relocation_index"], site=constructor["vtable_got_cell"],
        target=primary["header"],
    )
    got = constructor["vtable_got_load"]
    base_load = _instruction(blob, mappings, deps, got["base_literal_load_site"])
    index_load = _instruction(blob, mappings, deps, got["index_literal_load_site"])
    base_add = _instruction(blob, mappings, deps, got["base_add_site"])
    got_load = _instruction(blob, mappings, deps, got["load_site"])
    if (
        base_load.id != deps["ldr"]
        or base_load.operands[0].reg != deps["r5"]
        or base_load.operands[1].mem.base != deps["pc"]
        or ((base_load.address + 4) & ~3) + base_load.operands[1].mem.disp != got["base_literal_site"]
        or index_load.id != deps["ldr"]
        or index_load.operands[0].reg != deps["r3"]
        or index_load.operands[1].mem.base != deps["pc"]
        or ((index_load.address + 4) & ~3) + index_load.operands[1].mem.disp != got["index_literal_site"]
        or base_add.id != deps["add"]
        or base_add.operands[0].reg != deps["r5"]
        or base_add.operands[1].reg != deps["pc"]
        or got_load.id != deps["ldr"]
        or got_load.operands[0].reg != deps["r3"]
        or got_load.operands[1].mem.base != deps["r5"]
        or got_load.operands[1].mem.index != deps["r3"]
    ):
        raise RuntimeError("ViewCreativeStyle vtable GOT dataflow differs")
    calculated_got = (
        got["base_add_site"] + 4
        + _word(blob, mappings, got["base_literal_site"])
        + _word(blob, mappings, got["index_literal_site"])
    ) & 0xFFFFFFFF
    if calculated_got != constructor["vtable_got_cell"]:
        raise RuntimeError("ViewCreativeStyle calculated vtable GOT cell differs")
    primary_add = _instruction(blob, mappings, deps, 0x5CD67A)
    secondary_add = _instruction(blob, mappings, deps, 0x5CD67E)
    if (
        primary_add.id != deps["add"]
        or primary_add.operands[0].reg != deps["r2"]
        or primary_add.operands[1].reg != deps["r3"]
        or primary_add.operands[2].imm != primary["address_point"] - primary["header"]
        or secondary_add.id != deps["add"]
        or secondary_add.operands[0].reg != deps["r3"]
        or secondary_add.operands[1].reg != deps["r3"]
        or secondary_add.operands[2].imm != secondary["address_point"] - primary["header"]
    ):
        raise RuntimeError("ViewCreativeStyle vtable address-point derivation differs")
    for spec, source_reg in ((constructor["primary_vptr_store"], deps["r2"]), (constructor["secondary_vptr_store"], deps["r3"])):
        item = _instruction(blob, mappings, deps, spec["site"])
        memory = item.operands[1].mem
        if item.id != deps["str"] or item.operands[0].reg != source_reg or memory.base != deps["r4"] or memory.disp != spec["object_offset"]:
            raise RuntimeError("ViewCreativeStyle vptr store differs")

    initializer = expected["initializer"]
    _validate_relative(rels, by_site, blob, mappings, index=51795, site=initializer["cell"], target=initializer["target"])
    if _owner(exidx, initializer["target"]) != (initializer["owner"]["start"], initializer["owner"]["end"]):
        raise RuntimeError("ViewCreativeStyle initializer owner differs")
    if _call_symbol(blob, mappings, deps, plt_symbols, 0x5CD03E) != "_ZN17CmnModelAndTreeId11getInstanceEv":
        raise RuntimeError("model-id singleton call differs")
    if _call_symbol(blob, mappings, deps, plt_symbols, 0x5CD042) != "_ZN17CmnModelAndTreeId25getCurrentStillRecModelIdEv":
        raise RuntimeError("current model-id call differs")
    event_cell = initializer["event_attachment_cell"]
    _event_index, event_relocation = by_site[event_cell]
    if (
        event_cell != primary["address_point"] + initializer["event_attachment_vtable_slot"] * 4
        or event_relocation["r_info_type"] != 2
        or dynsym.get_symbol(event_relocation["r_info_sym"]).name != initializer["event_attachment_symbol"]
    ):
        raise RuntimeError("Creative Style event attachment slot differs")
    for record in initializer["event_attachments"]:
        address = record["name_add_site"] + 4 + _word(blob, mappings, record["literal_site"])
        if _cstring(blob, mappings, address) != record["name"]:
            raise RuntimeError("Creative Style event name differs")
        vptr = _instruction(blob, mappings, deps, record["vptr_load_site"])
        name_load = _instruction(blob, mappings, deps, record["name_load_site"])
        receiver = _instruction(blob, mappings, deps, record["receiver_site"])
        count = _instruction(blob, mappings, deps, record["count_site"])
        slot = _instruction(blob, mappings, deps, record["slot_load_site"])
        name_add = _instruction(blob, mappings, deps, record["name_add_site"])
        event_id = _instruction(blob, mappings, deps, record["event_id_site"])
        call = _instruction(blob, mappings, deps, record["site"])
        _require_mov_immediate(count, deps, deps["r2"], record["count"], "Creative Style event count")
        _require_mov_immediate(event_id, deps, deps["r3"], record["event_id"], "Creative Style event ID")
        if (
            vptr.id != deps["ldr"] or vptr.operands[0].reg != deps["r3"]
            or vptr.operands[1].mem.base != deps["r4"] or vptr.operands[1].mem.disp != 0
            or name_load.id != deps["ldr"] or name_load.operands[0].reg != deps["r1"]
            or name_load.operands[1].mem.base != deps["pc"]
            or ((name_load.address + 4) & ~3) + name_load.operands[1].mem.disp != record["literal_site"]
            or receiver.id != deps["mov"] or receiver.operands[0].reg != deps["r0"] or receiver.operands[1].reg != deps["r4"]
            or slot.id != deps["ldr"] or slot.operands[0].reg != deps["r5"]
            or slot.operands[1].mem.base != deps["r3"] or slot.operands[1].mem.disp != initializer["event_attachment_vtable_slot"] * 4
            or name_add.id != deps["add"] or name_add.operands[0].reg != deps["r1"] or name_add.operands[1].reg != deps["pc"]
            or call.id != deps["blx"] or call.operands[0].type != deps["reg"] or call.operands[0].reg != deps["r5"]
        ):
            raise RuntimeError("Creative Style event attachment dataflow differs")
    request = initializer["model_request"]
    request_item = _instruction(blob, mappings, deps, request["site"])
    if not request_item.group(deps["call_group"]):
        raise RuntimeError("Creative Style model request call differs")
    request_window = _decode(blob, mappings, deps, 0x5CD038, 0x5CD050)
    if not any(item.id == deps["ldr"] and item.operands[1].type == deps["mem"] and item.operands[1].mem.disp == request["vtable_slot"] * 4 for item in request_window):
        raise RuntimeError("Creative Style model request vtable slot differs")
    if not any(item.id == deps["mov"] and item.operands[0].reg == deps["r2"] and item.operands[1].imm == request["request_code"] for item in request_window):
        raise RuntimeError("Creative Style model request code differs")

    dispatcher = expected["dispatcher"]
    _validate_relative(rels, by_site, blob, mappings, index=dispatcher["relocation_index"], site=dispatcher["cell"], target=dispatcher["target"])
    if _owner(exidx, dispatcher["target"]) != (dispatcher["owner"]["start"], dispatcher["owner"]["end"]):
        raise RuntimeError("Creative Style dispatcher owner differs")
    table_item = _instruction(blob, mappings, deps, dispatcher["table_branch_site"])
    guard = dispatcher["guard"]
    compare = _instruction(blob, mappings, deps, guard["compare_site"])
    branch = _instruction(blob, mappings, deps, guard["branch_site"])
    table_memory = table_item.operands[0].mem
    if (
        compare.id != deps["cmp"] or compare.operands[0].reg != deps["r1"]
        or compare.operands[1].imm != dispatcher["selector_max"]
        or branch.cc != deps["hi"] or _direct_target(branch, deps) != guard["out_of_range_target"]
        or table_item.id != deps["tbh"] or not table_item.group(deps["jump_group"])
        or table_memory.base != deps["pc"] or table_memory.index != deps["r1"] or table_memory.lshift != 1
        or dispatcher["selector_min"] != 0
        or dispatcher["table_start"] != dispatcher["table_branch_site"] + 4
        or dispatcher["table_start"] + dispatcher["case_count"] * 2 > dispatcher["owner"]["end"]
    ):
        raise RuntimeError("Creative Style table branch differs")
    _require_register_unchanged(
        _decode(blob, mappings, deps, dispatcher["target"], guard["compare_site"], complete=False),
        deps["r1"], label="Creative Style dispatcher selector preservation",
    )
    actual_targets = []
    for index in range(dispatcher["case_count"]):
        entry = dispatcher["table_start"] + index * 2
        landing = dispatcher["table_start"] + 2 * int.from_bytes(_at(blob, mappings, entry, 2), "little")
        candidates = _decode(blob, mappings, deps, landing, min(landing + 10, dispatcher["owner"]["end"]), complete=False)
        transfers = [
            _direct_target(item, deps) for item in candidates[:3]
            if (item.group(deps["call_group"]) or item.group(deps["jump_group"])) and _direct_target(item, deps) is not None
        ]
        if not transfers:
            raise RuntimeError("Creative Style case transfer differs")
        actual_targets.append(transfers[0] if index not in (18, 19) else transfers[0])
    if actual_targets != CASE_TARGETS:
        raise RuntimeError("Creative Style case targets differ")
    return copy.deepcopy(expected)


def _validate_process_binding(elf, blob, mappings, deps, rels, by_site, dynsym, plt_symbols, exidx):
    expected = EXPECTED_EXPORT["process_binding"]
    manager = expected["manager"]
    _validate_si_rtti(
        elf, blob, mappings, rels, by_site, dynsym,
        rtti=manager["rtti"], encoding="21CmnViewProcessDataMgr",
    )
    if _word(blob, mappings, manager["vtable_header"], signed=True) != 0:
        raise RuntimeError("process manager vtable header differs")
    _manager_typeinfo_index, manager_typeinfo = by_site[manager["vtable_header"] + 4]
    if (
        manager["vtable_address_point"] != manager["vtable_header"] + 8
        or manager_typeinfo["r_info_type"] != 23 or manager_typeinfo["r_info_sym"] != 0
        or (_word(blob, mappings, manager["vtable_header"] + 4) & ~1) != manager["rtti"]
    ):
        raise RuntimeError("process manager vtable/typeinfo join differs")
    accessor = manager["instance_accessor"]
    if _owner(exidx, accessor["start"]) != (accessor["start"], accessor["end"]):
        raise RuntimeError("process manager instance accessor owner differs")
    accessor_receiver = _instruction(blob, mappings, deps, accessor["constructor_receiver_site"])
    accessor_return = _instruction(blob, mappings, deps, accessor["return_site"])
    if (
        accessor_receiver.id != deps["mov"] or accessor_receiver.operands[0].reg != deps["r0"]
        or accessor_receiver.operands[1].reg != deps["r5"]
        or _call_symbol(blob, mappings, deps, plt_symbols, accessor["constructor_call_site"]) != accessor["constructor_symbol"]
        or accessor_return.id != deps["mov"] or accessor_return.operands[0].reg != deps["r0"]
        or accessor_return.operands[1].reg != deps["r5"]
    ):
        raise RuntimeError("process manager typed instance accessor differs")
    view_join = expected["view_dispatch_join"]
    if (
        CASE_TARGETS[view_join["case_index"]] != view_join["case_target"]
        or _owner(exidx, view_join["case_target"]) != (view_join["owner"]["start"], view_join["owner"]["end"])
        or _direct_target(_instruction(blob, mappings, deps, view_join["read_helper_call_site"]), deps) != expected["read_helper"]["target"]
        or _direct_target(_instruction(blob, mappings, deps, view_join["write_helper_call_site"]), deps) != expected["write_helper"]["target"]
    ):
        raise RuntimeError("ViewCreativeStyle dispatcher/process-helper join differs")
    for helper_name in ("read_helper", "write_helper"):
        helper = expected[helper_name]
        mov_site = helper["process_id_site"]
        call_site = helper["manager_call_site"]
        manager_slot = helper["manager_vtable_slot"]
        if _owner(exidx, helper["target"]) != (helper["owner"]["start"], helper["owner"]["end"]):
            raise RuntimeError("Creative Style process helper owner differs")
        if _direct_target(_instruction(blob, mappings, deps, helper["manager_accessor_call_site"]), deps) != accessor["start"]:
            raise RuntimeError("Creative Style manager accessor edge differs")
        capture = _instruction(blob, mappings, deps, helper["manager_result_capture_site"])
        if capture.id != deps["mov"] or capture.operands[1].reg != deps["r0"]:
            raise RuntimeError("Creative Style manager result capture differs")
        manager_register = capture.operands[0].reg
        _require_register_unchanged(
            _decode(blob, mappings, deps, helper["manager_accessor_call_site"] + 4, helper["manager_result_capture_site"], complete=False),
            deps["r0"], label="Creative Style manager accessor result preservation",
        )
        manager_vptr = _instruction(blob, mappings, deps, helper["manager_vptr_load_site"])
        manager_receiver = _instruction(blob, mappings, deps, helper["manager_receiver_site"])
        if (
            manager_vptr.id != deps["ldr"] or manager_vptr.operands[0].reg != deps["r3"]
            or manager_vptr.operands[1].mem.base != manager_register or manager_vptr.operands[1].mem.disp != 0
            or manager_receiver.id != deps["mov"] or manager_receiver.operands[0].reg != deps["r0"]
            or manager_receiver.operands[1].reg != manager_register
        ):
            raise RuntimeError("Creative Style typed manager receiver/vptr differs")
        mov = _instruction(blob, mappings, deps, mov_site)
        if mov.id != deps["mov"] or mov.operands[0].reg != deps["r1"] or mov.operands[1].imm != expected["view_helper_process_id"]:
            raise RuntimeError("Creative Style process ID differs")
        _require_register_unchanged(
            _decode(blob, mappings, deps, mov_site + mov.size, call_site, complete=False),
            deps["r1"], label="Creative Style helper process ID preservation",
        )
        _require_register_unchanged(
            _decode(blob, mappings, deps, helper["manager_receiver_site"] + manager_receiver.size, call_site, complete=False),
            deps["r0"], label="Creative Style helper manager receiver preservation",
        )
        call = _instruction(blob, mappings, deps, call_site)
        target_load = _instruction(blob, mappings, deps, helper["manager_slot_load_site"])
        if (
            call.id != deps["blx"] or call.operands[0].type != deps["reg"]
            or target_load.id != deps["ldr"] or target_load.operands[0].type != deps["reg"]
            or target_load.operands[0].reg != call.operands[0].reg
            or target_load.operands[1].mem.base != manager_vptr.operands[0].reg
            or target_load.operands[1].mem.disp != manager_slot * 4
        ):
            raise RuntimeError("Creative Style manager vtable slot differs")
    for slot, target in ((6, 0x43926A), (16, 0x43911E)):
        cell = manager["vtable_address_point"] + slot * 4
        _index, relocation = by_site[cell]
        if relocation["r_info_type"] != 23 or (_word(blob, mappings, cell) & ~1) != target:
            raise RuntimeError("process manager vtable target differs")

    lookup = manager["lookup"]
    if _owner(exidx, lookup["start"]) != (0x43905C, lookup["end"]):
        raise RuntimeError("process manager lookup owner differs")
    table_base = 0x43909E + _word(blob, mappings, 0x4390B8)
    mapping = expected["manager_mapping"]
    if table_base != mapping["table"] or mapping["entry_site"] != table_base + mapping["index"] * 4 or _word(blob, mappings, mapping["entry_site"]) != mapping["value"]:
        raise RuntimeError("process manager mapping differs")

    join = expected["join_proof"]
    capture = _instruction(blob, mappings, deps, join["lookup_parameter_capture_site"])
    table_base_load = _instruction(blob, mappings, deps, join["lookup_table_base_load_site"])
    table_base_add = _instruction(blob, mappings, deps, join["lookup_table_base_add_site"])
    table_load = _instruction(blob, mappings, deps, join["lookup_table_load_site"])
    factory_call = _instruction(blob, mappings, deps, join["lookup_factory_call_site"])
    if (
        join["lookup_input_register"] != "r1"
        or capture.id != deps["mov"] or capture.operands[0].reg != deps["r5"] or capture.operands[1].reg != deps["r1"]
        or table_base_load.id != deps["ldr"] or table_base_load.operands[0].reg != deps["r3"]
        or table_base_load.operands[1].mem.base != deps["pc"]
        or ((table_base_load.address + 4) & ~3) + table_base_load.operands[1].mem.disp != join["lookup_table_base_literal_site"]
        or table_base_add.id != deps["add"] or table_base_add.operands[0].reg != deps["r3"] or table_base_add.operands[1].reg != deps["pc"]
        or table_load.id != deps["ldr"] or table_load.operands[0].reg != deps["r1"]
        or table_load.operands[1].mem.base != deps["r3"] or table_load.operands[1].mem.index != deps["r1"]
        or table_load.operands[1].shift.value != 2
        or factory_call.id != deps["bl"] or _direct_target(factory_call, deps) != expected["factory_dispatch"]["owner"]["start"]
    ):
        raise RuntimeError("process manager lookup selector dataflow differs")
    if (
        (join["lookup_table_base_add_site"] + 4 + _word(blob, mappings, join["lookup_table_base_literal_site"])) & 0xFFFFFFFF
        != mapping["table"]
    ):
        raise RuntimeError("process manager lookup table-base derivation differs")
    _require_register_unchanged(
        _decode(blob, mappings, deps, join["lookup_parameter_capture_site"] + capture.size, join["lookup_table_load_site"], complete=False),
        deps["r1"], label="process manager lookup ID preservation",
    )
    _require_register_unchanged(
        _decode(blob, mappings, deps, join["lookup_table_base_add_site"] + table_base_add.size, join["lookup_table_load_site"], complete=False),
        deps["r3"], label="process manager lookup table-base preservation",
    )
    _require_register_unchanged(
        _decode(blob, mappings, deps, join["lookup_table_load_site"] + table_load.size, join["lookup_factory_call_site"], complete=False),
        deps["r1"], label="process manager selector preservation",
    )
    lookup_vptr = _instruction(blob, mappings, deps, join["lookup_result_vptr_load_site"])
    lookup_capture = _instruction(blob, mappings, deps, join["lookup_result_capture_site"])
    lookup_slot = _instruction(blob, mappings, deps, join["lookup_result_slot_load_site"])
    lookup_call = _instruction(blob, mappings, deps, join["lookup_result_virtual_call_site"])
    lookup_return = _instruction(blob, mappings, deps, join["lookup_return_site"])
    if (
        lookup_vptr.id != deps["ldr"] or lookup_vptr.operands[0].reg != deps["r3"]
        or lookup_vptr.operands[1].mem.base != deps["r0"] or lookup_vptr.operands[1].mem.disp != 0
        or lookup_capture.id != deps["mov"] or lookup_capture.operands[0].reg != deps["r4"] or lookup_capture.operands[1].reg != deps["r0"]
        or lookup_slot.id != deps["ldr"] or lookup_slot.operands[0].reg != deps["r3"]
        or lookup_slot.operands[1].mem.base != deps["r3"] or lookup_slot.operands[1].mem.disp != 8
        or lookup_call.id != deps["blx"] or lookup_call.operands[0].reg != deps["r3"]
        or lookup_return.id != deps["mov"] or lookup_return.operands[0].reg != deps["r0"] or lookup_return.operands[1].reg != deps["r4"]
    ):
        raise RuntimeError("process manager lookup result join differs")

    dispatch = expected["factory_dispatch"]
    if _owner(exidx, dispatch["owner"]["start"]) != (dispatch["owner"]["start"], dispatch["owner"]["end"]):
        raise RuntimeError("process factory dispatcher owner differs")
    if dispatch["entry_site"] != dispatch["table"] + dispatch["selector_index"] * 4:
        raise RuntimeError("process factory table relation differs")
    dispatch_max = _instruction(blob, mappings, deps, dispatch["owner"]["start"])
    dispatch_compare = _instruction(blob, mappings, deps, 0x437AA8)
    dispatch_guard = _instruction(blob, mappings, deps, 0x437AAA)
    dispatch_table = _instruction(blob, mappings, deps, 0x437AB0)
    dispatch_base = _instruction(blob, mappings, deps, 0x437AAE)
    dispatch_add = _instruction(blob, mappings, deps, 0x437AB4)
    dispatch_jump = _instruction(blob, mappings, deps, 0x437AB6)
    if (
        dispatch_max.id != deps["mov"] or dispatch_max.operands[0].reg != deps["r3"]
        or dispatch_max.operands[1].imm != dispatch["selector_max"]
        or dispatch_compare.id != deps["cmp"] or dispatch_compare.operands[0].reg != deps["r1"] or dispatch_compare.operands[1].reg != deps["r3"]
        or dispatch_guard.cc != deps["hi"] or _direct_target(dispatch_guard, deps) != 0x438C70
        or dispatch_base.id != deps["adr"] or dispatch_base.operands[0].reg != deps["r0"]
        or (((dispatch_base.address + 4) & ~3) + dispatch_base.operands[1].imm) != dispatch["table"]
        or dispatch_table.id != deps["ldr"] or dispatch_table.operands[0].reg != deps["r2"]
        or dispatch_table.operands[1].mem.base != deps["r0"] or dispatch_table.operands[1].mem.index != deps["r1"]
        or dispatch_table.operands[1].shift.value != 2
        or dispatch_add.id != deps["add"] or dispatch_add.operands[0].reg != deps["r0"] or dispatch_add.operands[1].reg != deps["r2"]
        or dispatch_jump.id != deps["bx"] or dispatch_jump.operands[0].reg != deps["r0"]
        or dispatch["selector_min"] != 0
    ):
        raise RuntimeError("process factory dispatcher bounds or selector dataflow differs")
    _require_register_unchanged(
        _decode(blob, mappings, deps, dispatch["owner"]["start"], 0x437AB0, complete=False),
        deps["r1"], label="process factory selector preservation",
    )
    _require_register_unchanged(
        _decode(blob, mappings, deps, dispatch_base.address + dispatch_base.size, 0x437AB0, complete=False),
        deps["r0"], label="process factory table-base preservation",
    )
    offset = _word(blob, mappings, dispatch["entry_site"])
    if offset != dispatch["entry_offset"] or ((dispatch["table"] + offset) & ~1) != dispatch["stub"]:
        raise RuntimeError("process factory table entry differs")
    stub = _instruction(blob, mappings, deps, dispatch["stub"])
    branch = _instruction(blob, mappings, deps, dispatch["branch_site"])
    if stub.id != deps["pop"] or not branch.group(deps["jump_group"]) or _direct_target(branch, deps) != dispatch["accessor"]:
        raise RuntimeError("process factory stub differs")
    if _owner(exidx, dispatch["accessor"]) != (0x42ECA8, 0x42ED04):
        raise RuntimeError("Creative Style process accessor owner differs")
    accessor_items = _decode(blob, mappings, deps, 0x42ECA8, 0x42ECE6, complete=False)
    if _direct_target(next(item for item in accessor_items if item.address == 0x42ECCA), deps) != 0x48B7E8:
        raise RuntimeError("Creative Style process constructor edge differs")

    typed_join = join["typed_accessor"]
    accessor_receiver = _instruction(blob, mappings, deps, typed_join["constructor_receiver_site"])
    accessor_constructor = _instruction(blob, mappings, deps, typed_join["constructor_call_site"])
    accessor_return = _instruction(blob, mappings, deps, typed_join["accessor_return_site"])
    constructor_capture = _instruction(blob, mappings, deps, typed_join["constructor_object_capture_site"])
    constructor_got_load = _instruction(blob, mappings, deps, typed_join["vtable_got_load_site"])
    constructor_address_point = _instruction(blob, mappings, deps, typed_join["vtable_address_point_add_site"])
    constructor_vptr_store = _instruction(blob, mappings, deps, typed_join["vptr_store_site"])
    constructor_return = _instruction(blob, mappings, deps, typed_join["constructor_return_site"])
    constructor_got = (
        0x48B7F6 + 4 + _word(blob, mappings, 0x48B824) + _word(blob, mappings, 0x48B828)
    ) & 0xFFFFFFFF
    if (
        typed_join["constructor"] != 0x48B7E8
        or accessor_receiver.id != deps["mov"] or accessor_receiver.operands[0].reg != deps["r0"] or accessor_receiver.operands[1].reg != deps["r5"]
        or accessor_constructor.id != deps["bl"] or _direct_target(accessor_constructor, deps) != typed_join["constructor"]
        or accessor_return.id != deps["mov"] or accessor_return.operands[0].reg != deps["r0"] or accessor_return.operands[1].reg != deps["r5"]
        or constructor_capture.id != deps["mov"] or constructor_capture.operands[0].reg != deps["r4"] or constructor_capture.operands[1].reg != deps["r0"]
        or constructor_got != expected["typed_element"]["vtable_got_cell"]
        or constructor_got_load.id != deps["ldr"] or constructor_got_load.operands[0].reg != deps["r3"]
        or constructor_got_load.operands[1].mem.base != deps["r5"] or constructor_got_load.operands[1].mem.index != deps["r3"]
        or constructor_address_point.id != deps["add"] or constructor_address_point.operands[0].reg != deps["r3"]
        or constructor_address_point.operands[1].type != deps["imm"] or constructor_address_point.operands[1].imm != 8
        or constructor_vptr_store.id != deps["str"] or constructor_vptr_store.operands[0].reg != deps["r3"]
        or constructor_vptr_store.operands[1].mem.base != deps["r4"] or constructor_vptr_store.operands[1].mem.disp != 0
        or constructor_return.id != deps["mov"] or constructor_return.operands[0].reg != deps["r0"] or constructor_return.operands[1].reg != deps["r4"]
    ):
        raise RuntimeError("typed Creative Style singleton/vptr dataflow differs")
    _require_register_unchanged(
        _decode(blob, mappings, deps, typed_join["vtable_got_load_site"] + constructor_got_load.size, typed_join["vtable_address_point_add_site"], complete=False),
        deps["r3"], label="typed Creative Style vtable header preservation",
    )
    _require_register_unchanged(
        _decode(blob, mappings, deps, typed_join["vtable_address_point_add_site"] + constructor_address_point.size, typed_join["vptr_store_site"], complete=False),
        deps["r3"], label="typed Creative Style address-point preservation",
    )
    initialized_branch = _instruction(blob, mappings, deps, typed_join["initialized_branch_site"])
    guard_failure_branch = _instruction(blob, mappings, deps, typed_join["guard_failure_branch_site"])
    accessor_owner_items = _decode(blob, mappings, deps, dispatch["accessor"], 0x42ED04, complete=False)
    returns = [
        item for item in accessor_owner_items
        if item.id == deps["pop"] and any(operand.type == deps["reg"] and operand.reg == deps["pc"] for operand in item.operands)
    ]
    if (
        _direct_target(initialized_branch, deps) != typed_join["accessor_return_site"]
        or _direct_target(guard_failure_branch, deps) != typed_join["accessor_return_site"]
        or len(returns) != 1 or returns[0].address != typed_join["accessor_return_site"] + accessor_return.size
    ):
        raise RuntimeError("typed Creative Style accessor return-path coverage differs")

    for receiver_name in ("read_receiver", "write_receiver"):
        receiver = join[receiver_name]
        manager_entry = receiver["manager_entry"]
        lookup_call_site = receiver["lookup_call_site"]
        if _direct_target(_instruction(blob, mappings, deps, lookup_call_site), deps) != lookup["start"]:
            raise RuntimeError("process manager lookup call differs")
        _require_register_unchanged(
            _decode(blob, mappings, deps, manager_entry, lookup_call_site, complete=False),
            deps["r1"], label="process ID preservation to lookup",
        )
        vptr_load = _instruction(blob, mappings, deps, receiver["vptr_load_site"])
        slot_load = _instruction(blob, mappings, deps, receiver["slot_load_site"])
        virtual_call = _instruction(blob, mappings, deps, receiver["virtual_call_site"])
        _require_register_unchanged(
            _decode(blob, mappings, deps, lookup_call_site + 4, receiver["vptr_load_site"], complete=False),
            deps["r0"], label="lookup result receiver preservation",
        )
        _require_register_unchanged(
            _decode(blob, mappings, deps, receiver["vptr_load_site"] + vptr_load.size, receiver["virtual_call_site"], complete=False),
            deps["r0"], label="typed virtual receiver preservation",
        )
        if (
            vptr_load.id != deps["ldr"] or vptr_load.operands[0].reg != deps["r3"]
            or vptr_load.operands[1].mem.base != deps["r0"] or vptr_load.operands[1].mem.disp != 0
            or slot_load.id != deps["ldr"] or slot_load.operands[0].reg != deps["r4"]
            or slot_load.operands[1].mem.base != deps["r3"]
            or slot_load.operands[1].mem.disp != receiver["typed_element_slot"] * 4
            or virtual_call.id != deps["blx"] or virtual_call.operands[0].reg != deps["r4"]
        ):
            raise RuntimeError("typed Creative Style manager receiver/slot join differs")

    element = expected["typed_element"]
    _validate_si_rtti(
        elf, blob, mappings, rels, by_site, dynsym,
        rtti=element["rtti"], encoding=element["type_name_encoding"],
    )
    if _word(blob, mappings, element["vtable_header"], signed=True) != 0:
        raise RuntimeError("Creative Style process vtable header differs")
    _validate_relative(rels, by_site, blob, mappings, index=40019, site=element["vtable_header"] + 4, target=element["rtti"])
    _validate_relative(
        rels, by_site, blob, mappings,
        index=element["vtable_got_relocation_index"], site=element["vtable_got_cell"],
        target=element["vtable_header"],
    )
    _validate_relative(rels, by_site, blob, mappings, index=40025, site=element["value_getter_cell"], target=element["value_getter"])
    _validate_relative(rels, by_site, blob, mappings, index=40031, site=element["value_setter_cell"], target=element["value_setter"])
    base_getter_cell = 0x906F38 + element["value_getter_slot"] * 4
    _base_getter_index, base_getter_relocation = by_site[base_getter_cell]
    if (
        base_getter_relocation["r_info_type"] != 2
        or dynsym.get_symbol(base_getter_relocation["r_info_sym"]).name != "_ZN31CmnViewProcessDataElementNormal8getValueERiS0_S0_S0_S0_ii"
    ):
        raise RuntimeError("Creative Style getter base signature differs")
    base_setter_cell = 0x906F38 + element["value_setter_slot"] * 4
    _base_index, base_relocation = by_site[base_setter_cell]
    if base_relocation["r_info_type"] != 2 or dynsym.get_symbol(base_relocation["r_info_sym"]).name != "_ZN31CmnViewProcessDataElementNormal8setValueEiiiii":
        raise RuntimeError("Creative Style setter base signature differs")
    if _owner(exidx, element["value_setter"]) != (0x4893AC, 0x489644):
        raise RuntimeError("Creative Style setter owner differs")
    if _owner(exidx, element["value_getter"]) != (0x48B8AC, 0x48BC88):
        raise RuntimeError("Creative Style getter owner differs")
    return copy.deepcopy(expected)


def _validate_value_commit(blob, mappings, deps, plt_symbols, exidx):
    expected = EXPECTED_EXPORT["value_commit"]
    if _owner(exidx, expected["owner"]["start"]) != (expected["owner"]["start"], expected["owner"]["end"]):
        raise RuntimeError("Creative Style value-commit owner differs")
    for site in expected["backup_write_call_sites"]:
        if _call_symbol(blob, mappings, deps, plt_symbols, site) != expected["backup_write_symbol"]:
            raise RuntimeError("Creative Style backup-write call differs")
    if _word(blob, mappings, 0x48962C) != expected["first_backup_id"]:
        raise RuntimeError("Creative Style first backup ID differs")
    request = expected["model_request"]
    if _call_symbol(blob, mappings, deps, plt_symbols, request["site"]) != "_ZN21CmnViewModelIfWrapper19requestModelExecuteEPKcmP9ParamList":
        raise RuntimeError("Creative Style final model request differs")
    model = 0x4895FC + _word(blob, mappings, 0x489640)
    if _cstring(blob, mappings, model) != request["model"]:
        raise RuntimeError("Creative Style final model name differs")
    request_window = _decode(blob, mappings, deps, 0x4895E6, 0x4895FE)
    if not any(item.id == deps["mov"] and item.operands[0].reg == deps["r1"] and item.operands[1].imm == request["request_code"] for item in request_window):
        raise RuntimeError("Creative Style final model request code differs")
    owner_items = _decode(blob, mappings, deps, expected["owner"]["start"], expected["owner"]["end"], complete=False)
    add_count = sum(
        item.group(deps["call_group"])
        and _direct_target(item, deps) in {target for target, name in plt_symbols.items() if name == "_ZN9ParamList3addEmP9ParamBase"}
        for item in owner_items
    )
    if add_count != request["param_list_add_count"]:
        raise RuntimeError("Creative Style final parameter count differs")
    return copy.deepcopy(expected)


def _validate_controller_mode(blob, mappings, deps, plt_symbols, exidx):
    expected = EXPECTED_EXPORT["controller_mode"]
    for record in expected["observed_write_sites"]:
        item = _instruction(blob, mappings, deps, record["site"])
        source = item.operands[0].reg if item.operands and item.operands[0].type == deps["reg"] else None
        source_item = _instruction(blob, mappings, deps, record["value_source_site"])
        if (
            item.id != deps["str"] or item.size != expected["storage_width_bytes"]
            or item.operands[1].type != deps["mem"] or item.operands[1].mem.disp != expected["field_offset"]
            or source is None
        ):
            raise RuntimeError("Creative Style controller-mode store differs")
        _require_mov_immediate(source_item, deps, source, record["value"], "Creative Style controller-mode value")
        _require_register_unchanged(
            _decode(blob, mappings, deps, record["value_source_site"] + source_item.size, record["site"], complete=False),
            source, label="Creative Style controller-mode value dataflow",
        )
    read = expected["backup_read_helper"]
    write = expected["backup_write_helper"]
    if _owner(exidx, read["start"]) != (read["start"], read["end"]) or _owner(exidx, write["start"]) != (write["start"], write["end"]):
        raise RuntimeError("Creative Style controller backup helper owner differs")
    if _word(blob, mappings, 0x5CEE44) != expected["backup_id"] or _word(blob, mappings, 0x5CEFE0) != expected["backup_id"]:
        raise RuntimeError("Creative Style controller backup ID differs")
    if _call_symbol(blob, mappings, deps, plt_symbols, 0x5CEE32) != "_ZN13BackupManager9Bkup_ReadEiPv":
        raise RuntimeError("Creative Style controller backup read differs")
    if _call_symbol(blob, mappings, deps, plt_symbols, 0x5CEFD2) != "_ZN13BackupManager10Bkup_WriteEiPKv":
        raise RuntimeError("Creative Style controller backup write differs")
    read_zero = _instruction(blob, mappings, deps, 0x5CEE2A)
    read_byte_store = _instruction(blob, mappings, deps, 0x5CEE2E)
    read_signed_byte = _instruction(blob, mappings, deps, 0x5CEE36)
    write_byte_store = _instruction(blob, mappings, deps, 0x5CEFCC)
    _require_mov_immediate(read_zero, deps, deps["r3"], 0, "Creative Style controller backup initialization")
    if (
        expected["backup_storage_width_bytes"] != 1
        or read_byte_store.id != deps["strb"] or read_byte_store.operands[0].reg != deps["r3"]
        or read_signed_byte.id != deps["ldrsb"] or read_signed_byte.operands[0].reg != deps["r0"]
        or read_signed_byte.operands[1].mem.base != deps["r7"] or read_signed_byte.operands[1].mem.disp != 7
        or write_byte_store.id != deps["strb"] or write_byte_store.operands[0].reg != deps["r1"]
    ):
        raise RuntimeError("Creative Style controller backup payload width differs")
    reset = _instruction(blob, mappings, deps, expected["reset_site"])
    reset_source = _instruction(blob, mappings, deps, expected["reset_value_source_site"])
    reset_register = reset.operands[0].reg if reset.operands and reset.operands[0].type == deps["reg"] else None
    if (
        reset.id != deps["str"] or reset.size != expected["storage_width_bytes"]
        or reset.operands[1].mem.disp != expected["field_offset"] or reset_register is None
    ):
        raise RuntimeError("Creative Style controller reset differs")
    _require_mov_immediate(reset_source, deps, reset_register, 0, "Creative Style controller reset value")
    _require_register_unchanged(
        _decode(blob, mappings, deps, expected["reset_value_source_site"] + reset_source.size, expected["reset_site"], complete=False),
        reset_register, label="Creative Style controller reset dataflow",
    )
    tail = _instruction(blob, mappings, deps, 0x5CF03A)
    if not tail.group(deps["jump_group"]) or _direct_target(tail, deps) != write["start"]:
        raise RuntimeError("Creative Style controller reset persistence edge differs")
    return copy.deepcopy(expected)


def _validate_loader_registration(elf, blob, mappings, deps, rels, dynsym, exidx):
    expected = EXPECTED_EXPORT["loader_registration"]
    if _cstring(blob, mappings, expected["module_string_address"]) != expected["module_string"] or _cstring(blob, mappings, expected["factory_string_address"]) != expected["factory_string"]:
        raise RuntimeError("Creative Style loader strings differ")
    factory_symbol = 3418
    dynamic_count = sum(relocation["r_info_sym"] == factory_symbol for relocation in rels)
    plt_relocations = list(elf.get_section_by_name(".rel.plt").iter_relocations())
    plt_count = sum(relocation["r_info_sym"] == factory_symbol for relocation in plt_relocations)
    if (
        dynamic_count != expected["factory_rel_dyn_relocation_count"]
        or plt_count != expected["factory_rel_plt_relocation_count"]
    ):
        raise RuntimeError("Creative Style factory .rel.dyn/.rel.plt count differs")
    factory_range = EXPECTED_EXPORT["view"]["factory_entry"]["range"]
    factory = factory_range["start"]
    inbound, complete = _global_direct_inbound(blob, mappings, deps, exidx, factory)
    if complete != expected["factory_direct_call_scan_complete"] or len(inbound) != expected["factory_direct_call_count"]:
        raise RuntimeError("Creative Style factory direct-inbound scan differs")
    init = elf.get_section_by_name(".init_array")
    if init is None or init["sh_size"] % 4:
        raise RuntimeError("init-array metadata differs")
    init_targets = [
        int.from_bytes(blob[init["sh_offset"] + offset:init["sh_offset"] + offset + 4], "little") & ~1
        for offset in range(0, init["sh_size"], 4)
    ]
    init_count = _count_targets_in_range(init_targets, factory_range["start"], factory_range["end"])
    if init_count != expected["factory_init_array_target_count"]:
        raise RuntimeError("Creative Style factory init-array target count differs")
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
            view = _validate_view(elf, blob, mappings, deps, rels, by_site, dynsym, plt_symbols, exidx)
            process = _validate_process_binding(elf, blob, mappings, deps, rels, by_site, dynsym, plt_symbols, exidx)
            value_commit = _validate_value_commit(blob, mappings, deps, plt_symbols, exidx)
            controller_mode = _validate_controller_mode(blob, mappings, deps, plt_symbols, exidx)
            loader = _validate_loader_registration(elf, blob, mappings, deps, rels, dynsym, exidx)
        if _sha256(SOURCE_PATH) != before:
            raise RuntimeError("pinned viewUnified2 source changed during export")
        document = copy.deepcopy(EXPECTED_EXPORT)
        document.update({
            "view": view,
            "process_binding": process,
            "value_commit": value_commit,
            "controller_mode": controller_mode,
            "loader_registration": loader,
        })
        return document


def build_raw_export(adapter=None):
    document = (adapter or ElfAdapter()).metadata()
    return normalize_creative_style_view_model_binding_export(document)


def write_export(document, output_root=OUTPUT_ROOT):
    normalized = normalize_creative_style_view_model_binding_export(document)
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
    print("CREATIVE_STYLE_VIEW_MODEL_BINDING_EXPORT|view=1|typed_element=1|setter=1|touch=0|installable=0")
    print(output)


if __name__ == "__main__":
    main()
