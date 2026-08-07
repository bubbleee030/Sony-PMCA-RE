"""Read-only static exporter for α6400 generic Creative Style runtime binding."""
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

from pmca.analysis.creative_style_runtime_binding import (
    EXPECTED_EXPORT,
    SOURCES as SOURCE_IDENTITIES,
    build_creative_style_runtime_binding_report,
    normalize_creative_style_runtime_binding_export,
    validate_creative_style_runtime_binding_report,
)
from tools.static.export_a6400_creative_style_model_cursor_boundary import (
    _decoded_plt_addresses_exact,
)
from tools.static import export_a6400_creative_style_model_request_transport as _transport


FIRMWARE_LIB = ROOT / ".artifacts" / "decrypted" / "a6400-tw-v2.00" / "ma1co" / "firmware.tar_unpacked" / "0700_part_image" / "dev" / "nflasha15_unpacked" / "lib"
SOURCES = {"object": FIRMWARE_LIB / "libObj.so", "view": FIRMWARE_LIB / "viewUnified2.so"}
ARTIFACT_BASE = ROOT / ".artifacts"
OUTPUT_ROOT = ARTIFACT_BASE / "creative-style-runtime-binding" / "a6400-v2.00"
OUTPUT_NAME = "creative-style-runtime-binding-export.json"
REPORT_PATH = ROOT / "analysis" / "a6400-creative-style-runtime-binding.json"


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _dependencies():
    try:
        from elftools.elf.elffile import ELFFile
        deps = _transport._dependencies()
    except (ImportError, AttributeError, RuntimeError) as exc:
        raise RuntimeError("local Capstone and pyelftools are required") from exc
    deps = dict(deps)
    deps.update({"ELFFile": ELFFile})
    return deps


def dependencies_available():
    try:
        _dependencies()
    except RuntimeError:
        return False
    return True


def sources_available():
    return all(source.is_file() and not source.is_symlink() for source in SOURCES.values())


def _mappings(elf):
    return [
        (segment["p_vaddr"], segment["p_vaddr"] + segment["p_filesz"], segment["p_offset"])
        for segment in elf.iter_segments() if segment["p_type"] == "PT_LOAD"
    ]


def _at(blob, mappings, address, length):
    offsets = [offset + address - start for start, end, offset in mappings if start <= address and address + length <= end]
    if len(offsets) != 1:
        raise RuntimeError("static virtual address mapping differs")
    return blob[offsets[0]:offsets[0] + length]


def _word(blob, mappings, address):
    return int.from_bytes(_at(blob, mappings, address, 4), "little")


def _prel31(word, place):
    offset = word & 0x7fffffff
    if offset & 0x40000000:
        offset -= 0x80000000
    return (place + offset) & 0xffffffff


def _exidx_ranges(elf, blob):
    section = elf.get_section_by_name(".ARM.exidx")
    if section is None or section["sh_size"] % 8:
        raise RuntimeError("ARM exception-index metadata differs")
    starts = [_prel31(_word(blob, [(section["sh_addr"], section["sh_addr"] + section["sh_size"], section["sh_offset"])], section["sh_addr"] + offset), section["sh_addr"] + offset) & ~1 for offset in range(0, section["sh_size"], 8)]
    if starts != sorted(starts) or len(starts) != len(set(starts)):
        raise RuntimeError("ARM exception-index order differs")
    executable_ends = [segment["p_vaddr"] + segment["p_filesz"] for segment in elf.iter_segments() if segment["p_type"] == "PT_LOAD" and segment["p_flags"] & 1 and segment["p_vaddr"] <= starts[-1] < segment["p_vaddr"] + segment["p_filesz"]]
    if len(executable_ends) != 1:
        raise RuntimeError("final exception-index owner is ambiguous")
    return list(zip(starts, starts[1:] + executable_ends))


def _require_owner(exidx, owner, label):
    if (owner["start"], owner["end"]) not in exidx:
        raise RuntimeError(label + " owner boundary differs")


def _instruction(blob, mappings, deps, site):
    decoder = deps["Cs"](deps["arch"], deps["mode"])
    decoder.detail = True
    items = list(decoder.disasm(_at(blob, mappings, site, 4), site))
    if not items or (items[0].address & ~1) != site:
        raise RuntimeError("expected static instruction differs")
    return items[0]


def _decode_range(blob, mappings, deps, start, end):
    decoder = deps["Cs"](deps["arch"], deps["mode"])
    decoder.detail = True
    items = list(decoder.disasm(_at(blob, mappings, start, end - start), start))
    if not items or (items[0].address & ~1) != start or items[-1].address + items[-1].size != end:
        raise RuntimeError("bounded static decode is incomplete")
    return items


def _direct_target(item, deps):
    targets = [operand.imm & ~1 for operand in item.operands if operand.type == deps["imm"]]
    return targets[0] if len(targets) == 1 else None


def _require_direct_target(blob, mappings, deps, site, target, label, call=None):
    item = _instruction(blob, mappings, deps, site)
    if _direct_target(item, deps) != target or (call is True and not item.group(deps["call_group"])) or (call is False and not item.group(deps["jump_group"])):
        raise RuntimeError(label + " direct edge differs")


def _require_memory(blob, mappings, deps, site, instruction_id, register, base, offset, label):
    item = _instruction(blob, mappings, deps, site)
    if (
        item.id != instruction_id
        or len(item.operands) != 2
        or item.operands[0].type != deps["reg"]
        or item.operands[0].reg != register
        or item.operands[1].type != deps["mem"]
        or item.operands[1].mem.base != base
        or item.operands[1].mem.index != 0
        or item.operands[1].mem.disp != offset
        or item.writeback
    ):
        raise RuntimeError(label + " field access differs")


def _require_immediate(blob, mappings, deps, site, value, label):
    item = _instruction(blob, mappings, deps, site)
    if value not in [operand.imm for operand in item.operands if operand.type == deps["imm"]]:
        raise RuntimeError(label + " immediate differs")


def _require_move(blob, mappings, deps, site, destination, source, label):
    _transport._require_reg_to_reg(
        _instruction(blob, mappings, deps, site),
        deps, deps["mov"], destination, source, label,
    )


def _require_mov_immediate(blob, mappings, deps, site, destination, value, label):
    _transport._require_mov_immediate(
        _instruction(blob, mappings, deps, site), deps, destination, value, label,
    )


def _require_add_immediate(blob, mappings, deps, site, destination, source, value, label):
    _transport._require_add_immediate(
        _instruction(blob, mappings, deps, site), deps, destination, source, value, label,
    )


def _require_indirect_call_register(blob, mappings, deps, site, register, label):
    item = _instruction(blob, mappings, deps, site)
    if (
        not item.group(deps["call_group"])
        or _direct_target(item, deps) is not None
        or len(item.operands) != 1
        or item.operands[0].type != deps["reg"]
        or item.operands[0].reg != register
    ):
        raise RuntimeError(label + " indirect call differs")


def _require_pop_pc_return(blob, mappings, deps, site, label):
    item = _instruction(blob, mappings, deps, site)
    if (
        item.id != deps["pop"]
        or not item.operands
        or any(operand.type != deps["reg"] for operand in item.operands)
        or item.operands[-1].reg != deps["pc"]
        or sum(operand.reg == deps["pc"] for operand in item.operands) != 1
    ):
        raise RuntimeError(label + " return control differs")


def _require_ascii_at(blob, mappings, address, value, label):
    encoded = value.encode("ascii") + b"\0"
    if _at(blob, mappings, address, len(encoded)) != encoded:
        raise RuntimeError(label + " bounded string differs")


def _require_rel_dyn(obj, index, offset, relocation_type, symbol_index, target, label):
    section = obj["elf"].get_section_by_name(".rel.dyn")
    if section is None:
        raise RuntimeError(label + " relocation section is absent")
    relocations = list(section.iter_relocations())
    if not 0 <= index < len(relocations):
        raise RuntimeError(label + " relocation index differs")
    relocation = relocations[index]
    if (
        relocation["r_offset"] != offset
        or relocation["r_info_type"] != relocation_type
        or relocation["r_info_sym"] != symbol_index
        or (
            target is not None
            and (_word(obj["blob"], obj["mappings"], offset) & ~1) != (target & ~1)
        )
    ):
        raise RuntimeError(label + " relocation differs")


def _require_call_symbol(blob, mappings, deps, plt_symbols, site, symbol, label):
    item = _instruction(blob, mappings, deps, site)
    if not item.group(deps["call_group"]) or plt_symbols.get(_direct_target(item, deps)) != symbol:
        raise RuntimeError(label + " relocation/symbol binding differs")


def _require_dynsym_exact(obj, contract, label):
    symbol = obj["dynsym"].get_symbol(contract["dynsym_index"])
    if (
        symbol.name != contract["name"]
        or symbol["st_value"] != contract["address"]
        or symbol["st_shndx"] == "SHN_UNDEF"
    ):
        raise RuntimeError(label + " dynamic symbol differs")


def _require_bss_address(obj, address, label):
    section = obj["elf"].get_section_by_name(".bss")
    if section is None or not section["sh_addr"] <= address < section["sh_addr"] + section["sh_size"]:
        raise RuntimeError(label + " BSS address differs")


def _require_thumb_pic_pointer(blob, mappings, deps, load_site, add_site, register, address, label):
    load = _instruction(blob, mappings, deps, load_site)
    cell = _transport._thumb_literal_address(load, deps, register, label + " literal")
    add = _instruction(blob, mappings, deps, add_site)
    if (
        add.id != deps["add"]
        or len(add.operands) != 2
        or add.operands[0].type != deps["reg"]
        or add.operands[0].reg != register
        or add.operands[1].type != deps["reg"]
        or add.operands[1].reg != deps["pc"]
        or add.writeback
        or ((_word(blob, mappings, cell) + add.address + 4) & 0xFFFFFFFF) != address
    ):
        raise RuntimeError(label + " PIC pointer differs")


def _plt_symbols(elf, blob, mappings):
    dynsym = elf.get_section_by_name(".dynsym")
    relplt = elf.get_section_by_name(".rel.plt")
    if dynsym is None or relplt is None:
        raise RuntimeError("dynamic PLT metadata is unavailable")
    got_to_plt = _decoded_plt_addresses_exact(elf, blob, mappings)
    result = {}
    for relocation in relplt.iter_relocations():
        symbol = dynsym.get_symbol(relocation["r_info_sym"])
        address = got_to_plt.get(relocation["r_offset"])
        if address is None or address in result:
            raise RuntimeError("PLT relocation veneer differs")
        result[address] = symbol.name
    return result


def _validate_source(role, path):
    identity = SOURCE_IDENTITIES[role]
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.name != Path(identity["module"]).name:
        raise RuntimeError("pinned " + role + " source is not a literal regular file")
    digest = _sha256(path)
    if path.stat().st_size != identity["size"] or digest != identity["sha256"]:
        raise RuntimeError("pinned " + role + " source identity differs")
    return digest


def _validate_id_generator(obj, view, deps):
    expected = EXPECTED_EXPORT["id_generator"]
    _require_owner(obj["exidx"], expected["get_owner"], "IdGenerator Get")
    _require_owner(obj["exidx"], expected["splitter_owner"], "IdGenerator splitter")
    _require_direct_target(
        obj["blob"], obj["mappings"], deps,
        expected["splitter_call"]["site"], expected["splitter_call"]["target"],
        "IdGenerator splitter", True,
    )
    _require_add_immediate(
        obj["blob"], obj["mappings"], deps, expected["map_argument"]["site"],
        deps["r0"], deps["r4"], expected["map_argument"]["base_offset"],
        "IdGenerator map argument",
    )
    _require_owner(obj["exidx"], expected["map_lookup_call"]["owner"], "IdGenerator map lookup")
    _require_direct_target(
        obj["blob"], obj["mappings"], deps,
        expected["map_lookup_call"]["site"], expected["map_lookup_call"]["target"],
        "IdGenerator map lookup", True,
    )
    _require_owner(obj["exidx"], expected["find_id_call"]["owner"], "IdTable findId")
    _require_call_symbol(obj["blob"], obj["mappings"], deps, obj["plt"], expected["find_id_call"]["site"], expected["find_id_call"]["symbol"], "IdTable findId")
    _require_owner(obj["exidx"], expected["set_table"]["owner"], "IdGenerator SetTable")
    _require_memory(
        obj["blob"], obj["mappings"], deps, expected["set_table"]["entry_store_site"],
        deps["str"], deps["r4"], deps["r0"], expected["set_table"]["entry_store_offset"],
        "IdGenerator SetTable entry",
    )
    if expected["input_alias"] != "model/CAMERA":
        raise RuntimeError("IdGenerator input-alias boundary differs")
    if any(expected[field] is not False for field in (
        "splitter_delimiter_semantics_resolved", "model_table_key_resolved", "camera_row_key_resolved",
    )):
        raise RuntimeError("IdGenerator split semantics were over-promoted")
    registration = expected["validated_static_set_table_call"]
    if registration["table_key_resolved"] is not False:
        raise RuntimeError("view SetTable key was over-promoted")
    _require_call_symbol(
        view["blob"], view["mappings"], deps, view["plt"],
        registration["site"], registration["symbol"], "view SetTable call",
    )
    return copy.deepcopy(expected)


def _validate_transport_boundaries(obj, view):
    """Reuse the stricter independently-pinned transport proofs for shared edges."""
    deps = _transport._dependencies()
    _transport._validate_operation_38_model_alias(view, obj, deps)
    candidate = _transport._validate_model_manager_request_event_candidate(
        obj["blob"], obj["mappings"], deps, obj["plt_symbols"], obj["exidx"],
    )
    expected = EXPECTED_EXPORT["generic_executor"]
    if (
        candidate["model_manager_dispatch_owner"]["start"]
        != expected["model_manager_dispatch_owner"]["start"]
        or candidate["model_manager_dispatch_owner"]["end"]
        != expected["model_manager_dispatch_owner"]["end"]
        or candidate["parameter_keys"] != {
            "request_context": {"site": 0x84A95C, "key": 6},
            "model_id": {"site": 0x84A966, "key": 7},
            "mapped_operation": {"site": 0x84A97C, "key": 8},
        }
        or candidate["secondary_event_constructor_call_site"]
        != expected["secondary_event"]["constructor_call_site"]
        or candidate["executor_virtual_slot"] != expected["virtual_call"]["slot_offset"]
    ):
        raise RuntimeError("shared transport boundary no longer matches runtime-binding contract")
    return candidate


def _validate_records_and_loader(obj, deps):
    records = EXPECTED_EXPORT["model_manager_records"]
    loader = EXPECTED_EXPORT["dynamic_loader"]
    for owner_key, label in (("manager_constructor_owner", "ModelManager constructor"), ("lookup_owner", "ModelManager lookup"), ("registration_owner", "ModelManager registration"), ("record_constructor_owner", "model record constructor"), ("activation_owner", "model record activation")):
        _require_owner(obj["exidx"], records[owner_key], label)
    map_ctor = records["map_constructor"]
    _require_owner(obj["exidx"], map_ctor["target_owner"], "ModelManager map constructor target")
    _require_add_immediate(obj["blob"], obj["mappings"], deps, map_ctor["add_site"], deps["r6"], deps["r4"], records["map_offset"], "ModelManager constructor map")
    _require_move(obj["blob"], obj["mappings"], deps, map_ctor["receiver_site"], deps["r0"], deps["r6"], "ModelManager constructor map receiver")
    _require_direct_target(obj["blob"], obj["mappings"], deps, map_ctor["site"], map_ctor["target"], "ModelManager map constructor", True)

    lookup = records["lookup_call"]
    _require_owner(obj["exidx"], lookup["target_owner"], "ModelManager lookup target")
    _require_add_immediate(obj["blob"], obj["mappings"], deps, lookup["map_add_site"], deps["r4"], deps["r0"], records["map_offset"], "ModelManager lookup map")
    _require_move(obj["blob"], obj["mappings"], deps, lookup["receiver_site"], deps["r0"], deps["r4"], "ModelManager lookup receiver")
    _require_direct_target(obj["blob"], obj["mappings"], deps, lookup["site"], lookup["target"], "ModelManager lookup", True)
    _require_memory(obj["blob"], obj["mappings"], deps, records["lookup_result_site"], deps["ldr"], deps["r0"], deps["r0"], records["lookup_result_node_offset"], "ModelManager lookup result")

    registration = records["registration_map"]
    _require_add_immediate(obj["blob"], obj["mappings"], deps, registration["add_site"], deps["r5"], deps["r4"], records["map_offset"], "ModelManager registration map")
    _require_move(obj["blob"], obj["mappings"], deps, registration["receiver_site"], deps["r0"], deps["r5"], "ModelManager registration receiver")
    _require_direct_target(obj["blob"], obj["mappings"], deps, registration["call_site"], registration["target"], "ModelManager registration map call", True)

    allocation = records["record_allocation"]
    _require_mov_immediate(obj["blob"], obj["mappings"], deps, allocation["size_site"], deps["r0"], allocation["size"], "model record allocation size")
    _require_call_symbol(obj["blob"], obj["mappings"], deps, obj["plt"], allocation["call_site"], allocation["symbol"], "model record allocation")
    _require_direct_target(obj["blob"], obj["mappings"], deps, allocation["constructor_call_site"], allocation["constructor_target"], "model record constructor", True)

    initialization = records["executor_initialization"]
    _require_mov_immediate(obj["blob"], obj["mappings"], deps, initialization["value_site"], deps["r2"], initialization["value"], "record executor initial value")
    _require_memory(obj["blob"], obj["mappings"], deps, initialization["site"], deps["str"], deps["r2"], deps["r0"], initialization["record_offset"], "record executor initialization")

    _require_mov_immediate(obj["blob"], obj["mappings"], deps, loader["mode_argument"]["site"], deps["r1"], loader["mode_argument"]["value"], "dlopen mode")
    _require_move(obj["blob"], obj["mappings"], deps, 0x841128, deps["r4"], deps["r0"], "loader record capture")
    _transport._require_register_unchanged(
        _decode_range(obj["blob"], obj["mappings"], deps, 0x84112A, loader["component_path_load"]["site"]),
        deps["r0"], label="loader component receiver preservation",
    )
    _require_memory(obj["blob"], obj["mappings"], deps, loader["component_path_load"]["site"], deps["ldr"], deps["r0"], deps["r0"], loader["component_path_load"]["record_offset"], "loader component path")
    _require_call_symbol(obj["blob"], obj["mappings"], deps, obj["plt"], loader["dlopen_call"]["site"], loader["dlopen_call"]["symbol"], "dlopen")
    _require_memory(obj["blob"], obj["mappings"], deps, loader["handle_store"]["site"], deps["str"], deps["r0"], deps["r4"], loader["handle_store"]["record_offset"], "dlopen handle")
    _require_memory(obj["blob"], obj["mappings"], deps, loader["symbol_name_load"]["site"], deps["ldr"], deps["r1"], deps["r4"], loader["symbol_name_load"]["record_offset"], "loader symbol name")
    _require_call_symbol(obj["blob"], obj["mappings"], deps, obj["plt"], loader["dlsym_call"]["site"], loader["dlsym_call"]["symbol"], "dlsym")
    _require_move(obj["blob"], obj["mappings"], deps, loader["factory_symbol_capture"]["site"], deps[loader["factory_symbol_capture"]["register"]], deps["r0"], "dynamic factory symbol capture")
    factory = loader["factory_call"]
    _require_memory(obj["blob"], obj["mappings"], deps, factory["key_load_site"], deps["ldr"], deps["r0"], deps["r4"], factory["key_record_offset"], "dynamic factory key")
    _require_memory(obj["blob"], obj["mappings"], deps, factory["manager_load_site"], deps["ldr"], deps["r1"], deps["r4"], factory["manager_record_offset"], "dynamic factory manager")
    _require_indirect_call_register(obj["blob"], obj["mappings"], deps, factory["site"], deps[factory["target_register"]], "dynamic factory")
    _require_memory(obj["blob"], obj["mappings"], deps, factory["result_store_site"], deps["str"], deps["r0"], deps["r4"], factory["result_record_offset"], "factory result")
    for site in loader["guard_sites"]:
        item = _instruction(obj["blob"], obj["mappings"], deps, site)
        if not item.group(deps["jump_group"]) or item.group(deps["call_group"]):
            raise RuntimeError("dynamic-loader guard differs")
    if loader["descriptor_population_dataflow_resolved"] is not False:
        raise RuntimeError("descriptor population was over-promoted")
    return copy.deepcopy(records), copy.deepcopy(loader)


def _validate_modelcamera(obj, deps):
    expected = EXPECTED_EXPORT["modelcamera_candidate"]
    for record in expected["manifest"].values():
        _require_ascii_at(obj["blob"], obj["mappings"], record["address"], record["value"], "ModelCamera manifest")
    factory = expected["factory"]
    _require_owner(obj["exidx"], factory["owner"], "ModelCamera factory")
    symbol = obj["dynsym"].get_symbol(factory["dynsym_index"])
    if (
        symbol.name != factory["symbol"]
        or (symbol["st_value"] & ~1) != factory["owner"]["start"]
        or symbol["st_size"] != factory["owner"]["end"] - factory["owner"]["start"]
        or symbol["st_shndx"] == "SHN_UNDEF"
    ):
        raise RuntimeError("ModelCamera factory symbol differs")
    _require_mov_immediate(obj["blob"], obj["mappings"], deps, factory["size_site"], deps["r0"], factory["instance_size"], "ModelCamera allocation size")
    _require_move(obj["blob"], obj["mappings"], deps, factory["manager_capture_site"], deps["r5"], deps["r1"], "ModelCamera manager capture")
    _require_call_symbol(obj["blob"], obj["mappings"], deps, obj["plt"], factory["allocation_call_site"], factory["allocation_symbol"], "ModelCamera allocation")
    _require_move(obj["blob"], obj["mappings"], deps, factory["instance_capture_site"], deps["r4"], deps["r0"], "ModelCamera instance capture")
    _require_direct_target(obj["blob"], obj["mappings"], deps, factory["constructor_call_site"], factory["constructor_target"], "ModelCamera constructor", True)
    _require_owner(obj["exidx"], expected["constructor_owner"], "ModelCamera constructor")
    _require_memory(obj["blob"], obj["mappings"], deps, expected["manager_store"]["site"], deps["str"], deps["r5"], deps["r4"], expected["manager_store"]["instance_offset"], "ModelCamera manager")

    default_event = expected["default_scheduler_event"]
    _require_move(obj["blob"], obj["mappings"], deps, 0x4D3102, deps["r5"], deps["r0"], "ModelCamera constructor this capture")
    _transport._require_register_unchanged(
        _decode_range(obj["blob"], obj["mappings"], deps, 0x4D30FA, 0x4D3104),
        deps["r0"], label="ModelCamera base-constructor this preservation",
    )
    for edge, label in ((default_event["modelbase_constructor_call"], "ModelBase constructor"), (default_event["setter_call"], "ModelBase Event-ID setter")):
        _require_direct_target(obj["blob"], obj["mappings"], deps, edge["site"], edge["target"], label, True)
    _require_move(obj["blob"], obj["mappings"], deps, 0x3FE58E, deps["r5"], deps["r0"], "ModelBase constructor this capture")
    _require_move(obj["blob"], obj["mappings"], deps, 0x3FE5DE, deps["r0"], deps["r5"], "ModelBase Event-ID setter receiver")
    literal_load = _instruction(obj["blob"], obj["mappings"], deps, default_event["setter_call"]["target"])
    if (
        _transport._thumb_literal_address(literal_load, deps, deps["r3"], "ModelCamera default scheduler Event ID")
        != default_event["literal_address"]
        or _word(obj["blob"], obj["mappings"], default_event["literal_address"]) != default_event["value"]
    ):
        raise RuntimeError("ModelCamera default scheduler Event ID differs")
    _require_memory(obj["blob"], obj["mappings"], deps, default_event["store_site"], deps["str"], deps["r3"], deps["r0"], default_event["instance_offset"], "ModelCamera default scheduler Event ID")

    rtti = expected["rtti"]
    _require_ascii_at(obj["blob"], obj["mappings"], rtti["name_address"], rtti["name"], "ModelCamera RTTI name")
    _require_rel_dyn(obj, 78042, rtti["address"], 2, 292, None, "ModelCamera RTTI typeinfo")
    _require_rel_dyn(obj, rtti["name_relocation_index"], rtti["address"] + 4, 23, 0, rtti["name_address"], "ModelCamera RTTI name")
    if _word(obj["blob"], obj["mappings"], rtti["vtable_header"]) != 0:
        raise RuntimeError("ModelCamera vtable offset-to-top differs")
    _require_rel_dyn(obj, rtti["vtable_rtti_relocation_index"], rtti["vtable_header"] + 4, 23, 0, rtti["address"], "ModelCamera vtable RTTI")
    if rtti["vptr_address_point"] != rtti["vtable_header"] + 8:
        raise RuntimeError("ModelCamera vptr address point differs")
    _require_owner(obj["exidx"], expected["slot_target_owner"], "ModelCamera shared slot target")
    if expected["slot_cell"]["address"] != rtti["vptr_address_point"] + expected["slot_cell"]["offset"]:
        raise RuntimeError("ModelCamera slot geometry differs")
    _require_rel_dyn(obj, expected["slot_cell"]["relocation_index"], expected["slot_cell"]["address"], 23, 0, expected["slot_target_owner"]["start"], "ModelCamera shared slot")
    return copy.deepcopy(expected)


def _validate_default_route_descriptor_provider(obj, deps):
    expected = EXPECTED_EXPORT["default_route_descriptor_provider"]
    condition = expected["condition"]
    if condition != {"selector": "AppConfig.so", "runtime_selector_resolved": False}:
        raise RuntimeError("default descriptor-provider condition differs")

    constructor = expected["app_config_constructor"]
    resolver = expected["model_config_resolver"]
    _require_owner(obj["exidx"], constructor["owner"], "AppConfig constructor")
    model_config_store = constructor["model_config_store"]
    _require_direct_target(
        obj["blob"], obj["mappings"], deps, model_config_store["resolver_call_site"],
        resolver["owner"]["start"], "AppConfig ModelConfig resolver result", True,
    )
    resolver_call = _instruction(
        obj["blob"], obj["mappings"], deps, model_config_store["resolver_call_site"]
    )
    if resolver_call.address + resolver_call.size != model_config_store["site"]:
        raise RuntimeError("AppConfig ModelConfig resolver result is not stored directly")
    _require_memory(
        obj["blob"], obj["mappings"], deps, model_config_store["site"],
        deps["str"], deps["r0"], deps["r4"], model_config_store["offset"],
        "AppConfig ModelConfig store",
    )
    app_vtable = constructor["vtable"]
    vtable_sites = app_vtable["header_got_sites"]
    resolved_vtable_cell = _transport._resolve_thumb_got_cell(
        obj["blob"], obj["mappings"], deps,
        vtable_sites["base_literal_site"], vtable_sites["base_add_site"],
        vtable_sites["offset_literal_site"], "AppConfig vtable header",
        base_register=deps["r5"],
    )
    if (
        resolved_vtable_cell != app_vtable["header_got_cell"]
        or app_vtable["address_point"] != app_vtable["header"] + 8
    ):
        raise RuntimeError("AppConfig constructed vtable geometry differs")
    _require_rel_dyn(
        obj, app_vtable["header_relocation_index"], app_vtable["header_got_cell"], 23, 0,
        app_vtable["header"], "AppConfig constructed vtable header",
    )
    vtable_load = _instruction(
        obj["blob"], obj["mappings"], deps, vtable_sites["load_site"]
    )
    if (
        vtable_load.id != deps["ldr"]
        or len(vtable_load.operands) != 2
        or vtable_load.operands[0].type != deps["reg"]
        or vtable_load.operands[0].reg != deps["r3"]
        or vtable_load.operands[1].type != deps["mem"]
        or vtable_load.operands[1].mem.base != deps["r5"]
        or vtable_load.operands[1].mem.index != deps["r3"]
        or vtable_load.operands[1].mem.disp != 0
        or vtable_load.writeback
    ):
        raise RuntimeError("AppConfig constructed vtable load differs")
    address_point_add = _instruction(
        obj["blob"], obj["mappings"], deps, vtable_sites["address_point_add_site"]
    )
    if (
        address_point_add.id != deps["add"]
        or len(address_point_add.operands) != 2
        or address_point_add.operands[0].type != deps["reg"]
        or address_point_add.operands[0].reg != deps["r3"]
        or address_point_add.operands[1].type != deps["imm"]
        or address_point_add.operands[1].imm != 8
    ):
        raise RuntimeError("AppConfig constructed vtable address point differs")
    _require_memory(
        obj["blob"], obj["mappings"], deps, vtable_sites["store_site"], deps["str"],
        deps["r3"], deps["r4"], 0, "AppConfig constructed vptr store",
    )
    _require_owner(obj["exidx"], resolver["owner"], "ModelConfig resolver")
    if resolver["module"] != "libObj.so" or resolver["symbols"] != [
        "initializeModelConfig", "getModelConfig"
    ]:
        raise RuntimeError("ModelConfig resolver names differ")
    _require_call_symbol(
        obj["blob"], obj["mappings"], deps, obj["plt"], resolver["dlopen_call"]["site"],
        resolver["dlopen_call"]["symbol"], "ModelConfig resolver dlopen",
    )
    for site in resolver["dlsym_calls"]:
        _require_call_symbol(
            obj["blob"], obj["mappings"], deps, obj["plt"], site, "dlsym",
            "ModelConfig resolver dlsym",
        )
    for site in resolver["constructor_calls"]:
        _require_direct_target(
            obj["blob"], obj["mappings"], deps, site, resolver["owner"]["start"],
            "AppConfig ModelConfig resolver", True,
        )
    model_config_call = resolver["model_config_call"]
    if model_config_call["site"] != model_config_store["resolver_call_site"]:
        raise RuntimeError("AppConfig ModelConfig resolver call identity differs")
    for field, value in (("module", "libObj.so"), ("initialize", "initializeModelConfig"), ("get", "getModelConfig")):
        argument = model_config_call["arguments"][field]
        _require_thumb_pic_pointer(
            obj["blob"], obj["mappings"], deps, argument["load_site"], argument["add_site"],
            deps[argument["register"]], argument["address"], "ModelConfig resolver " + field,
        )
        _require_ascii_at(
            obj["blob"], obj["mappings"], argument["address"], value,
            "ModelConfig resolver " + field,
        )
    handle_argument = model_config_call["arguments"]["handle_slot"]
    _require_thumb_pic_pointer(
        obj["blob"], obj["mappings"], deps,
        handle_argument["load_site"], handle_argument["add_site"],
        deps[handle_argument["register"]], handle_argument["address"],
        "ModelConfig resolver handle slot",
    )
    _require_bss_address(obj, handle_argument["address"], "ModelConfig resolver handle slot")
    for field, preservation in model_config_call["pic_argument_preservation"].items():
        argument = model_config_call["arguments"][field]
        argument_load = _instruction(obj["blob"], obj["mappings"], deps, argument["load_site"])
        if (
            argument_load.address + argument_load.size != preservation["start"]
            or preservation["end"] != argument["add_site"]
            or preservation["register"] != argument["register"]
        ):
            raise RuntimeError("ModelConfig resolver caller " + field + " PIC span differs")
        _transport._require_register_unchanged(
            _decode_range(
                obj["blob"], obj["mappings"], deps,
                preservation["start"], preservation["end"],
            ),
            deps[preservation["register"]],
            label="ModelConfig resolver caller " + field + " PIC preservation",
        )
    adjacent_field = model_config_call["pic_adjacent_argument"]
    adjacent_argument = model_config_call["arguments"][adjacent_field]
    adjacent_load = _instruction(
        obj["blob"], obj["mappings"], deps, adjacent_argument["load_site"]
    )
    if adjacent_load.address + adjacent_load.size != adjacent_argument["add_site"]:
        raise RuntimeError("ModelConfig resolver caller adjacent PIC handoff differs")
    for field, preservation in model_config_call["argument_preservation"].items():
        argument = model_config_call["arguments"][field]
        argument_add = _instruction(obj["blob"], obj["mappings"], deps, argument["add_site"])
        if (
            argument_add.address + argument_add.size != preservation["start"]
            or preservation["end"] != model_config_call["site"]
            or preservation["register"] != argument["register"]
        ):
            raise RuntimeError("ModelConfig resolver caller " + field + " span differs")
        _transport._require_register_unchanged(
            _decode_range(
                obj["blob"], obj["mappings"], deps,
                preservation["start"], preservation["end"],
            ),
            deps[preservation["register"]],
            label="ModelConfig resolver caller " + field + " preservation",
        )
    get_argument = model_config_call["arguments"]["get"]
    get_argument_add = _instruction(
        obj["blob"], obj["mappings"], deps, get_argument["add_site"]
    )
    if get_argument_add.address + get_argument_add.size != model_config_call["site"]:
        raise RuntimeError("ModelConfig resolver caller get handoff differs")
    for symbol_key, label in (("initialize", "initializeModelConfig"), ("get", "getModelConfig")):
        _require_dynsym_exact(obj, expected["model_config_symbols"][symbol_key], label)
    _require_bss_address(obj, expected["model_config_singleton"], "ModelConfig singleton")

    initialize_callable = resolver["initialize_callable"]
    get_callable = resolver["get_callable"]
    handle_flow = resolver["handle_flow"]
    entry_consumers = {
        "module": resolver["dlopen_call"]["site"],
        "initialize": initialize_callable["symbol_capture"]["site"],
        "get": get_callable["symbol_capture"]["site"],
        "handle_slot": handle_flow["slot_capture"]["site"],
    }
    for field, preservation in resolver["entry_argument_preservation"].items():
        if (
            preservation["start"] != resolver["owner"]["start"]
            or preservation["end"] != entry_consumers[field]
            or preservation["register"] != model_config_call["arguments"][field]["register"]
        ):
            raise RuntimeError("ModelConfig resolver entry " + field + " span differs")
        _transport._require_register_unchanged(
            _decode_range(
                obj["blob"], obj["mappings"], deps,
                preservation["start"], preservation["end"],
            ),
            deps[preservation["register"]],
            label="ModelConfig resolver entry " + field + " preservation",
        )
    dlopen_flags = resolver["dlopen_flags"]
    _require_mov_immediate(
        obj["blob"], obj["mappings"], deps, dlopen_flags["site"],
        deps[dlopen_flags["register"]], dlopen_flags["value"],
        "ModelConfig resolver dlopen flags",
    )
    flags_item = _instruction(obj["blob"], obj["mappings"], deps, dlopen_flags["site"])
    flags_preservation = dlopen_flags["preservation"]
    if (
        flags_item.address + flags_item.size != flags_preservation["start"]
        or flags_preservation["end"] != resolver["dlopen_call"]["site"]
        or flags_preservation["register"] != dlopen_flags["register"]
    ):
        raise RuntimeError("ModelConfig resolver dlopen flags span differs")
    _transport._require_register_unchanged(
        _decode_range(
            obj["blob"], obj["mappings"], deps,
            flags_preservation["start"], flags_preservation["end"],
        ),
        deps[flags_preservation["register"]],
        label="ModelConfig resolver dlopen flags preservation",
    )

    slot_capture = handle_flow["slot_capture"]
    _require_move(
        obj["blob"], obj["mappings"], deps, slot_capture["site"],
        deps[slot_capture["destination"]], deps[slot_capture["source"]],
        "ModelConfig resolver handle-slot capture",
    )
    slot_capture_item = _instruction(
        obj["blob"], obj["mappings"], deps, slot_capture["site"]
    )
    slot_to_store = handle_flow["slot_base_to_store_preservation"]
    if (
        slot_capture_item.address + slot_capture_item.size != slot_to_store["start"]
        or slot_to_store["end"] != handle_flow["slot_store"]["site"]
        or slot_to_store["register"] != slot_capture["destination"]
    ):
        raise RuntimeError("ModelConfig resolver handle-slot/store span differs")
    _transport._require_register_unchanged(
        _decode_range(
            obj["blob"], obj["mappings"], deps,
            slot_to_store["start"], slot_to_store["end"],
        ),
        deps[slot_to_store["register"]],
        label="ModelConfig resolver handle-slot preservation to store",
    )

    dlopen_result_capture = handle_flow["dlopen_result_capture"]
    dlopen_call_item = _instruction(
        obj["blob"], obj["mappings"], deps, resolver["dlopen_call"]["site"]
    )
    if dlopen_call_item.address + dlopen_call_item.size != dlopen_result_capture["site"]:
        raise RuntimeError("ModelConfig resolver dlopen result capture is not direct")
    _require_move(
        obj["blob"], obj["mappings"], deps, dlopen_result_capture["site"],
        deps[dlopen_result_capture["destination"]], deps[dlopen_result_capture["source"]],
        "ModelConfig resolver dlopen result capture",
    )
    slot_store = handle_flow["slot_store"]
    dlopen_capture_item = _instruction(
        obj["blob"], obj["mappings"], deps, dlopen_result_capture["site"]
    )
    if dlopen_capture_item.address + dlopen_capture_item.size != slot_store["site"]:
        raise RuntimeError("ModelConfig resolver dlopen result store is not direct")
    _require_memory(
        obj["blob"], obj["mappings"], deps, slot_store["site"], deps["str"],
        deps[slot_store["source"]], deps[slot_store["base"]], slot_store["offset"],
        "ModelConfig resolver handle-slot store",
    )

    dlopen_success = resolver["dlopen_success_branch"]
    dlopen_result_preservation = handle_flow["dlopen_result_preservation"]
    slot_store_item = _instruction(obj["blob"], obj["mappings"], deps, slot_store["site"])
    if (
        dlopen_result_preservation["start"] != dlopen_result_capture["site"]
        or dlopen_result_preservation["end"] != dlopen_success["site"]
        or dlopen_result_preservation["register"] != dlopen_success["register"]
        or slot_store_item.address + slot_store_item.size != dlopen_success["site"]
    ):
        raise RuntimeError("ModelConfig resolver dlopen result span differs")
    _transport._require_register_unchanged(
        _decode_range(
            obj["blob"], obj["mappings"], deps,
            dlopen_result_preservation["start"], dlopen_result_preservation["end"],
        ),
        deps[dlopen_result_preservation["register"]],
        label="ModelConfig resolver dlopen result preservation",
    )
    _transport._require_cbnz(
        _instruction(obj["blob"], obj["mappings"], deps, dlopen_success["site"]),
        deps, deps[dlopen_success["register"]], dlopen_success["target"],
        "ModelConfig resolver dlopen success branch",
    )
    initialize_symbol_capture = initialize_callable["symbol_capture"]
    _require_move(
        obj["blob"], obj["mappings"], deps, initialize_symbol_capture["site"],
        deps[initialize_symbol_capture["destination"]], deps[initialize_symbol_capture["source"]],
        "initializeModelConfig symbol capture",
    )
    _transport._require_register_unchanged(
        _decode_range(
            obj["blob"], obj["mappings"], deps,
            initialize_symbol_capture["site"] + _instruction(
                obj["blob"], obj["mappings"], deps, initialize_symbol_capture["site"]
            ).size,
            dlopen_success["site"],
        ),
        deps[initialize_symbol_capture["destination"]],
        label="initializeModelConfig symbol preservation",
    )
    initialize_dlsym_argument = initialize_callable["dlsym_argument"]
    if initialize_dlsym_argument["site"] != dlopen_success["target"]:
        raise RuntimeError("initializeModelConfig dlsym is not on the dlopen success path")
    _require_move(
        obj["blob"], obj["mappings"], deps, initialize_dlsym_argument["site"],
        deps[initialize_dlsym_argument["destination"]], deps[initialize_dlsym_argument["source"]],
        "initializeModelConfig dlsym argument",
    )
    initialize_argument_item = _instruction(
        obj["blob"], obj["mappings"], deps, initialize_dlsym_argument["site"]
    )
    if initialize_argument_item.address + initialize_argument_item.size != initialize_callable["dlsym_call"]["site"]:
        raise RuntimeError("initializeModelConfig dlsym handle/argument handoff differs")
    _require_call_symbol(
        obj["blob"], obj["mappings"], deps, obj["plt"],
        initialize_callable["dlsym_call"]["site"], initialize_callable["dlsym_call"]["symbol"],
        "initializeModelConfig dlsym",
    )
    initialize_success = initialize_callable["success_branch"]
    initialize_result_preservation = initialize_callable["result_preservation"]
    initialize_dlsym_item = _instruction(
        obj["blob"], obj["mappings"], deps, initialize_callable["dlsym_call"]["site"]
    )
    if (
        initialize_dlsym_item.address + initialize_dlsym_item.size
        != initialize_result_preservation["start"]
        or initialize_result_preservation["end"] != initialize_success["site"]
        or initialize_result_preservation["register"] != initialize_success["register"]
    ):
        raise RuntimeError("initializeModelConfig dlsym result span differs")
    _transport._require_register_unchanged(
        _decode_range(
            obj["blob"], obj["mappings"], deps,
            initialize_result_preservation["start"], initialize_result_preservation["end"],
        ),
        deps[initialize_result_preservation["register"]],
        label="initializeModelConfig dlsym result preservation",
    )
    _transport._require_cbnz(
        _instruction(obj["blob"], obj["mappings"], deps, initialize_success["site"]),
        deps, deps[initialize_success["register"]], initialize_success["target"],
        "initializeModelConfig callable success branch",
    )
    initialize_call = initialize_callable["call"]
    if initialize_call["site"] != initialize_success["target"]:
        raise RuntimeError("initializeModelConfig callable branch/call identity differs")
    _require_indirect_call_register(
        obj["blob"], obj["mappings"], deps, initialize_call["site"],
        deps[initialize_call["target_register"]], "initializeModelConfig callable",
    )

    slot_base_spans = handle_flow["success_path_slot_base_preservation"]
    slot_reload = handle_flow["slot_reload"]
    expected_slot_base_spans = (
        (dlopen_success["target"], initialize_success["site"]),
        (initialize_success["target"], slot_reload["site"]),
    )
    if len(slot_base_spans) != len(expected_slot_base_spans):
        raise RuntimeError("ModelConfig resolver handle-slot success spans differ")
    for preservation, (start, end) in zip(slot_base_spans, expected_slot_base_spans):
        if (
            preservation["start"] != start
            or preservation["end"] != end
            or preservation["register"] != slot_capture["destination"]
        ):
            raise RuntimeError("ModelConfig resolver handle-slot success span differs")
        _transport._require_register_unchanged(
            _decode_range(
                obj["blob"], obj["mappings"], deps,
                preservation["start"], preservation["end"],
            ),
            deps[preservation["register"]],
            label="ModelConfig resolver handle-slot success-path preservation",
        )
    initialize_call_item = _instruction(
        obj["blob"], obj["mappings"], deps, initialize_call["site"]
    )
    if initialize_call_item.address + initialize_call_item.size != slot_reload["site"]:
        raise RuntimeError("ModelConfig resolver handle reload is not after initialization")
    if (
        slot_reload["base"] != slot_store["base"]
        or slot_reload["offset"] != slot_store["offset"]
        or slot_reload["destination"] != dlopen_result_capture["source"]
    ):
        raise RuntimeError("ModelConfig resolver handle store/reload identity differs")
    _require_memory(
        obj["blob"], obj["mappings"], deps, slot_reload["site"], deps["ldr"],
        deps[slot_reload["destination"]], deps[slot_reload["base"]], slot_reload["offset"],
        "ModelConfig resolver handle-slot reload",
    )

    symbol_capture = get_callable["symbol_capture"]
    _require_move(
        obj["blob"], obj["mappings"], deps, symbol_capture["site"],
        deps[symbol_capture["destination"]], deps[symbol_capture["source"]],
        "getModelConfig symbol capture",
    )
    dlsym_argument = get_callable["dlsym_argument"]
    for start, end in (
        (
            symbol_capture["site"] + _instruction(
                obj["blob"], obj["mappings"], deps, symbol_capture["site"]
            ).size,
            dlopen_success["site"],
        ),
        (dlopen_success["target"], initialize_success["site"]),
        (initialize_success["target"], dlsym_argument["site"]),
    ):
        _transport._require_register_unchanged(
            _decode_range(obj["blob"], obj["mappings"], deps, start, end),
            deps[symbol_capture["destination"]],
            label="getModelConfig symbol preservation on resolver success path",
        )
    _require_move(
        obj["blob"], obj["mappings"], deps, dlsym_argument["site"],
        deps[dlsym_argument["destination"]], deps[dlsym_argument["source"]],
        "getModelConfig dlsym argument",
    )
    slot_reload_item = _instruction(
        obj["blob"], obj["mappings"], deps, slot_reload["site"]
    )
    dlsym_argument_item = _instruction(
        obj["blob"], obj["mappings"], deps, dlsym_argument["site"]
    )
    if (
        slot_reload_item.address + slot_reload_item.size != dlsym_argument["site"]
        or dlsym_argument_item.address + dlsym_argument_item.size != get_callable["dlsym_call"]["site"]
    ):
        raise RuntimeError("getModelConfig dlsym handle/argument handoff differs")
    _require_call_symbol(
        obj["blob"], obj["mappings"], deps, obj["plt"],
        get_callable["dlsym_call"]["site"], get_callable["dlsym_call"]["symbol"],
        "getModelConfig dlsym",
    )
    success_branch = get_callable["success_branch"]
    get_result_preservation = get_callable["result_preservation"]
    get_dlsym_item = _instruction(
        obj["blob"], obj["mappings"], deps, get_callable["dlsym_call"]["site"]
    )
    if (
        get_dlsym_item.address + get_dlsym_item.size != get_result_preservation["start"]
        or get_result_preservation["end"] != success_branch["site"]
        or get_result_preservation["register"] != success_branch["register"]
    ):
        raise RuntimeError("getModelConfig dlsym result span differs")
    _transport._require_register_unchanged(
        _decode_range(
            obj["blob"], obj["mappings"], deps,
            get_result_preservation["start"], get_result_preservation["end"],
        ),
        deps[get_result_preservation["register"]],
        label="getModelConfig dlsym result preservation",
    )
    _transport._require_cbnz(
        _instruction(obj["blob"], obj["mappings"], deps, success_branch["site"]),
        deps, deps[success_branch["register"]], success_branch["target"],
        "getModelConfig callable success branch",
    )
    get_call = get_callable["call"]
    if get_call["site"] != success_branch["target"]:
        raise RuntimeError("getModelConfig callable branch/call identity differs")
    _require_indirect_call_register(
        obj["blob"], obj["mappings"], deps, get_call["site"],
        deps[get_call["target_register"]], "getModelConfig callable",
    )
    get_return = get_callable["return"]
    get_call_item = _instruction(obj["blob"], obj["mappings"], deps, get_call["site"])
    if get_call_item.address + get_call_item.size != get_return["site"]:
        raise RuntimeError("getModelConfig callable result is not returned directly")
    if get_return["control"] != "pop-pc":
        raise RuntimeError("getModelConfig resolver return contract differs")
    _require_pop_pc_return(
        obj["blob"], obj["mappings"], deps, get_return["site"],
        "getModelConfig resolver",
    )
    _transport._require_register_unchanged(
        [_instruction(obj["blob"], obj["mappings"], deps, get_return["site"])],
        deps[get_return["register"]], label="getModelConfig resolver return",
    )

    lifecycle = expected["model_config_singleton_lifecycle"]
    initialize = lifecycle["initialize"]
    model_constructor = lifecycle["constructor"]
    singleton_get = lifecycle["get"]
    _require_owner(obj["exidx"], initialize["owner"], "initializeModelConfig")
    _require_owner(obj["exidx"], model_constructor["owner"], "ModelConfig constructor")
    _require_owner(obj["exidx"], singleton_get["owner"], "getModelConfig")
    allocation_capture = initialize["allocation_result_capture"]
    _require_move(
        obj["blob"], obj["mappings"], deps, allocation_capture["site"],
        deps[allocation_capture["destination"]], deps[allocation_capture["source"]],
        "ModelConfig allocation result capture",
    )
    allocation_capture_item = _instruction(
        obj["blob"], obj["mappings"], deps, allocation_capture["site"]
    )
    if allocation_capture_item.address + allocation_capture_item.size != initialize["constructor_call"]["site"]:
        raise RuntimeError("ModelConfig allocation is not passed directly to its constructor")
    _require_direct_target(
        obj["blob"], obj["mappings"], deps, initialize["constructor_call"]["site"],
        initialize["constructor_call"]["target"], "ModelConfig constructor", True,
    )
    singleton_address = initialize["singleton_address"]
    if _transport._resolve_thumb_pc_relative_address(
        obj["blob"], obj["mappings"], deps, singleton_address["load_site"],
        singleton_address["add_site"], deps[singleton_address["register"]],
        "initializeModelConfig singleton",
    ) != singleton_address["address"] or singleton_address["address"] != expected["model_config_singleton"]:
        raise RuntimeError("initializeModelConfig singleton address differs")
    singleton_store = initialize["singleton_store"]
    _transport._require_register_unchanged(
        _decode_range(
            obj["blob"], obj["mappings"], deps,
            initialize["constructor_call"]["site"], singleton_store["site"],
        ),
        deps[singleton_store["source"]],
        label="ModelConfig instance preservation to singleton store",
    )
    _require_memory(
        obj["blob"], obj["mappings"], deps, singleton_store["site"], deps["str"],
        deps[singleton_store["source"]], deps[singleton_store["base"]], 0,
        "initializeModelConfig singleton store",
    )

    instance_capture = model_constructor["instance_capture"]
    _require_move(
        obj["blob"], obj["mappings"], deps, instance_capture["site"],
        deps[instance_capture["destination"]], deps[instance_capture["source"]],
        "ModelConfig constructor instance capture",
    )
    model_vtable_sites = model_constructor["vtable_header_got_sites"]
    instance_preservation = model_constructor["instance_preservation"]
    instance_capture_item = _instruction(
        obj["blob"], obj["mappings"], deps, instance_capture["site"]
    )
    if (
        instance_capture_item.address + instance_capture_item.size != instance_preservation["start"]
        or instance_preservation["end"] != model_vtable_sites["store_site"]
        or instance_preservation["register"] != instance_capture["destination"]
    ):
        raise RuntimeError("ModelConfig constructor instance span differs")
    _transport._require_register_unchanged(
        _decode_range(
            obj["blob"], obj["mappings"], deps,
            instance_preservation["start"], instance_preservation["end"],
        ),
        deps[instance_preservation["register"]],
        label="ModelConfig constructor instance preservation",
    )
    resolved_model_vtable_cell = _transport._resolve_thumb_got_cell(
        obj["blob"], obj["mappings"], deps,
        model_vtable_sites["base_literal_site"], model_vtable_sites["base_add_site"],
        model_vtable_sites["offset_literal_site"], "ModelConfig vtable header",
        base_register=deps["r4"],
    )
    if (
        resolved_model_vtable_cell != model_constructor["vtable_header_got_cell"]
        or model_constructor["vtable_address_point"] != model_constructor["vtable_header"] + 8
    ):
        raise RuntimeError("ModelConfig constructed vtable geometry differs")
    _require_rel_dyn(
        obj, model_constructor["vtable_header_relocation_index"],
        model_constructor["vtable_header_got_cell"], 23, 0,
        model_constructor["vtable_header"], "ModelConfig constructed vtable header",
    )
    model_vtable_load = _instruction(
        obj["blob"], obj["mappings"], deps, model_vtable_sites["load_site"]
    )
    if (
        model_vtable_load.id != deps["ldr"]
        or len(model_vtable_load.operands) != 2
        or model_vtable_load.operands[0].type != deps["reg"]
        or model_vtable_load.operands[0].reg != deps["r3"]
        or model_vtable_load.operands[1].type != deps["mem"]
        or model_vtable_load.operands[1].mem.base != deps["r4"]
        or model_vtable_load.operands[1].mem.index != deps["r3"]
        or model_vtable_load.operands[1].mem.disp != 0
        or model_vtable_load.writeback
    ):
        raise RuntimeError("ModelConfig constructed vtable load differs")
    model_address_point_add = _instruction(
        obj["blob"], obj["mappings"], deps, model_vtable_sites["address_point_add_site"]
    )
    if (
        model_address_point_add.id != deps["add"]
        or len(model_address_point_add.operands) != 2
        or model_address_point_add.operands[0].type != deps["reg"]
        or model_address_point_add.operands[0].reg != deps["r3"]
        or model_address_point_add.operands[1].type != deps["imm"]
        or model_address_point_add.operands[1].imm != 8
    ):
        raise RuntimeError("ModelConfig constructed vtable address point differs")
    _require_memory(
        obj["blob"], obj["mappings"], deps, model_vtable_sites["store_site"], deps["str"],
        deps["r3"], deps[instance_capture["destination"]], 0,
        "ModelConfig constructed vptr store",
    )

    get_singleton_address = singleton_get["singleton_address"]
    if _transport._resolve_thumb_pc_relative_address(
        obj["blob"], obj["mappings"], deps, get_singleton_address["load_site"],
        get_singleton_address["add_site"], deps[get_singleton_address["register"]],
        "getModelConfig singleton",
    ) != get_singleton_address["address"] or get_singleton_address["address"] != expected["model_config_singleton"]:
        raise RuntimeError("getModelConfig singleton address differs")
    singleton_load = singleton_get["singleton_load"]
    _require_memory(
        obj["blob"], obj["mappings"], deps, singleton_load["site"], deps["ldr"],
        deps[singleton_load["destination"]], deps[singleton_load["base"]], 0,
        "getModelConfig singleton load",
    )
    return_preservation = singleton_get["return_preservation"]
    singleton_load_item = _instruction(
        obj["blob"], obj["mappings"], deps, singleton_load["site"]
    )
    return_control = singleton_get["return_control"]
    if (
        singleton_load_item.address + singleton_load_item.size != return_preservation["start"]
        or return_preservation["end"] != return_control["site"]
        or return_preservation["register"] != singleton_load["destination"]
        or return_control["control"] != "pop-pc"
    ):
        raise RuntimeError("getModelConfig singleton return span differs")
    _transport._require_register_unchanged(
        _decode_range(
            obj["blob"], obj["mappings"], deps,
            return_preservation["start"], return_preservation["end"],
        ),
        deps[return_preservation["register"]],
        label="getModelConfig singleton return preservation",
    )
    _require_pop_pc_return(
        obj["blob"], obj["mappings"], deps, return_control["site"],
        "getModelConfig singleton",
    )

    provenance = expected["factory_to_manager_provenance"]
    _require_owner(obj["exidx"], provenance["config_factory_owner"], "configuration factory")
    _require_owner(obj["exidx"], provenance["outer_constructor_owner"], "outer constructor")
    _require_direct_target(
        obj["blob"], obj["mappings"], deps, provenance["factory_call"]["site"],
        provenance["factory_call"]["target"], "outer configuration factory", True,
    )
    _transport._require_register_unchanged(
        _decode_range(
            obj["blob"], obj["mappings"], deps,
            provenance["factory_call"]["site"] + 4,
            provenance["factory_result_store"]["site"],
        ),
        deps["r0"], label="configuration factory result preservation",
    )
    _require_memory(
        obj["blob"], obj["mappings"], deps, provenance["factory_result_store"]["site"],
        deps["str"], deps["r0"], deps["r4"], provenance["factory_result_store"]["outer_offset"],
        "outer configuration factory result",
    )
    _require_memory(
        obj["blob"], obj["mappings"], deps, provenance["manager_config_argument"]["site"],
        deps["ldr"], deps["r2"], deps["r4"], provenance["manager_config_argument"]["outer_offset"],
        "ModelManager configuration argument",
    )
    argument_preservation = provenance["manager_config_argument_preservation"]
    _transport._require_register_unchanged(
        _decode_range(
            obj["blob"], obj["mappings"], deps,
            argument_preservation["start"], argument_preservation["end"],
        ),
        deps[argument_preservation["register"]],
        label="ModelManager configuration argument preservation",
    )
    _require_direct_target(
        obj["blob"], obj["mappings"], deps, provenance["manager_constructor_call"]["site"],
        provenance["manager_constructor_call"]["target"], "ModelManager constructor provenance", True,
    )
    capture = provenance["manager_config_capture"]
    _require_move(
        obj["blob"], obj["mappings"], deps, capture["site"], deps[capture["destination"]],
        deps[capture["source"]], "ModelManager configuration capture",
    )
    receiver_preservation = provenance["manager_config_receiver_preservation"]
    _transport._require_register_unchanged(
        _decode_range(
            obj["blob"], obj["mappings"], deps,
            receiver_preservation["start"], receiver_preservation["end"],
        ),
        deps[receiver_preservation["register"]],
        label="ModelManager AppConfig receiver preservation",
    )

    manager = expected["app_config_to_manager"]
    vslot = manager["app_config_vslot"]
    if vslot["cell"] != 0x133E3E8 + vslot["offset"]:
        raise RuntimeError("AppConfig ModelConfig vslot geometry differs")
    _require_rel_dyn(
        obj, vslot["relocation_index"], vslot["cell"], 23, 0, vslot["target"],
        "AppConfig ModelConfig vslot",
    )
    _require_memory(
        obj["blob"], obj["mappings"], deps, vslot["model_config_load"]["site"], deps["ldr"],
        deps["r0"], deps["r0"], vslot["model_config_load"]["offset"], "AppConfig ModelConfig load",
    )
    _require_memory(
        obj["blob"], obj["mappings"], deps, vslot["model_config_vptr_load"]["site"], deps["ldr"],
        deps["r3"], deps["r0"], 0, "AppConfig ModelConfig vptr",
    )
    _require_memory(
        obj["blob"], obj["mappings"], deps, vslot["model_config_slot_load"]["site"], deps["ldr"],
        deps["r3"], deps["r3"], vslot["model_config_slot_load"]["offset"],
        "AppConfig ModelConfig descriptor slot",
    )
    _require_indirect_call_register(
        obj["blob"], obj["mappings"], deps, vslot["model_config_slot_call"]["site"],
        deps[vslot["model_config_slot_call"]["target_register"]], "AppConfig ModelConfig descriptor slot",
    )
    manager_ctor = manager["manager_constructor"]
    _require_owner(obj["exidx"], manager_ctor["owner"], "ModelManager constructor")
    receiver = manager_ctor["app_config_receiver"]
    _require_move(
        obj["blob"], obj["mappings"], deps, receiver["site"],
        deps[receiver["destination"]], deps[receiver["source"]], "ModelManager AppConfig receiver",
    )
    _require_memory(
        obj["blob"], obj["mappings"], deps, manager_ctor["vptr_load"]["site"], deps["ldr"],
        deps["r3"], deps[manager_ctor["vptr_load"]["receiver"]], 0, "ModelManager AppConfig vptr",
    )
    _require_memory(
        obj["blob"], obj["mappings"], deps, manager_ctor["vslot_load"]["site"], deps["ldr"],
        deps["r3"], deps["r3"], manager_ctor["vslot_load"]["offset"], "ModelManager AppConfig vslot",
    )
    _require_indirect_call_register(
        obj["blob"], obj["mappings"], deps, manager_ctor["vslot_call"]["site"],
        deps[manager_ctor["vslot_call"]["target_register"]], "ModelManager AppConfig vslot",
    )
    _require_memory(
        obj["blob"], obj["mappings"], deps, manager_ctor["result_store"]["site"], deps["str"],
        deps["r0"], deps["r4"], manager_ctor["result_store"]["manager_offset"],
        "ModelManager ModelConfig store",
    )

    vtable = expected["model_config_vtable"]
    if vtable["address_point"] != model_constructor["vtable_address_point"]:
        raise RuntimeError("constructed ModelConfig vtable/descriptor table identity differs")
    descriptor_slot = vtable["descriptor_slot"]
    if descriptor_slot["cell"] != vtable["address_point"] + descriptor_slot["offset"]:
        raise RuntimeError("ModelConfig descriptor slot geometry differs")
    _require_owner(obj["exidx"], descriptor_slot["owner"], "ModelConfig descriptor slot")
    _require_rel_dyn(
        obj, descriptor_slot["relocation_index"], descriptor_slot["cell"], 23, 0,
        descriptor_slot["target"], "ModelConfig descriptor slot",
    )

    table = expected["modelcamera_table_entry"]
    for record in table["manifest"].values():
        _require_ascii_at(
            obj["blob"], obj["mappings"], record["address"], record["value"],
            "default-route ModelCamera manifest",
        )
    _require_call_symbol(
        obj["blob"], obj["mappings"], deps, obj["plt"],
        table["id_generator_get"]["site"], table["id_generator_get"]["symbol"],
        "default-route IdGenerator Get",
    )
    _require_call_symbol(
        obj["blob"], obj["mappings"], deps, obj["plt"],
        table["id_so_table_add"]["site"], table["id_so_table_add"]["symbol"],
        "default-route IdSoTable add",
    )
    abi = table["argument_abi"]
    for field, label in (("get_alias", "IdGenerator alias"), ("component", "IdSoTable component"), ("factory", "IdSoTable factory")):
        pointer = abi[field]
        _require_thumb_pic_pointer(
            obj["blob"], obj["mappings"], deps, pointer["load_site"], pointer["add_site"],
            deps[pointer["register"]], pointer["address"], label,
        )
    key = abi["get_result_to_table_key"]
    _require_move(
        obj["blob"], obj["mappings"], deps, key["site"], deps[key["destination"]],
        deps[key["source"]], "IdGenerator result to IdSoTable key",
    )
    receiver = abi["table_receiver"]
    _require_move(
        obj["blob"], obj["mappings"], deps, receiver["site"], deps[receiver["destination"]],
        deps[receiver["source"]], "IdSoTable receiver",
    )

    lookup = expected["model_manager_descriptor_lookup"]
    _require_owner(obj["exidx"], lookup["registration_owner"], "ModelManager registration")
    _require_owner(obj["exidx"], lookup["lookup_owner"], "ModelManager descriptor lookup")
    _require_memory(
        obj["blob"], obj["mappings"], deps, lookup["provider_field"]["site"],
        deps["ldr"], deps["r0"], deps["r0"], lookup["provider_field"]["offset"],
        "ModelManager descriptor provider",
    )
    _require_direct_target(
        obj["blob"], obj["mappings"], deps, lookup["default_lookup_branch"]["site"],
        lookup["default_lookup_branch"]["target"], "ModelManager default descriptor lookup", False,
    )
    _require_direct_target(
        obj["blob"], obj["mappings"], deps, lookup["alternate_lookup_call"]["site"],
        lookup["alternate_lookup_call"]["target"], "ModelManager alternate descriptor lookup", False,
    )
    for label, owner in lookup["provider_lookup_owners"].items():
        _require_owner(obj["exidx"], owner, "ModelConfig " + label + " descriptor lookup")
    for field in lookup["provider_record_result_loads"]:
        _require_memory(
            obj["blob"], obj["mappings"], deps, field["site"], deps["ldr"], deps["r0"],
            deps["r0"], field["offset"], "ModelConfig descriptor record result",
        )
    for call in lookup["registration_lookup_calls"]:
        _require_direct_target(
            obj["blob"], obj["mappings"], deps, call["site"], call["target"],
            "ModelManager registration descriptor lookup", True,
        )
    if lookup["record_descriptor_fields"] != {"component_offset": 0x10, "factory_offset": 0x14}:
        raise RuntimeError("ModelManager descriptor record field layout differs")
    flow = lookup["record_construction_dataflow"]
    for site in flow["lookup_key_load_sites"]:
        _require_memory(
            obj["blob"], obj["mappings"], deps, site, deps["ldr"], deps["r1"], deps["r7"],
            0x20, "ModelManager descriptor lookup key",
        )
    for field, label in (("component_result_capture", "component lookup result"), ("factory_result_capture", "factory lookup result"), ("component_constructor_argument", "component constructor argument")):
        move = flow[field]
        _require_move(
            obj["blob"], obj["mappings"], deps, move["site"], deps[move["destination"]],
            deps[move["source"]], "ModelManager " + label,
        )
    factory_stack = flow["factory_stack_argument"]
    _require_memory(
        obj["blob"], obj["mappings"], deps, factory_stack["site"], deps["str"],
        deps[factory_stack["source"]], deps["sp"], factory_stack["stack_offset"],
        "ModelManager factory stack argument",
    )
    component_store = flow["component_store"]
    _require_memory(
        obj["blob"], obj["mappings"], deps, component_store["site"], deps["str"], deps["r3"],
        deps["r0"], component_store["record_offset"], "model record component store",
    )
    factory_stack_load = flow["factory_stack_load"]
    _require_memory(
        obj["blob"], obj["mappings"], deps, factory_stack_load["site"], deps["ldr"], deps["r3"],
        deps["r7"], factory_stack_load["stack_offset"], "model record factory stack load",
    )
    factory_store = flow["factory_store"]
    _require_memory(
        obj["blob"], obj["mappings"], deps, factory_store["site"], deps["str"], deps["r3"],
        deps["r0"], factory_store["record_offset"], "model record factory store",
    )
    return copy.deepcopy(expected)


def _validate_executor_and_destination(obj, deps):
    executor = EXPECTED_EXPORT["generic_executor"]
    destination = EXPECTED_EXPORT["destination_4"]
    _require_owner(obj["exidx"], executor["model_manager_dispatch_owner"], "ModelManager generic dispatch")
    candidate = executor["candidate_branch_range"]
    if not (executor["model_manager_dispatch_owner"]["start"] <= candidate["start"] < candidate["end"] <= executor["model_manager_dispatch_owner"]["end"]):
        raise RuntimeError("ModelManager candidate branch range differs")
    for key, label in (("dispatcher_owner", "generic executor dispatcher"), ("scheduler_owner", "generic scheduler")):
        _require_owner(obj["exidx"], executor[key], label)

    expected_parameters = {
        "request_context": (6, 0x84A95C, 0x84A960),
        "model_id": (7, 0x84A966, 0x84A968),
        "mapped_operation": (8, 0x84A97C, 0x84A97E),
    }
    if set(executor["scalar_event_parameters"]) != set(expected_parameters):
        raise RuntimeError("generic candidate parameter roles differ")
    for role, (key, key_site, call_site) in expected_parameters.items():
        record = executor["scalar_event_parameters"][role]
        if record != {"key_load_site": key_site, "key": key, "get_call_site": call_site, "get_target": 0x848190}:
            raise RuntimeError("generic candidate parameter metadata differs")
        _require_mov_immediate(obj["blob"], obj["mappings"], deps, key_site, deps["r1"], key, "generic candidate parameter key")
        _require_direct_target(obj["blob"], obj["mappings"], deps, call_site, record["get_target"], "generic candidate parameter get", True)

    secondary = executor["secondary_event"]
    _require_mov_immediate(obj["blob"], obj["mappings"], deps, secondary["destination_argument_site"], deps["r2"], secondary["destination"], "secondary Event destination")
    _require_move(obj["blob"], obj["mappings"], deps, secondary["id_argument_site"], deps["r1"], deps["r9"], "secondary Event ID")
    _require_move(obj["blob"], obj["mappings"], deps, secondary["queue_tag_argument_site"], deps["r3"], deps["r2"], "secondary Event queue tag")
    if secondary["queue_tag"] != 0 or secondary["destination"] != 0:
        raise RuntimeError("secondary Event header metadata differs")
    _require_move(obj["blob"], obj["mappings"], deps, secondary["capture_site"], deps["r6"], deps["r0"], "secondary Event capture")
    _require_call_symbol(obj["blob"], obj["mappings"], deps, obj["plt"], secondary["constructor_call_site"], "_ZN5EventC1Emhh", "secondary Event constructor")
    _require_move(obj["blob"], obj["mappings"], deps, 0x84A9C2, deps["r0"], deps["r5"], "source Event for ParamList clone")
    _require_call_symbol(obj["blob"], obj["mappings"], deps, obj["plt"], secondary["get_param_list_call_site"], "_ZNK5Event12getParamListEv", "source Event ParamList")
    _require_move(obj["blob"], obj["mappings"], deps, 0x84A9C8, deps["r9"], deps["r0"], "source ParamList capture")
    _require_mov_immediate(obj["blob"], obj["mappings"], deps, secondary["allocation_size_site"], deps["r0"], secondary["allocation_size"], "ParamList clone allocation size")
    _require_call_symbol(obj["blob"], obj["mappings"], deps, obj["plt"], secondary["allocation_call_site"], "_Znwj", "ParamList clone allocation")
    _require_move(obj["blob"], obj["mappings"], deps, 0x84A9D0, deps["r1"], deps["r9"], "ParamList clone source")
    _require_move(obj["blob"], obj["mappings"], deps, 0x84A9D2, deps["r5"], deps["r0"], "ParamList clone destination")
    _require_owner(obj["exidx"], secondary["clone_helper_owner"], "ParamList clone helper")
    _require_direct_target(obj["blob"], obj["mappings"], deps, secondary["clone_helper_call_site"], secondary["clone_helper_owner"]["start"], "ParamList clone helper", True)
    for source_site, destination_site, offset, register in (
        (0x841294, 0x84129C, 0, deps["r2"]),
        (0x84129E, 0x8412A8, 4, deps["r2"]),
        (0x84129A, 0x8412A0, 8, deps["r4"]),
        (0x8412A2, 0x8412AA, 12, deps["r4"]),
        (0x8412A4, 0x8412AE, 16, deps["r1"]),
    ):
        _require_memory(obj["blob"], obj["mappings"], deps, source_site, deps["ldr"], register, deps["r1"], offset, "ParamList clone source word")
        _require_memory(obj["blob"], obj["mappings"], deps, destination_site, deps["str"], register, deps["r0"], offset, "ParamList clone destination word")
    _require_memory(obj["blob"], obj["mappings"], deps, 0x8412A6, deps["ldr"], deps["r3"], deps["r2"], 0, "ParamList clone reference count")
    _require_memory(obj["blob"], obj["mappings"], deps, 0x8412B0, deps["str"], deps["r3"], deps["r2"], 0, "ParamList clone reference count update")
    _require_immediate(obj["blob"], obj["mappings"], deps, 0x8412AC, 1, "ParamList clone reference increment")
    _require_move(obj["blob"], obj["mappings"], deps, 0x84A9D8, deps["r1"], deps["r5"], "secondary Event ParamList")
    _require_move(obj["blob"], obj["mappings"], deps, 0x84A9DA, deps["r0"], deps["r6"], "secondary Event ParamList receiver")
    _require_call_symbol(obj["blob"], obj["mappings"], deps, obj["plt"], secondary["set_param_list_call_site"], "_ZN5Event12setParamListEP9ParamList", "secondary Event ParamList setter")
    if executor["param_list_clone_forwarded_to_secondary_event"] is not True:
        raise RuntimeError("secondary Event ParamList clone was demoted")

    _require_memory(obj["blob"], obj["mappings"], deps, executor["incoming_event_store"]["site"], deps["str"], deps["r1"], deps["r0"], executor["incoming_event_store"]["executor_offset"], "executor incoming Event")
    _require_memory(obj["blob"], obj["mappings"], deps, executor["virtual_call"]["load_site"], deps["ldr"], deps["r3"], deps["r3"], executor["virtual_call"]["slot_offset"], "executor virtual slot")
    virtual = _instruction(obj["blob"], obj["mappings"], deps, executor["virtual_call"]["site"])
    if not virtual.group(deps["call_group"]) or _direct_target(virtual, deps) is not None:
        raise RuntimeError("executor virtual dispatch differs")

    scheduler_id = executor["scheduled_event_id_accessor"]
    _require_direct_target(obj["blob"], obj["mappings"], deps, scheduler_id["call_site"], scheduler_id["target"], "scheduler Event-ID accessor", True)
    _require_memory(obj["blob"], obj["mappings"], deps, scheduler_id["load_site"], deps["ldr"], deps["r0"], deps["r0"], executor["scheduled_event_id_instance_offset"], "scheduler Event-ID field")
    _require_move(obj["blob"], obj["mappings"], deps, 0x3FE638, deps["r4"], deps["r0"], "scheduler Event-ID capture")
    _require_move(obj["blob"], obj["mappings"], deps, 0x3FE640, deps["r1"], deps["r4"], "scheduler Event-ID argument")
    _require_mov_immediate(obj["blob"], obj["mappings"], deps, 0x3FE642, deps["r2"], executor["scheduled_destination"], "scheduler Event destination")
    _require_mov_immediate(obj["blob"], obj["mappings"], deps, 0x3FE644, deps["r3"], executor["scheduled_queue_tag"], "scheduler Event queue tag")
    _require_call_symbol(obj["blob"], obj["mappings"], deps, obj["plt"], executor["scheduled_event_constructor_call_site"], "_ZN5EventC1Emhh", "scheduler Event constructor")
    if executor["scheduled_event_id_resolved_generically"] is not False:
        raise RuntimeError("generic scheduler Event ID was over-promoted")
    scheduler_items = _decode_range(obj["blob"], obj["mappings"], deps, executor["scheduler_owner"]["start"], executor["scheduler_owner"]["end"])
    if any(
        item.id == deps["ldr"] and len(item.operands) == 2
        and item.operands[1].type == deps["mem"]
        and item.operands[1].mem.base == deps["r5"]
        and item.operands[1].mem.disp == executor["incoming_event_store"]["executor_offset"]
        for item in scheduler_items
    ):
        raise RuntimeError("scheduler unexpectedly reads the incoming Event field")
    if executor["scheduler_direct_incoming_event_read_found"] is not False or executor["scheduler_direct_creative_style_field_read_found"] is not False:
        raise RuntimeError("scheduler direct field consumption was over-promoted")

    _require_owner(obj["exidx"], destination["model_manager_push_owner"], "ModelManager Event push")
    _decode_range(
        obj["blob"], obj["mappings"], deps,
        destination["model_manager_push_function"]["start"],
        destination["model_manager_push_function"]["end"],
    )
    _require_mov_immediate(obj["blob"], obj["mappings"], deps, 0x84826E, deps["r2"], 1, "ModelManager queue boolean")
    _require_memory(obj["blob"], obj["mappings"], deps, 0x848272, deps["ldr"], deps["r0"], deps["r0"], destination["manager_event_manager_offset"], "ModelManager EventManager")
    _require_direct_target(obj["blob"], obj["mappings"], deps, 0x848278, 0x100D5C, "ModelManager EventManager push", False)
    _require_owner(obj["exidx"], destination["central_dispatch_owner"], "central destination dispatch")
    bit_test = destination["destination_bit_test"]
    bit_item = _instruction(obj["blob"], obj["mappings"], deps, bit_test["site"])
    if (
        bit_item.id != deps["and"] or len(bit_item.operands) != 3
        or bit_item.operands[0].type != deps["reg"] or bit_item.operands[0].reg != deps["r3"]
        or bit_item.operands[1].type != deps["reg"] or bit_item.operands[1].reg != deps["r6"]
        or bit_item.operands[2].type != deps["imm"] or bit_item.operands[2].imm != bit_test["mask"]
    ):
        raise RuntimeError("destination-four bit test differs")
    skip = _instruction(obj["blob"], obj["mappings"], deps, bit_test["zero_skip_site"])
    if skip.id != deps["cbz"] or len(skip.operands) != 2 or skip.operands[0].type != deps["reg"] or skip.operands[0].reg != deps["r3"] or _direct_target(skip, deps) != bit_test["zero_skip_target"]:
        raise RuntimeError("destination-four zero-skip differs")
    _require_direct_target(obj["blob"], obj["mappings"], deps, destination["receiver_call_site"], destination["receiver"], "destination-four receiver", True)
    _require_owner(obj["exidx"], destination["receiver_owner"], "destination-four receiver")
    for record in destination["validated_event_id_comparisons"]:
        load = _instruction(obj["blob"], obj["mappings"], deps, record["literal_site"])
        literal_address = _transport._thumb_literal_address(load, deps, deps["r3"], "destination Event-ID literal")
        if _word(obj["blob"], obj["mappings"], literal_address) != record["value"]:
            raise RuntimeError("destination Event-ID literal differs")
        compare = _instruction(obj["blob"], obj["mappings"], deps, record["compare_site"])
        if compare.id != deps["cmp"] or len(compare.operands) != 2 or compare.operands[0].type != deps["reg"] or compare.operands[0].reg != deps["r0"] or compare.operands[1].type != deps["reg"] or compare.operands[1].reg != deps["r3"]:
            raise RuntimeError("destination Event-ID comparison differs")
    modelcamera_default = EXPECTED_EXPORT["modelcamera_candidate"]["default_scheduler_event"]["value"]
    if modelcamera_default in [record["value"] for record in destination["validated_event_id_comparisons"]]:
        raise RuntimeError("ModelCamera candidate default Event unexpectedly matches a validated comparison")
    if destination["modelcamera_candidate_default_event_matches_validated_comparisons"] is not False:
        raise RuntimeError("ModelCamera candidate default Event comparison was over-promoted")
    _require_owner(obj["exidx"], destination["default_predicate_owner"], "destination default predicate")
    _require_direct_target(obj["blob"], obj["mappings"], deps, destination["default_predicate_call"], destination["default_predicate_owner"]["start"], "destination default predicate", True)
    return copy.deepcopy(executor), copy.deepcopy(destination)


def _metadata_from_files(sources=SOURCES):
    before = {role: _validate_source(role, path) for role, path in sources.items()}
    deps = _dependencies()
    contexts = {}
    try:
        for role, path in sources.items():
            blob = Path(path).read_bytes()
            stream = io.BytesIO(blob)
            elf = deps["ELFFile"](stream)
            mappings = _mappings(elf)
            plt_symbols = _plt_symbols(elf, blob, mappings)
            contexts[role] = {"blob": blob, "elf": elf, "stream": stream, "mappings": mappings, "exidx": _exidx_ranges(elf, blob), "plt": plt_symbols, "plt_symbols": plt_symbols, "dynsym": elf.get_section_by_name(".dynsym")}
        id_generator = _validate_id_generator(contexts["object"], contexts["view"], deps)
        _validate_transport_boundaries(contexts["object"], contexts["view"])
        records, loader = _validate_records_and_loader(contexts["object"], deps)
        modelcamera = _validate_modelcamera(contexts["object"], deps)
        default_route_descriptor_provider = _validate_default_route_descriptor_provider(
            contexts["object"], deps
        )
        executor, destination = _validate_executor_and_destination(contexts["object"], deps)
    finally:
        for context in contexts.values():
            context["stream"].close()
    if any(_sha256(path) != before[role] for role, path in sources.items()):
        raise RuntimeError("pinned source changed during static export")
    document = copy.deepcopy(EXPECTED_EXPORT)
    document.update({"id_generator": id_generator, "model_manager_records": records, "dynamic_loader": loader, "modelcamera_candidate": modelcamera, "default_route_descriptor_provider": default_route_descriptor_provider, "generic_executor": executor, "destination_4": destination})
    return document


class FileAdapter:
    def __init__(self, sources=SOURCES):
        self.sources = sources

    def metadata(self):
        return _metadata_from_files(self.sources)


def build_raw_export(adapter=None):
    try:
        return normalize_creative_style_runtime_binding_export((adapter or FileAdapter()).metadata())
    except Exception as exc:
        raise RuntimeError("Creative Style runtime-binding static evidence differs") from exc


def _literal_directory_under(root, base):
    root, base = Path(os.path.abspath(os.fspath(root))), Path(os.path.abspath(os.fspath(base)))
    if base.is_symlink() or not base.is_dir() or base.resolve(strict=True) != base:
        raise RuntimeError("artifact base is not literal")
    try:
        root.relative_to(base)
    except ValueError as exc:
        raise RuntimeError("output root is outside approved artifact base") from exc
    if root.is_symlink() or not root.is_dir() or root.resolve(strict=True) != root:
        raise RuntimeError("output root is not literal")
    return root


def prepare_output_root(approved_root=OUTPUT_ROOT, artifact_base=ARTIFACT_BASE):
    base, root = Path(artifact_base), Path(approved_root)
    try:
        relative = root.relative_to(base)
    except ValueError as exc:
        raise RuntimeError("output root is outside approved artifact base") from exc
    current = base
    for component in relative.parts:
        current = current / component
        if current.is_symlink() or (current.exists() and not current.is_dir()):
            raise RuntimeError("output root has a non-literal ancestor")
        current.mkdir(exist_ok=True)
    return _literal_directory_under(root, base)


def write_json_atomic(output, document, approved_root=OUTPUT_ROOT, artifact_base=ARTIFACT_BASE):
    root = _literal_directory_under(approved_root, artifact_base)
    output = Path(os.path.abspath(os.fspath(output)))
    if output.name != OUTPUT_NAME or output.parent != root or output.is_symlink() or (output.exists() and not output.is_file()):
        raise RuntimeError("output containment is invalid")
    handle, temporary = tempfile.mkstemp(dir=str(root), prefix=".runtime-binding-", suffix=".tmp")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def write_checked_report(document, path=REPORT_PATH):
    """Atomically write only the validator-built checked report at its canonical path."""
    report = build_creative_style_runtime_binding_report(document)
    validate_creative_style_runtime_binding_report(report)
    path = Path(path)
    if path != REPORT_PATH:
        raise RuntimeError("checked report path differs")
    handle, temporary = tempfile.mkstemp(dir=str(path.parent), prefix=".runtime-binding-report-", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main():
    document = build_raw_export()
    prepare_output_root()
    write_json_atomic(OUTPUT_ROOT / OUTPUT_NAME, document)
    write_checked_report(document)
    print("CREATIVE_STYLE_RUNTIME_BINDING_EXPORT|generic=1|modelcamera_identity=0|pipeline=0|installable=0")


if __name__ == "__main__":
    main()
