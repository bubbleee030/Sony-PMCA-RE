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
        executor, destination = _validate_executor_and_destination(contexts["object"], deps)
    finally:
        for context in contexts.values():
            context["stream"].close()
    if any(_sha256(path) != before[role] for role, path in sources.items()):
        raise RuntimeError("pinned source changed during static export")
    document = copy.deepcopy(EXPECTED_EXPORT)
    document.update({"id_generator": id_generator, "model_manager_records": records, "dynamic_loader": loader, "modelcamera_candidate": modelcamera, "generic_executor": executor, "destination_4": destination})
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
