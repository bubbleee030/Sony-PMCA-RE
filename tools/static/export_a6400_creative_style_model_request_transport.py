"""Read-only exporter for Creative Style model-request transport evidence."""
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

from pmca.analysis.creative_style_model_request_transport import (
    EXPECTED_EXPORT,
    SOURCES,
    normalize_creative_style_model_request_transport_export,
)
from tools.static.export_a6400_creative_style_selector_code import (
    _dependencies as _selector_dependencies,
    _require_add_immediate,
    _require_memory,
    _require_reg_to_reg,
    _validate_request as _validate_selector_request,
)
from tools.static.export_a6400_creative_style_model_cursor_boundary import _decoded_plt_addresses_exact
from tools.static.export_a6400_creative_style_view_model_binding import (
    _call_symbol,
    _cstring,
    _decode,
    _direct_target,
    _exidx_ranges,
    _instruction,
    _mappings,
    _owner,
    _plt_symbols,
    _require_mov_immediate,
    _require_register_unchanged,
    _word,
)


SOURCE_ROOT = (
    ROOT / ".artifacts" / "decrypted" / "a6400-tw-v2.00" / "ma1co"
    / "firmware.tar_unpacked" / "0700_part_image" / "dev" / "nflasha15_unpacked"
    / "lib"
)
SOURCE_PATHS = {
    "view": SOURCE_ROOT / "viewUnified2.so",
    "object": SOURCE_ROOT / "libObj.so",
}
ARTIFACT_BASE = ROOT / ".artifacts"
OUTPUT_ROOT = ARTIFACT_BASE / "creative-style-model-request-transport" / "a6400-v2.00"
OUTPUT_NAME = "creative-style-model-request-transport-export.json"


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def dependencies_available():
    try:
        _dependencies()
    except RuntimeError:
        return False
    return True


def _dependencies():
    deps = _selector_dependencies()
    try:
        from capstone.arm import (
            ARM_CC_NE,
            ARM_INS_AND,
            ARM_INS_CBZ,
            ARM_INS_CBNZ,
            ARM_INS_LDRB,
            ARM_REG_LR,
            ARM_REG_R10,
            ARM_REG_R8,
            ARM_REG_R9,
            ARM_REG_SP,
        )
    except (ImportError, AttributeError) as exc:
        raise RuntimeError("local Capstone and pyelftools are required") from exc
    deps.update({
        "cbnz": ARM_INS_CBNZ,
        "cbz": ARM_INS_CBZ,
        "and": ARM_INS_AND,
        "ldrb": ARM_INS_LDRB,
        "lr": ARM_REG_LR,
        "r10": ARM_REG_R10,
        "ne": ARM_CC_NE,
        "r8": ARM_REG_R8,
        "r9": ARM_REG_R9,
        "sp": ARM_REG_SP,
    })
    return deps


def sources_available():
    return all(path.is_file() and not path.is_symlink() for path in SOURCE_PATHS.values())


def _require_source_identity(role, path):
    expected = SOURCES[role]
    digest = _sha256(path)
    if path.stat().st_size != expected["size"] or digest != expected["sha256"]:
        raise RuntimeError("pinned " + role + " source identity differs")
    return digest


def _require_owner(exidx, expected, label):
    actual = _owner(exidx, expected["start"])
    if actual != (expected["start"], expected["end"]):
        raise RuntimeError(label + " owner differs")


def _require_defined_symbol(dynsym, name, start, end, label):
    matches = [symbol for symbol in dynsym.iter_symbols() if symbol.name == name]
    if len(matches) != 1:
        raise RuntimeError(label + " symbol count differs")
    symbol = matches[0]
    value = symbol["st_value"] & ~1
    size = symbol["st_size"]
    if value != start or size != end - start or symbol["st_shndx"] == "SHN_UNDEF":
        raise RuntimeError(label + " symbol definition differs")


def _require_direct_edge(blob, mappings, deps, site, target, *, call, label):
    item = _instruction(blob, mappings, deps, site)
    group = deps["call_group"] if call else deps["jump_group"]
    if not item.group(group) or _direct_target(item, deps) != target:
        raise RuntimeError(label + " differs")


def _require_unindexed_memory(
    item, deps, instruction_id, source_or_destination, base, displacement, label,
):
    _require_memory(
        item, deps, instruction_id, source_or_destination, base, displacement, label,
    )
    if len(item.operands) != 2 or item.writeback or item.operands[1].mem.index != 0:
        raise RuntimeError(label + " addressing differs")


def _require_compare_immediate(item, deps, register, value, label):
    if (
        item.id != deps["cmp"]
        or len(item.operands) != 2
        or item.operands[0].type != deps["reg"]
        or item.operands[0].reg != register
        or item.operands[1].type != deps["imm"]
        or item.operands[1].imm != value
    ):
        raise RuntimeError(label + " differs")


def _require_compare_registers(item, deps, left, right, label):
    if (
        item.id != deps["cmp"]
        or len(item.operands) != 2
        or item.operands[0].type != deps["reg"]
        or item.operands[0].reg != left
        or item.operands[1].type != deps["reg"]
        or item.operands[1].reg != right
    ):
        raise RuntimeError(label + " differs")


def _thumb_literal_address(item, deps, destination, label):
    if (
        item.id != deps["ldr"]
        or len(item.operands) != 2
        or item.operands[0].type != deps["reg"]
        or item.operands[0].reg != destination
        or item.operands[1].type != deps["mem"]
        or item.operands[1].mem.base != deps["pc"]
        or item.operands[1].mem.index != 0
        or item.writeback
    ):
        raise RuntimeError(label + " differs")
    return ((item.address + 4) & ~3) + item.operands[1].mem.disp


def _resolve_thumb_got_cell(
    blob, mappings, deps, base_literal_site, base_add_site, offset_literal_site, label,
    *, base_register=None,
):
    base_register = deps["r4"] if base_register is None else base_register
    base_literal = _instruction(blob, mappings, deps, base_literal_site)
    base_address = _thumb_literal_address(base_literal, deps, base_register, label + " base literal")
    base_add = _instruction(blob, mappings, deps, base_add_site)
    if (
        base_add.id != deps["add"]
        or len(base_add.operands) != 2
        or base_add.operands[0].type != deps["reg"]
        or base_add.operands[0].reg != base_register
        or base_add.operands[1].type != deps["reg"]
        or base_add.operands[1].reg != deps["pc"]
    ):
        raise RuntimeError(label + " base add differs")
    offset_literal = _instruction(blob, mappings, deps, offset_literal_site)
    offset_address = _thumb_literal_address(offset_literal, deps, deps["r3"], label + " offset literal")
    base = _word(blob, mappings, base_address) + base_add.address + 4
    return base + _word(blob, mappings, offset_address)


def _arm_attribute_tags(elf):
    section = elf.get_section_by_name(".ARM.attributes")
    if section is None or not hasattr(section, "iter_subsections"):
        raise RuntimeError("ARM attribute section differs")
    tags = set()
    try:
        for subsection in section.iter_subsections():
            for subsubsection in subsection.iter_subsubsections():
                for attribute in subsubsection.iter_attributes():
                    if not isinstance(attribute.tag, str):
                        raise RuntimeError("ARM attribute tag differs")
                    tags.add(attribute.tag)
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError("ARM attribute structure differs") from exc
    return tags


def _require_default_r9_abi(elf, expected):
    required = {
        "attribute_section": ".ARM.attributes",
        "r9_tag": "TAG_ABI_PCS_R9_USE",
        "r9_tag_present": False,
        "tag_nodefaults_present": False,
        "effective_value": 0,
        "classification": "v6-callee-saved-register",
    }
    if expected != required:
        raise RuntimeError("R9 ABI metadata differs")
    tags = _arm_attribute_tags(elf)
    if expected["r9_tag"] in tags or "TAG_NODEFAULTS" in tags:
        raise RuntimeError("R9 ABI attribute contract differs")


def _validate_typed_request(blob, mappings, deps, plt_symbols, exidx):
    expected = EXPECTED_EXPORT["typed_request"]
    _require_owner(exidx, expected["owner"], "typed Creative Style request")
    request = _validate_selector_request(blob, mappings, deps, plt_symbols)
    actual = {
        "owner": copy.deepcopy(expected["owner"]),
        "site": request["request_call_site"],
        "symbol": request["request_symbol"],
        "model": request["request_model"],
        "request_code": request["request_code"],
        "param_list_add_count": len(request["param_add_call_sites"]),
        "classification": expected["classification"],
    }
    if actual != expected:
        raise RuntimeError("typed Creative Style request contract differs")
    return actual


def _validate_view_transport(blob, mappings, deps, dynsym, plt_symbols, exidx):
    expected = EXPECTED_EXPORT["view_wrapper_transport"]
    _require_defined_symbol(
        dynsym,
        expected["wrapper_symbol"],
        expected["wrapper_owner"]["start"],
        expected["wrapper_owner"]["end"],
        "Creative Style request wrapper",
    )
    for key, label in (
        ("wrapper_owner", "Creative Style request wrapper"),
        ("helper_owner", "Creative Style request helper"),
        ("dispatcher_owner", "Creative Style request dispatcher"),
    ):
        _require_owner(exidx, expected[key], label)
    if _call_symbol(blob, mappings, deps, plt_symbols, expected["mr_util_call_site"]) != expected["mr_util_symbol"]:
        raise RuntimeError("Creative Style MR-util lookup differs")
    _require_direct_edge(
        blob, mappings, deps,
        expected["tail_branch"]["site"], expected["tail_branch"]["target"],
        call=False, label="Creative Style wrapper tail branch",
    )
    _require_direct_edge(
        blob, mappings, deps,
        expected["helper_call"]["site"], expected["helper_call"]["target"],
        call=True, label="Creative Style helper dispatcher call",
    )
    return copy.deepcopy(expected)


def _validate_candidate_boundary(blob, mappings, deps, plt_symbols):
    expected = EXPECTED_EXPORT["candidate_cross_module_boundary"]
    if _call_symbol(blob, mappings, deps, plt_symbols, expected["site"]) != expected["symbol"]:
        raise RuntimeError("candidate shared request edge differs")
    dispatcher = EXPECTED_EXPORT["view_wrapper_transport"]["dispatcher_owner"]
    if not dispatcher["start"] <= expected["site"] < dispatcher["end"]:
        raise RuntimeError("candidate shared request edge is outside dispatcher")
    named_edges = []
    for item in _decode(blob, mappings, deps, dispatcher["start"], dispatcher["end"]):
        if not item.group(deps["call_group"]):
            continue
        target = _direct_target(item, deps)
        if target in plt_symbols and plt_symbols[target] == expected["symbol"]:
            named_edges.append(item.address)
    if named_edges != [expected["site"]]:
        raise RuntimeError("named shared request edge inventory differs")
    return copy.deepcopy(expected)


def _validate_operation_38_dispatch_path(blob, mappings, deps, plt_symbols, exidx):
    expected = EXPECTED_EXPORT["operation_38_dispatch_path"]
    _require_owner(exidx, expected["model_mapping_owner"], "operation-38 model mapper")

    captures = expected["wrapper_argument_capture_sites"]
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, captures["request_code"]),
        deps, deps["mov"], deps["r5"], deps["r1"], "wrapper request-code capture",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, captures["param_list"]),
        deps, deps["mov"], deps["r4"], deps["r2"], "wrapper ParamList capture",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, captures["model"]),
        deps, deps["mov"], deps["r6"], deps["r0"], "wrapper model capture",
    )
    forward_sites = expected["wrapper_argument_forward_sites"]
    for site, destination, source, label in (
        (forward_sites[0], deps["r1"], deps["r6"], "wrapper model forward"),
        (forward_sites[1], deps["r2"], deps["r5"], "wrapper request-code forward"),
        (forward_sites[2], deps["r3"], deps["r4"], "wrapper ParamList forward"),
    ):
        _require_reg_to_reg(
            _instruction(blob, mappings, deps, site), deps, deps["mov"], destination, source, label,
        )
    for register, start, end, label in (
        (deps["r5"], captures["request_code"] + 2, forward_sites[1], "wrapper request-code preservation"),
        (deps["r4"], captures["param_list"] + 2, forward_sites[2], "wrapper ParamList preservation"),
        (deps["r6"], captures["model"] + 2, forward_sites[0], "wrapper model preservation"),
        (deps["r1"], forward_sites[0] + 2, EXPECTED_EXPORT["view_wrapper_transport"]["tail_branch"]["site"], "wrapper forwarded model preservation"),
        (deps["r2"], forward_sites[1] + 2, EXPECTED_EXPORT["view_wrapper_transport"]["tail_branch"]["site"], "wrapper forwarded request-code preservation"),
        (deps["r3"], forward_sites[2] + 2, EXPECTED_EXPORT["view_wrapper_transport"]["tail_branch"]["site"], "wrapper forwarded ParamList preservation"),
    ):
        _require_register_unchanged(_decode(blob, mappings, deps, start, end, complete=False), register, label=label)

    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["helper_model_capture_site"]),
        deps, deps["mov"], deps["r5"], deps["r1"], "helper model capture",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["helper_code_capture_site"]),
        deps, deps["mov"], deps["r4"], deps["r2"], "helper request-code capture",
    )
    _require_unindexed_memory(
        _instruction(blob, mappings, deps, expected["helper_param_list_stack_store_site"]),
        deps, deps["str"], deps["r3"], deps["sp"], 0, "helper ParamList stack forward",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["helper_model_forward_site"]),
        deps, deps["mov"], deps["r2"], deps["r5"], "helper model forward",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["helper_code_forward_site"]),
        deps, deps["mov"], deps["r3"], deps["r4"], "helper request-code forward",
    )
    helper_call = EXPECTED_EXPORT["view_wrapper_transport"]["helper_call"]["site"]
    for register, start, end, label in (
        (deps["r3"], EXPECTED_EXPORT["view_wrapper_transport"]["helper_owner"]["start"], expected["helper_param_list_stack_store_site"], "helper ParamList preservation"),
        (deps["r5"], expected["helper_model_capture_site"] + 2, expected["helper_model_forward_site"], "helper model preservation"),
        (deps["r4"], expected["helper_code_capture_site"] + 2, expected["helper_code_forward_site"], "helper request-code preservation"),
        (deps["r0"], EXPECTED_EXPORT["view_wrapper_transport"]["helper_owner"]["start"], helper_call, "helper utility receiver preservation"),
    ):
        _require_register_unchanged(_decode(blob, mappings, deps, start, end, complete=False), register, label=label)

    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["dispatcher_model_capture_site"]),
        deps, deps["mov"], deps["r5"], deps["r2"], "dispatcher model capture",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["dispatcher_code_capture_site"]),
        deps, deps["mov"], deps["r8"], deps["r3"], "dispatcher request-code capture",
    )
    _require_unindexed_memory(
        _instruction(blob, mappings, deps, expected["dispatcher_param_list_capture_site"]),
        deps, deps["ldr"], deps["r6"], deps["r7"], expected["dispatcher_stack_param_offset"],
        "dispatcher ParamList stack capture",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["model_mapping_input_site"]),
        deps, deps["mov"], deps["r1"], deps["r5"], "model-mapping input",
    )
    model_segment = expected["dispatcher_model_preservation_segment"]
    if model_segment != [
        expected["dispatcher_model_capture_site"] + 2,
        expected["model_mapping_input_site"],
    ]:
        raise RuntimeError("dispatcher model preservation segment differs")
    _require_register_unchanged(
        _decode(blob, mappings, deps, model_segment[0], model_segment[1], complete=False),
        deps["r5"], label="dispatcher model preservation to mapper",
    )
    _require_direct_edge(
        blob, mappings, deps, expected["model_mapping_call_site"], expected["model_mapping_target"],
        call=True, label="operation-38 model-mapping call",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["model_mapping_result_capture_site"]),
        deps, deps["mov"], deps["r5"], deps["r0"], "mapped model result capture",
    )
    subtract = _instruction(blob, mappings, deps, expected["gate_subtract_site"])
    compare = _instruction(blob, mappings, deps, expected["gate_compare_site"])
    branch = _instruction(blob, mappings, deps, expected["gate_branch"]["site"])
    if (
        subtract.id != deps["sub"]
        or len(subtract.operands) != 3
        or subtract.operands[0].reg != deps["r3"]
        or subtract.operands[1].reg != deps["r8"]
        or subtract.operands[2].imm != expected["gate_subtract_value"]
        or compare.id != deps["cmp"]
        or compare.operands[0].reg != deps["r3"]
        or compare.operands[1].imm != expected["gate_compare_value"]
        or branch.cc != deps["hi"]
        or _direct_target(branch, deps) != expected["gate_branch"]["target"]
    ):
        raise RuntimeError("operation-38 unsigned dispatcher gate differs")
    normalized = (expected["input_request_code"] - expected["gate_subtract_value"]) & 0xFFFFFFFF
    if normalized != expected["normalized_gate_value"] or not normalized > expected["gate_compare_value"]:
        raise RuntimeError("operation-38 unsigned gate arithmetic differs")
    _require_register_unchanged(
        _decode(
            blob, mappings, deps,
            expected["dispatcher_code_capture_site"] + 2, expected["gate_subtract_site"], complete=False,
        ),
        deps["r8"], label="dispatcher request-code preservation to gate",
    )
    _require_register_unchanged(
        _decode(
            blob, mappings, deps,
            expected["dispatcher_param_list_capture_site"] + 4, expected["gate_branch"]["site"], complete=False,
        ),
        deps["r6"], label="dispatcher ParamList preservation to gate",
    )
    _require_register_unchanged(
        _decode(
            blob, mappings, deps,
            expected["model_mapping_call_site"] + 4, expected["model_mapping_result_capture_site"], complete=False,
        ),
        deps["r0"], label="mapped model return preservation",
    )
    args = expected["shared_call_argument_sites"]
    for site, destination, source, label in (
        (args["model_mapping_result"], deps["r0"], deps["r5"], "shared mapped-model argument"),
        (args["request_code"], deps["r1"], deps["r8"], "shared request-code argument"),
        (args["param_list"], deps["r2"], deps["r6"], "shared ParamList argument"),
    ):
        _require_reg_to_reg(
            _instruction(blob, mappings, deps, site), deps, deps["mov"], destination, source, label,
        )
    if _call_symbol(blob, mappings, deps, plt_symbols, expected["shared_call_site"]) != EXPECTED_EXPORT["candidate_cross_module_boundary"]["symbol"]:
        raise RuntimeError("operation-38 shared request call differs")
    return copy.deepcopy(expected)


def _validate_operation_38_model_alias(view, obj, deps):
    expected = EXPECTED_EXPORT["operation_38_model_alias"]
    _require_owner(view["exidx"], expected["mapper_owner"], "model-alias mapper")
    _require_owner(obj["exidx"], expected["id_generator_owner"], "model IdGenerator")
    _require_defined_symbol(
        obj["dynsym"], expected["id_generator_symbol"],
        expected["id_generator_owner"]["start"], expected["id_generator_owner"]["end"],
        "model IdGenerator",
    )
    _require_reg_to_reg(
        _instruction(view["blob"], view["mappings"], deps, expected["model_capture_site"]),
        deps, deps["mov"], deps["r4"], deps["r1"], "model-alias input capture",
    )
    for site_key, symbol_key, label in (
        ("utility_constructor_call_site", "utility_constructor_symbol", "model-alias utility constructor"),
        ("utility_destructor_call_site", "utility_destructor_symbol", "model-alias utility destructor"),
    ):
        if _call_symbol(
            view["blob"], view["mappings"], deps, view["plt_symbols"], expected[site_key],
        ) != expected[symbol_key]:
            raise RuntimeError(label + " differs")
    first_load = expected["first_byte_load"]
    _require_unindexed_memory(
        _instruction(view["blob"], view["mappings"], deps, first_load["site"]),
        deps, deps["ldrb"], deps["r3"], deps["r4"], first_load["offset"],
        "model-alias first-byte load",
    )
    _require_compare_immediate(
        _instruction(view["blob"], view["mappings"], deps, expected["first_byte_compare_site"]),
        deps, deps["r3"], expected["first_byte_value"], "model-alias first-byte gate",
    )
    _require_direct_edge(
        view["blob"], view["mappings"], deps,
        expected["non_alias_branch"]["site"], expected["non_alias_branch"]["target"],
        call=False, label="model-alias non-at branch",
    )
    if _instruction(
        view["blob"], view["mappings"], deps, expected["non_alias_branch"]["site"],
    ).cc != deps["ne"]:
        raise RuntimeError("model-alias non-at branch condition differs")

    register_by_name = {
        "r1": deps["r1"], "r5": deps["r5"], "r6": deps["r6"], "lr": deps["lr"],
    }
    for record in expected["input_byte_loads"]:
        _require_unindexed_memory(
            _instruction(view["blob"], view["mappings"], deps, record["site"]),
            deps, deps["ldrb"], register_by_name[record["register"]], deps["r4"],
            record["offset"], "model-alias input byte load",
        )
    for record in expected["candidate_byte_loads"]:
        _require_unindexed_memory(
            _instruction(view["blob"], view["mappings"], deps, record["site"]),
            deps, deps["ldrb"], register_by_name[record["register"]], deps["r1"],
            record["offset"], "model-alias candidate byte load",
        )
    compare_pairs = (
        (deps["r6"], deps["r5"]),
        (deps["lr"], deps["r6"]),
        (deps["r6"], deps["r1"]),
    )
    for site, (left, right) in zip(expected["byte_compare_sites"], compare_pairs):
        _require_compare_registers(
            _instruction(view["blob"], view["mappings"], deps, site),
            deps, left, right, "model-alias candidate byte comparison",
        )

    counter_init = _instruction(
        view["blob"], view["mappings"], deps, expected["counter_initialization_site"],
    )
    if (
        counter_init.id != deps["sub"]
        or len(counter_init.operands) != 2
        or counter_init.operands[0].type != deps["reg"]
        or counter_init.operands[0].reg != deps["r3"]
        or counter_init.operands[1].type != deps["imm"]
        or counter_init.operands[1].imm != expected["first_byte_value"]
    ):
        raise RuntimeError("model-alias counter initialization differs")
    table = expected["table"]
    literal = _instruction(view["blob"], view["mappings"], deps, table["literal_load_site"])
    literal_address = ((literal.address + 4) & ~3) + literal.operands[1].mem.disp
    if (
        literal.id != deps["ldr"]
        or len(literal.operands) != 2
        or literal.operands[0].reg != deps["r2"]
        or literal.operands[1].type != deps["mem"]
        or literal.operands[1].mem.base != deps["pc"]
        or literal.operands[1].mem.index != 0
        or literal_address != table["literal_address"]
    ):
        raise RuntimeError("model-alias table literal load differs")
    pc_add = _instruction(view["blob"], view["mappings"], deps, table["pc_add_site"])
    if (
        pc_add.id != deps["add"]
        or len(pc_add.operands) != 2
        or pc_add.operands[0].type != deps["reg"]
        or pc_add.operands[0].reg != deps["r2"]
        or pc_add.operands[1].type != deps["reg"]
        or pc_add.operands[1].reg != deps["pc"]
        or _word(view["blob"], view["mappings"], literal_address) + pc_add.address + 4
        != table["base"]
    ):
        raise RuntimeError("model-alias table base differs")
    scale = _instruction(view["blob"], view["mappings"], deps, 0x3391F2)
    if (
        scale.id != deps["lsl"]
        or len(scale.operands) != 3
        or scale.operands[0].reg != deps["r0"]
        or scale.operands[1].reg != deps["r3"]
        or scale.operands[2].imm != 3
        or table["entry_stride"] != 8
    ):
        raise RuntimeError("model-alias table index scale differs")
    candidate = _instruction(
        view["blob"], view["mappings"], deps, expected["candidate_pointer_load_site"],
    )
    if (
        candidate.id != deps["ldr"]
        or len(candidate.operands) != 2
        or candidate.operands[0].reg != deps["r1"]
        or candidate.operands[1].type != deps["mem"]
        or candidate.operands[1].mem.base != deps["r2"]
        or candidate.operands[1].mem.index != deps["r3"]
        or candidate.operands[1].mem.disp != 0
        or candidate.operands[1].shift.value != 3
        or candidate.writeback
    ):
        raise RuntimeError("model-alias candidate pointer differs")

    counter_increment = _instruction(
        view["blob"], view["mappings"], deps, expected["counter_increment_site"],
    )
    if (
        counter_increment.id != deps["add"]
        or len(counter_increment.operands) != 2
        or counter_increment.operands[0].reg != deps["r3"]
        or counter_increment.operands[1].imm != 1
    ):
        raise RuntimeError("model-alias counter increment differs")
    _require_compare_immediate(
        _instruction(view["blob"], view["mappings"], deps, expected["counter_compare_site"]),
        deps, deps["r3"], expected["counter_loop_bound"], "model-alias loop bound",
    )
    if table["entry_count"] != expected["counter_loop_bound"]:
        raise RuntimeError("model-alias table entry count differs")
    _require_direct_edge(
        view["blob"], view["mappings"], deps,
        expected["counter_loop_branch"]["site"], expected["counter_loop_branch"]["target"],
        call=False, label="model-alias loop branch",
    )
    if _instruction(
        view["blob"], view["mappings"], deps, expected["counter_loop_branch"]["site"],
    ).cc != deps["ne"]:
        raise RuntimeError("model-alias loop branch condition differs")
    result_address = _instruction(
        view["blob"], view["mappings"], deps, expected["match_result_address_site"],
    )
    if (
        result_address.id != deps["add"]
        or len(result_address.operands) != 3
        or [operand.reg for operand in result_address.operands]
        != [deps["r2"], deps["r2"], deps["r0"]]
    ):
        raise RuntimeError("model-alias result address differs")
    result_load = expected["match_result_load"]
    _require_unindexed_memory(
        _instruction(view["blob"], view["mappings"], deps, result_load["site"]),
        deps, deps["ldr"], deps["r4"], deps["r2"], result_load["offset"],
        "model-alias result load",
    )
    _require_reg_to_reg(
        _instruction(view["blob"], view["mappings"], deps, expected["return_site"]),
        deps, deps["mov"], deps["r0"], deps["r4"], "model-alias return",
    )

    entry = expected["entry_zero"]
    rel_dyn = list(view["elf"].get_section_by_name(entry["key_relocation"]["section"]).iter_relocations())
    for prefix in ("key", "result"):
        relocation_contract = entry[prefix + "_relocation"]
        relocation = rel_dyn[relocation_contract["index"]]
        cell = entry[prefix + "_cell"]
        if (
            relocation["r_offset"] != cell
            or relocation["r_info_type"] != relocation_contract["type"]
            or relocation["r_info_sym"] != relocation_contract["symbol_index"]
            or _word(view["blob"], view["mappings"], cell) != entry[prefix + "_address"]
        ):
            raise RuntimeError("model-alias entry-zero relocation target differs")
        if _cstring(
            view["blob"], view["mappings"], entry[prefix + "_address"],
        ) != entry[prefix]:
            raise RuntimeError("model-alias entry-zero string differs")
    if (
        entry["key_cell"] != table["base"]
        or entry["result_cell"] != table["base"] + 4
        or entry["key"] != expected["input_model"]
        or entry["result"] != expected["resolved_model_alias"]
        or EXPECTED_EXPORT["typed_request"]["model"] != expected["input_model"]
    ):
        raise RuntimeError("model-alias entry-zero semantic join differs")

    _require_register_unchanged(
        _decode(
            obj["blob"], obj["mappings"], deps,
            expected["id_generator_model_preservation_segment"][0],
            expected["id_generator_model_preservation_segment"][1], complete=False,
        ),
        deps["r0"], label="model IdGenerator argument preservation",
    )
    if _call_symbol(
        obj["blob"], obj["mappings"], deps, obj["plt_symbols"], expected["id_generator_call_site"],
    ) != expected["id_generator_symbol"]:
        raise RuntimeError("model IdGenerator call differs")
    _require_reg_to_reg(
        _instruction(obj["blob"], obj["mappings"], deps, expected["id_generator_result_capture_site"]),
        deps, deps["mov"], deps["r6"], deps["r0"], "model ID result capture",
    )
    _require_reg_to_reg(
        _instruction(obj["blob"], obj["mappings"], deps, expected["event_builder_id_argument_site"]),
        deps, deps["mov"], deps["r1"], deps["r6"], "model ID Event-builder argument",
    )
    result_segment = expected["id_generator_result_preservation_segment"]
    if result_segment != [
        expected["id_generator_result_capture_site"] + 2,
        expected["event_builder_id_argument_site"],
    ]:
        raise RuntimeError("model ID result preservation segment differs")
    _require_register_unchanged(
        _decode(
            obj["blob"], obj["mappings"], deps,
            result_segment[0], result_segment[1], complete=False,
        ),
        deps["r6"], label="model ID result preservation",
    )
    _require_reg_to_reg(
        _instruction(obj["blob"], obj["mappings"], deps, expected["builder_id_capture_site"]),
        deps, deps["mov"], deps["r6"], deps["r1"], "Event-builder model ID capture",
    )
    _require_reg_to_reg(
        _instruction(obj["blob"], obj["mappings"], deps, expected["builder_id_value_site"]),
        deps, deps["mov"], deps["r1"], deps["r6"], "Event-builder model ID scalar value",
    )
    builder_segment = expected["builder_id_preservation_segment"]
    if builder_segment != [
        expected["builder_id_capture_site"] + 2,
        expected["builder_id_value_site"],
    ]:
        raise RuntimeError("Event-builder model ID preservation segment differs")
    _require_register_unchanged(
        _decode(
            obj["blob"], obj["mappings"], deps,
            builder_segment[0], builder_segment[1], complete=False,
        ),
        deps["r6"], label="Event-builder model ID preservation",
    )
    _require_reg_to_reg(
        _instruction(obj["blob"], obj["mappings"], deps, expected["builder_id_holder_site"]),
        deps, deps["mov"], deps["r5"], deps["r0"], "Event-builder model ID holder",
    )
    _require_reg_to_reg(
        _instruction(obj["blob"], obj["mappings"], deps, expected["builder_parameter_value_site"]),
        deps, deps["mov"], deps["r2"], deps["r5"], "model ID Event parameter value",
    )
    _require_mov_immediate(
        _instruction(obj["blob"], obj["mappings"], deps, expected["builder_parameter_key_site"]),
        deps, deps["r1"], expected["event_parameter_key"], "model ID Event key",
    )
    _require_reg_to_reg(
        _instruction(obj["blob"], obj["mappings"], deps, expected["builder_event_receiver_site"]),
        deps, deps["mov"], deps["r0"], deps["r4"], "model ID Event receiver",
    )
    if _call_symbol(
        obj["blob"], obj["mappings"], deps, obj["plt_symbols"], expected["event_parameter_add_site"],
    ) != EXPECTED_EXPORT["shared_libobj_transport"]["scalar_parameter_add_symbol"]:
        raise RuntimeError("model ID Event parameter add differs")

    idgen_first = expected["id_generator_first_byte_load"]
    _require_unindexed_memory(
        _instruction(obj["blob"], obj["mappings"], deps, idgen_first["site"]),
        deps, deps["ldrb"], deps["r3"], deps["r0"], idgen_first["offset"],
        "IdGenerator first-byte load",
    )
    _require_compare_immediate(
        _instruction(
            obj["blob"], obj["mappings"], deps, expected["id_generator_first_byte_compare_site"],
        ),
        deps, deps["r3"], expected["first_byte_value"], "IdGenerator first-byte gate",
    )
    _require_direct_edge(
        obj["blob"], obj["mappings"], deps,
        expected["id_generator_special_at_branch"]["site"],
        expected["id_generator_special_at_branch"]["target"],
        call=False, label="IdGenerator special-at branch",
    )
    if _instruction(
        obj["blob"], obj["mappings"], deps, expected["id_generator_special_at_branch"]["site"],
    ).cc != deps["eq"]:
        raise RuntimeError("IdGenerator special-at branch condition differs")
    if ord(expected["resolved_model_alias"][0]) == expected["first_byte_value"]:
        raise RuntimeError("resolved model alias unexpectedly takes special-at branch")
    if _call_symbol(
        obj["blob"], obj["mappings"], deps, obj["plt_symbols"], expected["id_table_find_call_site"],
    ) != expected["id_table_find_symbol"]:
        raise RuntimeError("runtime model-ID lookup differs")
    _require_reg_to_reg(
        _instruction(obj["blob"], obj["mappings"], deps, expected["id_table_result_capture_site"]),
        deps, deps["mov"], deps["r4"], deps["r0"], "runtime model-ID result capture",
    )
    sentinel = _instruction(
        obj["blob"], obj["mappings"], deps, expected["id_generator_missing_sentinel_site"],
    )
    if not (
        len(sentinel.operands) == 2
        and sentinel.operands[0].type == deps["reg"]
        and sentinel.operands[0].reg == deps["r4"]
        and (
            (sentinel.id == deps["mov"] and (sentinel.operands[1].imm & 0xFFFFFFFF) == 0xFFFFFFFF)
            or (sentinel.id == deps["mvn"] and sentinel.operands[1].imm == 0)
        )
    ):
        raise RuntimeError("runtime model-ID missing sentinel differs")
    if (
        expected["semantic_model_alias_resolved"] is not True
        or expected["original_model_literal_preserved"] is not False
        or expected["numeric_model_id_resolved"] is not False
    ):
        raise RuntimeError("model-alias claim boundary differs")
    return copy.deepcopy(expected)


def _validate_shared_transport(blob, mappings, deps, dynsym, plt_symbols, exidx):
    expected = EXPECTED_EXPORT["shared_libobj_transport"]
    _require_defined_symbol(
        dynsym,
        expected["request_symbol"],
        expected["request_owner"]["start"],
        expected["request_owner"]["end"],
        "shared request transport",
    )
    _require_owner(exidx, expected["request_owner"], "shared request transport")
    _require_owner(exidx, expected["event_builder_owner"], "request event builder")
    calls = (
        (expected["id_generator_call_site"], expected["id_generator_symbol"], "request ID generator"),
        (expected["event_builder_call_site"], expected["event_builder_symbol"], "request event builder"),
        (expected["event_constructor_call_site"], expected["event_constructor_symbol"], "Event constructor"),
        (expected["param_list_attach_call_site"], expected["param_list_attach_symbol"], "Event ParamList attach"),
    )
    for site, symbol, label in calls:
        if _call_symbol(blob, mappings, deps, plt_symbols, site) != symbol:
            raise RuntimeError(label + " differs")
    for site in expected["scalar_parameter_add_call_sites"]:
        if _call_symbol(blob, mappings, deps, plt_symbols, site) != expected["scalar_parameter_add_symbol"]:
            raise RuntimeError("Event scalar parameter add differs")
    _require_direct_edge(
        blob, mappings, deps,
        expected["event_continuation_branch_site"], expected["event_continuation"],
        call=False, label="shared request event continuation",
    )
    return copy.deepcopy(expected)


def _validate_operation_38_event_mapping(elf, blob, mappings, deps, plt_symbols, exidx):
    expected = EXPECTED_EXPORT["operation_38_event_mapping"]
    _require_owner(exidx, expected["mapper_owner"], "operation-code event mapper")
    _require_default_r9_abi(elf, expected["r9_abi"])
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["request_code_capture_site"]),
        deps, deps["mov"], deps["r9"], deps["r1"], "shared request-code capture",
    )
    r9_segment = expected["request_code_r9_preservation_segment"]
    if r9_segment != [expected["request_code_capture_site"] + 2, expected["mapper_code_argument_site"]]:
        raise RuntimeError("shared request-code r9 segment differs")
    _require_register_unchanged(
        _decode(blob, mappings, deps, r9_segment[0], r9_segment[1], complete=False),
        deps["r9"], label="shared request-code r9 preservation",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["mapper_code_argument_site"]),
        deps, deps["mov"], deps["r1"], deps["r9"], "operation mapper code argument",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["mapper_model_argument_site"]),
        deps, deps["mov"], deps["r0"], deps["r5"], "operation mapper model argument",
    )
    _require_direct_edge(
        blob, mappings, deps, expected["mapper_call"]["site"], expected["mapper_call"]["target"],
        call=True, label="operation-code mapper call",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["mapper_code_capture_site"]),
        deps, deps["mov"], deps["r6"], deps["r1"], "operation mapper input capture",
    )
    _require_unindexed_memory(
        _instruction(blob, mappings, deps, expected["mapper_callback_object_load_site"]),
        deps, deps["ldr"], deps["r5"], deps["r0"], 0, "operation mapper callback object",
    )
    _require_unindexed_memory(
        _instruction(blob, mappings, deps, expected["mapper_callback_vptr_load_site"]),
        deps, deps["ldr"], deps["r3"], deps["r5"], 0, "operation mapper callback vptr",
    )
    _require_unindexed_memory(
        _instruction(blob, mappings, deps, expected["mapper_callback_target_load_site"]),
        deps, deps["ldr"], deps["r4"], deps["r3"], 8, "operation mapper callback target",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["mapper_callback_receiver_site"]),
        deps, deps["mov"], deps["r0"], deps["r5"], "operation mapper callback receiver",
    )
    callback_buffer = _instruction(blob, mappings, deps, expected["mapper_callback_buffer_site"])
    if (
        callback_buffer.id != deps["add"]
        or len(callback_buffer.operands) != 3
        or callback_buffer.operands[0].reg != deps["r1"]
        or callback_buffer.operands[1].reg != deps["r7"]
        or callback_buffer.operands[2].imm != expected["mapper_callback_buffer_offset"]
    ):
        raise RuntimeError("operation mapper callback buffer differs")
    for site in (expected["mapper_callback_code_argument_site"], expected["mapper_alternate_code_argument_site"]):
        _require_reg_to_reg(
            _instruction(blob, mappings, deps, site),
            deps, deps["mov"], deps["r2"], deps["r6"], "operation mapper callback code argument",
        )
    _require_register_unchanged(
        _decode(
            blob, mappings, deps,
            expected["mapper_code_capture_site"] + 2, expected["mapper_callback_code_argument_site"],
            complete=False,
        ),
        deps["r6"], label="operation mapper code preservation",
    )
    _require_register_unchanged(
        _decode(
            blob, mappings, deps,
            expected["mapper_code_capture_site"] + 2, expected["mapper_alternate_code_argument_site"],
            complete=False,
        ),
        deps["r6"], label="operation mapper alternate-route code preservation",
    )
    callback = _instruction(blob, mappings, deps, expected["mapper_callback_call_site"])
    if (
        not callback.group(deps["call_group"])
        or _direct_target(callback, deps) is not None
        or len(callback.operands) != 1
        or callback.operands[0].type != deps["reg"]
    ):
        raise RuntimeError("operation mapper indirect callback differs")
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["mapper_callback_result_capture_site"]),
        deps, deps["mov"], deps["r4"], deps["r0"], "operation mapper callback result",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["mapper_return_site"]),
        deps, deps["mov"], deps["r0"], deps["r4"], "operation mapper return",
    )
    for site in expected["mapper_sentinel_sites"]:
        sentinel = _instruction(blob, mappings, deps, site)
        if not (
            len(sentinel.operands) == 2
            and sentinel.operands[0].type == deps["reg"]
            and sentinel.operands[0].reg == deps["r4"]
            and (
                (sentinel.id == deps["mov"] and (sentinel.operands[1].imm & 0xFFFFFFFF) == 0xFFFFFFFF)
                or (sentinel.id == deps["mvn"] and sentinel.operands[1].imm == 0)
            )
        ):
            raise RuntimeError("operation mapper sentinel differs")
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["mapped_operation_builder_argument_site"]),
        deps, deps["mov"], deps["r2"], deps["r0"], "mapped operation Event-builder argument",
    )
    if _call_symbol(blob, mappings, deps, plt_symbols, expected["event_builder_call_site"]) != EXPECTED_EXPORT["shared_libobj_transport"]["event_builder_symbol"]:
        raise RuntimeError("mapped operation Event-builder call differs")
    _require_register_unchanged(
        _decode(
            blob, mappings, deps,
            expected["mapper_call"]["site"] + 4, expected["mapped_operation_builder_argument_site"],
            complete=False,
        ),
        deps["r0"], label="mapped operation return preservation",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["builder_operation_capture_site"]),
        deps, deps["mov"], deps["r8"], deps["r2"], "Event-builder mapped operation capture",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["builder_operation_value_site"]),
        deps, deps["mov"], deps["r1"], deps["r8"], "Event mapped operation value",
    )
    _require_register_unchanged(
        _decode(
            blob, mappings, deps,
            expected["builder_operation_capture_site"] + 2, expected["builder_operation_value_site"],
            complete=False,
        ),
        deps["r8"], label="Event-builder mapped operation preservation",
    )
    _require_mov_immediate(
        _instruction(blob, mappings, deps, expected["builder_parameter_key_site"]),
        deps, deps["r1"], expected["event_parameter_key"], "mapped operation Event key",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["builder_event_receiver_site"]),
        deps, deps["mov"], deps["r0"], deps["r4"], "mapped operation Event receiver",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["builder_parameter_value_site"]),
        deps, deps["mov"], deps["r2"], deps["r5"], "mapped operation Event holder",
    )
    if _call_symbol(blob, mappings, deps, plt_symbols, expected["event_parameter_add_site"]) != EXPECTED_EXPORT["shared_libobj_transport"]["scalar_parameter_add_symbol"]:
        raise RuntimeError("mapped operation Event parameter add differs")
    return copy.deepcopy(expected)


def _validate_operation_38_event_header(blob, mappings, deps, plt_symbols, exidx):
    expected = EXPECTED_EXPORT["operation_38_event_header"]
    for key, label in (
        ("builder_owner", "request Event builder"),
        ("constructor_owner", "Event constructor"),
        ("get_id_owner", "Event ID accessor"),
        ("get_destination_owner", "Event destination accessor"),
        ("get_queue_tag_owner", "Event queue-tag accessor"),
        ("set_param_list_owner", "Event ParamList setter"),
        ("add_parameter_owner", "Event add-parameter wrapper"),
    ):
        _require_owner(exidx, expected[key], label)
    if (
        expected["get_destination_function"] != {"start": 0x84247C, "end": 0x842484}
        or expected["get_queue_tag_function"] != {"start": 0x842484, "end": 0x84248C}
    ):
        raise RuntimeError("Event byte-accessor function range differs")
    for key in ("get_destination_function", "get_queue_tag_function"):
        function = expected[key]
        _decode(blob, mappings, deps, function["start"], function["end"])

    literal = _instruction(blob, mappings, deps, expected["event_id_literal_load_site"])
    if (
        literal.id != deps["ldr"]
        or len(literal.operands) != 2
        or literal.operands[0].type != deps["reg"]
        or literal.operands[0].reg != deps["r1"]
        or literal.operands[1].type != deps["mem"]
        or literal.operands[1].mem.base != deps["pc"]
        or literal.operands[1].mem.index != 0
        or literal.writeback
        or ((literal.address + 4) & ~3) + literal.operands[1].mem.disp
        != expected["event_id_literal_address"]
    ):
        raise RuntimeError("Event ID literal load differs")
    if _word(blob, mappings, expected["event_id_literal_address"]) != expected["event_id"]:
        raise RuntimeError("Event ID literal value differs")

    _require_mov_immediate(
        _instruction(blob, mappings, deps, expected["destination_argument_site"]),
        deps, deps["r2"], expected["destination"], "Event destination argument",
    )
    _require_mov_immediate(
        _instruction(blob, mappings, deps, expected["queue_tag_argument_site"]),
        deps, deps["r3"], expected["queue_tag"], "Event queue-tag argument",
    )
    header_segments = expected["header_argument_preservation_segments"]
    required_header_segments = {
        "event_id": [expected["event_id_literal_load_site"] + 2, expected["constructor_call_site"]],
        "destination": [expected["destination_argument_site"] + 2, expected["constructor_call_site"]],
        "queue_tag": [expected["queue_tag_argument_site"] + 2, expected["constructor_call_site"]],
    }
    if header_segments != required_header_segments:
        raise RuntimeError("Event header argument preservation segments differ")
    for key, register, label in (
        ("event_id", deps["r1"], "Event ID argument preservation"),
        ("destination", deps["r2"], "Event destination argument preservation"),
        ("queue_tag", deps["r3"], "Event queue-tag argument preservation"),
    ):
        start, end = header_segments[key]
        _require_register_unchanged(
            _decode(blob, mappings, deps, start, end, complete=False), register, label=label,
        )
    if _call_symbol(
        blob, mappings, deps, plt_symbols, expected["constructor_call_site"],
    ) != expected["constructor_symbol"]:
        raise RuntimeError("Event constructor call differs")

    stores = (
        ("event_id_store", deps["str"], deps["r1"], "Event ID store"),
        ("destination_store", deps["strb"], deps["r2"], "Event destination store"),
        ("queue_tag_store", deps["strb"], deps["r3"], "Event queue-tag store"),
    )
    for key, instruction_id, source, label in stores:
        record = expected[key]
        _require_unindexed_memory(
            _instruction(blob, mappings, deps, record["site"]),
            deps, instruction_id, source, deps["r0"], record["offset"], label,
        )
        width = 1 if instruction_id == deps["strb"] else 4
        if record["width"] != width:
            raise RuntimeError(label + " width differs")

    loads = (
        ("get_id_load", deps["ldr"], deps["r0"], deps["r0"], "Event ID load"),
        ("get_destination_load", deps["ldrb"], deps["r0"], deps["r0"], "Event destination load"),
        ("get_queue_tag_load", deps["ldrb"], deps["r0"], deps["r0"], "Event queue-tag load"),
        ("set_param_list_store", deps["str"], deps["r6"], deps["r4"], "Event ParamList store"),
        (
            "add_parameter_param_list_load", deps["ldr"], deps["r0"], deps["r0"],
            "Event add-parameter ParamList load",
        ),
    )
    for key, instruction_id, register, base, label in loads:
        record = expected[key]
        _require_unindexed_memory(
            _instruction(blob, mappings, deps, record["site"]),
            deps, instruction_id, register, base, record["offset"], label,
        )
        width = 1 if instruction_id == deps["ldrb"] else 4
        if record["width"] != width:
            raise RuntimeError(label + " width differs")

    setter_stores = [
        item.address
        for item in _decode(
            blob, mappings, deps,
            expected["set_param_list_owner"]["start"], expected["set_param_list_owner"]["end"],
        )
        if item.id in (deps["str"], deps["strb"])
    ]
    add_parameter_stores = [
        item.address
        for item in _decode(
            blob, mappings, deps,
            expected["add_parameter_owner"]["start"], expected["add_parameter_owner"]["end"],
        )
        if item.id in (deps["str"], deps["strb"])
    ]
    if (
        expected["parameter_method_direct_header_store_found"] is not False
        or setter_stores != [expected["set_param_list_store"]["site"]]
        or add_parameter_stores
    ):
        raise RuntimeError("Event parameter-method direct store inventory differs")
    return copy.deepcopy(expected)


def _validate_operation_38_queue_dispatch(blob, mappings, deps, exidx):
    expected = EXPECTED_EXPORT["operation_38_queue_dispatch"]
    _require_owner(exidx, expected["push_owner"], "operation-38 EventManager push")
    _require_owner(exidx, expected["queue_tag_reader_owner"], "Event queue-tag reader")
    _require_owner(exidx, expected["queue_zero_helper_owner"], "Event queue-zero helper")
    if (
        expected["queue_tag_reader_function"]
        != EXPECTED_EXPORT["operation_38_event_header"]["get_queue_tag_function"]
    ):
        raise RuntimeError("queue tag-reader function range differs")
    _require_direct_edge(
        blob, mappings, deps,
        expected["queue_tag_read_call"]["site"], expected["queue_tag_read_call"]["target"],
        call=True, label="queue tag reader call",
    )
    _require_compare_immediate(
        _instruction(blob, mappings, deps, expected["tag_one_compare_site"]),
        deps, deps["r0"], 1, "queue tag-one comparison",
    )
    _require_direct_edge(
        blob, mappings, deps,
        expected["tag_one_branch"]["site"], expected["tag_one_branch"]["target"],
        call=False, label="queue tag-one branch",
    )
    if _instruction(blob, mappings, deps, expected["tag_one_branch"]["site"]).cc != deps["eq"]:
        raise RuntimeError("queue tag-one branch condition differs")
    _require_compare_immediate(
        _instruction(blob, mappings, deps, expected["tag_three_compare_site"]),
        deps, deps["r0"], 3, "queue tag-three comparison",
    )
    _require_direct_edge(
        blob, mappings, deps,
        expected["other_tag_branch"]["site"], expected["other_tag_branch"]["target"],
        call=False, label="queue non-one-or-three branch",
    )
    if _instruction(blob, mappings, deps, expected["other_tag_branch"]["site"]).cc != deps["ne"]:
        raise RuntimeError("queue non-one-or-three branch condition differs")
    _require_register_unchanged(
        _decode(
            blob, mappings, deps,
            expected["queue_tag_read_call"]["site"] + 4, expected["other_tag_branch"]["site"],
            complete=False,
        ),
        deps["r0"], label="queue tag result preservation",
    )

    guard = _instruction(blob, mappings, deps, expected["tag_zero_fallthrough_site"])
    if (
        guard.id != deps["cbnz"]
        or len(guard.operands) != 2
        or guard.operands[0].type != deps["reg"]
        or guard.operands[0].reg != deps["r0"]
        or guard.operands[1].type != deps["imm"]
        or guard.operands[1].imm != expected["tag_zero_guard_target"]
    ):
        raise RuntimeError("queue tag-zero fallthrough differs")

    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["event_argument_capture_site"]),
        deps, deps["mov"], deps["r5"], deps["r1"], "queue Event argument capture",
    )
    required_event_segments = [
        [expected["event_argument_capture_site"] + 2, expected["other_tag_branch"]["site"]],
        [expected["other_tag_branch"]["target"], expected["event_argument_forward_site"]],
    ]
    if expected["event_argument_preservation_segments"] != required_event_segments:
        raise RuntimeError("queue Event argument preservation segments differ")
    for start, end in required_event_segments:
        _require_register_unchanged(
            _decode(blob, mappings, deps, start, end, complete=False),
            deps["r5"], label="queue Event argument preservation",
        )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["event_argument_forward_site"]),
        deps, deps["mov"], deps["r1"], deps["r5"], "queue-zero Event argument",
    )
    receiver_first, receiver_second = expected["queue_zero_receiver_sites"]
    _require_unindexed_memory(
        _instruction(blob, mappings, deps, receiver_first),
        deps, deps["ldr"], deps["r3"], deps["r4"], 0, "queue-zero container load",
    )
    _require_unindexed_memory(
        _instruction(blob, mappings, deps, receiver_second),
        deps, deps["ldr"], deps["r0"], deps["r3"], 0, "queue-zero receiver load",
    )
    _require_direct_edge(
        blob, mappings, deps,
        expected["queue_zero_call"]["site"], expected["queue_zero_call"]["target"],
        call=True, label="queue-zero direct call",
    )
    if (
        EXPECTED_EXPORT["operation_38_event_header"]["queue_tag"] != 0
        or expected["bypassed_indirect_call_sites"]
        != EXPECTED_EXPORT["event_queue_boundary"]["indirect_call_sites"]
        or expected["operation_38_indirect_reachability"] != []
        or expected["consumer_loop_join_proven"] is not False
    ):
        raise RuntimeError("operation-38 queue reachability metadata differs")
    return copy.deepcopy(expected)


def _validate_operation_38_queue_consumer_identity(elf, blob, mappings, deps, dynsym, exidx):
    expected = EXPECTED_EXPORT["operation_38_queue_consumer_identity"]
    for key, label in (
        ("producer_initialization_caller_owner", "producer initialization caller"),
        ("producer_initializer_owner", "producer global initializer"),
        ("continuation_owner", "producer queue continuation"),
        ("queue_helper_owner", "producer queue helper"),
        ("thread_owner", "consumer outer thread entry"),
        ("outer_constructor_owner", "consumer outer constructor"),
        ("consumer_loop_owner", "consumer loop"),
    ):
        _require_owner(exidx, expected[key], label)

    utility_load = expected["utility_manager_load"]
    _require_unindexed_memory(
        _instruction(blob, mappings, deps, utility_load["site"]),
        deps, deps["ldr"], deps["r0"], deps["r4"], utility_load["offset"],
        "UtilityManager source load",
    )
    _require_direct_edge(
        blob, mappings, deps,
        expected["producer_initializer_call"]["site"], expected["producer_initializer_call"]["target"],
        call=True, label="producer initializer call",
    )
    wrapper_load = expected["wrapper_load"]
    _require_unindexed_memory(
        _instruction(blob, mappings, deps, wrapper_load["site"]),
        deps, deps["ldr"], deps["r2"], deps["r0"], wrapper_load["offset"],
        "producer wrapper load",
    )
    producer_cell = _resolve_thumb_got_cell(
        blob, mappings, deps,
        expected["initializer_got_base_literal_site"], expected["initializer_got_base_add_site"],
        expected["initializer_got_offset_literal_site"], "producer initializer GOT",
    )
    if producer_cell != expected["producer_global"]["got_cell"]:
        raise RuntimeError("producer initializer GOT cell differs")
    producer_got_load = _instruction(blob, mappings, deps, expected["initializer_got_load_site"])
    if (
        producer_got_load.id != deps["ldr"]
        or len(producer_got_load.operands) != 2
        or producer_got_load.operands[0].reg != deps["r3"]
        or producer_got_load.operands[1].type != deps["mem"]
        or producer_got_load.operands[1].mem.base != deps["r4"]
        or producer_got_load.operands[1].mem.index != deps["r3"]
        or producer_got_load.operands[1].mem.disp != 0
    ):
        raise RuntimeError("producer initializer GOT load differs")
    _require_unindexed_memory(
        _instruction(blob, mappings, deps, expected["producer_global_store_site"]),
        deps, deps["str"], deps["r2"], deps["r3"], 0, "producer global store",
    )

    continuation_cell = _resolve_thumb_got_cell(
        blob, mappings, deps,
        expected["continuation_got_base_literal_site"], expected["continuation_got_base_add_site"],
        expected["continuation_got_offset_literal_site"], "producer continuation GOT",
    )
    if continuation_cell != producer_cell:
        raise RuntimeError("producer initializer/continuation GOT join differs")
    continuation_got_load = _instruction(
        blob, mappings, deps, expected["continuation_got_load_site"],
    )
    if (
        continuation_got_load.id != deps["ldr"]
        or len(continuation_got_load.operands) != 2
        or continuation_got_load.operands[0].reg != deps["r3"]
        or continuation_got_load.operands[1].type != deps["mem"]
        or continuation_got_load.operands[1].mem.base != deps["r4"]
        or continuation_got_load.operands[1].mem.index != deps["r3"]
        or continuation_got_load.operands[1].mem.disp != 0
    ):
        raise RuntimeError("producer continuation GOT load differs")
    _require_unindexed_memory(
        _instruction(blob, mappings, deps, expected["continuation_global_value_load_site"]),
        deps, deps["ldr"], deps["r0"], deps["r3"], 0, "producer global value load",
    )
    producer_receiver = expected["producer_receiver_load"]
    _require_unindexed_memory(
        _instruction(blob, mappings, deps, producer_receiver["site"]),
        deps, deps["ldr"], deps["r0"], deps["r0"], producer_receiver["offset"],
        "producer EventManager receiver load",
    )

    producer_relocation = expected["producer_global"]["relocation"]
    rel_dyn = list(elf.get_section_by_name(producer_relocation["section"]).iter_relocations())
    relocation = rel_dyn[producer_relocation["index"]]
    if (
        relocation["r_offset"] != producer_cell
        or relocation["r_info_type"] != producer_relocation["type"]
        or relocation["r_info_sym"] != producer_relocation["symbol_index"]
        or _word(blob, mappings, producer_cell) != producer_relocation["target"]
    ):
        raise RuntimeError("producer global relocation target differs")

    _require_add_immediate(
        _instruction(blob, mappings, deps, expected["outer_constructor_argument_site"]),
        deps, deps["r0"], deps["r7"], 4, "outer constructor argument",
    )
    _require_direct_edge(
        blob, mappings, deps,
        expected["outer_constructor_call"]["site"], expected["outer_constructor_call"]["target"],
        call=True, label="outer constructor call",
    )
    _require_add_immediate(
        _instruction(blob, mappings, deps, expected["outer_loop_argument_site"]),
        deps, deps["r0"], deps["r7"], 4, "outer consumer-loop argument",
    )
    _require_direct_edge(
        blob, mappings, deps,
        expected["outer_loop_call"]["site"], expected["outer_loop_call"]["target"],
        call=True, label="outer consumer-loop call",
    )
    _require_direct_edge(
        blob, mappings, deps,
        expected["event_manager_constructor_call"]["site"],
        expected["event_manager_constructor_call"]["target"],
        call=True, label="outer EventManager constructor call",
    )
    outer_store = expected["outer_event_manager_store"]
    _require_unindexed_memory(
        _instruction(blob, mappings, deps, outer_store["site"]),
        deps, deps["str"], deps["r6"], deps["r4"], outer_store["offset"],
        "outer EventManager store",
    )

    outer_global = expected["outer_event_manager_global"]
    outer_cell = _resolve_thumb_got_cell(
        blob, mappings, deps,
        outer_global["got_base_literal_site"], outer_global["got_base_add_site"],
        outer_global["got_offset_literal_site"], "outer EventManager global GOT",
        base_register=deps["r5"],
    )
    if outer_cell != outer_global["got_cell"] or outer_cell == producer_cell:
        raise RuntimeError("outer EventManager global channel differs")
    outer_got_load = _instruction(blob, mappings, deps, outer_global["got_load_site"])
    if (
        outer_got_load.id != deps["ldr"]
        or outer_got_load.operands[0].reg != deps["r3"]
        or outer_got_load.operands[1].mem.base != deps["r5"]
        or outer_got_load.operands[1].mem.index != deps["r3"]
    ):
        raise RuntimeError("outer EventManager global GOT load differs")
    _require_unindexed_memory(
        _instruction(blob, mappings, deps, outer_global["store_site"]),
        deps, deps["str"], deps["r6"], deps["r3"], 0, "outer EventManager global store",
    )
    outer_relocation_contract = outer_global["relocation"]
    outer_relocation = rel_dyn[outer_relocation_contract["index"]]
    if (
        outer_relocation["r_offset"] != outer_cell
        or outer_relocation["r_info_type"] != outer_relocation_contract["type"]
        or outer_relocation["r_info_sym"] != outer_relocation_contract["symbol_index"]
        or dynsym.get_symbol(outer_relocation["r_info_sym"]).name
        != outer_relocation_contract["symbol"]
    ):
        raise RuntimeError("outer EventManager global relocation differs")

    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["consumer_outer_capture_site"]),
        deps, deps["mov"], deps["r4"], deps["r0"], "consumer outer capture",
    )
    consumer_pop = expected["consumer_pop"]
    _require_mov_immediate(
        _instruction(blob, mappings, deps, consumer_pop["queue_index_site"]),
        deps, deps["r1"], consumer_pop["queue_index"], "consumer queue-zero index",
    )
    _require_unindexed_memory(
        _instruction(blob, mappings, deps, consumer_pop["receiver_load_site"]),
        deps, deps["ldr"], deps["r0"], deps["r4"], outer_store["offset"],
        "consumer EventManager receiver load",
    )
    _require_direct_edge(
        blob, mappings, deps,
        consumer_pop["call"]["site"], consumer_pop["call"]["target"],
        call=True, label="consumer queue-zero pop",
    )
    consumer_dispatch = expected["consumer_dispatch"]
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, consumer_dispatch["event_argument_site"]),
        deps, deps["mov"], deps["r1"], deps["r0"],
        "consumer central-dispatch Event argument",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, consumer_dispatch["receiver_site"]),
        deps, deps["mov"], deps["r0"], deps["r4"],
        "consumer central-dispatch receiver",
    )
    _require_direct_edge(
        blob, mappings, deps,
        consumer_dispatch["call"]["site"], consumer_dispatch["call"]["target"],
        call=True, label="consumer central Event dispatch",
    )
    required_consumer_segment = [
        consumer_dispatch["receiver_site"], consumer_dispatch["call"]["site"],
    ]
    if (
        consumer_dispatch["event_argument_site"] != consumer_pop["call"]["site"] + 4
        or consumer_dispatch["call"]["target"]
        != EXPECTED_EXPORT["model_manager_request_event_candidate"]["central_dispatch_owner"]["start"]
        or consumer_dispatch["event_preservation_segment"] != required_consumer_segment
    ):
        raise RuntimeError("consumer central-dispatch join differs")
    _require_register_unchanged(
        _decode(
            blob, mappings, deps,
            required_consumer_segment[0], required_consumer_segment[1], complete=False,
        ),
        deps["r1"], label="consumer central-dispatch Event preservation",
    )
    if (
        expected["producer_receiver_steps"] != [
            "utility_manager=load(app_config+0x10)",
            "wrapper=load(utility_manager+0x0c)",
            "producer_event_manager=load(wrapper+0x10)",
        ]
        or expected["consumer_receiver_steps"] != [
            "outer=thread_stack_frame+4",
            "consumer_event_manager=load(outer+0x10)",
        ]
        or expected["producer_receiver_expression_proven"] is not True
        or expected["consumer_receiver_expression_proven"] is not True
        or expected["utility_manager_outer_backref_proven"] is not False
        or expected["same_event_manager_instance_proven"] is not False
        or expected["operation_38_queue_to_consumer_identity_proven"] is not False
    ):
        raise RuntimeError("queue consumer identity claim boundary differs")
    return copy.deepcopy(expected)


def _validate_model_manager_request_event_candidate(blob, mappings, deps, plt_symbols, exidx):
    expected = EXPECTED_EXPORT["model_manager_request_event_candidate"]
    for key, label in (
        ("central_dispatch_owner", "central Event dispatcher"),
        ("model_manager_constructor_owner", "ModelManager constructor"),
        ("model_manager_dispatch_owner", "ModelManager Event dispatcher"),
        ("model_record_lookup_owner", "ModelManager model-record lookup"),
        ("model_executor_helper_owner", "model-record executor helper"),
        ("executor_dispatch_owner", "model executor dispatch"),
    ):
        _require_owner(exidx, expected[key], label)
    if (
        expected["event_id"] != EXPECTED_EXPORT["operation_38_event_header"]["event_id"]
        or expected["destination"] != EXPECTED_EXPORT["operation_38_event_header"]["destination"]
    ):
        raise RuntimeError("ModelManager candidate Event header join differs")

    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["event_argument_capture_site"]),
        deps, deps["mov"], deps["r5"], deps["r1"], "central Event argument capture",
    )
    if _call_symbol(
        blob, mappings, deps, plt_symbols, expected["get_destination_call_site"],
    ) != expected["get_destination_symbol"]:
        raise RuntimeError("Event destination call differs")
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["destination_result_capture_site"]),
        deps, deps["mov"], deps["r6"], deps["r0"], "Event destination result capture",
    )
    destination_mask = _instruction(
        blob, mappings, deps, expected["destination_two_mask_site"],
    )
    if (
        destination_mask.id != deps["and"]
        or len(destination_mask.operands) != 3
        or destination_mask.operands[0].reg != deps["r3"]
        or destination_mask.operands[1].reg != deps["r6"]
        or destination_mask.operands[2].type != deps["imm"]
        or destination_mask.operands[2].imm != expected["destination"]
    ):
        raise RuntimeError("destination-two mask differs")
    destination_skip = _instruction(
        blob, mappings, deps, expected["destination_two_skip"]["site"],
    )
    if (
        destination_skip.id != deps["cbz"]
        or len(destination_skip.operands) != 2
        or destination_skip.operands[0].reg != deps["r3"]
        or destination_skip.operands[1].imm != expected["destination_two_skip"]["target"]
    ):
        raise RuntimeError("destination-two skip differs")
    model_receiver = expected["model_manager_receiver_load"]
    _require_unindexed_memory(
        _instruction(blob, mappings, deps, model_receiver["site"]),
        deps, deps["ldr"], deps["r0"], deps["r4"], model_receiver["offset"],
        "ModelManager receiver load",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["event_argument_forward_site"]),
        deps, deps["mov"], deps["r1"], deps["r5"], "ModelManager Event argument",
    )
    central_segment = expected["central_event_preservation_segment"]
    if central_segment != [
        expected["event_argument_capture_site"] + 2, expected["event_argument_forward_site"],
    ]:
        raise RuntimeError("central Event preservation segment differs")
    _require_register_unchanged(
        _decode(blob, mappings, deps, central_segment[0], central_segment[1], complete=False),
        deps["r5"], label="central Event preservation",
    )
    _require_direct_edge(
        blob, mappings, deps,
        expected["destination_two_call"]["site"], expected["destination_two_call"]["target"],
        call=True, label="destination-two ModelManager call",
    )
    _require_direct_edge(
        blob, mappings, deps,
        expected["model_manager_constructor_call"]["site"],
        expected["model_manager_constructor_call"]["target"],
        call=True, label="ModelManager constructor call",
    )
    model_store = expected["model_manager_outer_store"]
    _require_unindexed_memory(
        _instruction(blob, mappings, deps, model_store["site"]),
        deps, deps["str"], deps["r5"], deps["r4"], model_store["offset"],
        "ModelManager outer store",
    )
    event_manager_store = expected["event_manager_field_store"]
    _require_unindexed_memory(
        _instruction(blob, mappings, deps, event_manager_store["site"]),
        deps, deps["str"], deps["r10"], deps["r4"], event_manager_store["offset"],
        "ModelManager EventManager field store",
    )

    if _call_symbol(
        blob, mappings, deps, plt_symbols, expected["get_id_call_site"],
    ) != expected["get_id_symbol"]:
        raise RuntimeError("Event ID call differs")
    model_id_flow = expected["model_id_value_flow"]
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, model_id_flow["event_capture_site"]),
        deps, deps["mov"], deps["r5"], deps["r1"], "ModelManager Event capture",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["event_id_capture_site"]),
        deps, deps["mov"], deps["r6"], deps["r0"], "Event ID result capture",
    )
    gate_literal = _instruction(
        blob, mappings, deps, expected["request_gate_literal_load_site"],
    )
    if (
        _thumb_literal_address(gate_literal, deps, deps["r3"], "request Event-ID literal")
        != expected["request_gate_literal_address"]
        or _word(blob, mappings, expected["request_gate_literal_address"])
        != expected["request_gate_literal_value"]
    ):
        raise RuntimeError("request Event-ID literal differs")
    _require_compare_registers(
        _instruction(blob, mappings, deps, expected["request_gate_initial_compare_site"]),
        deps, deps["r6"], deps["r3"], "request Event-ID initial comparison",
    )
    _require_direct_edge(
        blob, mappings, deps,
        expected["request_gate_higher_branch"]["site"],
        expected["request_gate_higher_branch"]["target"],
        call=False, label="request Event-ID higher branch",
    )
    if _instruction(
        blob, mappings, deps, expected["request_gate_higher_branch"]["site"],
    ).cc != deps["hi"]:
        raise RuntimeError("request Event-ID higher branch condition differs")
    subtract = _instruction(blob, mappings, deps, expected["request_gate_subtract_site"])
    if (
        subtract.id != deps["sub"]
        or len(subtract.operands) != 2
        or subtract.operands[0].reg != deps["r3"]
        or subtract.operands[1].imm != expected["request_gate_subtract_value"]
    ):
        raise RuntimeError("request Event-ID subtract differs")
    _require_compare_registers(
        _instruction(blob, mappings, deps, expected["request_gate_lower_compare_site"]),
        deps, deps["r6"], deps["r3"], "request Event-ID lower comparison",
    )
    _require_direct_edge(
        blob, mappings, deps,
        expected["request_gate_lower_equal_branch"]["site"],
        expected["request_gate_lower_equal_branch"]["target"],
        call=False, label="request Event-ID lower-equal branch",
    )
    if _instruction(
        blob, mappings, deps, expected["request_gate_lower_equal_branch"]["site"],
    ).cc != deps["eq"]:
        raise RuntimeError("request Event-ID lower-equal branch condition differs")
    add = _instruction(blob, mappings, deps, expected["request_gate_add_site"])
    if (
        add.id != deps["add"]
        or len(add.operands) != 2
        or add.operands[0].reg != deps["r3"]
        or add.operands[1].imm != expected["request_gate_add_value"]
    ):
        raise RuntimeError("request Event-ID add differs")
    _require_compare_registers(
        _instruction(blob, mappings, deps, expected["request_gate_event_compare_site"]),
        deps, deps["r6"], deps["r3"], "request Event-ID exact comparison",
    )
    _require_direct_edge(
        blob, mappings, deps,
        expected["request_gate_mismatch_branch"]["site"],
        expected["request_gate_mismatch_branch"]["target"],
        call=False, label="request Event-ID mismatch branch",
    )
    if _instruction(
        blob, mappings, deps, expected["request_gate_mismatch_branch"]["site"],
    ).cc != deps["ne"]:
        raise RuntimeError("request Event-ID mismatch branch condition differs")
    _require_direct_edge(
        blob, mappings, deps,
        expected["request_event_branch"]["site"], expected["request_event_branch"]["target"],
        call=False, label="request Event-ID branch",
    )
    derived_lower = expected["request_gate_literal_value"] - expected["request_gate_subtract_value"]
    if (
        expected["event_id"] >= expected["request_gate_literal_value"]
        or expected["event_id"] == derived_lower
        or expected["event_id"] != derived_lower + expected["request_gate_add_value"]
    ):
        raise RuntimeError("request Event-ID gate arithmetic differs")

    parameter_labels = {
        "request_context": "request-context",
        "model_id": "model-ID",
        "mapped_operation": "mapped-operation",
    }
    for role, record in expected["parameter_keys"].items():
        parameter_label = parameter_labels[role]
        _require_mov_immediate(
            _instruction(blob, mappings, deps, record["site"]),
            deps, deps["r1"], record["key"], parameter_label + " parameter key",
        )
        _require_direct_edge(
            blob, mappings, deps, expected["parameter_get_calls"][role],
            expected["parameter_get_helper"], call=True,
            label=parameter_label + " parameter get",
        )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, model_id_flow["parameter_receiver_site"]),
        deps, deps["mov"], deps["r0"], deps["r5"], "model-ID parameter receiver",
    )
    event_segment = model_id_flow["event_preservation_segment"]
    if event_segment != [
        model_id_flow["event_capture_site"] + 2, model_id_flow["parameter_receiver_site"],
    ]:
        raise RuntimeError("ModelManager Event preservation segment differs")
    _require_register_unchanged(
        _decode(blob, mappings, deps, event_segment[0], event_segment[1], complete=False),
        deps["r5"], label="ModelManager Event preservation",
    )
    missing_model_id = _instruction(
        blob, mappings, deps, model_id_flow["missing_branch"]["site"],
    )
    if (
        missing_model_id.id != deps["cbz"]
        or len(missing_model_id.operands) != 2
        or missing_model_id.operands[0].type != deps["reg"]
        or missing_model_id.operands[0].reg != deps["r0"]
        or missing_model_id.operands[1].type != deps["imm"]
        or missing_model_id.operands[1].imm != model_id_flow["missing_branch"]["target"]
    ):
        raise RuntimeError("model-ID missing branch differs")
    for site, label in (
        (expected["model_id_scalar_call_site"], "model-ID scalar value"),
        (expected["mapped_operation_scalar_call_site"], "mapped-operation scalar value"),
    ):
        _require_direct_edge(
            blob, mappings, deps, site, expected["scalar_value_target"],
            call=True, label=label,
        )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, model_id_flow["scalar_result_capture_site"]),
        deps, deps["mov"], deps["r6"], deps["r0"], "model-ID scalar result capture",
    )
    _require_direct_edge(
        blob, mappings, deps,
        model_id_flow["scalar_join_branch"]["site"],
        model_id_flow["scalar_join_branch"]["target"],
        call=False, label="model-ID scalar join branch",
    )
    model_id_sentinel = _instruction(blob, mappings, deps, model_id_flow["missing_sentinel_site"])
    _require_mov_immediate(
        model_id_sentinel,
        deps, deps["r6"], model_id_flow["missing_sentinel"], "model-ID missing sentinel",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, model_id_flow["lookup_argument_site"]),
        deps, deps["mov"], deps["r1"], deps["r6"], "model-ID lookup argument",
    )
    required_model_id_segment = [
        model_id_flow["scalar_join_branch"]["target"], model_id_flow["lookup_argument_site"],
    ]
    if (
        model_id_flow["preservation_segment"] != required_model_id_segment
        or model_id_sentinel.address + model_id_sentinel.size != required_model_id_segment[0]
    ):
        raise RuntimeError("model-ID joined preservation segment differs")
    _require_register_unchanged(
        _decode(
            blob, mappings, deps,
            required_model_id_segment[0], required_model_id_segment[1], complete=False,
        ),
        deps["r6"], label="model-ID joined value preservation",
    )
    mapped_flow = expected["mapped_operation_value_flow"]
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, mapped_flow["parameter_receiver_site"]),
        deps, deps["mov"], deps["r0"], deps["r5"],
        "mapped-operation parameter receiver",
    )
    mapped_event_segment = mapped_flow["event_preservation_segment"]
    if mapped_event_segment != [
        model_id_flow["event_capture_site"] + 2, mapped_flow["parameter_receiver_site"],
    ]:
        raise RuntimeError("mapped-operation Event preservation segment differs")
    _require_register_unchanged(
        _decode(
            blob, mappings, deps,
            mapped_event_segment[0], mapped_event_segment[1], complete=False,
        ),
        deps["r5"], label="ModelManager Event preservation to mapped operation",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, mapped_flow["pointer_or_null_capture_site"]),
        deps, deps["mov"], deps["r9"], deps["r0"],
        "mapped-operation getter result capture",
    )
    _require_direct_edge(
        blob, mappings, deps,
        mapped_flow["missing_branch"]["site"], mapped_flow["missing_branch"]["target"],
        call=False, label="mapped-operation missing branch",
    )
    mapped_missing = _instruction(blob, mappings, deps, mapped_flow["missing_branch"]["site"])
    if (
        mapped_missing.id != deps["cbz"]
        or len(mapped_missing.operands) != 2
        or mapped_missing.operands[0].type != deps["reg"]
        or mapped_missing.operands[0].reg != deps["r0"]
        or mapped_missing.operands[1].type != deps["imm"]
        or mapped_missing.operands[1].imm != mapped_flow["missing_branch"]["target"]
    ):
        raise RuntimeError("mapped-operation missing branch differs")
    if (
        mapped_flow["pointer_or_null_capture_site"] + 2 != mapped_flow["missing_branch"]["site"]
        or mapped_flow["missing_branch"]["site"] + 2
        != expected["mapped_operation_scalar_call_site"]
    ):
        raise RuntimeError("mapped-operation getter-to-scalar path differs")
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, mapped_flow["scalar_result_capture_site"]),
        deps, deps["mov"], deps["r9"], deps["r0"],
        "mapped-operation scalar result capture",
    )
    required_mapped_segment = [
        mapped_flow["missing_branch"]["target"], mapped_flow["secondary_event_id_site"],
    ]
    if (
        mapped_flow["scalar_result_capture_site"] + 2 != required_mapped_segment[0]
        or mapped_flow["joined_preservation_segment"] != required_mapped_segment
        or mapped_flow["secondary_event_id_site"] != expected["secondary_event_id_site"]
    ):
        raise RuntimeError("mapped-operation joined preservation segment differs")
    _require_register_unchanged(
        _decode(
            blob, mappings, deps,
            required_mapped_segment[0], required_mapped_segment[1], complete=False,
        ),
        deps["r9"], label="mapped-operation joined value preservation",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, mapped_flow["secondary_event_id_site"]),
        deps, deps["mov"], deps["r1"], deps["r9"],
        "secondary Event mapped-operation ID",
    )
    lookup = expected["model_record_lookup_call"]
    _require_direct_edge(
        blob, mappings, deps, lookup["site"], lookup["target"],
        call=True, label="model-record lookup call",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["model_record_result_capture_site"]),
        deps, deps["mov"], deps["r8"], deps["r0"], "model-record result capture",
    )
    record_validity = expected["model_record_validity"]
    _require_compare_immediate(
        _instruction(blob, mappings, deps, record_validity["compare_site"]),
        deps, deps["r0"], 0, "model-record validity comparison",
    )
    _require_direct_edge(
        blob, mappings, deps,
        record_validity["missing_branch"]["site"], record_validity["missing_branch"]["target"],
        call=False, label="missing model-record branch",
    )
    if _instruction(
        blob, mappings, deps, record_validity["missing_branch"]["site"],
    ).cc != deps["eq"]:
        raise RuntimeError("missing model-record branch condition differs")

    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["mapped_operation_scalar_result_capture_site"]),
        deps, deps["mov"], deps["r9"], deps["r0"], "mapped-operation scalar result",
    )
    _require_mov_immediate(
        _instruction(blob, mappings, deps, expected["secondary_event_destination_site"]),
        deps, deps["r2"], 0, "secondary Event destination",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["secondary_event_id_site"]),
        deps, deps["mov"], deps["r1"], deps["r9"], "secondary Event ID",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["secondary_event_queue_tag_site"]),
        deps, deps["mov"], deps["r3"], deps["r2"], "secondary Event queue tag",
    )
    executor_inputs = expected["model_executor_inputs"]
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, executor_inputs["secondary_event_capture_site"]),
        deps, deps["mov"], deps["r6"], deps["r0"], "secondary Event capture",
    )
    if _call_symbol(
        blob, mappings, deps, plt_symbols, expected["secondary_event_constructor_call_site"],
    ) != EXPECTED_EXPORT["operation_38_event_header"]["constructor_symbol"]:
        raise RuntimeError("secondary Event constructor differs")
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, executor_inputs["record_argument_site"]),
        deps, deps["mov"], deps["r0"], deps["r8"], "model-record executor argument",
    )
    if executor_inputs["record_argument_site"] != record_validity["executor_argument_site"]:
        raise RuntimeError("model-record executor argument join differs")
    record_segment = record_validity["record_preservation_segment"]
    if record_segment != [
        record_validity["compare_site"], executor_inputs["record_argument_site"],
    ]:
        raise RuntimeError("model-record preservation segment differs")
    _require_register_unchanged(
        _decode(blob, mappings, deps, record_segment[0], record_segment[1], complete=False),
        deps["r8"], label="model-record preservation",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, executor_inputs["event_argument_site"]),
        deps, deps["mov"], deps["r1"], deps["r6"], "model-executor Event argument",
    )
    secondary_segment = executor_inputs["secondary_event_preservation_segment"]
    if secondary_segment != [
        executor_inputs["secondary_event_capture_site"] + 2,
        executor_inputs["event_argument_site"],
    ]:
        raise RuntimeError("secondary Event preservation segment differs")
    _require_register_unchanged(
        _decode(blob, mappings, deps, secondary_segment[0], secondary_segment[1], complete=False),
        deps["r6"], label="secondary Event preservation",
    )
    _require_direct_edge(
        blob, mappings, deps,
        expected["model_executor_call"]["site"], expected["model_executor_call"]["target"],
        call=True, label="model-executor call",
    )
    executor_load = expected["record_executor_load"]
    _require_unindexed_memory(
        _instruction(blob, mappings, deps, executor_load["site"]),
        deps, deps["ldr"], deps["r0"], deps["r0"], executor_load["offset"],
        "model-record executor load",
    )
    executor_validity = expected["executor_validity"]
    executor_branch = _instruction(
        blob, mappings, deps, executor_validity["presence_branch"]["site"],
    )
    if (
        executor_branch.id != deps["cbz"]
        or len(executor_branch.operands) != 2
        or executor_branch.operands[0].type != deps["reg"]
        or executor_branch.operands[0].reg != deps["r0"]
        or executor_branch.operands[1].type != deps["imm"]
        or executor_branch.operands[1].imm != executor_validity["presence_branch"]["target"]
    ):
        raise RuntimeError("model-executor presence branch differs")
    _require_direct_edge(
        blob, mappings, deps,
        expected["executor_dispatch_call"]["site"], expected["executor_dispatch_call"]["target"],
        call=True, label="executor dispatch call",
    )
    _require_mov_immediate(
        _instruction(blob, mappings, deps, executor_validity["missing_sentinel_site"]),
        deps, deps["r0"], executor_validity["missing_sentinel"],
        "model-executor missing sentinel",
    )
    executor_event_segment = executor_validity["event_preservation_segment"]
    if executor_event_segment != [
        expected["model_executor_helper_owner"]["start"],
        expected["executor_dispatch_call"]["site"],
    ]:
        raise RuntimeError("executor Event preservation segment differs")
    _require_register_unchanged(
        _decode(
            blob, mappings, deps,
            executor_event_segment[0], executor_event_segment[1], complete=False,
        ),
        deps["r1"], label="executor Event preservation",
    )
    event_store = expected["executor_event_store"]
    _require_unindexed_memory(
        _instruction(blob, mappings, deps, event_store["site"]),
        deps, deps["str"], deps["r1"], deps["r0"], event_store["offset"],
        "executor Event store",
    )
    state_store = expected["executor_state_store"]
    _require_mov_immediate(
        _instruction(blob, mappings, deps, expected["executor_state_value_site"]),
        deps, deps["r3"], state_store["value"], "executor state value",
    )
    _require_unindexed_memory(
        _instruction(blob, mappings, deps, state_store["site"]),
        deps, deps["str"], deps["r3"], deps["r0"], state_store["offset"],
        "executor state store",
    )
    virtual_target = expected["executor_virtual_target_load"]
    _require_unindexed_memory(
        _instruction(blob, mappings, deps, virtual_target["site"]),
        deps, deps["ldr"], deps["r3"], deps["r3"], virtual_target["offset"],
        "executor virtual target load",
    )
    virtual_call = _instruction(blob, mappings, deps, expected["executor_virtual_call_site"])
    if (
        virtual_call.id != deps["blx"]
        or not virtual_call.group(deps["call_group"])
        or _direct_target(virtual_call, deps) is not None
        or len(virtual_call.operands) != 1
        or virtual_call.operands[0].type != deps["reg"]
        or virtual_call.operands[0].reg != deps["r3"]
        or expected["executor_virtual_slot"] != virtual_target["offset"]
    ):
        raise RuntimeError("executor virtual call differs")
    if (
        expected["model_manager_request_event_branch_found"] is not True
        or expected["operation_38_queue_join_proven"] is not False
        or expected["concrete_model_record_found"] is not False
        or expected["concrete_model_executor_handler_found"] is not False
        or EXPECTED_EXPORT["operation_38_queue_consumer_identity"][
            "operation_38_queue_to_consumer_identity_proven"
        ] is not False
    ):
        raise RuntimeError("ModelManager candidate claim boundary differs")
    return copy.deepcopy(expected)


def _validate_shared_request_to_event_queue_join(elf, blob, mappings, deps, dynsym, plt_symbols, exidx):
    expected = EXPECTED_EXPORT["shared_request_to_event_queue_join"]
    _require_owner(exidx, expected["continuation_owner"], "shared request continuation")
    _require_owner(exidx, expected["queue_helper_owner"], "shared request queue helper")
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["event_result_capture_site"]),
        deps, deps["mov"], deps["r5"], deps["r0"], "shared request Event result capture",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["parameter_receiver_site"]),
        deps, deps["mov"], deps["r0"], deps["r5"], "Event parameter receiver",
    )
    _require_mov_immediate(
        _instruction(blob, mappings, deps, expected["parameter_key_site"]),
        deps, deps["r1"], expected["parameter_key"], "Event parameter key",
    )
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["parameter_value_site"]),
        deps, deps["mov"], deps["r2"], deps["r6"], "Event parameter value",
    )
    if _call_symbol(blob, mappings, deps, plt_symbols, expected["parameter_add_call_site"]) != expected["parameter_add_symbol"]:
        raise RuntimeError("shared request Event parameter add differs")
    _require_reg_to_reg(
        _instruction(blob, mappings, deps, expected["event_argument_site"]),
        deps, deps["mov"], deps["r1"], deps["r5"], "Event queue argument",
    )
    literal = _instruction(blob, mappings, deps, expected["queue_manager_literal_load_site"])
    got_load = _instruction(blob, mappings, deps, expected["queue_manager_got_load_site"])
    instance = _instruction(blob, mappings, deps, expected["queue_manager_instance_load_site"])
    if (
        literal.id != deps["ldr"]
        or literal.operands[0].reg != deps["r3"]
        or literal.operands[1].mem.base != deps["pc"]
        or literal.operands[1].mem.index != 0
        or got_load.id != deps["ldr"]
        or got_load.operands[0].reg != deps["r3"]
        or got_load.operands[1].mem.base != deps["r4"]
        or got_load.operands[1].mem.index != deps["r3"]
        or instance.id != deps["ldr"]
        or instance.operands[0].reg != deps["r0"]
        or instance.operands[1].mem.base != deps["r3"]
        or instance.operands[1].mem.index != 0
        or instance.operands[1].mem.disp != 0
    ):
        raise RuntimeError("Event queue manager receiver path differs")
    _require_direct_edge(
        blob, mappings, deps,
        expected["continuation_tail_branch"]["site"], expected["continuation_tail_branch"]["target"],
        call=False, label="shared request continuation tail branch",
    )
    _require_register_unchanged(
        _decode(
            blob, mappings, deps,
            expected["event_result_capture_site"] + 2, expected["event_argument_site"], complete=False,
        ),
        deps["r5"], label="shared request Event preservation",
    )
    _require_register_unchanged(
        _decode(
            blob, mappings, deps,
            expected["event_argument_site"] + 2, expected["continuation_tail_branch"]["site"], complete=False,
        ),
        deps["r1"], label="Event queue argument preservation",
    )
    _require_mov_immediate(
        _instruction(blob, mappings, deps, expected["queue_boolean_true_site"]),
        deps, deps["r2"], 1, "Event queue boolean",
    )
    _require_unindexed_memory(
        _instruction(blob, mappings, deps, expected["queue_receiver_load_site"]),
        deps, deps["ldr"], deps["r0"], deps["r0"], expected["queue_receiver_offset"],
        "Event queue receiver refinement",
    )
    _require_register_unchanged(
        _decode(
            blob, mappings, deps,
            expected["queue_helper_owner"]["start"], expected["queue_helper_tail_branch"]["site"], complete=False,
        ),
        deps["r1"], label="queue helper Event preservation",
    )
    _require_register_unchanged(
        _decode(
            blob, mappings, deps,
            expected["queue_boolean_true_site"] + 2, expected["queue_helper_tail_branch"]["site"], complete=False,
        ),
        deps["r2"], label="queue helper boolean preservation",
    )
    _require_direct_edge(
        blob, mappings, deps,
        expected["queue_helper_tail_branch"]["site"], expected["queue_helper_tail_branch"]["target"],
        call=False, label="queue helper PLT tail branch",
    )
    gate = _instruction(blob, mappings, deps, expected["thumb_to_arm_gate"])
    if (
        gate.id != deps["bx"]
        or len(gate.operands) != 1
        or gate.operands[0].type != deps["reg"]
        or gate.operands[0].reg != deps["pc"]
        or expected["thumb_to_arm_gate"] + 4 != expected["arm_plt_veneer"]
    ):
        raise RuntimeError("EventManager push interworking gate differs")
    decoded_plt = _decoded_plt_addresses_exact(elf, blob, mappings)
    if decoded_plt.get(expected["got_cell"]) != expected["arm_plt_veneer"]:
        raise RuntimeError("EventManager push PLT veneer differs")
    relocation_contract = expected["relocation"]
    relplt = elf.get_section_by_name(relocation_contract["section"])
    relocations = list(relplt.iter_relocations()) if relplt is not None else []
    if relocation_contract["index"] >= len(relocations):
        raise RuntimeError("EventManager push relocation index differs")
    relocation = relocations[relocation_contract["index"]]
    if (
        relocation["r_offset"] != expected["got_cell"]
        or relocation["r_info_type"] != relocation_contract["type"]
        or relocation["r_info_sym"] != relocation_contract["symbol_index"]
        or dynsym.get_symbol(relocation["r_info_sym"]).name != expected["push_symbol"]
    ):
        raise RuntimeError("EventManager push relocation contract differs")
    return copy.deepcopy(expected)


def _validate_event_queue(blob, mappings, deps, dynsym, exidx):
    expected = EXPECTED_EXPORT["event_queue_boundary"]
    _require_defined_symbol(
        dynsym,
        expected["push_symbol"],
        expected["push_owner"]["start"],
        expected["push_owner"]["end"],
        "EventManager queue boundary",
    )
    _require_owner(exidx, expected["push_owner"], "EventManager queue boundary")
    indirect = []
    for item in _decode(blob, mappings, deps, expected["push_owner"]["start"], expected["push_owner"]["end"]):
        if item.group(deps["call_group"]) and _direct_target(item, deps) is None:
            indirect.append(item)
    if [item.address for item in indirect] != expected["indirect_call_sites"]:
        raise RuntimeError("EventManager indirect call inventory differs")
    for item in indirect:
        if len(item.operands) != 1 or item.operands[0].type != deps["reg"]:
            raise RuntimeError("EventManager indirect call shape differs")
    if len(indirect) != expected["indirect_call_count"]:
        raise RuntimeError("EventManager indirect call count differs")
    return copy.deepcopy(expected)


class ElfAdapter:
    def metadata(self):
        if not sources_available():
            raise RuntimeError("pinned Creative Style request-transport sources are unavailable")
        before = {role: _require_source_identity(role, path) for role, path in SOURCE_PATHS.items()}
        deps = _dependencies()
        contexts = {}
        for role, path in SOURCE_PATHS.items():
            blob = path.read_bytes()
            handle = path.open("rb")
            try:
                elf = deps["ELFFile"](handle)
                contexts[role] = {
                    "handle": handle,
                    "blob": blob,
                    "elf": elf,
                    "mappings": _mappings(elf),
                    "dynsym": elf.get_section_by_name(".dynsym"),
                    "plt_symbols": _plt_symbols(elf, blob, _mappings(elf)),
                    "exidx": _exidx_ranges(elf, blob),
                }
            except Exception:
                handle.close()
                raise
        try:
            view = contexts["view"]
            obj = contexts["object"]
            typed_request = _validate_typed_request(
                view["blob"], view["mappings"], deps, view["plt_symbols"], view["exidx"]
            )
            view_transport = _validate_view_transport(
                view["blob"], view["mappings"], deps, view["dynsym"], view["plt_symbols"], view["exidx"]
            )
            candidate = _validate_candidate_boundary(
                view["blob"], view["mappings"], deps, view["plt_symbols"]
            )
            operation_38_path = _validate_operation_38_dispatch_path(
                view["blob"], view["mappings"], deps, view["plt_symbols"], view["exidx"]
            )
            operation_38_model_alias = _validate_operation_38_model_alias(view, obj, deps)
            shared = _validate_shared_transport(
                obj["blob"], obj["mappings"], deps, obj["dynsym"], obj["plt_symbols"], obj["exidx"]
            )
            operation_38_event_mapping = _validate_operation_38_event_mapping(
                obj["elf"], obj["blob"], obj["mappings"], deps, obj["plt_symbols"], obj["exidx"]
            )
            operation_38_event_header = _validate_operation_38_event_header(
                obj["blob"], obj["mappings"], deps, obj["plt_symbols"], obj["exidx"]
            )
            shared_queue_join = _validate_shared_request_to_event_queue_join(
                obj["elf"], obj["blob"], obj["mappings"], deps, obj["dynsym"],
                obj["plt_symbols"], obj["exidx"],
            )
            queue = _validate_event_queue(
                obj["blob"], obj["mappings"], deps, obj["dynsym"], obj["exidx"]
            )
            operation_38_queue_dispatch = _validate_operation_38_queue_dispatch(
                obj["blob"], obj["mappings"], deps, obj["exidx"]
            )
            operation_38_queue_consumer_identity = _validate_operation_38_queue_consumer_identity(
                obj["elf"], obj["blob"], obj["mappings"], deps, obj["dynsym"], obj["exidx"]
            )
            model_manager_request_event_candidate = _validate_model_manager_request_event_candidate(
                obj["blob"], obj["mappings"], deps, obj["plt_symbols"], obj["exidx"]
            )
        finally:
            for context in contexts.values():
                context["handle"].close()
        for role, path in SOURCE_PATHS.items():
            if _sha256(path) != before[role]:
                raise RuntimeError("pinned " + role + " source changed during export")
        document = copy.deepcopy(EXPECTED_EXPORT)
        document.update({
            "typed_request": typed_request,
            "view_wrapper_transport": view_transport,
            "candidate_cross_module_boundary": candidate,
            "operation_38_dispatch_path": operation_38_path,
            "operation_38_model_alias": operation_38_model_alias,
            "shared_libobj_transport": shared,
            "operation_38_event_mapping": operation_38_event_mapping,
            "operation_38_event_header": operation_38_event_header,
            "shared_request_to_event_queue_join": shared_queue_join,
            "event_queue_boundary": queue,
            "operation_38_queue_dispatch": operation_38_queue_dispatch,
            "operation_38_queue_consumer_identity": operation_38_queue_consumer_identity,
            "model_manager_request_event_candidate": model_manager_request_event_candidate,
        })
        return document


def build_raw_export(adapter=None):
    document = (adapter or ElfAdapter()).metadata()
    return normalize_creative_style_model_request_transport_export(document)


def write_export(document, output_root=OUTPUT_ROOT):
    normalized = normalize_creative_style_model_request_transport_export(document)
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
    print("CREATIVE_STYLE_MODEL_REQUEST_TRANSPORT_EXPORT|typed=1|candidate=1|handler=0|sink=0|installable=0")
    print(output)


if __name__ == "__main__":
    main()
