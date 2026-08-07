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
    _require_memory,
    _require_reg_to_reg,
    _validate_request as _validate_selector_request,
)
from tools.static.export_a6400_creative_style_model_cursor_boundary import _decoded_plt_addresses_exact
from tools.static.export_a6400_creative_style_view_model_binding import (
    _call_symbol,
    _decode,
    _direct_target,
    _exidx_ranges,
    _instruction,
    _mappings,
    _owner,
    _plt_symbols,
    _require_mov_immediate,
    _require_register_unchanged,
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
        from capstone.arm import ARM_REG_R8, ARM_REG_R9, ARM_REG_SP
    except (ImportError, AttributeError) as exc:
        raise RuntimeError("local Capstone and pyelftools are required") from exc
    deps.update({"r8": ARM_REG_R8, "r9": ARM_REG_R9, "sp": ARM_REG_SP})
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
            shared = _validate_shared_transport(
                obj["blob"], obj["mappings"], deps, obj["dynsym"], obj["plt_symbols"], obj["exidx"]
            )
            operation_38_event_mapping = _validate_operation_38_event_mapping(
                obj["elf"], obj["blob"], obj["mappings"], deps, obj["plt_symbols"], obj["exidx"]
            )
            shared_queue_join = _validate_shared_request_to_event_queue_join(
                obj["elf"], obj["blob"], obj["mappings"], deps, obj["dynsym"],
                obj["plt_symbols"], obj["exidx"],
            )
            queue = _validate_event_queue(
                obj["blob"], obj["mappings"], deps, obj["dynsym"], obj["exidx"]
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
            "shared_libobj_transport": shared,
            "operation_38_event_mapping": operation_38_event_mapping,
            "shared_request_to_event_queue_join": shared_queue_join,
            "event_queue_boundary": queue,
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
