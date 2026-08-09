"""Read-only exporter for the α6400 Creative Style selected-node boundary."""

from __future__ import annotations

import copy
from collections import deque
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

from pmca.analysis.creative_style_selected_node_identity_boundary import (
    CANDIDATE_LIFECYCLE,
    CONSTRUCTOR_GRAPH,
    DEPENDENCIES,
    EXPECTED_EXPORT,
    PRODUCTACTION_DELIVERY,
    PRODUCT_ROOT_SELECTION,
    ROOT_INITIALIZATION,
    RUNTIME_SELECTION,
    SELECTED_ORDINAL_WRITERS,
    SELECTED_CHILD_MECHANISM,
    SOURCE,
    STATIC_PATH,
    SUPPORTING_SOURCE,
    build_creative_style_selected_node_identity_boundary_report,
    normalize_creative_style_selected_node_identity_boundary_export,
    validate_creative_style_selected_node_identity_boundary_report,
)
from pmca.analysis.creative_style_activation_caller_boundary import (
    validate_creative_style_activation_caller_boundary_report,
)
from pmca.analysis.creative_style_definition_registration import (
    validate_creative_style_definition_registration_report,
)
from pmca.analysis.creative_style_menu_list_construction import (
    validate_creative_style_menu_list_construction_report,
)
from tools.static.export_a6400_creative_style_activation_caller_boundary import (
    _context,
    _literal_address,
)
from tools.static.export_a6400_creative_style_view_model_binding import (
    _at,
    _call_symbol,
    _decode,
    _direct_target,
    _instruction,
    _owner,
    _word,
)


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
ACTIVATION_DEPENDENCY_PATH = ROOT / DEPENDENCIES[0]["report"]
DEFINITION_DEPENDENCY_PATH = ROOT / DEPENDENCIES[1]["report"]
MENU_LIST_DEPENDENCY_PATH = ROOT / DEPENDENCIES[2]["report"]
REPORT_PATH = (
    ROOT / "analysis" / "a6400-creative-style-selected-node-identity-boundary.json"
)


def _dependencies():
    try:
        from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
        from capstone.arm import (
            ARM_CC_AL,
            ARM_CC_HI,
            ARM_CC_INVALID,
            ARM_INS_ADD,
            ARM_INS_B,
            ARM_INS_BLX,
            ARM_INS_BX,
            ARM_INS_CMP,
            ARM_INS_LDR,
            ARM_INS_LDRB,
            ARM_INS_LSL,
            ARM_INS_MOV,
            ARM_INS_STR,
            ARM_INS_SUB,
            ARM_INS_TBB,
            ARM_INS_TBH,
            ARM_OP_IMM,
            ARM_OP_MEM,
            ARM_OP_REG,
            ARM_REG_PC,
            ARM_REG_R0,
            ARM_REG_R1,
            ARM_REG_R2,
            ARM_REG_R3,
            ARM_REG_R4,
            ARM_REG_R5,
            ARM_REG_R6,
            ARM_REG_R7,
            ARM_REG_R8,
            ARM_REG_R9,
        )
        from tools.static.export_a6400_creative_style_view_model_binding import (
            _dependencies as base_dependencies,
        )
    except (ImportError, AttributeError) as exc:
        raise RuntimeError("local Capstone and pyelftools are required") from exc
    result = base_dependencies()
    result.update(
        {
            "ret_group": CS_GRP_RET,
            "jump_group": CS_GRP_JUMP,
            "call_group": CS_GRP_CALL,
            "cc_al": ARM_CC_AL,
            "cc_hi": ARM_CC_HI,
            "cc_invalid": ARM_CC_INVALID,
            "b": ARM_INS_B,
            "blx": ARM_INS_BLX,
            "bx": ARM_INS_BX,
            "cmp": ARM_INS_CMP,
            "ldr": ARM_INS_LDR,
            "ldrb": ARM_INS_LDRB,
            "lsl": ARM_INS_LSL,
            "mov": ARM_INS_MOV,
            "str": ARM_INS_STR,
            "sub": ARM_INS_SUB,
            "tbb": ARM_INS_TBB,
            "tbh": ARM_INS_TBH,
            "imm": ARM_OP_IMM,
            "mem": ARM_OP_MEM,
            "reg": ARM_OP_REG,
            "pc": ARM_REG_PC,
            "r0": ARM_REG_R0,
            "r1": ARM_REG_R1,
            "r2": ARM_REG_R2,
            "r3": ARM_REG_R3,
            "r4": ARM_REG_R4,
            "r5": ARM_REG_R5,
            "r6": ARM_REG_R6,
            "r7": ARM_REG_R7,
            "r8": ARM_REG_R8,
            "r9": ARM_REG_R9,
        }
    )
    return result


def dependencies_available():
    try:
        _dependencies()
    except RuntimeError:
        return False
    return True


def sources_available():
    return all(
        path.is_file() and not path.is_symlink()
        for path in (
            SOURCE_PATH,
            CAUTION_SOURCE_PATH,
            ACTIVATION_DEPENDENCY_PATH,
            DEFINITION_DEPENDENCY_PATH,
            MENU_LIST_DEPENDENCY_PATH,
        )
    )


def _sha256_bytes(blob):
    return hashlib.sha256(blob).hexdigest()


def _literal_json(path, label):
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file():
        raise RuntimeError(label + " must be a literal regular file")
    try:
        return json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(label + " differs") from exc


def _validate_dependencies(paths):
    activation = validate_creative_style_activation_caller_boundary_report(
        _literal_json(paths[0], "activation dependency")
    )
    definition = validate_creative_style_definition_registration_report(
        _literal_json(paths[1], "definition dependency")
    )
    menu_list = validate_creative_style_menu_list_construction_report(
        _literal_json(paths[2], "menu-list dependency")
    )
    actual = (
        activation["evidence_digest"],
        definition["summary"]["artifact_sha256"],
        menu_list["summary"]["canonical_export_sha256"],
    )
    expected = tuple(item["digest"] for item in DEPENDENCIES)
    if actual != expected:
        raise RuntimeError("selected-node dependency digest differs")


def _require_owner(context, start, end, label):
    if _owner(context["exidx"], start) != (start, end):
        raise RuntimeError(label + " owner differs")


def _require_register(item, index, register, deps, label):
    if (
        len(item.operands) <= index
        or item.operands[index].type != deps["reg"]
        or item.operands[index].reg != register
    ):
        raise RuntimeError(label + " register differs")


def _require_immediate(item, index, value, deps, label):
    if (
        len(item.operands) <= index
        or item.operands[index].type != deps["imm"]
        or item.operands[index].imm != value
    ):
        raise RuntimeError(label + " immediate differs")


def _require_memory(item, index, base, displacement, deps, label, *, source=None):
    if (
        len(item.operands) <= index
        or item.operands[index].type != deps["mem"]
        or item.operands[index].mem.base != base
        or item.operands[index].mem.index != 0
        or item.operands[index].mem.disp != displacement
    ):
        raise RuntimeError(label + " memory operand differs")
    if source is not None:
        _require_register(item, 0, source, deps, label)


def _resolve_pc_value(context, deps, load_site, add_site, register, label):
    load = _instruction(
        context["blob"], context["mappings"], deps, load_site
    )
    add = _instruction(context["blob"], context["mappings"], deps, add_site)
    if load.id != deps["ldr"] or add.id != deps["add"]:
        raise RuntimeError(label + " instruction class differs")
    _require_register(load, 0, register, deps, label)
    _require_memory(load, 1, deps["pc"], load.operands[1].mem.disp, deps, label)
    _require_register(add, 0, register, deps, label)
    _require_register(add, 1, deps["pc"], deps, label)
    literal = _literal_address(load, deps)
    return (_word(context["blob"], context["mappings"], literal) + add.address + 4) & 0xFFFFFFFF


def _canonical(document):
    encoded = (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _resolve_return_root(context, deps, landing):
    item = _instruction(context["blob"], context["mappings"], deps, landing)
    if item.id == deps["mov"]:
        _require_register(item, 0, deps["r0"], deps, "selector return")
        _require_immediate(item, 1, 0, deps, "selector return")
        next_site = item.address + item.size
        root = 0
    elif item.id == deps["ldr"]:
        _require_register(item, 0, deps["r0"], deps, "selector return")
        _require_memory(
            item,
            1,
            deps["pc"],
            item.operands[1].mem.disp,
            deps,
            "selector return",
        )
        add = _instruction(
            context["blob"], context["mappings"], deps, item.address + item.size
        )
        if add.id != deps["add"]:
            raise RuntimeError("selector return add differs")
        _require_register(add, 0, deps["r0"], deps, "selector return")
        _require_register(add, 1, deps["pc"], deps, "selector return")
        root = (
            _word(
                context["blob"],
                context["mappings"],
                _literal_address(item, deps),
            )
            + add.address
            + 4
        ) & 0xFFFFFFFF
        next_site = add.address + add.size
    else:
        raise RuntimeError("selector return instruction differs")
    if next_site != 0x208824:
        branch = _instruction(
            context["blob"], context["mappings"], deps, next_site
        )
        if branch.id != deps["b"] or _direct_target(branch, deps) != 0x208824:
            raise RuntimeError("selector return join differs")
    return root


def _validate_product_root(context, deps):
    expected = PRODUCT_ROOT_SELECTION
    owner = expected["selector_owner"]
    _require_owner(context, owner["start"], owner["end"], "product-root selector")
    load = _instruction(context["blob"], context["mappings"], deps, 0x208654)
    if load.id != deps["ldr"]:
        raise RuntimeError("product-root backup ID load differs")
    _require_register(load, 0, deps["r0"], deps, "product-root backup ID")
    if _literal_address(load, deps) != expected["backup_record_id_literal_cell"]:
        raise RuntimeError("product-root backup ID literal cell differs")
    if _word(
        context["blob"], context["mappings"], expected["backup_record_id_literal_cell"]
    ) != expected["backup_record_id"]:
        raise RuntimeError("product-root backup ID differs")
    if (
        _call_symbol(
            context["blob"],
            context["mappings"],
            deps,
            context["plt_symbols"],
            expected["backup_read_call_site"],
        )
        != "_ZN13BackupManager9Bkup_ReadEiPv"
    ):
        raise RuntimeError("product-root BackupManager call differs")

    selector = _instruction(context["blob"], context["mappings"], deps, 0x20865E)
    subtract = _instruction(context["blob"], context["mappings"], deps, 0x208660)
    compare = _instruction(context["blob"], context["mappings"], deps, 0x208662)
    bound = _instruction(context["blob"], context["mappings"], deps, 0x208664)
    table = _instruction(
        context["blob"], context["mappings"], deps, expected["table_branch_site"]
    )
    if selector.id != deps["ldrb"]:
        raise RuntimeError("product-root selector load differs")
    _require_register(selector, 0, deps["r3"], deps, "product-root selector")
    _require_memory(selector, 1, deps["r7"], 7, deps, "product-root selector")
    if subtract.id != deps["sub"]:
        raise RuntimeError("product-root selector normalization differs")
    _require_register(subtract, 0, deps["r3"], deps, "product-root selector")
    _require_immediate(subtract, 1, 1, deps, "product-root selector")
    if compare.id != deps["cmp"]:
        raise RuntimeError("product-root selector bound differs")
    _require_register(compare, 0, deps["r3"], deps, "product-root selector")
    _require_immediate(compare, 1, 0x4A, deps, "product-root selector")
    if (
        bound.id != deps["b"]
        or bound.cc != deps["cc_hi"]
        or _direct_target(bound, deps) != 0x20881A
    ):
        raise RuntimeError("product-root default branch differs")
    if table.id != deps["tbh"]:
        raise RuntimeError("product-root table branch differs")
    memory = table.operands[0]
    if (
        memory.type != deps["mem"]
        or memory.mem.base != deps["pc"]
        or memory.mem.index != deps["r3"]
        or memory.shift.value != 1
    ):
        raise RuntimeError("product-root table branch operands differ")

    table_base = (table.address + 4) & ~3
    rows = []
    for index in range(expected["selector_value_count"]):
        offset = int.from_bytes(
            _at(
                context["blob"],
                context["mappings"],
                table_base + index * 2,
                2,
            ),
            "little",
        )
        landing = table_base + offset * 2
        rows.append(
            {
                "selector": index + 1,
                "landing": landing,
                "root": _resolve_return_root(context, deps, landing),
            }
        )
    unique_returns = sorted({row["root"] for row in rows})
    default_values = [
        row["selector"] for row in rows if row["root"] == expected["default_root"]
    ]
    null_values = [row["selector"] for row in rows if row["root"] == 0]
    if (
        len(unique_returns) != expected["unique_return_count"]
        or unique_returns != expected["unique_returns"]
        or _canonical(rows) != expected["selector_return_map_digest"]
        or default_values != expected["default_root_selector_values"]
        or null_values != expected["null_selector_values"]
        or _resolve_return_root(context, deps, 0x20881A) != expected["default_root"]
    ):
        raise RuntimeError("product-root selector table differs")

    slot_owner = expected["slot_54_owner"]
    _require_owner(context, slot_owner["start"], slot_owner["end"], "slot-54")
    capture = _instruction(context["blob"], context["mappings"], deps, 0x2108BC)
    if capture.id != deps["mov"]:
        raise RuntimeError("slot-54 receiver capture differs")
    _require_register(capture, 0, deps["r5"], deps, "slot-54 receiver")
    _require_register(capture, 1, deps["r0"], deps, "slot-54 receiver")
    call = _instruction(
        context["blob"], context["mappings"], deps, expected["slot_54_call_site"]
    )
    if not call.group(deps["call_group"]) or _direct_target(call, deps) != owner["start"]:
        raise RuntimeError("slot-54 product-root call differs")
    store = _instruction(
        context["blob"], context["mappings"], deps, expected["slot_54_store_site"]
    )
    if store.id != deps["str"]:
        raise RuntimeError("slot-54 product-root store differs")
    _require_register(store, 0, deps["r0"], deps, "slot-54 product-root store")
    _require_memory(
        store,
        1,
        deps["r5"],
        expected["product_root_field_offset"],
        deps,
        "slot-54 product-root store",
    )
    items = _decode(
        context["blob"],
        context["mappings"],
        deps,
        capture.address + capture.size,
        call.address,
        complete=True,
    )
    if any(deps["r5"] in item.regs_access()[1] for item in items):
        raise RuntimeError("slot-54 receiver preservation differs")
    return copy.deepcopy(expected)


def _reachable_thumb_cfg(context, deps, start=0x213B8C, end=0x228BA4):
    pending = deque([start])
    instructions = {}
    successors = {}
    calls = []
    while pending:
        site = pending.popleft()
        if site in instructions:
            continue
        if not start <= site < end:
            raise RuntimeError("constructor CFG successor leaves owner")
        item = _instruction(context["blob"], context["mappings"], deps, site)
        instructions[site] = item
        fallthrough = site + item.size
        if item.group(deps["ret_group"]) or item.id == deps["bx"]:
            next_sites = []
        elif item.group(deps["call_group"]):
            calls.append((site, _direct_target(item, deps)))
            next_sites = [fallthrough]
        elif item.group(deps["jump_group"]):
            target = _direct_target(item, deps)
            if item.id in (deps["tbb"], deps["tbh"]) or target is None:
                raise RuntimeError("constructor CFG has unresolved jump")
            if item.id == deps["b"] and item.cc in (
                deps["cc_al"],
                deps["cc_invalid"],
            ):
                next_sites = [target] if start <= target < end else []
            else:
                next_sites = [
                    value
                    for value in (target, fallthrough)
                    if start <= value < end
                ]
        else:
            next_sites = [fallthrough] if fallthrough < end else []
        successors[site] = tuple(next_sites)
        for value in next_sites:
            if value not in instructions:
                pending.append(value)
    return instructions, successors, calls


def _validate_constructor_graph(context, deps):
    expected = CONSTRUCTOR_GRAPH
    owner = expected["owner"]
    _require_owner(context, owner["start"], owner["end"], "constructor graph")
    instructions, _successors, calls = _reachable_thumb_cfg(
        context, deps, owner["start"], owner["end"]
    )
    constructor_calls = [site for site, target in calls if target == expected["generic_constructor_plt"]]
    if (
        len(instructions) != expected["reachable_instruction_count"]
        or len(constructor_calls) != expected["generic_constructor_call_count"]
    ):
        raise RuntimeError("constructor graph traversal count differs")
    pic_base = _resolve_pc_value(
        context, deps, 0x213B92, 0x213B9C, deps["r5"], "constructor PIC base"
    )
    if pic_base != 0x9446A0:
        raise RuntimeError("constructor PIC base differs")
    for row in expected["path_constructors"]:
        call_site = row["call_site"]
        if call_site not in instructions or call_site not in constructor_calls:
            raise RuntimeError("path constructor is not CFG-reachable")
        node = _resolve_pc_value(
            context,
            deps,
            call_site - 0x16,
            call_site - 0x08,
            deps["r8"],
            "path constructor node",
        )
        child_list = _resolve_pc_value(
            context,
            deps,
            call_site - 0x0C,
            call_site - 0x02,
            deps["r1"],
            "path constructor list",
        )
        prop_offset_load = _instruction(
            context["blob"], context["mappings"], deps, call_site - 0x12
        )
        count = _instruction(
            context["blob"], context["mappings"], deps, call_site - 0x0E
        )
        receiver = _instruction(
            context["blob"], context["mappings"], deps, call_site - 0x06
        )
        property_load = _instruction(
            context["blob"], context["mappings"], deps, call_site - 0x04
        )
        if prop_offset_load.id != deps["ldr"] or count.id != deps["mov"]:
            raise RuntimeError("path constructor argument class differs")
        _require_register(prop_offset_load, 0, deps["r3"], deps, "path property offset")
        _require_memory(
            prop_offset_load,
            1,
            deps["pc"],
            prop_offset_load.operands[1].mem.disp,
            deps,
            "path property offset",
        )
        _require_register(count, 0, deps["r2"], deps, "path child count")
        _require_immediate(count, 1, row["child_count"], deps, "path child count")
        if receiver.id != deps["mov"] or property_load.id != deps["ldr"]:
            raise RuntimeError("path constructor receiver/property load differs")
        _require_register(receiver, 0, deps["r0"], deps, "path constructor receiver")
        _require_register(receiver, 1, deps["r8"], deps, "path constructor receiver")
        _require_register(property_load, 0, deps["r3"], deps, "path properties")
        memory = property_load.operands[1]
        if (
            memory.type != deps["mem"]
            or memory.mem.base != deps["r5"]
            or memory.mem.index != deps["r3"]
            or memory.mem.disp != 0
        ):
            raise RuntimeError("path property GOT load differs")
        property_offset = _word(
            context["blob"],
            context["mappings"],
            _literal_address(prop_offset_load, deps),
        )
        properties = _word(
            context["blob"], context["mappings"], pic_base + property_offset
        )
        if (
            node != row["node"]
            or child_list != row["child_list"]
            or properties != row["properties"]
            or _call_symbol(
                context["blob"],
                context["mappings"],
                deps,
                context["plt_symbols"],
                call_site,
            )
            != expected["generic_constructor_symbol"]
        ):
            raise RuntimeError("path constructor arguments differ")
    return copy.deepcopy(expected)


def _validate_static_path(context):
    expected = STATIC_PATH
    constructors = CONSTRUCTOR_GRAPH["path_constructors"]
    dynsym = context["elf"].get_section_by_name(".dynsym")
    for row, constructor in zip(expected["edges"], constructors):
        if not (
            constructor["child_list"]
            <= row["cell"]
            < constructor["child_list"] + constructor["child_count"] * 4
        ) or row["cell"] != constructor["child_list"] + row["index"] * 4:
            raise RuntimeError("Creative Style path list boundary differs")
        try:
            actual_index, relocation = context["by_site"][row["cell"]]
        except KeyError as exc:
            raise RuntimeError("Creative Style path relocation is missing") from exc
        if (
            actual_index != row["relocation_index"]
            or relocation["r_info_type"] != row["relocation_type"]
            or relocation["r_info_sym"] != row["symbol_index"]
        ):
            raise RuntimeError("Creative Style path relocation differs")
        word = _word(context["blob"], context["mappings"], row["cell"])
        if row["relocation_type"] == 23:
            if word != row["target"]:
                raise RuntimeError("Creative Style path relocation target differs")
        else:
            symbol = dynsym.get_symbol(row["symbol_index"])
            if (
                word != 0
                or symbol.name != expected["final_symbol"]
                or symbol["st_shndx"] != "SHN_UNDEF"
            ):
                raise RuntimeError("Creative Style path symbol differs")
    return copy.deepcopy(expected)


def _require_vptr_call(context, deps, receiver_site, slot_site, call_site, receiver, label):
    vptr = _instruction(context["blob"], context["mappings"], deps, receiver_site)
    slot = _instruction(context["blob"], context["mappings"], deps, slot_site)
    call = _instruction(context["blob"], context["mappings"], deps, call_site)
    if vptr.id != deps["ldr"] or slot.id != deps["ldr"] or call.id != deps["blx"]:
        raise RuntimeError(label + " instruction class differs")
    _require_register(vptr, 0, deps["r3"], deps, label)
    _require_memory(vptr, 1, receiver, 0, deps, label)
    _require_register(slot, 0, deps["r3"], deps, label)
    _require_memory(slot, 1, deps["r3"], 0x28, deps, label)
    _require_register(call, 0, deps["r3"], deps, label)


def _validate_selected_child_mechanism(context, deps):
    expected = SELECTED_CHILD_MECHANISM
    owner = expected["owner"]
    _require_owner(context, owner["start"], owner["end"], "selected-child helper")
    root = _instruction(context["blob"], context["mappings"], deps, 0x207C52)
    if root.id != deps["ldr"]:
        raise RuntimeError("selected-child root load differs")
    _require_register(root, 0, deps["r0"], deps, "selected-child root")
    _require_memory(root, 1, deps["r0"], expected["root_field_offset"], deps, "selected-child root")
    stages = (
        (0x207C5E, 0x207C64, 0x207C66, deps["r0"], 0x207C68, 0xC),
        (0x207C6C, 0x207C72, 0x207C74, deps["r0"], 0x207C76, 0x8),
        (0x207C7A, 0x207C7E, 0x207C80, deps["r0"], None, None),
    )
    for index, (vptr, slot, call, receiver, reload_site, displacement) in enumerate(stages):
        _require_vptr_call(
            context, deps, vptr, slot, call, receiver, f"selected-child stage {index + 1}"
        )
        if reload_site is not None:
            reload = _instruction(
                context["blob"], context["mappings"], deps, reload_site
            )
            if reload.id != deps["ldr"]:
                raise RuntimeError("selected-child chained result differs")
            _require_register(reload, 0, deps["r0"], deps, "selected-child result")
            _require_memory(
                reload,
                1,
                deps["r7"],
                displacement,
                deps,
                "selected-child result",
            )
    final = _instruction(context["blob"], context["mappings"], deps, 0x207C82)
    if final.id != deps["ldr"]:
        raise RuntimeError("selected-child final return differs")
    _require_register(final, 0, deps["r0"], deps, "selected-child final return")
    _require_memory(final, 1, deps["r7"], 4, deps, "selected-child final return")
    return copy.deepcopy(expected)


def _validate_symbol_relocation(context, expected, label):
    try:
        actual_index, relocation = context["by_site"][expected["cell"]]
        symbol = context["elf"].get_section_by_name(".dynsym").get_symbol(
            relocation["r_info_sym"]
        )
    except (AttributeError, KeyError, TypeError) as exc:
        raise RuntimeError(label + " relocation is missing") from exc
    symbol_range = expected.get("owner") or expected.get("symbol_range")
    if (
        actual_index != expected["relocation_index"]
        or relocation["r_info_type"] != expected.get("relocation_type", 2)
        or relocation["r_info_sym"] != expected.get(
            "symbol_index", relocation["r_info_sym"]
        )
        or symbol.name != expected["symbol"]
        or (symbol["st_value"] & ~1) != symbol_range["start"]
        or symbol["st_size"] != symbol_range["end"] - symbol_range["start"]
        or symbol["st_shndx"] == "SHN_UNDEF"
        or _word(context["blob"], context["mappings"], expected["cell"]) != 0
    ):
        raise RuntimeError(label + " relocation/symbol differs")


def _validate_runtime_selection(context, deps):
    expected = RUNTIME_SELECTION
    selected = expected["candidate_get_selected_item"]
    sub_node = expected["candidate_get_sub_node"]
    if selected["cell"] != selected["vtable_address_point"] + selected["slot"] * 4:
        raise RuntimeError("getSelectedItem slot relation differs")
    if sub_node["cell"] != sub_node["vtable_address_point"] + sub_node["slot"] * 4:
        raise RuntimeError("getSubNode slot relation differs")
    _validate_symbol_relocation(context, selected, "getSelectedItem")
    _validate_symbol_relocation(context, sub_node, "getSubNode")
    owner = selected["owner"]
    _require_owner(context, owner["start"], owner["end"], "getSelectedItem")

    checks = (
        (0x7C6BDC, deps["ldr"], deps["r3"], deps["r0"], 0),
        (0x7C6BE6, deps["ldr"], deps["r3"], deps["r3"], 0xF0),
        (0x7C6BEE, deps["ldr"], deps["r3"], deps["r4"], selected["selected_ordinal_offset"]),
        (0x7C6BF4, deps["ldr"], deps["r2"], deps["r7"], 4),
        (0x7C6BFE, deps["ldr"], deps["r2"], deps["r7"], 0),
    )
    for site, kind, target, base, displacement in checks:
        item = _instruction(context["blob"], context["mappings"], deps, site)
        if item.id != kind:
            raise RuntimeError("getSelectedItem memory class differs")
        _require_register(item, 0, target, deps, "getSelectedItem")
        _require_memory(item, 1, base, displacement, deps, "getSelectedItem")
    virtual_call = _instruction(context["blob"], context["mappings"], deps, 0x7C6BEA)
    if virtual_call.id != deps["blx"]:
        raise RuntimeError("getSelectedItem getSubNode call differs")
    _require_register(virtual_call, 0, deps["r3"], deps, "getSelectedItem")
    subtract = _instruction(context["blob"], context["mappings"], deps, 0x7C6C02)
    indexed = _instruction(context["blob"], context["mappings"], deps, 0x7C6C04)
    output = _instruction(context["blob"], context["mappings"], deps, 0x7C6C08)
    if subtract.id != deps["sub"] or indexed.id != deps["ldr"] or output.id != deps["str"]:
        raise RuntimeError("getSelectedItem ordinal/index flow differs")
    _require_register(subtract, 0, deps["r3"], deps, "getSelectedItem")
    _require_immediate(subtract, 1, 1, deps, "getSelectedItem")
    memory = indexed.operands[1]
    if (
        memory.type != deps["mem"]
        or memory.mem.base != deps["r2"]
        or memory.mem.index != deps["r3"]
        or memory.shift.value != 2
    ):
        raise RuntimeError("getSelectedItem indexed child load differs")
    _require_register(output, 0, deps["r3"], deps, "getSelectedItem output")
    _require_memory(output, 1, deps["r6"], 0, deps, "getSelectedItem output")

    sub_checks = (
        (0x7C72CC, deps["r3"], deps["r0"], sub_node["child_list_offset"]),
        (0x7C72D4, deps["r0"], deps["r0"], sub_node["child_count_offset"]),
        (0x7C72DA, deps["r3"], deps["r1"], 0),
        (0x7C72DC, deps["r0"], deps["r2"], 0),
    )
    for site, register, base, displacement in sub_checks:
        item = _instruction(context["blob"], context["mappings"], deps, site)
        expected_kind = deps["ldr"] if site in (0x7C72CC, 0x7C72D4) else deps["str"]
        if item.id != expected_kind:
            raise RuntimeError("getSubNode list/count flow differs")
        _require_register(item, 0, register, deps, "getSubNode")
        _require_memory(item, 1, base, displacement, deps, "getSubNode")
    return copy.deepcopy(expected)


def _require_text(context, deps, site, mnemonic, operands, label):
    item = _instruction(context["blob"], context["mappings"], deps, site)
    if item.mnemonic != mnemonic or item.op_str != operands:
        raise RuntimeError(label + " instruction/operands differ")
    return item


def _pic_address(context, deps, load_site, add_site, register, label):
    load = _instruction(context["blob"], context["mappings"], deps, load_site)
    add = _instruction(context["blob"], context["mappings"], deps, add_site)
    if load.id != deps["ldr"] or add.id != deps["add"]:
        raise RuntimeError(label + " PIC instruction differs")
    _require_register(load, 0, register, deps, label)
    _require_memory(load, 1, deps["pc"], load.operands[1].mem.disp, deps, label)
    _require_register(add, 0, register, deps, label)
    _require_register(add, 1, deps["pc"], deps, label)
    literal = _literal_address(load, deps)
    pc = add.address + 4
    return (_word(context["blob"], context["mappings"], literal) + pc) & 0xFFFFFFFF


def _validate_dynamic_binding(context, expected, label):
    try:
        actual_index, relocation = context["by_site"][expected["got"]]
        symbol = context["elf"].get_section_by_name(".dynsym").get_symbol(
            relocation["r_info_sym"]
        )
    except (AttributeError, KeyError, TypeError) as exc:
        raise RuntimeError(label + " binding is missing") from exc
    if (
        actual_index != expected["relocation_index"]
        or relocation["r_info_type"] != expected["relocation_type"]
        or relocation["r_info_sym"] != expected["symbol_index"]
        or symbol.name != expected["symbol"]
        or symbol["st_shndx"] != "SHN_UNDEF"
        or _word(context["blob"], context["mappings"], expected["got"]) != 0
    ):
        raise RuntimeError(label + " binding differs")


def _validate_root_initialization(context, deps):
    expected = ROOT_INITIALIZATION
    owner = expected["slot_54_owner"]
    _require_owner(context, owner["start"], owner["end"], "root initialization")
    helper = expected["list_helper_owner"]
    _require_owner(context, helper["start"], helper["end"], "root-list helper")

    for binding in expected["default_root_bindings"]:
        _validate_dynamic_binding(context, binding, binding["role"])

    root_sites = (
        (0x21098A, "mov", "sb, r0"),
        (0x21098C, "str.w", "r0, [r5, #0x1a0]"),
        (0x210992, "ldr", "r3, [r0]"),
        (0x210994, "ldr", "r4, [r3, #8]"),
        (0x210996, "bl", "#0x2084ec"),
        (0x21099A, "ldr", "r3, [pc, #0x94]"),
        (0x21099C, "ldr", "r3, [r6, r3]"),
        (0x21099E, "ldr", "r2, [r3]"),
        (0x2109A0, "mov", "r1, r0"),
        (0x2109A2, "mov", "r0, sb"),
        (0x2109A4, "blx", "r4"),
    )
    for site, mnemonic, operands in root_sites:
        _require_text(context, deps, site, mnemonic, operands, "root initialization")
    helper_call = _instruction(context["blob"], context["mappings"], deps, 0x210996)
    if _direct_target(helper_call, deps) != expected["list_helper_target"]:
        raise RuntimeError("root-list helper call differs")

    caller_pic = _pic_address(context, deps, 0x210928, 0x210942, deps["r6"], "root count")
    count_offset_load = _instruction(
        context["blob"], context["mappings"], deps, 0x21099A
    )
    count_got = (
        caller_pic
        + _word(
            context["blob"],
            context["mappings"],
            _literal_address(count_offset_load, deps),
        )
    ) & 0xFFFFFFFF
    if count_got != expected["default_root_bindings"][1]["got"]:
        raise RuntimeError("root count GOT flow differs")

    helper_sites = (
        (0x2084FE, "ldr", "r3, [pc, #0x3c]"),
        (0x208500, "ldr.w", "r8, [r4, r3]"),
        (0x208504, "ldr.w", "r0, [r8]"),
        (0x208508, "lsls", "r0, r0, #2"),
        (0x20850A, "blx", "#0x154480"),
        (0x20850E, "ldr.w", "r2, [r8]"),
        (0x208518, "ldr", "r1, [pc, #0x24]"),
        (0x20851C, "ldr", "r1, [r4, r1]"),
        (0x20851E, "ldr", "r1, [r6, r1]"),
        (0x208520, "str", "r1, [r0, r6]"),
        (0x208528, "ldr", "r0, [pc, #0x18]"),
        (0x20852A, "add", "r0, pc"),
        (0x20852C, "ldr", "r0, [r0]"),
    )
    for site, mnemonic, operands in helper_sites:
        _require_text(context, deps, site, mnemonic, operands, "root-list helper")
    if (
        _call_symbol(
            context["blob"],
            context["mappings"],
            deps,
            context["plt_symbols"],
            0x20850A,
        )
        != "_Znaj"
    ):
        raise RuntimeError("root-list allocation binding differs")

    helper_pic = _pic_address(context, deps, 0x2084F4, 0x2084F8, deps["r4"], "root list")
    count_load = _instruction(context["blob"], context["mappings"], deps, 0x2084FE)
    list_load = _instruction(context["blob"], context["mappings"], deps, 0x208518)
    if (
        helper_pic
        + _word(
            context["blob"],
            context["mappings"],
            _literal_address(count_load, deps),
        )
        != expected["default_root_bindings"][1]["got"]
        or helper_pic
        + _word(
            context["blob"],
            context["mappings"],
            _literal_address(list_load, deps),
        )
        != expected["default_root_bindings"][0]["got"]
    ):
        raise RuntimeError("root-list helper GOT flow differs")
    if _pic_address(context, deps, 0x2084F2, 0x2084F6, deps["r5"], "root cache") != _pic_address(
        context, deps, 0x208528, 0x20852A, deps["r0"], "root cache return"
    ):
        raise RuntimeError("root-list cache identity differs")
    return copy.deepcopy(expected)


def _validate_candidate_lifecycle(context, deps):
    expected = CANDIDATE_LIFECYCLE
    for label in ("init_setting_node", "recursive_init", "set_head_selected"):
        record = expected[label]
        _validate_symbol_relocation(context, record, label.replace("_", "-"))
        owner = record["owner"]
        _require_owner(context, owner["start"], owner["end"], label.replace("_", "-"))

    init_sites = (
        (0x7C6AF2, "ldr.w", "r3, [r3, #0xe8]"),
        (0x7C6AFC, "blx", "r3"),
        (0x7C6B08, "ldr.w", "r5, [r3, #0xf8]"),
        (0x7C6B0E, "blx", "r5"),
        (0x7C6B16, "ldr.w", "r3, [r3, #0xec]"),
        (0x7C6B1A, "blx", "r3"),
    )
    recursive_sites = (
        (0x7C73B8, "add.w", "r8, r8, #1"),
        (0x7C73BE, "str", "r4, [r2, #0x10]"),
        (0x7C73C4, "str.w", "r8, [r2, #0x20]"),
        (0x7C73C8, "str", "r3, [r0, #0x24]"),
        (0x7C73CA, "subs", "r3, #2"),
        (0x7C73CE, "str", "r3, [r0, #0x18]"),
        (0x7C73FA, "ldr.w", "r6, [r3, #0xf8]"),
        (0x7C7402, "blx", "r6"),
        (0x7C740C, "ldr.w", "r3, [r3, #0x94]"),
        (0x7C7410, "blx", "r3"),
        (0x7C741A, "ldr.w", "r3, [r3, #0xb8]"),
        (0x7C741E, "blx", "r3"),
        (0x7C7428, "ldr", "r3, [r4]"),
        (0x7C742A, "mov", "r0, r4"),
        (0x7C7430, "ldr", "r3, [r3, #0x28]"),
        (0x7C7432, "blx", "r3"),
        (0x7C7436, "ldr", "r3, [r4]"),
        (0x7C7438, "mov", "r0, r4"),
        (0x7C743A, "ldr.w", "r3, [r3, #0xfc]"),
        (0x7C743E, "blx", "r3"),
    )
    fallback_sites = (
        (0x7C7452, "movs", "r1, #1"),
        (0x7C745A, "ldr", "r3, [r3, #0x38]"),
        (0x7C745C, "blx", "r3"),
        (0x7C7464, "ldr.w", "r3, [r3, #0xb8]"),
        (0x7C7468, "blx", "r3"),
        (0x7C746C, "mov.w", "r3, #-1"),
        (0x7C7470, "str", "r3, [r4, #0x18]"),
    )
    for label, records in (
        ("init-setting-node", init_sites),
        ("recursive-init", recursive_sites),
        ("set-head-selected", fallback_sites),
    ):
        for site, mnemonic, operands in records:
            _require_text(context, deps, site, mnemonic, operands, label)
    return copy.deepcopy(expected)


def _validate_selected_ordinal_writers(context, deps):
    expected = SELECTED_ORDINAL_WRITERS
    owners = (
        (0x7C6BD2, 0x7C6C16),
        (0x7C705A, 0x7C70DA),
        (0x7C732C, 0x7C744C),
        (0x7C744C, 0x7C747A),
    )
    required = (
        (0x7C6BFA, "it", "ge"),
        (0x7C6BFC, "mov", "r3, r2"),
        (0x7C6C00, "str", "r3, [r4, #0x18]"),
        (0x7C70A4, "ldr", "r2, [r4, #0x20]"),
        (0x7C70A6, "ldr", "r3, [r7, #4]"),
        (0x7C70AA, "str", "r2, [r3, #0x18]"),
        (0x7C734E, "subs", "r3, #1"),
        (0x7C7358, "str", "r3, [r0, #0x18]"),
        (0x7C73CA, "subs", "r3, #2"),
        (0x7C73CE, "str", "r3, [r0, #0x18]"),
        (0x7C746C, "mov.w", "r3, #-1"),
        (0x7C7470, "str", "r3, [r4, #0x18]"),
    )
    try:
        decoder = deps["Cs"](deps["arch"], deps["mode"])
        decoder.detail = True
        sites = []
        for start, end in owners:
            _require_owner(context, start, end, "selected-ordinal writer")
            items = list(
                decoder.disasm(
                    _at(context["blob"], context["mappings"], start, end - start),
                    start,
                )
            )
            if (
                not items
                or items[0].address != start
                or items[-1].address + items[-1].size != end
            ):
                raise RuntimeError("selected-ordinal writer owner decode differs")
            for item in items:
                if (
                    item.id == deps["str"]
                    and len(item.operands) >= 2
                    and item.operands[1].type == deps["mem"]
                    and item.operands[1].mem.index == 0
                    and item.operands[1].mem.disp == expected["field_offset"]
                ):
                    sites.append(item.address & ~1)
        if sites != [record["site"] for record in expected["writers"]]:
            raise RuntimeError("selected-ordinal writer inventory differs")
        for site, mnemonic, operands in required:
            _require_text(
                context,
                deps,
                site,
                mnemonic,
                operands,
                "selected-ordinal writer",
            )
    except (KeyError, RuntimeError, ValueError) as exc:
        raise RuntimeError("selected-ordinal writer evidence differs") from exc
    return copy.deepcopy(expected)


def _written_registers(instruction):
    try:
        return set(instruction.regs_access()[1])
    except (AttributeError, ValueError):
        return set()


def _validate_productaction_interface(context, deps):
    expected = PRODUCTACTION_DELIVERY
    address_point = expected["viewsettingmenu_vtable_address_point"]
    slot_37 = expected["slot_37"]
    productaction = expected["productaction"]
    slot_64 = expected["slot_64"]
    if (
        slot_37["cell"] != address_point + 37 * 4
        or slot_64["cell"] != address_point + 64 * 4
    ):
        raise RuntimeError("ViewSettingMenu ProductAction slot relation differs")

    slot_37_record = dict(slot_37)
    slot_37_record["symbol_range"] = productaction["symbol_range"]
    _validate_symbol_relocation(context, slot_37_record, "ViewSettingMenu slot 37")
    owner = productaction["exidx_owner"]
    _require_owner(context, owner["start"], owner["end"], "ProductAction")
    symbol_range = productaction["symbol_range"]
    items = _decode(
        context["blob"],
        context["mappings"],
        deps,
        symbol_range["start"],
        symbol_range["end"],
    )
    if (
        len(items) != productaction["instruction_count"]
        or items[0].address != symbol_range["start"]
        or items[-1].address + items[-1].size != symbol_range["end"]
    ):
        raise RuntimeError("ProductAction instruction coverage differs")
    exact = (
        (0x2F1350, "ldr", "r3, [r0]"),
        (0x2F1352, "push", "{r7, lr}"),
        (0x2F1354, "add", "r7, sp, #0"),
        (0x2F1356, "ldr.w", "r3, [r3, #0x100]"),
        (0x2F135A, "blx", "r3"),
        (0x2F135C, "pop", "{r7, pc}"),
    )
    for site, mnemonic, operands in exact:
        _require_text(context, deps, site, mnemonic, operands, "ProductAction")
    if any(deps["r1"] in _written_registers(item) for item in items):
        raise RuntimeError("ProductAction selector register preservation differs")

    try:
        actual_index, relocation = context["by_site"][slot_64["cell"]]
    except (KeyError, TypeError) as exc:
        raise RuntimeError("ViewSettingMenu slot 64 relocation is missing") from exc
    if (
        actual_index != slot_64["relocation_index"]
        or relocation["r_info_type"] != slot_64["relocation_type"]
        or relocation["r_info_sym"] != 0
        or _word(context["blob"], context["mappings"], slot_64["cell"])
        != slot_64["target"] | 1
    ):
        raise RuntimeError("ViewSettingMenu slot 64 relocation differs")

    return {
        "viewsettingmenu_vtable_address_point": address_point,
        "slot_37": copy.deepcopy(slot_37),
        "productaction": copy.deepcopy(productaction),
        "slot_64": copy.deepcopy(slot_64),
    }


def _known_immediate_before(items, call_index, register, deps):
    for item in reversed(items[:call_index]):
        if item.group(deps["call_group"]):
            return None
        if register not in _written_registers(item):
            continue
        if (
            item.id == deps["mov"]
            and len(item.operands) == 2
            and item.operands[0].type == deps["reg"]
            and item.operands[0].reg == register
            and item.operands[1].type == deps["imm"]
        ):
            return item.operands[1].imm & 0xFFFFFFFF
        return None
    return None


def _canonical_slot_37_calls(context, deps):
    decoder = deps["Cs"](deps["arch"], deps["mode"])
    decoder.detail = True
    calls = []
    complete_count = 0
    incomplete_count = 0
    for start, end in context["exidx"]:
        items = list(
            decoder.disasm(
                _at(context["blob"], context["mappings"], start, end - start),
                start,
            )
        )
        complete = bool(
            items
            and items[0].address == start
            and items[-1].address + items[-1].size == end
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
            slot_index = None
            for candidate_index in range(call_index - 1, max(-1, call_index - 7), -1):
                candidate = items[candidate_index]
                if call_register not in _written_registers(candidate):
                    continue
                if (
                    candidate.id == deps["ldr"]
                    and len(candidate.operands) == 2
                    and candidate.operands[0].type == deps["reg"]
                    and candidate.operands[0].reg == call_register
                    and candidate.operands[1].type == deps["mem"]
                    and candidate.operands[1].mem.index == 0
                    and candidate.operands[1].mem.disp == 0x94
                ):
                    slot_index = candidate_index
                break
            if slot_index is None:
                continue
            vptr_register = items[slot_index].operands[1].mem.base
            vptr_index = None
            for candidate_index in range(slot_index - 1, max(-1, slot_index - 9), -1):
                candidate = items[candidate_index]
                if vptr_register not in _written_registers(candidate):
                    continue
                if (
                    candidate.id == deps["ldr"]
                    and len(candidate.operands) == 2
                    and candidate.operands[0].type == deps["reg"]
                    and candidate.operands[0].reg == vptr_register
                    and candidate.operands[1].type == deps["mem"]
                    and candidate.operands[1].mem.index == 0
                    and candidate.operands[1].mem.disp == 0
                ):
                    vptr_index = candidate_index
                break
            if vptr_index is None:
                continue
            receiver = items[vptr_index].operands[1].mem.base
            selector_10 = (
                _known_immediate_before(items, call_index, deps["r1"], deps) == 10
            )
            receiver_identity = False
            calls.append(
                {
                    "owner": {"start": start, "end": end, "complete": True},
                    "vptr_load_site": items[vptr_index].address,
                    "slot_load_site": items[slot_index].address,
                    "call_site": call.address,
                    "receiver_register": decoder.reg_name(receiver),
                    "receiver_identity_proven": receiver_identity,
                    "selector_10_proven": selector_10,
                    "accepted": receiver_identity and selector_10,
                }
            )
    return calls, complete_count, incomplete_count


def _validate_productaction_scan_result(document):
    if document != PRODUCTACTION_DELIVERY:
        raise RuntimeError("bounded ProductAction delivery inventory differs")
    return copy.deepcopy(document)


def _validate_productaction_delivery(context, deps):
    document = _validate_productaction_interface(context, deps)
    calls, complete_count, incomplete_count = _canonical_slot_37_calls(context, deps)
    document.update(
        {
            "fully_decoded_owner_count": complete_count,
            "incomplete_or_terminal_owner_count": incomplete_count,
            "canonical_slot_37_call_count": len(calls),
            "canonical_slot_37_calls": calls,
            "accepted_candidates": [item for item in calls if item["accepted"]],
            "receiver_identity_proven": any(
                item["receiver_identity_proven"] for item in calls
            ),
            "selector_10_proven": any(item["selector_10_proven"] for item in calls),
            "whole_program_absence_proven": False,
        }
    )
    return _validate_productaction_scan_result(document)


def _metadata_from_blobs(view_blob, caution_blob, deps):
    if len(view_blob) != SOURCE["size"] or _sha256_bytes(view_blob) != SOURCE["sha256"]:
        raise RuntimeError("viewUnified2 source identity differs")
    if (
        len(caution_blob) != SUPPORTING_SOURCE["size"]
        or _sha256_bytes(caution_blob) != SUPPORTING_SOURCE["sha256"]
    ):
        raise RuntimeError("CautionConfig source identity differs")
    view = _context(view_blob, deps)
    caution = _context(caution_blob, deps)
    document = copy.deepcopy(EXPECTED_EXPORT)
    document["product_root_selection"] = _validate_product_root(view, deps)
    document["constructor_graph"] = _validate_constructor_graph(view, deps)
    document["static_path"] = _validate_static_path(view)
    document["selected_child_mechanism"] = _validate_selected_child_mechanism(
        view, deps
    )
    document["runtime_selection"] = _validate_runtime_selection(caution, deps)
    document["root_initialization"] = _validate_root_initialization(view, deps)
    document["candidate_lifecycle"] = _validate_candidate_lifecycle(caution, deps)
    document["selected_ordinal_writers"] = _validate_selected_ordinal_writers(
        caution, deps
    )
    document["productaction_delivery"] = _validate_productaction_delivery(
        view, deps
    )
    return normalize_creative_style_selected_node_identity_boundary_export(document)


class FileAdapter:
    """Derive the contract from authenticated local files."""

    def __init__(
        self,
        source_path=SOURCE_PATH,
        caution_source_path=CAUTION_SOURCE_PATH,
        dependency_paths=(
            ACTIVATION_DEPENDENCY_PATH,
            DEFINITION_DEPENDENCY_PATH,
            MENU_LIST_DEPENDENCY_PATH,
        ),
    ):
        self.source_path = Path(source_path)
        self.caution_source_path = Path(caution_source_path)
        self.dependency_paths = tuple(Path(path) for path in dependency_paths)

    def metadata(self):
        for path, label in (
            (self.source_path, "viewUnified2 source"),
            (self.caution_source_path, "CautionConfig source"),
        ):
            if path.is_symlink() or not path.is_file():
                raise RuntimeError(label + " must be a literal regular file")
        _validate_dependencies(self.dependency_paths)
        return _metadata_from_blobs(
            self.source_path.read_bytes(),
            self.caution_source_path.read_bytes(),
            _dependencies(),
        )


def build_raw_export(adapter=None):
    """Build and normalize the exact selected-node boundary export."""
    source = adapter or FileAdapter()
    try:
        return normalize_creative_style_selected_node_identity_boundary_export(
            source.metadata()
        )
    except ValueError as exc:
        raise RuntimeError("selected-node source or dependency differs") from exc


def build_report(adapter=None):
    raw = build_raw_export(adapter)
    return validate_creative_style_selected_node_identity_boundary_report(
        build_creative_style_selected_node_identity_boundary_report(raw)
    )


def _encoded(document):
    return (
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def _validate_output_path():
    if REPORT_PATH.is_symlink():
        raise RuntimeError("selected-node report target may not be a symlink")
    current = REPORT_PATH.parent
    while current != ROOT.parent:
        if current.exists() and current.is_symlink():
            raise RuntimeError("selected-node report ancestor may not be a symlink")
        if current == ROOT:
            return
        current = current.parent
    raise RuntimeError("selected-node report target escapes the repository")


def write_report(report):
    """Validate then atomically replace only the checked selected-node report."""
    validated = validate_creative_style_selected_node_identity_boundary_report(
        report
    )
    _validate_output_path()
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=REPORT_PATH.name + ".", suffix=".tmp", dir=REPORT_PATH.parent
    )
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_encoded(validated))
            stream.flush()
            os.fsync(stream.fileno())
        serialized = json.loads(temporary_path.read_text(encoding="utf-8"))
        validate_creative_style_selected_node_identity_boundary_report(serialized)
        os.replace(temporary_path, REPORT_PATH)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
    return copy.deepcopy(validated)


def main():
    report = write_report(build_report())
    print(
        "CREATIVE_STYLE_SELECTED_NODE_IDENTITY_BOUNDARY|"
        f"static_path={report['static_path']['zero_based_indices']}|"
        "runtime_selection=0|creative_look=0|installable=0|camera=0"
    )


if __name__ == "__main__":
    main()
