"""Read-only α6400 Creative Style selected-state dispatch exporter."""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pmca.analysis.creative_style_selected_state_dispatch import (
    BACKUP_READ_BINDING,
    BOUNDED_TABLE_BRANCH,
    CAUTION_CONFIG_SHA256,
    CAUTION_CONFIG_SIZE,
    CLAIMS,
    CREATIVE_STYLE_VTABLE,
    EDGES,
    EXPECTED_RAW_EXPORT,
    METHODS,
    PRODUCT_SELECTORS,
    normalize_creative_style_selected_state_dispatch_export,
)
from tools.static import export_a6400_creative_style_menu_list_construction as menu_exporter
from tools.static.export_a6400_creative_style_definition_registration import (
    _decoded_plt_addresses,
    _load_mappings,
)


SOURCE = ROOT / ".artifacts" / "decrypted" / "a6400-tw-v2.00" / "ma1co" / "firmware.tar_unpacked" / "0700_part_image" / "dev" / "nflasha15_unpacked" / "lib" / "CautionConfig.so"
ARTIFACT_BASE = ROOT / ".artifacts"
OUTPUT_ROOT = ARTIFACT_BASE / "creative-style-selected-state-dispatch" / "a6400-v2.00"
OUTPUT_NAME = "selected-state-dispatch-export.json"


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _at(blob, mappings, address, length):
    offsets = [
        offset + address - start
        for start, end, offset in mappings
        if start <= address and address + length <= end
    ]
    if len(offsets) != 1:
        raise RuntimeError("virtual address does not map exactly once")
    return blob[offsets[0] : offsets[0] + length]


def _word(blob, mappings, address):
    return struct.unpack("<I", _at(blob, mappings, address, 4))[0]


def _dependencies():
    deps = menu_exporter._deps()
    from capstone.arm import ARM_INS_LDRB, ARM_INS_POP, ARM_INS_PUSH, ARM_INS_STR, ARM_INS_STRB, ARM_REG_SP
    return deps, {"sp": ARM_REG_SP, "ldrb": ARM_INS_LDRB, "pop": ARM_INS_POP, "push": ARM_INS_PUSH, "str": ARM_INS_STR, "strb": ARM_INS_STRB}


def _binding(elf, blob, mappings, dynsym):
    relplt = list(elf.get_section_by_name(".rel.plt").iter_relocations())
    relocation = relplt[BACKUP_READ_BINDING["relocation_index"]]
    symbol = dynsym.get_symbol(relocation["r_info_sym"])
    got_to_plt = _decoded_plt_addresses(elf, blob, mappings)
    result = {
        "symbol": symbol.name,
        "symbol_index": relocation["r_info_sym"],
        "symbol_defined": symbol["st_shndx"] != "SHN_UNDEF",
        "relocation_index": BACKUP_READ_BINDING["relocation_index"],
        "relocation_type": relocation["r_info_type"],
        "got": relocation["r_offset"],
        "plt": got_to_plt.get(relocation["r_offset"]),
    }
    if result != BACKUP_READ_BINDING:
        raise RuntimeError("BackupManager read binding differs")
    return result


def _selector_transfer(item, state, stack_evidence, blob, mappings, deps, extra):
    mov_id, movt_id, movw_id, add_id, sub_id, ldr_id = deps[10], deps[11], deps[12], deps[7], deps[13], deps[9]
    immediate_kind, memory_kind, register_kind, pc = deps[14], deps[15], deps[16], deps[17]
    operands = item.operands
    if item.id in (extra["push"], extra["pop"]):
        stack = state.get(extra["sp"])
        if stack and stack.get("kind") == "stack-local":
            delta = len(operands) * 4 * (-1 if item.id == extra["push"] else 1)
            state[extra["sp"]] = {"kind": "stack-local", "offset": stack["offset"] + delta}
        else:
            state.pop(extra["sp"], None)
        return
    if item.id in (extra["strb"], extra["ldrb"]) and len(operands) >= 2 and operands[1].type == memory_kind:
        memory = operands[1].mem
        base = state.get(memory.base)
        if base and base.get("kind") == "stack-local" and memory.index == 0:
            offset = base["offset"] + memory.disp
            if item.id == extra["strb"] and operands[0].type == register_kind:
                source = state.get(operands[0].reg)
                stack_evidence.append({"site": item.address & ~1, "access": "write", "offset": offset, "width": 1, "zero": bool(source and source.get("kind") == "constant" and source.get("value") == 0)})
            elif item.id == extra["ldrb"]:
                stack_evidence.append({"site": item.address & ~1, "access": "read", "offset": offset, "width": 1})
            if item.writeback:
                state[memory.base] = {"kind": "stack-local", "offset": offset}
            if item.id == extra["ldrb"] and operands[0].type == register_kind:
                state[operands[0].reg] = {"kind": "stack-value", "offset": offset, "width": 1}
            return
    if len(operands) < 2 or operands[0].type != register_kind:
        return
    destination = operands[0].reg
    if item.id in (mov_id, movw_id):
        source = operands[1]
        if source.type == immediate_kind:
            state[destination] = {"kind": "constant", "value": source.imm & 0xFFFFFFFF}
        elif source.type == register_kind:
            state[destination] = copy.deepcopy(state.get(source.reg, {"kind": "unknown"}))
        return
    if item.id == movt_id and operands[1].type == immediate_kind:
        previous = state.get(destination)
        state[destination] = (
            {
                "kind": "constant",
                "value": ((operands[1].imm & 0xFFFF) << 16) | (previous["value"] & 0xFFFF),
            }
            if previous and previous.get("kind") == "constant"
            else {"kind": "unknown"}
        )
        return
    if item.id == add_id and len(operands) >= 3 and operands[1].type == register_kind and operands[2].type == immediate_kind:
        base = state.get(operands[1].reg)
        if base and base.get("kind") == "stack-local":
            state[destination] = {"kind": "stack-local", "offset": base["offset"] + operands[2].imm}
        return
    if item.id == sub_id:
        if len(operands) >= 3 and operands[1].type == register_kind and operands[2].type == immediate_kind:
            base, amount = state.get(operands[1].reg), operands[2].imm
        elif len(operands) == 2 and operands[1].type == immediate_kind:
            base, amount = state.get(destination), operands[1].imm
        else:
            base, amount = None, None
        if base and base.get("kind") == "stack-local" and amount is not None:
            state[destination] = {"kind": "stack-local", "offset": base["offset"] - amount}
        return
    if item.id == ldr_id and operands[1].type == memory_kind:
        memory = operands[1].mem
        if memory.base == pc and memory.index == 0:
            literal = ((item.address + 4) & ~3) + memory.disp
            state[destination] = {"kind": "constant", "value": _word(blob, mappings, literal), "literal": literal}
            return
    try:
        _reads, writes = item.regs_access()
    except Exception:
        writes = []
    for register in writes:
        state.pop(register, None)


def _selectors(blob, mappings, dynsym, decoder, deps, extra, binding):
    r0, r1, r2, r3, call_group, jump_group, return_group, immediate_kind = deps[18], deps[19], deps[20], deps[21], deps[4], deps[5], deps[6], deps[14]
    result = []
    for expected in PRODUCT_SELECTORS:
        matches = [(index, symbol) for index, symbol in enumerate(dynsym.iter_symbols()) if symbol.name == expected["symbol"]]
        if len(matches) != 1:
            raise RuntimeError("product selector identity differs")
        symbol_index, symbol = matches[0]
        owner = symbol["st_value"] & ~1
        items = list(decoder.disasm(_at(blob, mappings, owner, symbol["st_size"]), owner))
        state = {extra["sp"]: {"kind": "stack-local", "offset": 0}}
        stack_evidence = []
        calls = []
        for item in items:
            if not item.group(call_group):
                _selector_transfer(item, state, stack_evidence, blob, mappings, deps, extra)
                continue
            targets = [operand.imm & ~1 for operand in item.operands if operand.type == immediate_kind]
            calls.append({"site": item.address & ~1, "target": targets[0] if targets else None, "r0": copy.deepcopy(state.get(r0)), "r1": copy.deepcopy(state.get(r1))})
            for register in (r0, r1, r2, r3):
                state.pop(register, None)
        if len(calls) != 1:
            raise RuntimeError("product selector call count differs")
        call = calls[0]
        output_offset = call["r1"].get("offset") if call["r1"] else None
        writes = [item for item in stack_evidence if item["access"] == "write" and item["offset"] == output_offset and item.get("zero") is True]
        reads = [item for item in stack_evidence if item["access"] == "read" and item["offset"] == output_offset]
        if len(writes) != 1 or len(reads) != 1:
            raise RuntimeError("product selector stack-local access differs")
        write, read = writes[0], reads[0]
        prefix = [item for item in items if (item.address & ~1) <= call["site"]]
        pre_call_straight_line = bool(prefix) and all(
            left.address + left.size == right.address for left, right in zip(prefix, prefix[1:])
        ) and not any((item.group(jump_group) and not item.group(call_group)) or item.group(return_group) for item in prefix)
        output = {
            "kind": call["r1"].get("kind") if call["r1"] else None,
            "width": 1 if write["width"] == read["width"] == 1 else None,
            "zero_initialized": write.get("zero") is True,
            "zero_init_site": write["site"],
            "readback_site": read["site"],
            "same_storage": write["offset"] == output_offset == read["offset"],
            "write_before_call": write["site"] < call["site"],
            "read_after_call": read["site"] > call["site"],
            "pre_call_straight_line": pre_call_straight_line,
        }
        record = {
            "role": expected["role"],
            "symbol": symbol.name,
            "symbol_index": symbol_index,
            "owner": owner,
            "size": symbol["st_size"],
            "call_site": call["site"],
            "target": call["target"],
            "backup_id_literal_cell": call["r0"].get("literal") if call["r0"] else None,
            "backup_id": call["r0"].get("value") if call["r0"] else None,
            "output": output,
        }
        if record != expected or call["target"] != binding["plt"]:
            differing = sorted(key for key in set(record) | set(expected) if record.get(key) != expected.get(key))
            if differing == ["output"]:
                differing = ["output." + key for key in sorted(set(record["output"]) | set(expected["output"])) if record["output"].get(key) != expected["output"].get(key)]
            raise RuntimeError("product selector argument flow differs in: " + ",".join(differing))
        result.append(record)
    return result


def _vtable_and_methods(elf, rel_dyn, dynsym):
    symbols = list(dynsym.iter_symbols())
    matches = [(index, symbol) for index, symbol in enumerate(symbols) if symbol.name == CREATIVE_STYLE_VTABLE["symbol"]]
    if len(matches) != 1:
        raise RuntimeError("Creative Style vtable identity differs")
    symbol_index, symbol = matches[0]
    start = symbol["st_value"]
    end = start + symbol["st_size"]
    typed = [(index, relocation) for index, relocation in enumerate(rel_dyn) if start <= relocation["r_offset"] < end and relocation["r_info_type"] == 2 and relocation["r_info_sym"] != 0]
    table = {
        "symbol": symbol.name,
        "symbol_index": symbol_index,
        "start": start,
        "address_point": start + 8,
        "size": symbol["st_size"],
        "word_count": symbol["st_size"] // 4,
        "typed_relocation_count": len(typed),
    }
    if table != CREATIVE_STYLE_VTABLE:
        raise RuntimeError("Creative Style vtable metadata differs")
    by_cell = {relocation["r_offset"]: (index, relocation) for index, relocation in enumerate(rel_dyn)}
    methods = []
    for expected in METHODS:
        cell = start + expected["table_word"] * 4
        relocation_index, relocation = by_cell[cell]
        method_symbol = symbols[relocation["r_info_sym"]]
        record = {
            "table_word": expected["table_word"],
            "vptr_offset": cell - table["address_point"],
            "symbol": method_symbol.name,
            "owner": method_symbol["st_value"] & ~1,
            "size": method_symbol["st_size"],
            "relocation_index": relocation_index,
            "relocation_type": relocation["r_info_type"],
        }
        if record != expected:
            raise RuntimeError("selected-state method binding differs")
        methods.append(record)
    slot_symbols = {}
    for _index, relocation in typed:
        table_word = (relocation["r_offset"] - start) // 4
        slot_symbols[table_word] = symbols[relocation["r_info_sym"]].name
    return table, methods, slot_symbols


def _method_transfer(item, incoming, deps, call_site=False):
    ldr_id, mov_id, memory_kind, register_kind = deps[9], deps[10], deps[15], deps[16]
    r0, r1, r2, r3 = deps[18], deps[19], deps[20], deps[21]
    state = copy.deepcopy(incoming)
    if call_site:
        for register in (r0, r1, r2, r3):
            state.pop(register, None)
        state[r0] = {"kind": "value", "identity": f"return:{item.address & ~1:x}"}
        return state
    try:
        _reads, writes = item.regs_access()
    except Exception:
        writes = []
    for register in writes:
        state.pop(register, None)
    operands = item.operands
    if len(operands) < 2 or operands[0].type != register_kind:
        return state
    destination = operands[0].reg
    if item.id == mov_id and operands[1].type == register_kind:
        if operands[1].reg in incoming:
            state[destination] = copy.deepcopy(incoming[operands[1].reg])
        return state
    if item.id != ldr_id or operands[1].type != memory_kind:
        return state
    memory = operands[1].mem
    base = incoming.get(memory.base)
    if base and base.get("kind") == "value" and memory.disp == 0 and memory.index == 0:
        state[destination] = {"kind": "vtable", "object_identity": base["identity"]}
    elif base and base.get("kind") == "vtable" and memory.index == 0 and memory.disp % 4 == 0:
        state[destination] = {
            "kind": "vtable-function",
            "object_identity": base["object_identity"],
            "table_word": 2 + memory.disp // 4,
        }
    else:
        state[destination] = {"kind": "value", "identity": f"load:{item.address & ~1:x}"}
    return state


def _state_intersection(left, right):
    return {register: value for register, value in left.items() if register in right and right[register] == value}


def _non_branch_pc_write_is_terminal(item, call_group, jump_group, pc_register):
    if item.group(call_group) or item.group(jump_group):
        return False
    try:
        _reads, writes = item.regs_access()
    except Exception:
        return False
    return pc_register in writes


def _method_cfg(items, deps, table_branches):
    call_group, jump_group, return_group = deps[4], deps[5], deps[6]
    immediate_kind, pc_register, arm_cc_al, arm_cc_invalid = deps[14], deps[17], deps[22], deps[23]
    by_address = {item.address & ~1: item for item in items}
    ordered = sorted(by_address)
    next_address = {left: right for left, right in zip(ordered, ordered[1:])}
    successors = {}
    for address in ordered:
        item = by_address[address]
        following = next_address.get(address)
        targets = [operand.imm & ~1 for operand in item.operands if operand.type == immediate_kind]
        outgoing = []
        if item.group(call_group):
            if following is not None:
                outgoing.append(following)
        elif item.group(return_group) or _non_branch_pc_write_is_terminal(item, call_group, jump_group, pc_register):
            outgoing = []
        elif item.group(jump_group):
            outgoing.extend(target for target in table_branches.get(address, targets) if target in by_address)
            if address not in table_branches and following is not None and menu_exporter._jump_has_fallthrough(item.mnemonic, getattr(item, "cc", arm_cc_invalid), arm_cc_al, arm_cc_invalid):
                outgoing.append(following)
        elif following is not None:
            outgoing.append(following)
        successors[address] = list(dict.fromkeys(outgoing))
    return by_address, successors


def _method_states(items, method, deps, table_branches):
    if not items or (items[0].address & ~1) != method["owner"] or items[-1].address + items[-1].size != method["owner"] + method["size"]:
        raise RuntimeError("selected-state method decode is incomplete")
    by_address, successors = _method_cfg(items, deps, table_branches)
    r0 = deps[18]
    incoming = {method["owner"]: {r0: {"kind": "value", "identity": "this"}}}
    queue = [method["owner"]]
    while queue:
        address = queue.pop(0)
        item = by_address[address]
        outgoing = _method_transfer(item, incoming[address], deps, call_site=item.group(deps[4]))
        for target in successors[address]:
            merged = copy.deepcopy(outgoing) if target not in incoming else _state_intersection(incoming[target], outgoing)
            if target not in incoming or merged != incoming[target]:
                incoming[target] = merged
                queue.append(target)
    if set(incoming) != set(by_address):
        raise RuntimeError(f"selected-state real-code CFG reachability differs at table word {method['table_word']}")
    return by_address, incoming


def _decode_method(blob, mappings, decoder, method):
    owner, end = method["owner"], method["owner"] + method["size"]
    if method["table_word"] != BOUNDED_TABLE_BRANCH["caller_table_word"]:
        items = list(decoder.disasm(_at(blob, mappings, owner, method["size"]), owner))
        return items, {}, None
    expected = BOUNDED_TABLE_BRANCH
    data_start = expected["data_start"]
    data_end = data_start + expected["entry_count"]
    resume = (data_end + 1) & ~1
    prefix = list(decoder.disasm(_at(blob, mappings, owner, data_start - owner), owner))
    suffix = list(decoder.disasm(_at(blob, mappings, resume, end - resume), resume))
    items = prefix + suffix
    table = _at(blob, mappings, data_start, expected["entry_count"])
    targets = sorted(set(expected["site"] + 4 + 2 * value for value in table))
    record = {
        "caller_table_word": method["table_word"],
        "site": expected["site"],
        "entry_count": len(table),
        "data_start": data_start,
        "data_end": data_end,
        "resume": resume,
        "targets": targets,
    }
    by_address = {item.address & ~1: item for item in items}
    branch = by_address.get(record["site"])
    if record != expected or branch is None or branch.mnemonic != "tbb":
        raise RuntimeError("selected-state bounded table branch differs")
    return items, {record["site"]: record["targets"]}, record


def _dispatch(blob, mappings, decoder, deps, extra, methods, slot_symbols):
    r0 = deps[18]
    call_group, immediate_kind, register_kind = deps[4], deps[14], deps[16]
    edges = []
    leaf_words = []
    accesses_by_offset = {0x18: [], 0x20: [], 0x24: []}
    bounded_table = None
    for method in methods:
        items, table_branches, table_record = _decode_method(blob, mappings, decoder, method)
        if table_record is not None:
            if bounded_table is not None:
                raise RuntimeError("multiple selected-state bounded table branches")
            bounded_table = table_record
        by_address, incoming_states = _method_states(items, method, deps, table_branches)
        method_calls = 0
        for address in sorted(incoming_states):
            item = by_address[address]
            state = incoming_states[address]
            if not item.group(call_group):
                operands = item.operands
                if item.id in (deps[9], extra["str"]) and len(operands) >= 2 and operands[1].type == deps[15]:
                    memory = operands[1].mem
                    base = state.get(memory.base)
                    if base and base.get("kind") == "value" and base.get("identity") == "this" and memory.index == 0 and memory.disp in accesses_by_offset:
                        accesses_by_offset[memory.disp].append({
                            "table_word": method["table_word"],
                            "site": item.address & ~1,
                            "access": "read" if item.id == deps[9] else "write",
                        })
                continue
            direct = [operand.imm & ~1 for operand in item.operands if operand.type == immediate_kind]
            registers = [operand.reg for operand in item.operands if operand.type == register_kind]
            if direct or len(registers) != 1:
                raise RuntimeError("selected-state dispatch is not the bounded indirect form")
            target = state.get(registers[0], {"kind": "unknown"})
            if target.get("kind") != "vtable-function" or target["table_word"] not in slot_symbols:
                raise RuntimeError("selected-state virtual target differs")
            actual_receiver = state.get(r0)
            if not actual_receiver or actual_receiver.get("kind") != "value" or actual_receiver.get("identity") != target.get("object_identity"):
                raise RuntimeError("selected-state virtual receiver identity differs")
            table_word = target["table_word"]
            receiver = "this" if target["object_identity"] == "this" else "resolved-object"
            edges.append({
                "caller_table_word": method["table_word"],
                "call_site": item.address & ~1,
                "dispatch": "indirect-vtable",
                "receiver": receiver,
                "target_table_word": table_word,
                "target_vptr_offset": (table_word - 2) * 4,
                "interface_symbol": slot_symbols[table_word],
                "final_target_resolved": receiver == "this",
            })
            method_calls += 1
        if method_calls == 0:
            leaf_words.append(method["table_word"])
    if edges != EDGES:
        raise RuntimeError("selected-state virtual-dispatch edges differ")
    roles = {0x18: "selected-item-cache-field", 0x20: "set-selection-adjacent-field", 0x24: "generic-selection-state-field"}
    field_accesses = [
        {"offset": offset, "width": 4, "role": roles[offset], "accesses": accesses_by_offset[offset]}
        for offset in (0x18, 0x20, 0x24)
    ]
    return {
        "edges": edges,
        "edge_count": len(edges),
        "edge_digest": hashlib.sha256((json.dumps(edges, sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest(),
        "local_leaf_table_words": leaf_words,
        "field_accesses": field_accesses,
        "field_access_digest": hashlib.sha256((json.dumps(field_accesses, sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest(),
        "unresolved_callback_sites": [edge["call_site"] for edge in edges if not edge["final_target_resolved"]],
        "method_decode_complete": True,
        "reported_sites_cfg_reachable": True,
        "receiver_identity_checked": True,
        "unhandled_register_writes_invalidated": True,
        "bounded_table_branch": bounded_table,
    }


def _metadata_from_file(source=SOURCE):
    source = Path(source)
    if source.is_symlink() or not source.is_file():
        raise RuntimeError("source must be a literal regular file")
    before = _sha(source)
    if source.name != "CautionConfig.so" or source.stat().st_size != CAUTION_CONFIG_SIZE or before != CAUTION_CONFIG_SHA256:
        raise RuntimeError("source identity differs")
    deps, extra = _dependencies()
    ELFFile = deps[-1]
    blob = source.read_bytes()
    with io.BytesIO(blob) as stream:
        elf = ELFFile(stream)
        mappings = _load_mappings(elf)
        dynsym = elf.get_section_by_name(".dynsym")
        rel_dyn_section = elf.get_section_by_name(".rel.dyn")
        if dynsym is None or rel_dyn_section is None:
            raise RuntimeError("dynamic metadata differs")
        rel_dyn = list(rel_dyn_section.iter_relocations())
        decoder = deps[0](deps[1], deps[3]); decoder.detail = True
        binding = _binding(elf, blob, mappings, dynsym)
        selectors = _selectors(blob, mappings, dynsym, decoder, deps, extra, binding)
        table, methods, slot_symbols = _vtable_and_methods(elf, rel_dyn, dynsym)
        dispatch = _dispatch(blob, mappings, decoder, deps, extra, methods, slot_symbols)
    document = copy.deepcopy(EXPECTED_RAW_EXPORT)
    document.update({
        "creative_style_vtable": table,
        "product_graph_selector": {
            "backup_read_binding": binding,
            "selectors": selectors,
            "classification": "shared-product-menu-graph-selector",
            "is_current_user_selection": False,
        },
        "methods": methods,
        "selected_state_dispatch": dispatch,
        "claims": copy.deepcopy(CLAIMS),
    })
    normalize_creative_style_selected_state_dispatch_export(document)
    if _sha(source) != before:
        raise RuntimeError("source changed during static export")
    return document


class FileAdapter:
    def __init__(self, source=SOURCE):
        self.source = source

    def metadata(self):
        return _metadata_from_file(self.source)


def build_raw_export(adapter=None):
    try:
        return normalize_creative_style_selected_state_dispatch_export((adapter or FileAdapter()).metadata())
    except Exception as exc:
        raise RuntimeError("Creative Style selected-state metadata differs from exact bounded static result") from exc


def _literal_directory_under(root, base):
    base = Path(os.path.abspath(os.fspath(base)))
    root = Path(os.path.abspath(os.fspath(root)))
    if base.is_symlink() or not base.is_dir() or base.resolve(strict=True) != base:
        raise RuntimeError("artifact base is not a literal directory")
    try:
        root.relative_to(base)
        resolved = root.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise RuntimeError("approved output root is not contained") from exc
    if root.is_symlink() or not root.is_dir() or resolved != root:
        raise RuntimeError("approved output root escapes through a symlink")
    return root


def prepare_output_root(approved_root=OUTPUT_ROOT, artifact_base=ARTIFACT_BASE):
    base = Path(os.path.abspath(os.fspath(artifact_base)))
    root = Path(os.path.abspath(os.fspath(approved_root)))
    if base.is_symlink() or not base.is_dir() or base.resolve(strict=True) != base:
        raise RuntimeError("artifact base is not literal")
    try:
        relative = root.relative_to(base)
    except ValueError as exc:
        raise RuntimeError("approved output root is not contained") from exc
    current = base
    for component in relative.parts:
        candidate = current / component
        if candidate.is_symlink() or (candidate.exists() and not candidate.is_dir()):
            raise RuntimeError("approved output root has a non-literal ancestor")
        if not candidate.exists():
            candidate.mkdir()
        if candidate.is_symlink() or not candidate.is_dir() or candidate.resolve(strict=True) != candidate:
            raise RuntimeError("approved output root escapes through a symlink")
        current = candidate
    return _literal_directory_under(root, base)


def write_json_atomic(output, document, approved_root=OUTPUT_ROOT, artifact_base=ARTIFACT_BASE):
    root = _literal_directory_under(approved_root, artifact_base)
    output = Path(os.path.abspath(os.fspath(output)))
    if output.name != OUTPUT_NAME or output.parent != root or output.is_symlink() or (output.exists() and not output.is_file()):
        raise RuntimeError("output containment is invalid")
    handle, temporary = tempfile.mkstemp(dir=str(root), prefix=".selected-state-dispatch-", suffix=".tmp")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(json.dumps(document, sort_keys=True, separators=(",", ":")).encode() + b"\n")
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, output)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


if __name__ == "__main__":
    prepare_output_root()
    write_json_atomic(OUTPUT_ROOT / OUTPUT_NAME, build_raw_export())
    print("CREATIVE_STYLE_SELECTED_STATE_DISPATCH_EXPORT|selectors=2|methods=16|edges=22|model_value=0|persistence=0")
