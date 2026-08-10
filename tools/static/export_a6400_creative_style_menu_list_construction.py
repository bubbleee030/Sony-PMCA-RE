"""Read-only α6400 Creative Style menu-list construction exporter."""
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
from pmca.analysis.creative_style_definition_registration import validate_creative_style_definition_registration_report
from pmca.analysis.creative_style_menu_list_construction import (
    CLAIMS,
    CONSTRUCTOR_BINDING,
    CONSTRUCTOR_TRACE_DIGEST,
    EXPECTED_RAW_EXPORT,
    LIST_CONSTRUCTIONS,
    PRIOR_DEFINITION_DIGEST,
    PRIOR_REGISTRY_DIGEST,
    ROOT_INVENTORY,
    VIEW_STLREC_VTABLE,
    VIEW_UNIFIED2_SHA256,
    VIEW_UNIFIED2_SIZE,
    normalize_creative_style_menu_list_construction_export,
)
from pmca.analysis.creative_style_registry_consumers import validate_creative_style_registry_consumers_report


SOURCE = ROOT / ".artifacts" / "decrypted" / "a6400-tw-v2.00" / "ma1co" / "firmware.tar_unpacked" / "0700_part_image" / "dev" / "nflasha15_unpacked" / "lib" / "viewUnified2.so"
PRIOR_DEFINITION_REPORT = ROOT / "analysis" / "a6400-creative-style-definition-registration.json"
PRIOR_REGISTRY_REPORT = ROOT / "analysis" / "a6400-creative-style-registry-consumers.json"
ARTIFACT_BASE = ROOT / ".artifacts"
OUTPUT_ROOT = ARTIFACT_BASE / "creative-style-menu-list-construction" / "a6400-v2.00"
OUTPUT_NAME = "raw-creative-style-menu-list-construction.json"


def _deps():
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
        from capstone.arm import (
            ARM_INS_ADD, ARM_INS_ADR, ARM_INS_LDR, ARM_INS_MOV, ARM_INS_MOVT,
            ARM_CC_AL, ARM_CC_INVALID, ARM_INS_MOVW, ARM_INS_SUB, ARM_OP_IMM,
            ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC, ARM_REG_R0, ARM_REG_R1,
            ARM_REG_R2, ARM_REG_R3,
        )
        from elftools.elf.elffile import ELFFile
    except ImportError:
        for path in (ROOT / ".artifacts" / "pydeps_vlf", ROOT / ".artifacts" / "pydeps", ROOT / ".artifacts" / "python-packages"):
            if path.is_dir():
                sys.path.insert(0, str(path))
        try:
            from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
            from capstone.arm import (
                ARM_INS_ADD, ARM_INS_ADR, ARM_INS_LDR, ARM_INS_MOV, ARM_INS_MOVT,
                ARM_CC_AL, ARM_CC_INVALID, ARM_INS_MOVW, ARM_INS_SUB, ARM_OP_IMM,
                ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC, ARM_REG_R0, ARM_REG_R1,
                ARM_REG_R2, ARM_REG_R3,
            )
            from elftools.elf.elffile import ELFFile
        except ImportError as exc:
            raise RuntimeError("local Capstone and pyelftools are required") from exc
    return (
        Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_GRP_CALL, CS_GRP_JUMP,
        CS_GRP_RET, ARM_INS_ADD, ARM_INS_ADR, ARM_INS_LDR, ARM_INS_MOV,
        ARM_INS_MOVT, ARM_INS_MOVW, ARM_INS_SUB, ARM_OP_IMM, ARM_OP_MEM,
        ARM_OP_REG, ARM_REG_PC, ARM_REG_R0, ARM_REG_R1, ARM_REG_R2,
        ARM_REG_R3, ARM_CC_AL, ARM_CC_INVALID, ELFFile,
    )


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _canonical(value):
    return hashlib.sha256((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest()


def _literal_json(path, label):
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file():
        raise RuntimeError(label + " must be a literal regular file")
    try:
        return json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(label + " differs") from exc


def _prior_evidence(definition_report=PRIOR_DEFINITION_REPORT, registry_report=PRIOR_REGISTRY_REPORT):
    definition = validate_creative_style_definition_registration_report(_literal_json(definition_report, "definition report"))
    registry = validate_creative_style_registry_consumers_report(_literal_json(registry_report, "registry report"))
    if definition["summary"]["artifact_sha256"] != PRIOR_DEFINITION_DIGEST:
        raise RuntimeError("prior definition evidence differs")
    if registry["summary"]["artifact_sha256"] != PRIOR_REGISTRY_DIGEST:
        raise RuntimeError("prior registry evidence differs")


def _prel31(value, address):
    value &= 0x7FFFFFFF
    return address + (value - 0x80000000 if value & 0x40000000 else value)


def _mappings(elf):
    return [
        (segment["p_vaddr"], segment["p_vaddr"] + segment["p_filesz"], segment["p_offset"])
        for segment in elf.iter_segments()
        if segment["p_type"] == "PT_LOAD"
    ]


def _at(blob, mappings, address, length):
    offsets = [offset + address - start for start, end, offset in mappings if start <= address and address + length <= end]
    if len(offsets) != 1:
        raise RuntimeError("virtual range does not map exactly once")
    return blob[offsets[0]:offsets[0] + length]


def _word(blob, mappings, address):
    return int.from_bytes(_at(blob, mappings, address, 4), "little")


def _cstring(blob, mappings, address):
    values = []
    while len(values) <= 128:
        value = _at(blob, mappings, address + len(values), 1)[0]
        if value == 0:
            return bytes(values).decode("ascii")
        values.append(value)
    raise RuntimeError("bounded string differs")


def _section_name(elf, address):
    matches = [section.name for section in elf.iter_sections() if section["sh_addr"] <= address < section["sh_addr"] + section["sh_size"]]
    if len(matches) != 1:
        raise RuntimeError("section identity differs")
    return matches[0]


def _owners(elf):
    section = elf.get_section_by_name(".ARM.exidx")
    if section is None or section["sh_size"] % 8:
        raise RuntimeError("exception index differs")
    values = sorted(
        _prel31(int.from_bytes(section.data()[offset:offset + 4], "little"), section["sh_addr"] + offset)
        for offset in range(0, section["sh_size"], 8)
    )
    return [(start, values[index + 1] if index + 1 < len(values) else None) for index, start in enumerate(values)]


def _selected_owners(elf, blob, mappings):
    deps = _deps()
    decoder = deps[0](deps[1], deps[3]); decoder.detail = True
    expected = {item["owner"]: item["owner_end"] for item in LIST_CONSTRUCTIONS}
    rows = {}
    for owner, end in _owners(elf):
        if owner not in expected:
            continue
        if end != expected[owner]:
            raise RuntimeError("selected owner boundary differs")
        items = list(decoder.disasm(_at(blob, mappings, owner, end - owner), owner | 1))
        if sum(item.size for item in items) != end - owner:
            raise RuntimeError("selected owner is not fully decoded")
        rows[owner] = (end, items)
    if set(rows) != set(expected):
        raise RuntimeError("selected owner coverage differs")
    return rows


def _root_inventory(rel_dyn, dynsym):
    rows = []
    for index, relocation in enumerate(rel_dyn):
        if relocation["r_info_type"] != 2 or not relocation["r_info_sym"]:
            continue
        name = dynsym.get_symbol(relocation["r_info_sym"]).name
        if name.startswith("cmnViewSettingNodeRoot"):
            rows.append({"cell": relocation["r_offset"], "name": name, "relocation_index": index})
    rows.sort(key=lambda item: item["cell"])
    runs, current = [], []
    for row in rows:
        if current and row["cell"] != current[-1]["cell"] + 4:
            runs.append(current); current = []
        current.append(row)
    if current:
        runs.append(current)
    creative = [run for run in runs if any(item["name"] == "cmnViewSettingNodeRootCreativeStyle" for item in run)]
    compact = [
        {
            "start": run[0]["cell"],
            "end": run[-1]["cell"] + 4,
            "entry_count": len(run),
            "creative_style_index": next(index for index, item in enumerate(run) if item["name"] == "cmnViewSettingNodeRootCreativeStyle"),
        }
        for run in creative
    ]
    result = {
        "root_pointer_relocation_count": len(rows),
        "maximal_contiguous_run_count": len(runs),
        "creative_style_occurrence_count": sum(item["name"] == "cmnViewSettingNodeRootCreativeStyle" for item in rows),
        "creative_style_contiguous_run_count": len(creative),
        "creative_style_contiguous_run_digest": _canonical(compact),
        "contiguous_runs_are_constructor_boundaries": False,
        "constructor_bounded_list_count": len(LIST_CONSTRUCTIONS),
    }
    if result != ROOT_INVENTORY:
        raise RuntimeError("root relocation inventory differs")
    return result


def _plt_stubs(elf, blob, mappings):
    deps = _deps()
    decoder = deps[0](deps[1], deps[2]); decoder.detail = True
    section = elf.get_section_by_name(".plt")
    if section is None:
        raise RuntimeError("PLT differs")
    result = {}
    for address in range(section["sh_addr"], section["sh_addr"] + section["sh_size"] - 11, 4):
        items = list(decoder.disasm(_at(blob, mappings, address, 12), address))
        if len(items) != 3 or [item.mnemonic for item in items] != ["add", "add", "ldr"]:
            continue
        try:
            got = address + 8 + items[0].operands[2].imm + items[1].operands[2].imm + items[2].operands[1].mem.disp
        except (AttributeError, IndexError):
            continue
        if got in result:
            raise RuntimeError("PLT mapping is ambiguous")
        result[got] = address
    return result


def _constructor_binding(elf, blob, mappings, dynsym):
    matches = [(index, symbol) for index, symbol in enumerate(dynsym.iter_symbols()) if symbol.name == CONSTRUCTOR_BINDING["symbol"]]
    if len(matches) != 1:
        raise RuntimeError("constructor symbol differs")
    symbol_index, symbol = matches[0]
    relocations = list(elf.get_section_by_name(".rel.plt").iter_relocations())
    rows = [(index, relocation) for index, relocation in enumerate(relocations) if relocation["r_info_sym"] == symbol_index]
    if len(rows) != 1:
        raise RuntimeError("constructor PLT binding differs")
    relocation_index, relocation = rows[0]
    result = {
        "symbol": symbol.name,
        "demangled": CONSTRUCTOR_BINDING["demangled"],
        "symbol_index": symbol_index,
        "symbol_defined": symbol["st_shndx"] != "SHN_UNDEF",
        "relocation_index": relocation_index,
        "relocation_type": relocation["r_info_type"],
        "got": relocation["r_offset"],
        "plt": _plt_stubs(elf, blob, mappings).get(relocation["r_offset"]),
    }
    if result != CONSTRUCTOR_BINDING:
        raise RuntimeError("constructor binding identity differs")
    return result


def _value(value, origin, cell=None, load_site=None, move_site=None):
    result = {"value": value & 0xFFFFFFFF, "origin": origin}
    if cell is not None:
        result["cell"] = cell
    if load_site is not None:
        result["load_site"] = load_site
    if move_site is not None:
        result["move_site"] = move_site
    return result


def _transfer_state(item, incoming, blob, mappings, deps):
    (call_group, add_id, adr_id, ldr_id, mov_id, movt_id, movw_id, sub_id,
     immediate_kind, mem_kind, reg_kind, pc, r0, r1, r2, r3) = (
        deps[4], deps[7], deps[8], deps[9], deps[10], deps[11], deps[12],
        deps[13], deps[14], deps[15], deps[16], deps[17], deps[18], deps[19],
        deps[20], deps[21],
    )
    state = copy.deepcopy(incoming)
    site = item.address & ~1
    operands = item.operands
    if item.group(call_group):
        for register in (r0, r1, r2, r3):
            state.pop(register, None)
        return state
    handled = set()
    if item.id == ldr_id and len(operands) == 2 and operands[0].type == reg_kind and operands[1].type == mem_kind:
        destination, memory = operands[0].reg, operands[1].mem
        handled.add(destination)
        if memory.base == pc:
            cell = ((site + 4) & ~3) + memory.disp
            state[destination] = _value(_word(blob, mappings, cell), "pc-literal", cell, site)
        else:
            base = state.get(memory.base)
            index = state.get(memory.index) if memory.index else _value(0, "zero")
            if base is None or index is None:
                state.pop(destination, None)
            else:
                cell = (base["value"] + (index["value"] << memory.lshift) + memory.disp) & 0xFFFFFFFF
                try:
                    loaded = _word(blob, mappings, cell)
                except RuntimeError:
                    state.pop(destination, None)
                else:
                    state[destination] = _value(loaded, "memory-load", cell, site)
    elif item.id == adr_id and len(operands) == 2 and operands[0].type == reg_kind and operands[1].type == immediate_kind:
        handled.add(operands[0].reg); state[operands[0].reg] = _value(operands[1].imm, "address")
    elif item.id in (add_id, sub_id) and operands and operands[0].type == reg_kind:
        destination = operands[0].reg; handled.add(destination)
        if len(operands) == 2:
            left = state.get(destination)
            right = _value(site + 4, "pc") if operands[1].type == reg_kind and operands[1].reg == pc else state.get(operands[1].reg) if operands[1].type == reg_kind else _value(operands[1].imm, "immediate") if operands[1].type == immediate_kind else None
        elif len(operands) == 3:
            left = _value(site + 4, "pc") if operands[1].type == reg_kind and operands[1].reg == pc else state.get(operands[1].reg) if operands[1].type == reg_kind else None
            right = state.get(operands[2].reg) if operands[2].type == reg_kind else _value(operands[2].imm, "immediate") if operands[2].type == immediate_kind else None
        else:
            left = right = None
        if left is None or right is None:
            state.pop(destination, None)
        else:
            result = left["value"] + right["value"] if item.id == add_id else left["value"] - right["value"]
            state[destination] = _value(result, "arithmetic")
    elif item.id == mov_id and len(operands) == 2 and operands[0].type == reg_kind:
        destination = operands[0].reg; handled.add(destination)
        if operands[1].type == reg_kind and operands[1].reg in state:
            state[destination] = copy.deepcopy(state[operands[1].reg])
            state[destination]["move_site"] = site
        elif operands[1].type == immediate_kind:
            state[destination] = _value(operands[1].imm, "immediate", move_site=site)
        else:
            state.pop(destination, None)
    elif item.id == movw_id and len(operands) == 2 and operands[0].type == reg_kind and operands[1].type == immediate_kind:
        destination = operands[0].reg; handled.add(destination)
        state[destination] = _value(operands[1].imm & 0xFFFF, "wide-immediate")
    elif item.id == movt_id and len(operands) == 2 and operands[0].type == reg_kind and operands[1].type == immediate_kind:
        destination = operands[0].reg; handled.add(destination)
        prior = state.get(destination)
        if prior is None:
            state.pop(destination, None)
        else:
            state[destination] = _value((prior["value"] & 0xFFFF) | ((operands[1].imm & 0xFFFF) << 16), "wide-immediate")
    try:
        _reads, writes = item.regs_access()
    except Exception:
        writes = []
    for destination in writes:
        if destination not in handled and destination != pc:
            state.pop(destination, None)
    return state


def _argument_snapshots(selected, blob, mappings):
    deps = _deps()
    call_group, immediate_kind = deps[4], deps[14]
    r0, r1, r2, r3 = deps[18], deps[19], deps[20], deps[21]
    expected_sites = {item["constructor_call_site"] for item in LIST_CONSTRUCTIONS}
    rows = {}
    for owner, (_end, items) in selected.items():
        by_address, _next_address, successors = _cfg_successors(items)
        incoming = {owner: {}}
        queue = [owner]
        while queue:
            site = queue.pop(0)
            item = by_address[site]
            state = incoming[site]
            if item.group(call_group) and site in expected_sites:
                targets = [operand.imm & ~1 for operand in item.operands if operand.type == immediate_kind]
                rows[site] = {"target": targets[0] if targets else None, "arguments": {register: copy.deepcopy(state.get(register)) for register in (r0, r1, r2, r3)}}
            outgoing = _transfer_state(item, state, blob, mappings, deps)
            for target in successors.get(site, []):
                if target not in incoming:
                    merged = copy.deepcopy(outgoing)
                else:
                    merged = {register: copy.deepcopy(value) for register, value in incoming[target].items() if outgoing.get(register) == value}
                if target not in incoming or merged != incoming[target]:
                    incoming[target] = merged
                    if target not in queue:
                        queue.append(target)
    if set(rows) != expected_sites:
        raise RuntimeError("constructor call CFG snapshots differ")
    return rows


def _jump_has_fallthrough(mnemonic, condition_code, always_code, invalid_code):
    return mnemonic in ("cbz", "cbnz") or condition_code not in (always_code, invalid_code)


def _cfg_successors(items):
    deps = _deps()
    call_group, jump_group, ret_group, immediate_kind = deps[4], deps[5], deps[6], deps[14]
    always_code, invalid_code = deps[22], deps[23]
    by_address = {item.address & ~1: item for item in items}
    addresses = sorted(by_address)
    next_address = {address: addresses[index + 1] if index + 1 < len(addresses) else None for index, address in enumerate(addresses)}
    successors = {}
    for address, item in by_address.items():
        following = next_address[address]
        if item.group(call_group):
            candidates = [following] if following is not None else []
        elif item.group(ret_group):
            candidates = []
        elif item.group(jump_group):
            direct = [operand.imm & ~1 for operand in item.operands if operand.type == immediate_kind]
            has_fallthrough = following is not None and _jump_has_fallthrough(item.mnemonic, item.cc, always_code, invalid_code)
            candidates = direct + ([following] if has_fallthrough else [])
        else:
            candidates = [following] if following is not None else []
        successors[address] = [candidate for candidate in candidates if candidate in by_address]
    return by_address, next_address, successors


def _cfg_distance(items, start, goal):
    _by_address, _next_address, successors = _cfg_successors(items)
    seen = {start}
    queue = [(start, 0)]
    while queue:
        address, distance = queue.pop(0)
        if address == goal:
            return distance
        for candidate in successors.get(address, []):
            if candidate not in seen:
                seen.add(candidate); queue.append((candidate, distance + 1))
    return None


def _prep_chain_proof(items, owner, sites):
    by_address, next_address, successors = _cfg_successors(items)
    predecessors = {address: set() for address in by_address}
    for address, targets in successors.items():
        for target in targets:
            predecessors[target].add(address)
    reachable = {owner}
    queue = [owner]
    while queue:
        address = queue.pop(0)
        for target in successors.get(address, []):
            if target not in reachable:
                reachable.add(target); queue.append(target)
    return {
        "entry_reachable": all(site in reachable for site in sites),
        "direct_fallthrough": all(next_address.get(left) == right and successors.get(left) == [right] for left, right in zip(sites, sites[1:])),
        "unique_predecessors": all(predecessors.get(right) == {left} for left, right in zip(sites, sites[1:])),
    }


def _relocation_record(rel_by_offset, elf, cell):
    pair = rel_by_offset.get(cell)
    if pair is None:
        raise RuntimeError("pinned relocation is absent")
    index, relocation = pair
    return {
        "section": _section_name(elf, cell),
        "cell": cell,
        "relocation_index": index,
        "relocation_type": relocation["r_info_type"],
    }


def _list_constructions(elf, blob, mappings, rel_dyn, dynsym, selected, snapshots):
    rel_by_offset = {relocation["r_offset"]: (index, relocation) for index, relocation in enumerate(rel_dyn)}
    results, trace_rows = [], []
    for expected in LIST_CONSTRUCTIONS:
        owner, call_site = expected["owner"], expected["constructor_call_site"]
        end, items = selected[owner]
        snapshot = snapshots[call_site]
        args = snapshot["arguments"]
        deps = _deps(); r0, r1, r2, r3 = deps[18], deps[19], deps[20], deps[21]
        if snapshot["target"] != CONSTRUCTOR_BINDING["plt"]:
            raise RuntimeError("constructor call target differs")
        if args[r0] is None or args[r1] is None or args[r2] is None or args[r3] is None:
            raise RuntimeError("constructor argument provenance is incomplete")
        incoming = _relocation_record(rel_by_offset, elf, expected["incoming_reference"]["cell"])
        if (_word(blob, mappings, incoming["cell"]) & ~1) != owner:
            raise RuntimeError("owner incoming reference differs")
        this_cell = args[r0].get("cell")
        root_cell = args[r1].get("cell")
        this_index, this_relocation = rel_by_offset[this_cell]
        root_index, root_relocation = rel_by_offset[root_cell]
        this_source = {"cell": this_cell, "relocation_index": this_index, "relocation_type": this_relocation["r_info_type"], "target": args[r0]["value"]}
        root_source = {"cell": root_cell, "relocation_index": root_index, "relocation_type": root_relocation["r_info_type"], "target": args[r1]["value"]}
        count = args[r2]["value"]
        start = args[r1]["value"]
        entries = []
        for item_index in range(count):
            cell = start + item_index * 4
            relocation_index, relocation = rel_by_offset[cell]
            if relocation["r_info_type"] != 2 or not relocation["r_info_sym"]:
                raise RuntimeError("constructor-bounded list member differs")
            entries.append({
                "index": item_index,
                "cell": cell,
                "relocation_index": relocation_index,
                "relocation_type": relocation["r_info_type"],
                "symbol": dynsym.get_symbol(relocation["r_info_sym"]).name,
                "addend": _word(blob, mappings, cell),
            })
        creative_matches = [index for index, item in enumerate(entries) if item["symbol"] == "cmnViewSettingNodeRootCreativeStyle"]
        if len(creative_matches) != 1:
            raise RuntimeError("constructor list Creative Style membership differs")
        distance = _cfg_distance(items, owner, args[r1]["load_site"])
        argument_definition_sites = {
            "r0_indexed_load": args[r0].get("load_site"),
            "r0_move": args[r0].get("move_site"),
            "r1_root_list_load": args[r1].get("load_site"),
            "r2_count_immediate": args[r2].get("move_site"),
            "r3_null_immediate": args[r3].get("move_site"),
        }
        _by_address, next_address, _successors = _cfg_successors(items)
        prep_sites = [argument_definition_sites["r2_count_immediate"]]
        while prep_sites[-1] != call_site and len(prep_sites) <= 16:
            following = next_address.get(prep_sites[-1])
            if following is None:
                break
            prep_sites.append(following)
        prep_proof = _prep_chain_proof(items, owner, prep_sites)
        result = {
            "role": expected["role"],
            "owner": owner,
            "owner_end": end,
            "owner_range_size": end - owner,
            "decoded_item_count": len(items),
            "owner_complete": True,
            "entry_path_mode": "bounded-direct-intra-owner-cfg-dataflow",
            "entry_path_reachable": distance is not None,
            "entry_path_edge_count": distance,
            "runtime_branch_feasibility_proven": False,
            "incoming_reference": incoming,
            "root_list_load_site": args[r1]["load_site"],
            "constructor_call_site": call_site,
            "constructor_target": snapshot["target"],
            "this_source": this_source,
            "root_list_source": root_source,
            "root_list_start": start,
            "root_list_end": start + count * 4,
            "entry_count": count,
            "creative_style_index": creative_matches[0],
            "entries": entries,
            "argument_definition_sites": argument_definition_sites,
            "prep_chain_sites": prep_sites,
            "prep_chain_entry_reachable": prep_proof["entry_reachable"],
            "prep_chain_direct_fallthrough": prep_proof["direct_fallthrough"],
            "prep_chain_unique_predecessors": prep_proof["unique_predecessors"],
            "r0_flows_directly_to_constructor": args[r0]["origin"] == "memory-load",
            "r1_flows_directly_to_constructor": args[r1]["origin"] == "memory-load",
            "r2_immediate_count": count if args[r2]["origin"] == "immediate" else None,
            "r3_properties_null": args[r3]["origin"] == "immediate" and args[r3]["value"] == 0,
        }
        results.append(result)
        trace_rows.append({
            "owner": owner, "end": end, "size": end - owner,
            "style_load_site": args[r1]["load_site"], "style_cell": root_cell,
            "constructor_call_site": call_site, "constructor_plt": snapshot["target"],
            "constructor_dynsym": CONSTRUCTOR_BINDING["symbol_index"],
            "constructor_symbol": CONSTRUCTOR_BINDING["symbol"],
            "style_argument_register": "r1", "this_argument_register": "r0",
            "this_source_move_site": args[r0].get("move_site"),
            "this_source_indexed_load_site": args[r0].get("load_site"),
            "this_source_cell": this_cell,
            "this_cell_distinct_from_style_cell": this_cell != root_cell,
            "entry_to_style_site_reachable": distance is not None,
            "entry_to_style_site_min_cfg_edges": distance,
            "full_owner_decoded": True,
        })
    trace_summary = {
        "source_sha256": VIEW_UNIFIED2_SHA256,
        "records": trace_rows,
        "coverage": {"owners": 3, "all_full_decoded": True, "cfg": "direct-intra-owner-fallthrough-and-direct-branch-only"},
    }
    digest = _canonical(trace_summary)
    if results != list(LIST_CONSTRUCTIONS) or digest != CONSTRUCTOR_TRACE_DIGEST:
        raise RuntimeError("constructor list/dataflow trace differs")
    return results, digest


def _view_stlrec_vtable(elf, blob, mappings, rel_dyn, dynsym):
    rel_by_offset = {relocation["r_offset"]: (index, relocation) for index, relocation in enumerate(rel_dyn)}
    expected = VIEW_STLREC_VTABLE
    shape = []
    for slot, cell in enumerate(range(expected["address_point"], expected["slot_cell"] + 4, 4)):
        pair = rel_by_offset.get(cell)
        if pair is None:
            shape.append({"slot": slot, "relocation_type": None, "symbol_index": None, "unrelocated_word": _word(blob, mappings, cell)})
            continue
        _index, relocation = pair
        row = {"slot": slot, "relocation_type": relocation["r_info_type"], "symbol_index": relocation["r_info_sym"]}
        if relocation["r_info_sym"]:
            row["symbol_name"] = dynsym.get_symbol(relocation["r_info_sym"]).name
        else:
            row["local_thumb_target"] = _word(blob, mappings, cell)
        shape.append(row)
    shape_digest = hashlib.sha256(json.dumps(shape, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    abi_index, abi_relocation = rel_by_offset[expected["abi_vptr_cell"]]
    abi_symbol = dynsym.get_symbol(abi_relocation["r_info_sym"])
    name_index, name_relocation = rel_by_offset[expected["name_cell"]]
    base_index, base_relocation = rel_by_offset[expected["base_link_cell"]]
    base_symbol = dynsym.get_symbol(base_relocation["r_info_sym"])
    typeinfo_index, typeinfo_relocation = rel_by_offset[expected["vtable_typeinfo_cell"]]
    slot_index, slot_relocation = rel_by_offset[expected["slot_cell"]]
    result = {
        "section": _section_name(elf, expected["slot_cell"]),
        "typeinfo": expected["typeinfo"],
        "abi_vptr_cell": expected["abi_vptr_cell"],
        "abi_vptr_relocation_index": abi_index,
        "abi_vptr_relocation_type": abi_relocation["r_info_type"],
        "abi_vptr_symbol_index": abi_relocation["r_info_sym"],
        "abi_vptr_symbol": abi_symbol.name,
        "abi_vptr_addend": _word(blob, mappings, expected["abi_vptr_cell"]),
        "name_cell": expected["name_cell"],
        "name_relocation_index": name_index,
        "name_relocation_type": name_relocation["r_info_type"],
        "name_symbol_index": name_relocation["r_info_sym"],
        "name_target": _word(blob, mappings, expected["name_cell"]),
        "type_name_encoding": _cstring(blob, mappings, _word(blob, mappings, expected["name_cell"])),
        "type_name": "ViewStlrec",
        "base_link_cell": expected["base_link_cell"],
        "base_link_relocation_index": base_index,
        "base_link_relocation_type": base_relocation["r_info_type"],
        "base_link_symbol_index": base_relocation["r_info_sym"],
        "base_link_addend": _word(blob, mappings, expected["base_link_cell"]),
        "base_rtti_symbol": base_symbol.name,
        "base_rtti_defined": base_symbol["st_shndx"] != "SHN_UNDEF",
        "base_rtti_value": base_symbol["st_value"],
        "base_rtti_size": base_symbol["st_size"],
        "offset_to_top_cell": expected["offset_to_top_cell"],
        "offset_to_top_value": _word(blob, mappings, expected["offset_to_top_cell"]),
        "vtable_typeinfo_cell": expected["vtable_typeinfo_cell"],
        "vtable_typeinfo_relocation_index": typeinfo_index,
        "vtable_typeinfo_relocation_type": typeinfo_relocation["r_info_type"],
        "vtable_typeinfo_symbol_index": typeinfo_relocation["r_info_sym"],
        "vtable_typeinfo_target": _word(blob, mappings, expected["vtable_typeinfo_cell"]),
        "address_point": expected["address_point"],
        "slot": (expected["slot_cell"] - expected["address_point"]) // 4,
        "slot_cell": expected["slot_cell"],
        "slot_relocation_index": slot_index,
        "slot_relocation_type": slot_relocation["r_info_type"],
        "slot_symbol_index": slot_relocation["r_info_sym"],
        "target_thumb_addend": _word(blob, mappings, expected["slot_cell"]),
        "target": _word(blob, mappings, expected["slot_cell"]) & ~1,
        "observed_prefix_start_slot": 0,
        "observed_prefix_end_slot": (expected["slot_cell"] - expected["address_point"]) // 4,
        "observed_prefix_slot_count": len(shape),
        "prefix_absolute_named_slot_count": sum(row["relocation_type"] == 2 and row["symbol_index"] != 0 for row in shape),
        "prefix_relative_local_slot_count": sum(row["relocation_type"] == 23 and row["symbol_index"] == 0 for row in shape),
        "prefix_relocation_shape_digest": shape_digest,
        "table_end_established": False,
    }
    if result != expected:
        raise RuntimeError("ViewStlrec RTTI/vtable identity differs")
    return result


def _metadata_from_file(source=SOURCE, definition_report=PRIOR_DEFINITION_REPORT, registry_report=PRIOR_REGISTRY_REPORT):
    source = Path(source)
    if source.is_symlink() or not source.is_file():
        raise RuntimeError("source must be a literal regular file")
    before = _sha(source)
    if source.name != "viewUnified2.so" or source.stat().st_size != VIEW_UNIFIED2_SIZE or before != VIEW_UNIFIED2_SHA256:
        raise RuntimeError("source identity differs")
    _prior_evidence(definition_report, registry_report)
    *_deps_values, ELFFile = _deps()
    blob = source.read_bytes()
    with io.BytesIO(blob) as stream:
        elf = ELFFile(stream)
        mappings = _mappings(elf)
        dynsym = elf.get_section_by_name(".dynsym")
        rel_dyn_section = elf.get_section_by_name(".rel.dyn")
        if dynsym is None or rel_dyn_section is None:
            raise RuntimeError("dynamic metadata differs")
        rel_dyn = list(rel_dyn_section.iter_relocations())
        root_inventory = _root_inventory(rel_dyn, dynsym)
        constructor_binding = _constructor_binding(elf, blob, mappings, dynsym)
        selected = _selected_owners(elf, blob, mappings)
        snapshots = _argument_snapshots(selected, blob, mappings)
        lists, trace_digest = _list_constructions(elf, blob, mappings, rel_dyn, dynsym, selected, snapshots)
        table = _view_stlrec_vtable(elf, blob, mappings, rel_dyn, dynsym)
    document = copy.deepcopy(EXPECTED_RAW_EXPORT)
    document.update({
        "root_inventory": root_inventory,
        "constructor_binding": constructor_binding,
        "list_constructions": lists,
        "constructor_trace_digest": trace_digest,
        "view_stlrec_vtable": table,
        "claims": copy.deepcopy(CLAIMS),
    })
    normalize_creative_style_menu_list_construction_export(document)
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
        return normalize_creative_style_menu_list_construction_export((adapter or FileAdapter()).metadata())
    except Exception as exc:
        raise RuntimeError("Creative Style menu-list metadata differs from exact bounded static result") from exc


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
    handle, temporary = tempfile.mkstemp(dir=str(root), prefix=".creative-style-menu-list-", suffix=".tmp")
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
    print("CREATIVE_STYLE_MENU_LIST_CONSTRUCTION_EXPORT|lists=3|sizes=4,4,2|selected_state=0|touch=0")
