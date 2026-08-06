"""Read-only α6400 orientation/AF wrapper and helper exporter."""
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
from pmca.analysis.orientation_af_helper import (
    EXPECTED_RAW_EXPORT, GETTER_BINDING, HELPER, HELPER_CALL_INVENTORY,
    JUMP_SLOT_RELOCATION_INDICES, MEMBER_INVENTORY, PRIOR_SLOT37_DIGEST,
    RELOCATION_SUMMARY, SETTER_BINDING, VIEW_UNIFIED2_SHA256, VIEW_UNIFIED2_SIZE,
    normalize_orientation_af_helper_export,
)
from pmca.analysis.widget_ishit_dispatch import (
    normalize_widget_ishit_dispatch_export, summarize_widget_ishit_dispatch_export,
    validate_widget_ishit_dispatch_report,
)


SOURCE = ROOT / ".artifacts" / "decrypted" / "a6400-tw-v2.00" / "ma1co" / "firmware.tar_unpacked" / "0700_part_image" / "dev" / "nflasha15_unpacked" / "lib" / "viewUnified2.so"
PRIOR_SLOT37 = ROOT / ".artifacts" / "widget-ishit-dispatch-trace" / "a6400-v2.00" / "raw-widget-ishit-dispatch.json"
PRIOR_SLOT37_REPORT = ROOT / "analysis" / "a6400-widget-ishit-dispatch.json"
ARTIFACT_BASE = ROOT / ".artifacts"
OUTPUT_ROOT = ARTIFACT_BASE / "orientation-af-helper-trace" / "a6400-v2.00"
OUTPUT_NAME = "raw-orientation-af-helper.json"
CLASS_PREFIX = "_ZN27CmnWrpOrientationRegisterAF"
GETTER_SYMBOL = CLASS_PREFIX + "26getRecallRegisteredAfFrameEv"
SETTER_SYMBOL = CLASS_PREFIX + "26setRecallRegisteredAfFrameEi"


def _deps():
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_GRP_CALL, CS_GRP_JUMP, CS_OP_IMM
        from capstone.arm import ARM_INS_ADD, ARM_INS_LDR, ARM_INS_POP, ARM_INS_PUSH, ARM_OP_MEM, ARM_OP_REG, ARM_REG_LR, ARM_REG_PC, ARM_REG_R0, ARM_REG_R1, ARM_REG_R2
        from elftools.elf.elffile import ELFFile
    except ImportError:
        for path in (ROOT / ".artifacts" / "pydeps_vlf", ROOT / ".artifacts" / "pydeps", ROOT / ".artifacts" / "python-packages"):
            if path.is_dir(): sys.path.insert(0, str(path))
        try:
            from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_GRP_CALL, CS_GRP_JUMP, CS_OP_IMM
            from capstone.arm import ARM_INS_ADD, ARM_INS_LDR, ARM_INS_POP, ARM_INS_PUSH, ARM_OP_MEM, ARM_OP_REG, ARM_REG_LR, ARM_REG_PC, ARM_REG_R0, ARM_REG_R1, ARM_REG_R2
            from elftools.elf.elffile import ELFFile
        except ImportError as exc:
            raise RuntimeError("local Capstone and pyelftools are required") from exc
    return (Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_GRP_CALL, CS_GRP_JUMP, CS_OP_IMM,
            ARM_INS_ADD, ARM_INS_LDR, ARM_INS_POP, ARM_INS_PUSH, ARM_OP_MEM, ARM_OP_REG,
            ARM_REG_LR, ARM_REG_PC, ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ELFFile)


def _sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _canonical(value):
    return hashlib.sha256((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest()


def _prel31(value, address):
    value &= 0x7fffffff
    return address + (value - 0x80000000 if value & 0x40000000 else value)


def _mappings(elf):
    return [(segment["p_vaddr"], segment["p_vaddr"] + segment["p_filesz"], segment["p_offset"]) for segment in elf.iter_segments() if segment["p_type"] == "PT_LOAD"]


def _at(blob, mappings, address, length):
    offsets = [offset + address - start for start, end, offset in mappings if start <= address and address + length <= end]
    if len(offsets) != 1: raise RuntimeError("virtual range does not map exactly once")
    return blob[offsets[0]:offsets[0] + length]


def _try_word(blob, mappings, address):
    try: return int.from_bytes(_at(blob, mappings, address, 4), "little")
    except RuntimeError: return None


def _owners(elf):
    section = elf.get_section_by_name(".ARM.exidx")
    if section is None or section["sh_size"] % 8: raise RuntimeError("exception index differs")
    values = sorted(_prel31(int.from_bytes(section.data()[offset:offset + 4], "little"), section["sh_addr"] + offset) for offset in range(0, section["sh_size"], 8))
    return [(value, values[index + 1] if index + 1 < len(values) else None) for index, value in enumerate(values)]


def _complete_edges(owners, blob, mappings):
    Cs, arch, _arm, thumb, call, jump, immediate, *_rest = _deps()
    decoder = Cs(arch, thumb); decoder.detail = True
    edges, incomplete, terminal = {}, 0, 0
    for owner, end in owners:
        if end is None: terminal += 1; continue
        items = list(decoder.disasm(_at(blob, mappings, owner, end - owner), owner | 1))
        if sum(item.size for item in items) != end - owner:
            incomplete += 1; continue
        direct = []
        for item in items:
            if item.group(call) or item.group(jump):
                for operand in item.operands:
                    if operand.type == immediate: direct.append((item.address & ~1, operand.imm & ~1))
        edges[owner] = direct
    if (len(owners), len(edges), incomplete, terminal) != (30463, 28869, 1593, 1):
        raise RuntimeError("complete owner accounting differs")
    return edges


def _member_records(dynsym):
    records = []
    for index, symbol in enumerate(dynsym.iter_symbols()):
        if symbol.name.startswith(CLASS_PREFIX) and symbol["st_info"]["type"] == "STT_FUNC" and symbol["st_shndx"] != "SHN_UNDEF":
            records.append({"dynsym": index, "entry": symbol["st_value"] & ~1, "size": symbol["st_size"], "name": symbol.name})
    records.sort(key=lambda item: item["dynsym"])
    summary = {"method_count": len(records), "aggregate_size": sum(item["size"] for item in records), "canonical_digest": _canonical(records)}
    if summary != MEMBER_INVENTORY: raise RuntimeError("orientation/AF member inventory differs")
    return records


def _helper_calls(edges, members):
    all_calls = sorted({(owner, site) for owner, owner_edges in edges.items() for site, target in owner_edges if target == HELPER["address"]})
    typed = []
    for member in members:
        sites = [(owner, site) for owner, site in all_calls if member["entry"] <= site < member["entry"] + member["size"]]
        if len(sites) != 1: raise RuntimeError("member helper link is not exact")
        _owner, site = sites[0]
        typed.append({"dynsym": member["dynsym"], "entry": member["entry"], "site": site, "helper": HELPER["address"]})
    typed.sort(key=lambda item: item["dynsym"])
    typed_site_values = {item["site"] for item in typed}
    remainder = [{"owner": owner, "site": site, "helper": HELPER["address"]} for owner, site in all_calls if site not in typed_site_values]
    all_records = [{"owner": owner, "site": site, "helper": HELPER["address"]} for owner, site in all_calls]
    summary = {
        "helper": HELPER["address"], "total_count": len(all_calls), "typed_member_count": len(typed), "non_member_count": len(remainder),
        "typed_member_digest": _canonical(typed), "non_member_digest": _canonical(remainder), "all_call_digest": _canonical(all_records),
    }
    if summary != HELPER_CALL_INVENTORY: raise RuntimeError("helper caller inventory differs")
    return summary


def _plt_stubs(elf, blob, mappings):
    Cs, arch, arm, *_rest = _deps()
    decoder = Cs(arch, arm); decoder.detail = True
    section = elf.get_section_by_name(".plt")
    if section is None: raise RuntimeError("PLT is absent")
    result = {}
    for address in range(section["sh_addr"], section["sh_addr"] + section["sh_size"] - 11, 4):
        items = list(decoder.disasm(_at(blob, mappings, address, 12), address))
        if len(items) != 3 or [item.mnemonic for item in items] != ["add", "add", "ldr"]: continue
        try: got = address + 8 + items[0].operands[2].imm + items[1].operands[2].imm + items[2].operands[1].mem.disp
        except (AttributeError, IndexError): continue
        if got in result: raise RuntimeError("PLT GOT mapping is ambiguous")
        result[got] = address
    return result


def _binding(symbol_name, expected, dynsym, relplt, stubs, edges):
    symbol = dynsym.get_symbol(expected["dynsym"])
    relocations = list(relplt.iter_relocations())
    relocation = relocations[expected["relocation_index"]]
    if symbol.name != symbol_name or (symbol["st_value"] & ~1, symbol["st_size"]) != (expected["entry"], expected["size"]):
        raise RuntimeError("recall-frame symbol differs")
    if relocation.entry.r_info_sym != expected["dynsym"] or relocation.entry.r_offset != expected["got"] or stubs.get(expected["got"]) != expected["plt"]:
        raise RuntimeError("recall-frame dynamic binding differs")
    rows = sorted((owner, site) for owner, owner_edges in edges.items() for site, target in owner_edges if target == expected["plt"])
    result = dict(expected)
    result["direct_site_count"] = len(rows); result["direct_owner_count"] = len({owner for owner, _site in rows})
    result["callsite_digest"] = hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest()
    if result != expected: raise RuntimeError("recall-frame caller inventory differs")
    return result


def _jump_slots_and_relocations(elf, blob, mappings, members):
    dynsym, relplt, reldyn = (elf.get_section_by_name(name) for name in (".dynsym", ".rel.plt", ".rel.dyn"))
    if dynsym is None or relplt is None or reldyn is None: raise RuntimeError("dynamic relocation sections differ")
    indices = []
    for index, relocation in enumerate(relplt.iter_relocations()):
        symbol = dynsym.get_symbol(relocation.entry.r_info_sym)
        if symbol.name.startswith(CLASS_PREFIX):
            if relocation.entry.r_info_type != 22: raise RuntimeError("class PLT relocation type differs")
            indices.append(index)
    if tuple(indices) != JUMP_SLOT_RELOCATION_INDICES: raise RuntimeError("class JUMP_SLOT inventory differs")
    method_entries = {item["entry"] for item in members}
    addend_hits = 0; named_storage = 0
    for relocation in reldyn.iter_relocations():
        value = _try_word(blob, mappings, relocation.entry.r_offset)
        if value is not None and (value & ~1) in method_entries: addend_hits += 1
        if relocation.entry.r_offset in {HELPER["guard_storage"], HELPER["return_storage"]} and relocation.entry.r_info_sym:
            named_storage += 1
    for relocation in relplt.iter_relocations():
        if relocation.entry.r_offset in {HELPER["guard_storage"], HELPER["return_storage"]} and relocation.entry.r_info_sym:
            named_storage += 1
    names = [symbol.name for symbol in dynsym.iter_symbols()]
    type_prefixes = (CLASS_PREFIX + "C1", CLASS_PREFIX + "C2", CLASS_PREFIX + "D0", CLASS_PREFIX + "D1", CLASS_PREFIX + "D2", "_ZTV27CmnWrpOrientationRegisterAF", "_ZTI27CmnWrpOrientationRegisterAF", "_ZTS27CmnWrpOrientationRegisterAF")
    summary = {"rel_dyn_count": reldyn.num_relocations(), "rel_plt_count": relplt.num_relocations(), "method_entry_addend_hit_count": addend_hits, "object_or_guard_named_relocation_count": named_storage, "class_ctor_dtor_vtable_rtti_symbol_count": sum(any(name.startswith(prefix) for prefix in type_prefixes) for name in names)}
    if summary != RELOCATION_SUMMARY: raise RuntimeError("relocation correlation differs")
    return list(indices), summary


def _helper_metadata(elf, blob, mappings, owners, relplt, dynsym, stubs):
    (Cs, arch, _arm, thumb, call, jump, immediate, add, ldr, pop, push, mem, reg,
     lr, pc, r0, r1, r2, _ELFFile) = _deps()
    from capstone.arm import ARM_INS_BLX, ARM_REG_R4
    ranges = {owner: end for owner, end in owners}
    if ranges.get(HELPER["address"]) != HELPER["end"]: raise RuntimeError("helper exidx range differs")
    decoder = Cs(arch, thumb); decoder.detail = True
    items = list(decoder.disasm(_at(blob, mappings, HELPER["address"], HELPER["range_size"]), HELPER["address"] | 1))
    if sum(item.size for item in items) != HELPER["decoded_prefix_size"] or len(items) != HELPER["decoded_item_count"]:
        raise RuntimeError("helper executable prefix differs")
    controls = []
    for item in items:
        if item.group(call) or item.group(jump):
            targets = [operand.imm & ~1 for operand in item.operands if operand.type == immediate]
            if len(targets) != 1: raise RuntimeError("helper control target differs")
            site, target = item.address & ~1, targets[0]
            if item.group(call):
                kind = "call-local" if target == HELPER["initializer_target"] else "call-guard-abort" if target == HELPER["guard_abort_binding"]["plt"] else "call-unresolved-plt"
            else: kind = "conditional"
            controls.append({"kind": kind, "site": site, "target": target})
    if controls != HELPER["control_edges"]: raise RuntimeError("helper CFG edge inventory differs")
    returns = [item.address & ~1 for item in items if item.id == pop and pc in [operand.reg for operand in item.operands if operand.type == reg]]
    if returns != [HELPER["return_site"]]: raise RuntimeError("helper return differs")
    pending, materializations = {}, []
    for item in items:
        site = item.address & ~1
        if item.id == ldr and len(item.operands) == 2 and item.operands[0].type == reg and item.operands[1].type == mem and item.operands[1].mem.base == pc:
            cell = ((site + 4) & ~3) + item.operands[1].mem.disp
            pending[item.operands[0].reg] = (site, int.from_bytes(_at(blob, mappings, cell, 4), "little"))
        elif item.id == add and len(item.operands) >= 2 and item.operands[0].type == reg:
            destination = item.operands[0].reg; reads, _writes = item.regs_access()
            if destination in pending and pc in reads:
                load_site, value = pending.pop(destination)
                materializations.append((load_site, site, value + ((site + 4) & ~3), destination))
    expected_materializations = [(0x35F424, 0x35F428, 0xB2EFF0, r0), (0x35F42A, 0x35F430, 0x9446A0, ARM_REG_R4), (0x35F43E, 0x35F440, 0xB2EFF4, r0), (0x35F446, 0x35F448, 0xB2EFF0, r0), (0x35F450, 0x35F454, 0xB2EFF4, r0), (0x35F45E, 0x35F460, 0xB2EFF4, r0), (0x35F464, 0x35F466, 0xB2EFEE, r0)]
    if materializations != expected_materializations: raise RuntimeError("helper address materialization differs")
    by_site = {item.address & ~1: item for item in items}
    initializer = by_site.get(HELPER["initializer_call_site"])
    if initializer is None or not initializer.group(call) or [operand.imm & ~1 for operand in initializer.operands if operand.type == immediate] != [HELPER["initializer_target"]]:
        raise RuntimeError("helper initializer call differs")
    if [item.address & ~1 for item in items if 0x35F440 < (item.address & ~1) < HELPER["initializer_call_site"]]:
        raise RuntimeError("helper initializer argument is not adjacent")
    if [item.address & ~1 for item in items if 0x35F460 < (item.address & ~1) < HELPER["return_site"]]:
        raise RuntimeError("helper return value is not adjacent")
    first_access = {}
    for item in items:
        reads, writes = item.regs_access()
        for register in (r0, r1, r2):
            if register not in first_access and (register in reads or register in writes): first_access[register] = (register in reads, register in writes)
    if first_access.get(r0) != (False, True) or any(first_access.get(register, (False, False))[0] for register in (r1, r2)):
        raise RuntimeError("helper entry argument provenance differs")
    lr_reads = [item.address & ~1 for item in items if lr in item.regs_access()[0]]
    if lr_reads != [0x35F426] or next(item for item in items if (item.address & ~1) == 0x35F426).id != push:
        raise RuntimeError("helper LR provenance differs")
    abort = HELPER["guard_abort_binding"]; relocation = list(relplt.iter_relocations())[abort["relocation_index"]]
    if relocation.entry.r_info_sym != abort["dynsym"] or relocation.entry.r_offset != abort["got"] or stubs.get(abort["got"]) != abort["plt"] or dynsym.get_symbol(abort["dynsym"]).name != "__cxa_guard_abort":
        raise RuntimeError("guard-abort binding differs")
    receiver_items = list(decoder.disasm(_at(blob, mappings, 0x35F66C, 0x12), 0x35F66D))
    receiver_by_site = {item.address & ~1: item for item in receiver_items}
    helper_call = receiver_by_site.get(0x35F670)
    if helper_call is None or not helper_call.group(call) or [operand.imm & ~1 for operand in helper_call.operands if operand.type == immediate] != [HELPER["address"]]:
        raise RuntimeError("helper receiver call differs")
    vptr_load, slot_load, virtual_call = (receiver_by_site.get(site) for site in (0x35F674, 0x35F676, 0x35F67A))
    if (vptr_load is None or vptr_load.id != ldr or len(vptr_load.operands) != 2 or vptr_load.operands[0].type != reg or vptr_load.operands[1].type != mem or vptr_load.operands[1].mem.base != r0 or vptr_load.operands[1].mem.disp != 0):
        raise RuntimeError("helper-returned receiver vptr load differs")
    vptr_register = vptr_load.operands[0].reg
    if (slot_load is None or slot_load.id != ldr or len(slot_load.operands) != 2 or slot_load.operands[0].type != reg or slot_load.operands[1].type != mem or slot_load.operands[1].mem.base != vptr_register or slot_load.operands[1].mem.disp != 0x94):
        raise RuntimeError("helper-returned receiver slot load differs")
    call_register = slot_load.operands[0].reg
    if virtual_call is None or virtual_call.id != ARM_INS_BLX or len(virtual_call.operands) != 1 or virtual_call.operands[0].type != reg or virtual_call.operands[0].reg != call_register:
        raise RuntimeError("helper-returned receiver virtual call differs")
    return copy.deepcopy(HELPER)


def _literal_json(path, label):
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file(): raise RuntimeError(label + " must be a literal regular file")
    try: return json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc: raise RuntimeError(label + " differs") from exc


def _prior_slot37(raw_path, report_path):
    raw = _literal_json(raw_path, "prior slot-37 evidence"); normalize_widget_ishit_dispatch_export(raw)
    report = validate_widget_ishit_dispatch_report(_literal_json(report_path, "prior slot-37 report"))
    summary = summarize_widget_ishit_dispatch_export(raw)
    if summary["canonical_export_sha256"] != PRIOR_SLOT37_DIGEST or report["dispatch_summary"] != summary:
        raise RuntimeError("prior slot-37 evidence differs")
    return {"analysis_contract": "generic_slot37_dispatch", "canonical_export_sha256": PRIOR_SLOT37_DIGEST}


def _metadata_from_file(source=SOURCE, prior_slot37=PRIOR_SLOT37, prior_slot37_report=PRIOR_SLOT37_REPORT):
    source = Path(source); before = _sha(source)
    if source.name != "viewUnified2.so" or source.stat().st_size != VIEW_UNIFIED2_SIZE or before != VIEW_UNIFIED2_SHA256:
        raise RuntimeError("source identity differs")
    prior = _prior_slot37(prior_slot37, prior_slot37_report)
    *_deps_values, ELFFile = _deps(); blob = source.read_bytes()
    with io.BytesIO(blob) as stream:
        elf = ELFFile(stream); mappings = _mappings(elf); owners = _owners(elf); edges = _complete_edges(owners, blob, mappings)
        dynsym, relplt = elf.get_section_by_name(".dynsym"), elf.get_section_by_name(".rel.plt")
        if dynsym is None or relplt is None: raise RuntimeError("dynamic metadata differs")
        members = _member_records(dynsym); helper_calls = _helper_calls(edges, members); stubs = _plt_stubs(elf, blob, mappings)
        getter = _binding(GETTER_SYMBOL, GETTER_BINDING, dynsym, relplt, stubs, edges)
        setter = _binding(SETTER_SYMBOL, SETTER_BINDING, dynsym, relplt, stubs, edges)
        jump_slots, relocation_summary = _jump_slots_and_relocations(elf, blob, mappings, members)
        helper = _helper_metadata(elf, blob, mappings, owners, relplt, dynsym, stubs)
    document = copy.deepcopy(EXPECTED_RAW_EXPORT)
    document.update({"prior_slot37_dispatch": prior, "member_inventory": MEMBER_INVENTORY, "helper_call_inventory": helper_calls, "jump_slot_relocation_indices": jump_slots, "getter_binding": getter, "setter_binding": setter, "helper": helper, "relocation_summary": relocation_summary})
    normalize_orientation_af_helper_export(document)
    if _sha(source) != before: raise RuntimeError("source changed during static export")
    return document


class FileAdapter:
    def __init__(self, source=SOURCE, prior_slot37=PRIOR_SLOT37, prior_slot37_report=PRIOR_SLOT37_REPORT):
        self.source, self.prior_slot37, self.prior_slot37_report = source, prior_slot37, prior_slot37_report
    def metadata(self): return _metadata_from_file(self.source, self.prior_slot37, self.prior_slot37_report)


def build_raw_export(adapter=None):
    try: return normalize_orientation_af_helper_export((adapter or FileAdapter()).metadata())
    except Exception as exc: raise RuntimeError("orientation/AF helper metadata differs from exact bounded static result") from exc


def _literal_directory_under(root, base):
    base, root = Path(os.path.abspath(os.fspath(base))), Path(os.path.abspath(os.fspath(root)))
    if base.is_symlink() or not base.is_dir() or base.resolve(strict=True) != base: raise RuntimeError("artifact base is not literal")
    try: root.relative_to(base); resolved = root.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc: raise RuntimeError("output root is not contained") from exc
    if root.is_symlink() or not root.is_dir() or resolved != root: raise RuntimeError("output root escapes through a symlink")
    return root


def prepare_output_root(approved_root=OUTPUT_ROOT, artifact_base=ARTIFACT_BASE):
    base, root = Path(os.path.abspath(os.fspath(artifact_base))), Path(os.path.abspath(os.fspath(approved_root)))
    _literal_directory_under(base, base)
    try: relative = root.relative_to(base)
    except ValueError as exc: raise RuntimeError("output root is not contained") from exc
    current = base
    for part in relative.parts:
        candidate = current / part
        if candidate.is_symlink() or (candidate.exists() and not candidate.is_dir()): raise RuntimeError("output ancestor is not literal")
        if not candidate.exists(): candidate.mkdir()
        if candidate.is_symlink() or candidate.resolve(strict=True) != candidate: raise RuntimeError("output root escapes through a symlink")
        current = candidate
    return _literal_directory_under(root, base)


def write_json_atomic(output, document, approved_root=OUTPUT_ROOT, artifact_base=ARTIFACT_BASE):
    root = _literal_directory_under(approved_root, artifact_base); output = Path(os.path.abspath(os.fspath(output)))
    if output.name != OUTPUT_NAME or output.parent != root or output.is_symlink() or (output.exists() and not output.is_file()): raise RuntimeError("output containment differs")
    handle, temporary = tempfile.mkstemp(dir=str(root), prefix=".orientation-af-helper-", suffix=".tmp")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(json.dumps(document, sort_keys=True, separators=(",", ":")).encode() + b"\n"); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, output)
    except BaseException:
        try: os.unlink(temporary)
        except FileNotFoundError: pass
        raise


if __name__ == "__main__":
    prepare_output_root(); write_json_atomic(OUTPUT_ROOT / OUTPUT_NAME, build_raw_export())
    print("ORIENTATION_AF_HELPER_EXPORT|members=42|helper_callers=62|stable_storage=1|concrete_type=0")
