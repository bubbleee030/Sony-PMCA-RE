"""Read-only α6400 orientation object/table boundary exporter."""
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
    HELPER,
    normalize_orientation_af_helper_export,
    summarize_orientation_af_helper_export,
    validate_orientation_af_helper_report,
)
from pmca.analysis.orientation_object_table_boundary import (
    DIRECT_GRAPH_SUMMARY,
    EXPECTED_RAW_EXPORT,
    INITIALIZERS,
    PRIOR_ORIENTATION_DIGEST,
    PRIOR_SLOT37_DIGEST,
    PRIOR_WIDGET_TABLE_DIGEST,
    SLOT37_BINDING,
    STORAGE_CONSUMERS,
    TABLE_STORES,
    TYPE_TABLES,
    VIEW_UNIFIED2_SHA256,
    VIEW_UNIFIED2_SIZE,
    normalize_orientation_object_table_boundary_export,
)
from pmca.analysis.widget_hit_test_vtables import (
    normalize_widget_hit_test_vtables_export,
    validate_widget_hit_test_vtables_report,
)
from pmca.analysis.widget_ishit_dispatch import (
    normalize_widget_ishit_dispatch_export,
    summarize_widget_ishit_dispatch_export,
    validate_widget_ishit_dispatch_report,
)


SOURCE = ROOT / ".artifacts" / "decrypted" / "a6400-tw-v2.00" / "ma1co" / "firmware.tar_unpacked" / "0700_part_image" / "dev" / "nflasha15_unpacked" / "lib" / "viewUnified2.so"
PRIOR_ORIENTATION = ROOT / ".artifacts" / "orientation-af-helper-trace" / "a6400-v2.00" / "raw-orientation-af-helper.json"
PRIOR_ORIENTATION_REPORT = ROOT / "analysis" / "a6400-orientation-af-helper.json"
PRIOR_SLOT37 = ROOT / ".artifacts" / "widget-ishit-dispatch-trace" / "a6400-v2.00" / "raw-widget-ishit-dispatch.json"
PRIOR_SLOT37_REPORT = ROOT / "analysis" / "a6400-widget-ishit-dispatch.json"
PRIOR_WIDGET_TABLES = ROOT / ".artifacts" / "widget-hit-test-vtable-trace" / "a6400-v2.00" / "raw-widget-hit-test-vtables.json"
PRIOR_WIDGET_TABLES_REPORT = ROOT / "analysis" / "a6400-widget-hit-test-vtables.json"
ARTIFACT_BASE = ROOT / ".artifacts"
OUTPUT_ROOT = ARTIFACT_BASE / "orientation-object-table-boundary" / "a6400-v2.00"
OUTPUT_NAME = "raw-orientation-object-table-boundary.json"


def _deps():
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_GRP_CALL, CS_OP_IMM
        from capstone.arm import ARM_INS_ADD, ARM_INS_LDR, ARM_INS_MOV, ARM_INS_STR, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC, ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3
        from elftools.elf.elffile import ELFFile
    except ImportError:
        for path in (ROOT / ".artifacts" / "pydeps_vlf", ROOT / ".artifacts" / "pydeps", ROOT / ".artifacts" / "python-packages"):
            if path.is_dir():
                sys.path.insert(0, str(path))
        try:
            from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_GRP_CALL, CS_OP_IMM
            from capstone.arm import ARM_INS_ADD, ARM_INS_LDR, ARM_INS_MOV, ARM_INS_STR, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC, ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3
            from elftools.elf.elffile import ELFFile
        except ImportError as exc:
            raise RuntimeError("local Capstone and pyelftools are required") from exc
    return Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_GRP_CALL, CS_OP_IMM, ARM_INS_ADD, ARM_INS_LDR, ARM_INS_MOV, ARM_INS_STR, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC, ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3, ELFFile


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


def _prior_evidence(orientation, orientation_report, slot37, slot37_report, widget_tables, widget_tables_report):
    orientation_raw = _literal_json(orientation, "prior orientation evidence")
    normalize_orientation_af_helper_export(orientation_raw)
    orientation_summary = summarize_orientation_af_helper_export(orientation_raw)
    orientation_checked = validate_orientation_af_helper_report(_literal_json(orientation_report, "prior orientation report"))
    if orientation_summary["canonical_export_sha256"] != PRIOR_ORIENTATION_DIGEST or orientation_checked["summary"] != orientation_summary:
        raise RuntimeError("prior orientation evidence differs")

    slot37_raw = _literal_json(slot37, "prior slot-37 evidence")
    normalize_widget_ishit_dispatch_export(slot37_raw)
    slot37_summary = summarize_widget_ishit_dispatch_export(slot37_raw)
    slot37_checked = validate_widget_ishit_dispatch_report(_literal_json(slot37_report, "prior slot-37 report"))
    if slot37_summary["canonical_export_sha256"] != PRIOR_SLOT37_DIGEST or slot37_checked["dispatch_summary"] != slot37_summary:
        raise RuntimeError("prior slot-37 evidence differs")

    widget_raw = _literal_json(widget_tables, "prior Widget-compatible table evidence")
    widget_summary = normalize_widget_hit_test_vtables_export(widget_raw)
    widget_checked = validate_widget_hit_test_vtables_report(_literal_json(widget_tables_report, "prior Widget-compatible table report"))
    if widget_summary["artifact_sha256"] != PRIOR_WIDGET_TABLE_DIGEST or widget_checked["export_summary"]["artifact_sha256"] != PRIOR_WIDGET_TABLE_DIGEST:
        raise RuntimeError("prior Widget-compatible table evidence differs")
    address_points = {item["address_point"] for item in widget_raw["families"]}
    if len(address_points) != 407:
        raise RuntimeError("prior Widget-compatible address points differ")
    return address_points


def _mappings(elf):
    return [(segment["p_vaddr"], segment["p_vaddr"] + segment["p_filesz"], segment["p_offset"]) for segment in elf.iter_segments() if segment["p_type"] == "PT_LOAD"]


def _at(blob, mappings, address, length):
    offsets = [offset + address - start for start, end, offset in mappings if start <= address and address + length <= end]
    if len(offsets) != 1:
        raise RuntimeError("virtual range does not map exactly once")
    return blob[offsets[0]:offsets[0] + length]


def _word(blob, mappings, address):
    return int.from_bytes(_at(blob, mappings, address, 4), "little")


def _section_name(elf, address):
    names = [section.name for section in elf.iter_sections() if section["sh_addr"] <= address < section["sh_addr"] + section["sh_size"]]
    if len(names) != 1:
        raise RuntimeError("address section identity differs")
    return names[0]


def _prel31(value, address):
    value &= 0x7FFFFFFF
    return address + (value - 0x80000000 if value & 0x40000000 else value)


def _owner_ranges(elf):
    section = elf.get_section_by_name(".ARM.exidx")
    if section is None or section["sh_size"] % 8:
        raise RuntimeError("exception index differs")
    values = sorted(_prel31(int.from_bytes(section.data()[offset:offset + 4], "little"), section["sh_addr"] + offset) for offset in range(0, section["sh_size"], 8))
    return {owner: values[index + 1] if index + 1 < len(values) else None for index, owner in enumerate(values)}


def _operand_value(registers, operand, site, reg_kind, immediate_kind, pc):
    if operand.type == reg_kind:
        if operand.reg == pc:
            return {"value": site + 4, "source_cell": None}
        return registers.get(operand.reg)
    if operand.type == immediate_kind:
        return {"value": operand.imm, "source_cell": None}
    return None


def _add_values(left, right):
    if left is None or right is None or left["value"] is None or right["value"] is None:
        return None
    return {"value": left["value"] + right["value"], "source_cell": left.get("source_cell") or right.get("source_cell"), "provenance": None}


def _derive_initializers(elf, blob, mappings, address_points, rel_dyn, dynsym):
    (Cs, arch, thumb, call_group, immediate_kind, add_id, ldr_id, mov_id, str_id,
     mem_kind, reg_kind, pc, r0, r1, r2, r3, _ELFFile) = _deps()
    decoder = Cs(arch, thumb); decoder.detail = True
    ranges = _owner_ranges(elf)
    relocation_by_offset = {relocation["r_offset"]: (index, relocation) for index, relocation in enumerate(rel_dyn)}
    initializer_rows, store_rows = [], []
    for expected in INITIALIZERS:
        owner, end = expected["owner"], expected["end"]
        if ranges.get(owner) != end:
            raise RuntimeError("initializer exidx range differs")
        items = list(decoder.disasm(_at(blob, mappings, owner, end - owner), owner | 1))
        if sum(item.size for item in items) != end - owner:
            raise RuntimeError("initializer decode differs")
        direct_calls = []
        registers = {r0: {"value": None, "source_cell": None, "provenance": "entry-r0"}}
        stores = []
        call_receivers = {}
        for item in items:
            site = item.address & ~1
            operands = item.operands
            if item.group(call_group):
                targets = [operand.imm & ~1 for operand in operands if operand.type == immediate_kind]
                if targets:
                    direct_calls.append({"site": site, "target": targets[0]})
                    receiver = registers.get(r0)
                    call_receivers[site] = None if receiver is None else receiver.get("provenance")
                    for register in (r0, r1, r2, r3):
                        registers.pop(register, None)
            if item.id == ldr_id and len(operands) == 2 and operands[0].type == reg_kind and operands[1].type == mem_kind:
                memory = operands[1].mem
                if memory.base == pc:
                    address = ((site + 4) & ~3) + memory.disp
                else:
                    base = registers.get(memory.base)
                    index = registers.get(memory.index) if memory.index else {"value": 0}
                    address = None if base is None or index is None else base["value"] + (index["value"] << memory.lshift) + memory.disp
                registers[operands[0].reg] = None if address is None else {"value": _word(blob, mappings, address), "source_cell": address, "provenance": None}
            elif item.id == add_id and operands and operands[0].type == reg_kind:
                if len(operands) == 2:
                    left = registers.get(operands[0].reg)
                    right = _operand_value(registers, operands[1], site, reg_kind, immediate_kind, pc)
                else:
                    left = _operand_value(registers, operands[1], site, reg_kind, immediate_kind, pc)
                    right = _operand_value(registers, operands[2], site, reg_kind, immediate_kind, pc)
                registers[operands[0].reg] = _add_values(left, right)
            elif item.id == mov_id and len(operands) == 2 and operands[0].type == reg_kind:
                registers[operands[0].reg] = _operand_value(registers, operands[1], site, reg_kind, immediate_kind, pc)
            elif item.id == str_id and len(operands) == 2 and operands[0].type == reg_kind and operands[1].type == mem_kind and operands[1].mem.disp == 0:
                value = registers.get(operands[0].reg)
                base = registers.get(operands[1].mem.base)
                if value is not None and base is not None and not operands[1].mem.index:
                    stores.append({
                        "site": site,
                        "source_cell": value.get("source_cell"),
                        "target": value["value"],
                        "base_register": decoder.reg_name(operands[1].mem.base),
                        "receiver_provenance": base.get("provenance"),
                    })
        row = {
            "role": expected["role"], "owner": owner, "end": end, "range_size": end - owner,
            "decoded_item_count": len(items), "complete": True, "direct_calls": direct_calls,
            "offset_zero_store_site": stores[-1]["site"] if stores else None,
            "store_base_register": stores[-1]["base_register"] if stores else None,
            "store_receiver_provenance": stores[-1]["receiver_provenance"] if stores else None,
        }
        if expected["role"] == "derived":
            row.update({
                "base_call_receiver_provenance": call_receivers.get(0x30E9F0),
                "saved_entry_register": stores[-1]["base_register"] if stores else None,
            })
        if row != expected or len(stores) != 1:
            raise RuntimeError("initializer structure differs")
        initializer_rows.append(row)
        store = stores[0]
        relocation_pair = relocation_by_offset.get(store["source_cell"])
        if relocation_pair is None:
            raise RuntimeError("initializer table-source relocation is absent")
        relocation_index, relocation = relocation_pair
        store_row = {
            "role": expected["role"], "site": store["site"], "source_cell": store["source_cell"],
            "source_section": _section_name(elf, store["source_cell"]), "relocation_index": relocation_index,
            "relocation_type": relocation["r_info_type"], "target": store["target"],
            "target_section": _section_name(elf, store["target"]),
            "widget_address_point_match_count": int(store["target"] in address_points),
        }
        store_rows.append(store_row)
    if store_rows != list(TABLE_STORES):
        raise RuntimeError("initializer table stores differ")
    return initializer_rows, store_rows


def _cstring(blob, mappings, address):
    pieces = []
    while len(pieces) <= 128:
        value = _at(blob, mappings, address + len(pieces), 1)[0]
        if value == 0:
            return bytes(pieces).decode("ascii")
        pieces.append(value)
    raise RuntimeError("RTTI name is not bounded")


def _relocation_rows(rel_dyn, dynsym, start, end):
    return [
        {
            "index": index,
            "offset": relocation["r_offset"],
            "type": relocation["r_info_type"],
            "symbol_index": relocation["r_info_sym"],
            "symbol": dynsym.get_symbol(relocation["r_info_sym"]).name if relocation["r_info_sym"] else "",
        }
        for index, relocation in enumerate(rel_dyn)
        if start <= relocation["r_offset"] < end
    ]


def _derive_type_tables(elf, blob, mappings, rel_dyn, dynsym):
    relocation_by_offset = {relocation["r_offset"]: (index, relocation) for index, relocation in enumerate(rel_dyn)}
    rows = []
    for expected in TYPE_TABLES:
        address_point = expected["address_point"]
        typeinfo = _word(blob, mappings, address_point - 4)
        typeinfo_relocation = relocation_by_offset.get(typeinfo)
        name_relocation = relocation_by_offset.get(typeinfo + 4)
        if typeinfo_relocation is None or name_relocation is None:
            raise RuntimeError("RTTI relocation identity differs")
        abi_name = dynsym.get_symbol(typeinfo_relocation[1]["r_info_sym"]).name
        abi_type = "__si_class_type_info" if abi_name.endswith("20__si_class_type_infoE") else "__class_type_info" if abi_name.endswith("17__class_type_infoE") else ""
        encoded = _cstring(blob, mappings, _word(blob, mappings, typeinfo + 4))
        prefix_length = "".join(character for character in encoded if character.isdigit())
        type_name = encoded[len(prefix_length):]
        base_typeinfo = _word(blob, mappings, typeinfo + 8) if abi_type == "__si_class_type_info" else None
        relocations = _relocation_rows(rel_dyn, dynsym, expected["window_start"], expected["window_end"])
        result = {
            "role": expected["role"], "type_name": type_name, "rtti_encoding": encoded,
            "typeinfo": typeinfo, "abi_type_info": abi_type, "base_typeinfo": base_typeinfo,
            "address_point": address_point, "window_start": expected["window_start"], "window_end": expected["window_end"],
            "slot_count": (expected["window_end"] - address_point) // 4,
            "relocation_count": len(relocations),
            "relative_relocation_count": sum(item["type"] == 23 for item in relocations),
            "absolute_relocation_count": sum(item["type"] == 2 for item in relocations),
            "pure_virtual_reference_count": sum(item["symbol"] == "__cxa_pure_virtual" for item in relocations),
            "relocation_digest": _canonical(relocations),
        }
        if abi_type == "__si_class_type_info":
            base_link_cell = typeinfo + 8
            base_link_pair = relocation_by_offset.get(base_link_cell)
            if base_link_pair is None:
                raise RuntimeError("RTTI base-link relocation is absent")
            base_link_index, base_link_relocation = base_link_pair
            result.update({
                "base_link_cell": base_link_cell,
                "base_link_relocation_index": base_link_index,
                "base_link_relocation_type": base_link_relocation["r_info_type"],
                "base_link_relocation_symbol": base_link_relocation["r_info_sym"],
            })
        rows.append(result)
    if rows != list(TYPE_TABLES):
        raise RuntimeError("AF RTTI/vtable identity differs")
    cell = TYPE_TABLES[1]["address_point"] + 0x94
    relocation_index, relocation = relocation_by_offset[cell]
    target = _word(blob, mappings, cell) & ~1
    matches = sum((symbol["st_value"] & ~1) == target and symbol["st_shndx"] != "SHN_UNDEF" for symbol in dynsym.iter_symbols())
    binding = {
        "slot": 37, "offset": 0x94, "cell": cell, "relocation_index": relocation_index,
        "relocation_type": relocation["r_info_type"], "target": target,
        "target_section": _section_name(elf, target), "defined_dynsym_match_count": matches,
    }
    if binding != SLOT37_BINDING:
        raise RuntimeError("derived slot-37 binding differs")
    return rows, binding


def _derive_storage_consumers(blob, mappings):
    (Cs, arch, thumb, call_group, immediate_kind, add_id, ldr_id, _mov_id, _str_id,
     mem_kind, reg_kind, pc, _r0, _r1, _r2, _r3, _ELFFile) = _deps()
    decoder = Cs(arch, thumb); decoder.detail = True
    items = list(decoder.disasm(_at(blob, mappings, HELPER["address"], HELPER["decoded_prefix_size"]), HELPER["address"] | 1))
    if sum(item.size for item in items) != HELPER["decoded_prefix_size"]:
        raise RuntimeError("helper prefix decode differs")
    pending, register_values, materializations, zero_loads, calls = {}, {}, [], [], []
    for item in items:
        site = item.address & ~1
        operands = item.operands
        if item.group(call_group):
            targets = [operand.imm & ~1 for operand in operands if operand.type == immediate_kind]
            if targets:
                calls.append({"site": site, "target": targets[0]})
        if item.id == ldr_id and len(operands) == 2 and operands[0].type == reg_kind and operands[1].type == mem_kind:
            memory = operands[1].mem
            if memory.base == pc:
                cell = ((site + 4) & ~3) + memory.disp
                pending[operands[0].reg] = (site, _word(blob, mappings, cell))
            elif memory.disp == 0 and register_values.get(memory.base) in (HELPER["guard_storage"], HELPER["return_storage"]):
                zero_loads.append(site)
        elif item.id == add_id and operands and operands[0].type == reg_kind:
            destination = operands[0].reg
            reads, _writes = item.regs_access()
            if destination in pending and pc in reads:
                load_site, value = pending.pop(destination)
                resolved = value + ((site + 4) & ~3)
                register_values[destination] = resolved
                materializations.append({"load_site": load_site, "site": site, "target": resolved})
    core = {
        "guard_storage": HELPER["guard_storage"],
        "object_storage": HELPER["return_storage"],
        "guard_materialization_sites": [item["site"] for item in materializations if item["target"] == HELPER["guard_storage"]],
        "object_materialization_sites": [item["site"] for item in materializations if item["target"] == HELPER["return_storage"]],
        "offset_zero_load_sites": zero_loads,
        "initializer_calls": [item for item in calls if item["target"] == INITIALIZERS[1]["owner"]],
        "post_initializer_unresolved_calls": [item for item in calls if item["target"] in (0x156344, 0x1563BC)],
    }
    result = {**core, "canonical_digest": _canonical(core)}
    if result != STORAGE_CONSUMERS:
        raise RuntimeError("direct storage consumer inventory differs")
    return result


def _metadata_from_file(
    source=SOURCE,
    prior_orientation=PRIOR_ORIENTATION,
    prior_orientation_report=PRIOR_ORIENTATION_REPORT,
    prior_slot37=PRIOR_SLOT37,
    prior_slot37_report=PRIOR_SLOT37_REPORT,
    prior_widget_tables=PRIOR_WIDGET_TABLES,
    prior_widget_tables_report=PRIOR_WIDGET_TABLES_REPORT,
):
    source = Path(source)
    before = _sha(source)
    if source.name != "viewUnified2.so" or source.stat().st_size != VIEW_UNIFIED2_SIZE or before != VIEW_UNIFIED2_SHA256:
        raise RuntimeError("source identity differs")
    address_points = _prior_evidence(prior_orientation, prior_orientation_report, prior_slot37, prior_slot37_report, prior_widget_tables, prior_widget_tables_report)
    *_deps_values, ELFFile = _deps()
    blob = source.read_bytes()
    with io.BytesIO(blob) as stream:
        elf = ELFFile(stream)
        mappings = _mappings(elf)
        rel_dyn_section = elf.get_section_by_name(".rel.dyn")
        dynsym = elf.get_section_by_name(".dynsym")
        if rel_dyn_section is None or dynsym is None:
            raise RuntimeError("dynamic metadata differs")
        rel_dyn = list(rel_dyn_section.iter_relocations())
        initializers, stores = _derive_initializers(elf, blob, mappings, address_points, rel_dyn, dynsym)
        type_tables, slot37_binding = _derive_type_tables(elf, blob, mappings, rel_dyn, dynsym)
        storage_consumers = _derive_storage_consumers(blob, mappings)
    document = copy.deepcopy(EXPECTED_RAW_EXPORT)
    document.update({
        "initializers": initializers,
        "table_stores": stores,
        "type_tables": type_tables,
        "slot37_binding": slot37_binding,
        "storage_consumers": storage_consumers,
        "direct_graph_summary": copy.deepcopy(DIRECT_GRAPH_SUMMARY),
    })
    normalize_orientation_object_table_boundary_export(document)
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
        return normalize_orientation_object_table_boundary_export((adapter or FileAdapter()).metadata())
    except Exception as exc:
        raise RuntimeError("orientation object/table metadata differs from exact bounded static result") from exc


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
    handle, temporary = tempfile.mkstemp(dir=str(root), prefix=".orientation-object-table-", suffix=".tmp")
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
    print("ORIENTATION_OBJECT_TABLE_BOUNDARY_EXPORT|types=2|widget_matches=0|menu_touch=0")
