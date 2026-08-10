"""Read-only α6400 Creative Style root-cell consumer exporter."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile

from pmca.analysis.creative_style_root_consumers import (
    EXPECTED_RAW_EXPORT,
    UI_LAYOUT_HEADER_GOT_BOUNDARY_DIGEST,
    VIEW_UNIFIED7_SHA256,
    VIEW_UNIFIED7_SIZE,
    normalize_creative_style_root_consumers_export,
)
from pmca.analysis.ui_layout_header_got_boundary import (
    normalize_ui_layout_header_got_boundary_export,
    summarize_ui_layout_header_got_boundary_export,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_ROOT = REPOSITORY_ROOT / ".artifacts" / "creative-style-root-consumer-trace" / "a6400-v2.00"
EXPECTED_PROGRAM = "viewUnified7.so"
_ROOT_CELLS = frozenset(EXPECTED_RAW_EXPORT["executable_scan"]["root_cells"])


def _dependencies():
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
        from capstone.arm import (
            ARM_INS_ADD, ARM_INS_ADR, ARM_INS_LDR, ARM_INS_MOV, ARM_INS_MOVT,
            ARM_INS_MOVW, ARM_INS_SUB, ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG,
            ARM_REG_PC,
        )
        from elftools.elf.elffile import ELFFile
    except ImportError as error:
        raise RuntimeError("Creative Style root consumer export requires local capstone and pyelftools") from error
    return (
        Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, ARM_INS_ADD, ARM_INS_ADR,
        ARM_INS_LDR, ARM_INS_MOV, ARM_INS_MOVT, ARM_INS_MOVW, ARM_INS_SUB,
        ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC, ELFFile,
    )


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _prel31(value, place):
    value &= 0x7FFFFFFF
    return place + (value - 0x80000000 if value & 0x40000000 else value)


def _file_offset(elf, address, width):
    matches = []
    for segment in elf.iter_segments():
        if segment["p_type"] == "PT_LOAD" and segment["p_vaddr"] <= address and address + width <= segment["p_vaddr"] + segment["p_filesz"]:
            matches.append(segment["p_offset"] + address - segment["p_vaddr"])
    if len(matches) != 1:
        raise RuntimeError("address is not uniquely file-backed")
    return matches[0]


def _word(elf, blob, address):
    offset = _file_offset(elf, address, 4)
    return int.from_bytes(blob[offset:offset + 4], "little")


def _prior(path):
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file():
        raise RuntimeError("prior UI layout-header evidence must be a regular JSON file")
    try:
        document = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError("prior UI layout-header evidence is invalid JSON") from error
    normalize_ui_layout_header_got_boundary_export(document)
    result = {
        "analysis_contract": "ui_layout_header_got_boundary",
        "canonical_export_sha256": summarize_ui_layout_header_got_boundary_export(document)["canonical_export_sha256"],
    }
    if result["canonical_export_sha256"] != UI_LAYOUT_HEADER_GOT_BOUNDARY_DIGEST:
        raise RuntimeError("prior UI layout-header evidence digest is not pinned")
    return result


def _symbol_coverage(symbol_table, address):
    exact, covering = [], []
    if symbol_table is None:
        return {"table_present": False, "exact": exact, "covering": covering}
    for symbol in symbol_table.iter_symbols():
        value, size = symbol["st_value"], symbol["st_size"]
        if value == address:
            exact.append(symbol.name)
        elif size and value < address < value + size:
            covering.append(symbol.name)
    return {"table_present": True, "exact": sorted(exact), "covering": sorted(covering)}


def _dynamic_coverage(symbol_table, address):
    coverage = _symbol_coverage(symbol_table, address)
    return {"exact": coverage["exact"], "covering": coverage["covering"]}


def _function_ranges(elf, blob):
    text = elf.get_section_by_name(".text")
    exidx = elf.get_section_by_name(".ARM.exidx")
    if text is None or exidx is None or exidx["sh_size"] % 8:
        raise RuntimeError("executable range sections are invalid")
    starts = []
    for index, offset in enumerate(range(exidx["sh_offset"], exidx["sh_offset"] + exidx["sh_size"], 8)):
        starts.append(_prel31(int.from_bytes(blob[offset:offset + 4], "little"), exidx["sh_addr"] + index * 8))
    text_start, text_end = text["sh_addr"], text["sh_addr"] + text["sh_size"]
    if len(starts) != 1358 or starts != sorted(starts) or len(set(starts)) != len(starts) or any(start < text_start or start >= text_end for start in starts):
        raise RuntimeError(".ARM.exidx ranges are not the pinned complete executable coverage")
    return text, [(start, starts[index + 1] if index + 1 < len(starts) else text_end) for index, start in enumerate(starts)]


def _pc_value(address, thumb):
    return (address + 4) & ~3 if thumb else address + 8


def _instruction_operands(instruction):
    """Return operands only for real Capstone instructions, never skipdata."""

    return None if instruction.id == 0 else instruction.operands


def _advance_root_cell_provenance(instruction, known, ids, root_cells):
    """Advance only bounded register provenance and return an exact cell load."""

    operands = instruction.operands
    if instruction.id == ids.ldr and len(operands) == 2 and operands[0].type == ids.reg and operands[1].type == ids.mem:
        destination, source = operands[0].reg, operands[1].mem
        base = known.get(source.base)
        candidate = base + source.disp if base is not None else None
        known.pop(destination, None)
        return candidate if candidate in root_cells else None
    if instruction.id == ids.adr and len(operands) == 2 and operands[0].type == ids.reg and operands[1].type == ids.imm:
        known[operands[0].reg] = operands[1].imm & 0xFFFFFFFF
        return None
    if instruction.id in (ids.add, ids.sub) and len(operands) == 3 and operands[0].type == ids.reg and operands[1].type == ids.reg and operands[2].type == ids.imm:
        destination, base, amount = operands[0].reg, operands[1].reg, operands[2].imm
        base_value = known.get(base)
        if base_value is None:
            known.pop(destination, None)
        else:
            known[destination] = (base_value + amount if instruction.id == ids.add else base_value - amount) & 0xFFFFFFFF
        return None
    if instruction.id == ids.movw and len(operands) == 2 and operands[0].type == ids.reg and operands[1].type == ids.imm:
        known[operands[0].reg] = operands[1].imm & 0xFFFF
        return None
    if instruction.id == ids.movt and len(operands) == 2 and operands[0].type == ids.reg and operands[1].type == ids.imm:
        destination = operands[0].reg
        if destination in known:
            known[destination] = (known[destination] & 0xFFFF) | ((operands[1].imm & 0xFFFF) << 16)
        return None
    if instruction.id == ids.mov and len(operands) == 2 and operands[0].type == ids.reg:
        destination, source = operands[0].reg, operands[1]
        if source.type == ids.reg and source.reg in known:
            known[destination] = known[source.reg]
        elif source.type == ids.imm:
            known[destination] = source.imm & 0xFFFFFFFF
        else:
            known.pop(destination, None)
    return None


def _scan_mode(elf, blob, text, ranges, thumb):
    (
        Cs, arch, arm_mode, thumb_mode, add, adr, ldr, mov, movt, movw, sub,
        imm, mem, reg, pc, _,
    ) = _dependencies()
    disassembler = Cs(arch, thumb_mode if thumb else arm_mode)
    disassembler.detail = True
    disassembler.skipdata = True
    ids = type("RootCellInstructionIds", (), {
        "add": add, "adr": adr, "ldr": ldr, "mov": mov, "movt": movt,
        "movw": movw, "sub": sub, "imm": imm, "mem": mem, "reg": reg,
    })
    data = text.data()
    candidates = []
    for start, end in ranges:
        known = {}
        for instruction in disassembler.disasm(data[start - text["sh_addr"]:end - text["sh_addr"]], start):
            operands = _instruction_operands(instruction)
            if operands is None:
                continue
            if instruction.id == ldr and len(operands) == 2 and operands[0].type == reg and operands[1].type == mem:
                destination, source = operands[0].reg, operands[1].mem
                if source.base == pc:
                    literal_address = _pc_value(instruction.address, thumb) + source.disp
                    try:
                        known[destination] = _word(elf, blob, literal_address)
                    except RuntimeError:
                        known.pop(destination, None)
                    continue
            if instruction.id in (add, sub) and len(operands) == 3 and operands[0].type == reg and operands[1].type == reg and operands[1].reg == pc and operands[2].type == imm:
                known[operands[0].reg] = (_pc_value(instruction.address, thumb) + operands[2].imm if instruction.id == add else _pc_value(instruction.address, thumb) - operands[2].imm) & 0xFFFFFFFF
                continue
            cell = _advance_root_cell_provenance(instruction, known, ids, _ROOT_CELLS)
            if cell is not None:
                candidates.append({
                    "mode": "thumb" if thumb else "arm",
                    "function": start,
                    "site": instruction.address,
                    "root_cell": cell,
                })
    return candidates


def _metadata_from_file(source_path, layout_header_raw_path):
    *_, ELFFile = _dependencies()
    source = Path(source_path)
    before = _sha256(source)
    if source.name != EXPECTED_PROGRAM or source.stat().st_size != VIEW_UNIFIED7_SIZE or before != VIEW_UNIFIED7_SHA256:
        raise RuntimeError("Creative Style root consumer source identity is not pinned")
    prior = _prior(layout_header_raw_path)
    blob = source.read_bytes()
    with source.open("rb") as stream:
        elf = ELFFile(stream)
        dynsym = elf.get_section_by_name(".dynsym")
        rel_dyn = elf.get_section_by_name(".rel.dyn")
        rel_plt = elf.get_section_by_name(".rel.plt")
        got = elf.get_section_by_name(".got")
        data = elf.get_section_by_name(".data")
        if dynsym is None or rel_dyn is None or rel_plt is None or got is None or data is None:
            raise RuntimeError("required Creative Style ELF metadata is missing")
        symbol = dynsym.get_symbol(544)
        if symbol.name != "cmnViewSettingNodeRootCreativeStyle" or symbol["st_info"]["bind"] != "STB_GLOBAL" or symbol["st_other"]["visibility"] != "STV_DEFAULT" or symbol["st_shndx"] != "SHN_UNDEF":
            raise RuntimeError("Creative Style dynamic symbol attributes differ")
        relocations = list(rel_dyn.iter_relocations())
        records = []
        for expected in EXPECTED_RAW_EXPORT["relocations"]:
            relocation = relocations[expected["index"]]
            if relocation["r_offset"] != expected["site"] or relocation["r_info_sym"] != 544:
                raise RuntimeError("Creative Style root relocation identity differs")
            expected_type = 21 if expected["relocation_type"] == "R_ARM_GLOB_DAT" else 2
            if relocation["r_info_type"] != expected_type:
                raise RuntimeError("Creative Style root relocation type differs")
            section = got if expected["section"] == ".got" else data
            if not section["sh_addr"] <= expected["site"] < section["sh_addr"] + section["sh_size"]:
                raise RuntimeError("Creative Style root relocation section differs")
            records.append(copy.deepcopy(expected))
        if [item["r_info_sym"] for item in rel_plt.iter_relocations() if item["r_info_sym"] == 544]:
            raise RuntimeError("Creative Style root unexpectedly has a PLT relocation")
        coverage = {
            "dynamic": _dynamic_coverage(dynsym, 0x8056C),
            "static": _symbol_coverage(elf.get_section_by_name(".symtab"), 0x8056C),
        }
        if coverage != EXPECTED_RAW_EXPORT["data_cell_symbol_coverage"]:
            raise RuntimeError("Creative Style data root cell symbol coverage differs")
        text, ranges = _function_ranges(elf, blob)
        thumb_candidates = _scan_mode(elf, blob, text, ranges, True)
        arm_candidates = _scan_mode(elf, blob, text, ranges, False)
    if _sha256(source) != before:
        raise RuntimeError("source changed during read-only static export")
    result = copy.deepcopy(EXPECTED_RAW_EXPORT)
    result["prior_ui_layout_header_got_boundary"] = prior
    result["relocations"] = records
    result["executable_scan"]["accepted_candidates"] = sorted(thumb_candidates + arm_candidates, key=lambda item: (item["mode"], item["function"], item["site"], item["root_cell"]))
    return result


def build_raw_export(adapter):
    try:
        return normalize_creative_style_root_consumers_export(adapter.metadata())
    except Exception as error:
        raise RuntimeError("Creative Style root consumer metadata differs from the exact bounded result") from error


class FileAdapter:
    def __init__(self, source_path, layout_header_raw_path):
        self.source_path = Path(source_path)
        self.layout_header_raw_path = Path(layout_header_raw_path)

    def metadata(self):
        return _metadata_from_file(self.source_path, self.layout_header_raw_path)


def write_json_atomic(output_path, document):
    output = Path(output_path)
    literal = Path(OUTPUT_ROOT).absolute()
    try:
        root = literal.resolve(strict=True)
    except OSError as error:
        raise RuntimeError("Creative Style output root must be an existing regular directory") from error
    expected = root / "raw-creative-style-root-consumers.json"
    if root != literal or root.is_symlink() or not root.is_dir() or Path(os.path.abspath(output)) != expected or output.parent.resolve(strict=True) != root or output.is_symlink() or (output.exists() and not output.is_file()):
        raise RuntimeError("Creative Style root consumer output escapes the pinned artifact root")
    handle, temporary = tempfile.mkstemp(dir=str(root), prefix=".creative-style-root-", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(document, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main(args=None):
    args = list(args if args is not None else __import__("sys").argv[1:])
    if len(args) != 3:
        raise SystemExit("usage: <source.so> <raw-ui-layout-header-got-boundary.json> <output.json>")
    output = Path(args[2])
    if Path(os.path.abspath(output)) != Path(os.path.abspath(OUTPUT_ROOT / "raw-creative-style-root-consumers.json")):
        raise RuntimeError("Creative Style root consumer main output is not the pinned artifact path")
    write_json_atomic(output, build_raw_export(FileAdapter(args[0], args[1])))
    print("CREATIVE_STYLE_ROOT_CONSUMER_EXPORT|root_relocations=2|ranges=1358|accepted=0|selector=0|touch=0")


if __name__ == "__main__":
    main()
