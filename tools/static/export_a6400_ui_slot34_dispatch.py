"""Read-only bounded structural search for α6400 UI slot-34 dispatches."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile

from pmca.analysis.ui_factory_owner_registration import (
    normalize_ui_factory_owner_registration_export,
    summarize_ui_factory_owner_registration_export,
)
from pmca.analysis.ui_layout_vtable_interface import (
    normalize_ui_layout_vtable_interface_export,
    summarize_ui_layout_vtable_interface_export,
)
from pmca.analysis.ui_slot34_dispatch import (
    EXPECTED_RAW_EXPORT,
    OWNER_DIGEST,
    SLOT_OFFSET,
    VTABLE_DIGEST,
    VIEW_UNIFIED7_SHA256,
    VIEW_UNIFIED7_SIZE,
    normalize_ui_slot34_dispatch_export,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_ROOT = REPOSITORY_ROOT / ".artifacts" / "ui-slot34-dispatch-trace" / "a6400-v2.00"
EXPECTED_PROGRAM = "viewUnified7.so"


def _dependencies():
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
        from capstone.arm import ARM_INS_ADD, ARM_INS_BLX, ARM_INS_LDR, ARM_INS_MOV, ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC, ARM_REG_SP
        from elftools.elf.elffile import ELFFile
    except ImportError as error:
        raise RuntimeError("UI slot-34 export requires local capstone and pyelftools") from error
    return Cs, CS_ARCH_ARM, CS_MODE_THUMB, ARM_INS_ADD, ARM_INS_BLX, ARM_INS_LDR, ARM_INS_MOV, ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC, ARM_REG_SP, ELFFile


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _prel31(value, place):
    value &= 0x7FFFFFFF
    return place + (value - 0x80000000 if value & 0x40000000 else value)


def _file_offset(elf, address, width):
    matches = []
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD":
            continue
        if segment["p_vaddr"] <= address and address + width <= segment["p_vaddr"] + segment["p_filesz"]:
            matches.append(segment["p_offset"] + address - segment["p_vaddr"])
    if len(matches) != 1:
        raise RuntimeError("relocation source is not uniquely file-backed")
    return matches[0]


def _prior(path, normalizer, summarizer, contract, digest):
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file():
        raise RuntimeError("prior evidence must be a regular JSON file")
    try:
        document = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError("prior evidence is invalid JSON") from error
    normalizer(document)
    result = {"analysis_contract": contract, "canonical_export_sha256": summarizer(document)["canonical_export_sha256"]}
    if result["canonical_export_sha256"] != digest:
        raise RuntimeError("prior evidence digest is not pinned")
    return result


def _function_starts(elf, blob, exidx, text):
    values = set()
    for index, offset in enumerate(range(exidx["sh_offset"], exidx["sh_offset"] + exidx["sh_size"], 8)):
        values.add(_prel31(int.from_bytes(blob[offset:offset + 4], "little"), exidx["sh_addr"] + index * 8))
    return sorted(item for item in values if text["sh_addr"] <= item < text["sh_addr"] + text["sh_size"])


def _structural_scan(elf, blob):
    Cs, arch, thumb_mode, add, blx, ldr, mov, imm, mem, reg, pc, sp, _ = _dependencies()
    text = elf.get_section_by_name(".text")
    exidx = elf.get_section_by_name(".ARM.exidx")
    if text is None or exidx is None:
        raise RuntimeError("structural scan sections are missing")
    starts = _function_starts(elf, blob, exidx, text)
    thumb = Cs(arch, thumb_mode)
    thumb.detail = True
    thumb.skipdata = True
    stack, literal, accepted = [], [], []
    text_end = text["sh_addr"] + text["sh_size"]
    data = text.data()
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else text_end
        provenance, possible = {}, []
        for instruction in thumb.disasm(data[start - text["sh_addr"]:end - text["sh_addr"]], start):
            if instruction.id == ldr and len(instruction.operands) == 2 and instruction.operands[0].type == reg and instruction.operands[1].type == mem:
                destination, operand = instruction.operands[0].reg, instruction.operands[1].mem
                if operand.disp == SLOT_OFFSET and operand.base == pc:
                    # This instruction itself is a direct PC-relative +0x88 load,
                    # not a receiver-vptr/slot dispatch candidate.
                    literal.append({"kind": "direct-pc-literal-load", "function": start, "site": instruction.address})
                    provenance.pop(destination, None)
                elif operand.disp == SLOT_OFFSET and (operand.base == sp or provenance.get(operand.base, (None,))[0] == "stack"):
                    stack.append({"kind": "stack-slot-load", "function": start, "site": instruction.address})
                    provenance.pop(destination, None)
                elif operand.base == pc:
                    provenance[destination] = ("pc", instruction.address)
                elif operand.disp == 0 and operand.base != sp:
                    provenance[destination] = ("vptr", instruction.address)
                elif operand.disp == SLOT_OFFSET:
                    prior = provenance.get(operand.base)
                    if prior and prior[0] == "pc":
                        literal.append({"kind": "direct-pc-literal-load", "function": start, "site": instruction.address})
                    elif prior and prior[0] == "vptr":
                        possible.append((destination, instruction.address, prior[1]))
                    provenance.pop(destination, None)
                else:
                    provenance.pop(destination, None)
            elif instruction.id in (add, mov) and len(instruction.operands) >= 2 and instruction.operands[0].type == reg and instruction.operands[1].type == reg and instruction.operands[1].reg == sp:
                provenance[instruction.operands[0].reg] = ("stack", instruction.address)
            elif instruction.id == blx and len(instruction.operands) == 1 and instruction.operands[0].type == reg:
                for destination, site, vptr_site in possible:
                    if destination == instruction.operands[0].reg:
                        accepted.append({"function": start, "receiver_vptr_load": vptr_site, "slot_load": site, "indirect_call": instruction.address})
    def ordered(records):
        return sorted(records, key=lambda item: tuple(item[key] for key in sorted(item)))
    return {"rule": copy.deepcopy(EXPECTED_RAW_EXPORT["structural_scan"]["rule"]), "accepted_candidates": ordered(accepted), "rejected_stack_candidates": ordered(stack), "direct_pc_literal_loads": ordered(literal)}


def _metadata_from_file(source_path, vtable_path, owner_path):
    _, _, _, _, _, _, _, _, _, _, _, _, ELFFile = _dependencies()
    source = Path(source_path)
    before = _sha256(source)
    if source.name != EXPECTED_PROGRAM or before != VIEW_UNIFIED7_SHA256 or source.stat().st_size != VIEW_UNIFIED7_SIZE:
        raise RuntimeError("slot-34 source identity is not pinned")
    vtable = _prior(vtable_path, normalize_ui_layout_vtable_interface_export, summarize_ui_layout_vtable_interface_export, "ui_layout_vtable_interface", VTABLE_DIGEST)
    owner = _prior(owner_path, normalize_ui_factory_owner_registration_export, summarize_ui_factory_owner_registration_export, "ui_factory_owner_registration", OWNER_DIGEST)
    blob = source.read_bytes()
    with source.open("rb") as stream:
        elf = ELFFile(stream)
        rel = elf.get_section_by_name(".rel.dyn")
        if rel is None:
            raise RuntimeError("typed relocation section is missing")
        actual = {}
        expected = EXPECTED_RAW_EXPORT["header_references"]
        relocations = {item["r_offset"]: item for item in rel.iter_relocations()}
        for table in EXPECTED_RAW_EXPORT["table_evidence"]:
            header_relocation = table["rtti_header_relocation"]
            slot = table["slot_34"]
            incoming = table["incoming_header_reference"]
            for check, expected_addend in ((header_relocation, header_relocation["target"]), (slot, slot["thumb_target"]), (incoming, incoming["addend"])):
                item = relocations.get(check["address"])
                if item is None or item["r_info_type"] != 23:
                    raise RuntimeError("typed table relocation is not R_ARM_RELATIVE")
                offset = _file_offset(elf, check["address"], 4)
                if int.from_bytes(blob[offset:offset + 4], "little") != expected_addend:
                    raise RuntimeError("typed table relocation addend differs")
            if table["slot_34"]["address"] != table["address_point"] + SLOT_OFFSET or table["slot_34"]["normalized_owner"] != 0x529CC:
                raise RuntimeError("typed table slot-34 relationship differs")
        by_site = {item["reference_address"]: item for item in expected}
        for relocation in rel.iter_relocations():
            site = relocation["r_offset"]
            if site not in by_site:
                continue
            record = by_site[site]
            if relocation["r_info_type"] != 23:
                raise RuntimeError("vtable-header reference is not R_ARM_RELATIVE")
            addend = int.from_bytes(blob[_file_offset(elf, site, 4):_file_offset(elf, site, 4) + 4], "little")
            if addend != record["addend"]:
                raise RuntimeError("vtable-header relocation addend differs")
            actual[site] = copy.deepcopy(record)
        if [actual.get(item["reference_address"]) for item in expected] != expected:
            raise RuntimeError("incoming vtable-header references are not the exact five typed records")
        scan = _structural_scan(elf, blob)
    if _sha256(source) != before:
        raise RuntimeError("source changed during read-only static export")
    result = copy.deepcopy(EXPECTED_RAW_EXPORT)
    result["prior_vtable_interface"] = vtable
    result["prior_owner_registration"] = owner
    result["structural_scan"] = scan
    return result


def build_raw_export(adapter):
    document = adapter.metadata()
    try:
        return normalize_ui_slot34_dispatch_export(document)
    except Exception as error:
        raise RuntimeError("slot-34 metadata differs from the exact bounded result") from error


class FileAdapter:
    def __init__(self, source_path, vtable_path, owner_path):
        self.source_path, self.vtable_path, self.owner_path = Path(source_path), Path(vtable_path), Path(owner_path)
    def metadata(self):
        return _metadata_from_file(self.source_path, self.vtable_path, self.owner_path)


def write_json_atomic(output_path, document):
    output = Path(output_path)
    literal = Path(OUTPUT_ROOT).absolute()
    root = Path(OUTPUT_ROOT).resolve(strict=True)
    expected = root / "raw-ui-slot34-dispatch.json"
    if root != literal or root.is_symlink() or Path(os.path.abspath(output)) != expected or output.parent.resolve(strict=True) != root or output.is_symlink() or (output.exists() and not output.is_file()):
        raise RuntimeError("slot-34 output escapes the pinned artifact root")
    handle, temporary = tempfile.mkstemp(dir=str(root), prefix=".ui-slot34-", suffix=".tmp")
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
    if len(args) != 4:
        raise SystemExit("usage: <source.so> <vtable.json> <owner.json> <output.json>")
    output = Path(args[3])
    if Path(os.path.abspath(output)) != Path(os.path.abspath(OUTPUT_ROOT / "raw-ui-slot34-dispatch.json")):
        raise RuntimeError("slot-34 main output is not the pinned artifact path")
    document = build_raw_export(FileAdapter(args[0], args[1], args[2]))
    write_json_atomic(output, document)
    print("UI_SLOT34_DISPATCH_EXPORT|header_refs=5|accepted=0|selector=0|touch=0")


if __name__ == "__main__":
    main()
