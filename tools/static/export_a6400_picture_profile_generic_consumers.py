"""Deterministic, bounded static exporter for α6400 Picture Profile base consumers."""
from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from pmca.analysis.picture_profile_clone_boundary import normalize_picture_profile_clone_boundary_export
from pmca.analysis.picture_profile_generic_consumers import (
    ANALYSIS_LOAD_BIAS, CAUTION_CONFIG_SHA256, CAUTION_CONFIG_SIZE, CONSTRUCTOR_PLT_BINDINGS,
    GENERIC_METHODS, PRIOR_ARTIFACTS, normalize_picture_profile_generic_consumer_export,
)
from pmca.analysis.picture_profile_handoff import normalize_picture_profile_handoff_export
from pmca.analysis.picture_profile_vtable_interface import normalize_picture_profile_vtable_interface_export

SOURCE = ROOT / ".artifacts" / "decrypted" / "a6400-tw-v2.00" / "ma1co" / "firmware.tar_unpacked" / "0700_part_image" / "dev" / "nflasha15_unpacked" / "lib" / "CautionConfig.so"
HANDOFF_ARTIFACT = ROOT / ".artifacts" / "picture-profile-handoff-trace" / "a6400-v2.00" / "raw-picture-profile-handoff.json"
CLONE_ARTIFACT = ROOT / ".artifacts" / "picture-profile-clone-boundary-trace" / "a6400-v2.00" / "raw-picture-profile-clone-boundary.json"
VTABLE_ARTIFACT = ROOT / ".artifacts" / "picture-profile-vtable-interface-trace" / "a6400-v2.00" / "raw-picture-profile-vtable-interface.json"
OUTPUT_ROOT = ROOT / ".artifacts" / "picture-profile-generic-consumer-trace" / "a6400-v2.00"
VTABLE_ADDRESS = 0xB01D20


def _elf_metadata(binary):
    if binary[:4] != b"\x7fELF" or binary[4] != 1 or binary[5] != 1:
        raise RuntimeError("expected a 32-bit little-endian ELF")
    section_offset = struct.unpack_from("<I", binary, 32)[0]
    program_offset = struct.unpack_from("<I", binary, 28)[0]
    program_size = struct.unpack_from("<H", binary, 42)[0]
    program_count = struct.unpack_from("<H", binary, 44)[0]
    entry_size = struct.unpack_from("<H", binary, 46)[0]
    section_count = struct.unpack_from("<H", binary, 48)[0]
    names_index = struct.unpack_from("<H", binary, 50)[0]
    if entry_size != 40 or program_size != 32:
        raise RuntimeError("unexpected ELF table entry size")
    sections = [struct.unpack_from("<IIIIIIIIII", binary, section_offset + index * entry_size) for index in range(section_count)]
    programs = [struct.unpack_from("<IIIIIIII", binary, program_offset + index * program_size) for index in range(program_count)]
    name_section = sections[names_index]
    names = binary[name_section[4]:name_section[4] + name_section[5]]

    def section_name(index):
        start = sections[index][0]
        end = names.find(b"\0", start)
        if end < 0:
            raise RuntimeError("section name is unterminated")
        return names[start:end].decode("ascii", "strict")

    by_name = {section_name(index): section for index, section in enumerate(sections)}
    for required in (".dynsym", ".dynstr", ".rel.dyn", ".rel.plt", ".plt"):
        if required not in by_name:
            raise RuntimeError("required ELF metadata section is absent")
    dynsym, dynstr, reldyn, relplt, plt = (by_name[item] for item in (".dynsym", ".dynstr", ".rel.dyn", ".rel.plt", ".plt"))
    if dynsym[9] != 16 or reldyn[9] != 8 or relplt[9] != 8:
        raise RuntimeError("unexpected dynamic metadata entry size")
    strings = binary[dynstr[4]:dynstr[4] + dynstr[5]]

    def symbol(index):
        offset = dynsym[4] + index * dynsym[9]
        name_offset, value, size, info, _other, section = struct.unpack_from("<IIIBBH", binary, offset)
        end = strings.find(b"\0", name_offset)
        if end < 0:
            raise RuntimeError("dynamic symbol name is unterminated")
        return {"name": strings[name_offset:end].decode("ascii", "strict"), "value": value, "size": size, "type": info & 15, "section": section}

    symbols = [symbol(index) for index in range(dynsym[5] // dynsym[9])]

    def relocations(section):
        records = []
        for index in range(section[5] // section[9]):
            offset, info = struct.unpack_from("<II", binary, section[4] + index * section[9])
            symbol_index = info >> 8
            if symbol_index >= len(symbols):
                raise RuntimeError("relocation symbol index is invalid")
            records.append({"index": index, "offset": offset, "type": info & 255, "symbol": symbols[symbol_index]})
        return records

    load_segments = [record for record in programs if record[0] == 1]
    if not load_segments or any(record[4] > record[5] for record in load_segments):
        raise RuntimeError("load segments are invalid")
    return {"symbols": symbols, "rel_dyn": relocations(reldyn), "rel_plt": relocations(relplt), "plt": plt, "load_segments": load_segments}


def _file_offset_for_va(metadata, address, length):
    matches = []
    for _type, offset, virtual, _physical, file_size, memory_size, _flags, _align in metadata["load_segments"]:
        if virtual <= address and address + length <= virtual + file_size:
            matches.append(offset + (address - virtual))
    if len(matches) != 1:
        raise RuntimeError("bounded function does not map to one file range")
    return matches[0]


def _capstone():
    try:
        from capstone import CS_ARCH_ARM, CS_GRP_CALL, CS_GRP_JUMP, CS_MODE_THUMB, CS_OP_IMM, CS_OP_MEM, Cs
        from capstone.arm import ARM_REG_PC
    except ImportError:
        dependency_root = ROOT / ".artifacts" / "python-packages"
        if dependency_root.is_dir():
            sys.path.insert(0, str(dependency_root))
        try:
            from capstone import CS_ARCH_ARM, CS_GRP_CALL, CS_GRP_JUMP, CS_MODE_THUMB, CS_OP_IMM, CS_OP_MEM, Cs
            from capstone.arm import ARM_REG_PC
        except ImportError as exc:
            raise RuntimeError("Capstone Thumb decoder is required for bounded control-flow evidence") from exc
    return CS_OP_IMM, CS_OP_MEM, ARM_REG_PC, CS_ARCH_ARM, CS_GRP_CALL, CS_GRP_JUMP, CS_MODE_THUMB, Cs


def capstone_available():
    try:
        _capstone()
    except RuntimeError:
        return False
    return True


def _prior_artifacts():
    handoff = normalize_picture_profile_handoff_export(json.loads(HANDOFF_ARTIFACT.read_text(encoding="utf-8")))
    clone = normalize_picture_profile_clone_boundary_export(json.loads(CLONE_ARTIFACT.read_text(encoding="utf-8")))
    vtable = normalize_picture_profile_vtable_interface_export(json.loads(VTABLE_ARTIFACT.read_text(encoding="utf-8")))
    result = {"handoff_sha256": handoff["artifact_sha256"], "clone_boundary_sha256": clone["artifact_sha256"], "vtable_interface_sha256": vtable["artifact_sha256"]}
    if result != PRIOR_ARTIFACTS:
        raise RuntimeError("prior artifact digest differs")
    return result


def _methods(metadata):
    relocations = {record["offset"]: record for record in metadata["rel_dyn"]}
    if len(relocations) != len(metadata["rel_dyn"]):
        raise RuntimeError("dynamic relocation offsets are duplicated")
    records = []
    for expected in GENERIC_METHODS:
        record = relocations.get(VTABLE_ADDRESS + expected["slot"] * 4)
        if record is None or record["type"] != 2 or record["symbol"]["type"] != 2:
            raise RuntimeError("generic vtable slot is not a typed ABS32 relocation")
        candidate = {
            "group": expected["group"], "slot": expected["slot"], "relocation_index": record["index"], "relocation_type": "R_ARM_ABS32", "symbol": record["symbol"]["name"],
            "elf_thumb_target": "0x%x" % record["symbol"]["value"], "elf_owner": "0x%x" % (record["symbol"]["value"] & ~1),
            "analysis_owner": "0x%x" % ((record["symbol"]["value"] & ~1) + ANALYSIS_LOAD_BIAS), "function_size": record["symbol"]["size"],
        }
        if candidate != expected:
            raise RuntimeError("generic vtable method metadata differs")
        records.append(candidate)
    return records


def _plt_bindings(binary, metadata):
    ARM_OP_IMM, _ARM_OP_MEM, _ARM_REG_PC, CS_ARCH_ARM, _CS_GRP_CALL, _CS_GRP_JUMP, CS_MODE_THUMB, Cs = _capstone()
    del ARM_OP_IMM, CS_MODE_THUMB
    from capstone import CS_MODE_ARM
    decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    decoder.detail = True
    plt_address, plt_offset, plt_size = metadata["plt"][3], metadata["plt"][4], metadata["plt"][5]
    by_got = {record["offset"]: record for record in metadata["rel_plt"]}
    if len(by_got) != len(metadata["rel_plt"]):
        raise RuntimeError("PLT GOT offsets are duplicated")
    bindings = {}
    for address in range(plt_address, plt_address + plt_size - 12 + 1, 4):
        offset = plt_offset + address - plt_address
        instructions = list(decoder.disasm(binary[offset:offset + 12], address))
        if len(instructions) != 3 or [item.mnemonic for item in instructions] != ["add", "add", "ldr"]:
            continue
        try:
            got = address + 8 + instructions[0].operands[2].imm + instructions[1].operands[2].imm + instructions[2].operands[1].mem.disp
        except (AttributeError, IndexError):
            continue
        relocation = by_got.get(got)
        if relocation is None:
            continue
        if got in bindings:
            raise RuntimeError("PLT GOT offset has more than one decoded binding")
        bindings[got] = {"address": address, "relocation": relocation}
    result = []
    for expected in CONSTRUCTOR_PLT_BINDINGS:
        got = int(expected["got_address"], 16)
        binding = bindings.get(got)
        if binding is None:
            raise RuntimeError("constructor PLT GOT binding is absent")
        relocation = binding["relocation"]
        candidate = {"role": expected["role"], "relocation_index": relocation["index"], "relocation_type": "R_ARM_JUMP_SLOT", "got_address": "0x%x" % got, "plt_elf_address": "0x%x" % binding["address"], "plt_analysis_address": "0x%x" % (binding["address"] + ANALYSIS_LOAD_BIAS), "symbol": relocation["symbol"]["name"]}
        if relocation["type"] != 22 or candidate != expected:
            raise RuntimeError("constructor PLT binding differs")
        result.append(candidate)
    if result[0]["got_address"] == result[1]["got_address"] or result[0]["plt_elf_address"] == result[1]["plt_elf_address"]:
        raise RuntimeError("construction and copy-construction bindings are not distinct")
    return result


def _targets_from_handoff():
    document = json.loads(HANDOFF_ARTIFACT.read_text(encoding="utf-8"))
    normalize_picture_profile_handoff_export(document)
    property_addresses = {int(item["address"], 16) for item in document["property_lists"]}
    node_addresses = {int(item["target"], 16) - ANALYSIS_LOAD_BIAS for item in document["constructor_parameter_references"]}
    if len(property_addresses) != 9 or len(node_addresses) != 9:
        raise RuntimeError("prior PP target set is incomplete")
    return property_addresses | node_addresses


def _bounded_empty_results(binary, metadata, methods):
    ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC, CS_ARCH_ARM, CS_GRP_CALL, CS_GRP_JUMP, CS_MODE_THUMB, Cs = _capstone()
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    named_targets = {symbol["value"] & ~1 for symbol in metadata["symbols"] if symbol["name"] and symbol["type"] == 2}
    pp_targets = _targets_from_handoff()
    named_edges, pp_references = [], []
    for method in methods:
        owner = int(method["elf_owner"], 16)
        size = method["function_size"]
        offset = _file_offset_for_va(metadata, owner, size)
        instructions = list(decoder.disasm(binary[offset:offset + size], owner | 1))
        if sum(item.size for item in instructions) != size:
            raise RuntimeError("bounded Thumb function does not decode completely")
        for instruction in instructions:
            if instruction.group(CS_GRP_CALL) or instruction.group(CS_GRP_JUMP):
                for operand in instruction.operands:
                    if operand.type == ARM_OP_IMM and (operand.imm & ~1) in named_targets:
                        named_edges.append({"method": method["symbol"], "target": operand.imm & ~1})
            for operand in instruction.operands:
                if operand.type == ARM_OP_IMM and operand.imm in pp_targets:
                    pp_references.append({"method": method["symbol"], "target": operand.imm})
                if operand.type == ARM_OP_MEM and operand.mem.base == ARM_REG_PC:
                    literal_address = (instruction.address + 4 + operand.mem.disp) & ~3
                    literal_offset = _file_offset_for_va(metadata, literal_address, 4)
                    target = struct.unpack_from("<I", binary, literal_offset)[0] & ~1
                    if target in pp_targets:
                        pp_references.append({"method": method["symbol"], "target": target})
    dynamic_relocations = []
    for method in methods:
        start = int(method["elf_owner"], 16)
        end = start + method["function_size"]
        dynamic_relocations.extend(record for record in metadata["rel_dyn"] if start <= record["offset"] < end)
    if named_edges or dynamic_relocations or pp_references:
        raise RuntimeError("bounded generic method has non-empty typed consumer evidence")
    return [], [], []


def build_raw_export(source=SOURCE):
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    if before != CAUTION_CONFIG_SHA256 or source.stat().st_size != CAUTION_CONFIG_SIZE:
        raise RuntimeError("source identity differs")
    binary = source.read_bytes()
    metadata = _elf_metadata(binary)
    methods = _methods(metadata)
    named_edges, dynamic_relocations, pp_references = _bounded_empty_results(binary, metadata, methods)
    document = {
        "program": "CautionConfig.so", "sha256": CAUTION_CONFIG_SHA256, "file_size": CAUTION_CONFIG_SIZE,
        "analysis_mode": {"read_only": True, "static_elf_metadata": True, "thumb_control_flow": True}, "program_changed": False,
        "analysis_load_bias": "0x%x" % ANALYSIS_LOAD_BIAS, "generic_methods": methods,
        "named_direct_control_flow": named_edges, "dynamic_typed_relocations": dynamic_relocations,
        "pp1_pp9_references": pp_references, "constructor_plt_bindings": _plt_bindings(binary, metadata),
        "prior_artifacts": _prior_artifacts(), "selected_state_paths": [], "persistence_paths": [],
        "processing_paths": [], "output_paths": [], "reuse_paths": [], "truncated": False,
    }
    normalize_picture_profile_generic_consumer_export(document)
    after = hashlib.sha256(source.read_bytes()).hexdigest()
    if after != before:
        raise RuntimeError("source changed during read-only export")
    return document


def write_json_atomic(output, document, approved_root=OUTPUT_ROOT):
    output = Path(output)
    root = Path(approved_root)
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError("approved output root is not a literal directory")
    if output.name != "raw-picture-profile-generic-consumers.json" or output.parent != root or output.is_symlink() or (output.exists() and not output.is_file()):
        raise RuntimeError("output containment is invalid")
    descriptor, temporary = tempfile.mkstemp(dir=str(root), prefix=".pp-generic-", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n")
            handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, output)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


if __name__ == "__main__":
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    write_json_atomic(OUTPUT_ROOT / "raw-picture-profile-generic-consumers.json", build_raw_export())
    print("PICTURE_PROFILE_GENERIC_CONSUMER_EXPORT|methods=14|named_edges=0|typed_relocations=0|pp_refs=0")
