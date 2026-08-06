"""Deterministic static α6400 Picture Profile clone-boundary metadata exporter."""
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
from pmca.analysis.picture_profile_clone_boundary import (
    CAUTION_CONFIG_SHA256, CAUTION_CONFIG_SIZE, CLONE_EDGES, CLONE_OWNER,
    COPY_CONSTRUCTOR_RELOCATION, COPY_CONSTRUCTOR_SYMBOL, COPY_CONSTRUCTOR_VTABLE, OTHER_IMPORT,
    OTHER_IMPORT_SYMBOL, TYPED_VTABLE, normalize_picture_profile_clone_boundary_export,
)
from pmca.analysis.picture_profile_trace import normalize_picture_profile_export

SOURCE = ROOT / ".artifacts" / "decrypted" / "a6400-tw-v2.00" / "ma1co" / "firmware.tar_unpacked" / "0700_part_image" / "dev" / "nflasha15_unpacked" / "lib" / "CautionConfig.so"
EDGE_ARTIFACT = ROOT / ".artifacts" / "picture-profile-trace" / "a6400-v2.00" / "raw-picture-profile.json"
OUTPUT_ROOT = ROOT / ".artifacts" / "picture-profile-clone-boundary-trace" / "a6400-v2.00"
ANALYSIS_LOAD_BIAS = 0x10000
ARM_PLT_FIRST_STUB_OFFSET = 0x1C
ARM_PLT_STUB_SIZE = 12


def _elf_metadata(binary):
    if binary[:4] != b"\x7fELF" or binary[4] != 1 or binary[5] != 1:
        raise RuntimeError("expected a 32-bit little-endian ELF")
    section_offset = struct.unpack_from("<I", binary, 32)[0]
    entry_size = struct.unpack_from("<H", binary, 46)[0]
    section_count = struct.unpack_from("<H", binary, 48)[0]
    names_index = struct.unpack_from("<H", binary, 50)[0]
    sections = [struct.unpack_from("<IIIIIIIIII", binary, section_offset + index * entry_size) for index in range(section_count)]
    name_section = sections[names_index]
    names = binary[name_section[4]:name_section[4] + name_section[5]]
    def name(index):
        start = sections[index][0]
        end = names.find(b"\0", start)
        return names[start:end].decode("ascii", "strict")
    by_name = {name(index): section for index, section in enumerate(sections)}
    for required in (".dynsym", ".dynstr", ".rel.plt", ".plt"):
        if required not in by_name:
            raise RuntimeError("required ELF metadata section is absent")
    dynsym, dynstr, relplt, plt = (by_name[item] for item in (".dynsym", ".dynstr", ".rel.plt", ".plt"))
    strings = binary[dynstr[4]:dynstr[4] + dynstr[5]]
    def symbol(index):
        offset = dynsym[4] + index * dynsym[9]
        name_offset, value, size, info, _other, section = struct.unpack_from("<IIIBBH", binary, offset)
        end = strings.find(b"\0", name_offset)
        return {"name": strings[name_offset:end].decode("ascii", "strict"), "value": value, "size": size, "type": info & 15, "section": section}
    relocs = []
    for index in range(relplt[5] // relplt[9]):
        offset, info = struct.unpack_from("<II", binary, relplt[4] + index * relplt[9])
        relocs.append({"index": index, "offset": offset, "type": info & 255, "symbol": symbol(info >> 8)})
    return {"relocations": relocs, "plt": plt, "symbols": [symbol(index) for index in range(dynsym[5] // dynsym[9])]}


def _edge_evidence():
    source = json.loads(EDGE_ARTIFACT.read_text(encoding="utf-8"))
    required = {"program", "sha256", "file_size", "analysis_mode", "roots", "slot_nodes", "direct_calls", "data_references", "unresolved_indirect_edges", "truncated", "depth_cap"}
    if set(source) != required or source["program"] != "CautionConfig.so" or source["sha256"] != CAUTION_CONFIG_SHA256 or source["file_size"] != CAUTION_CONFIG_SIZE or source["analysis_mode"] != {"read_only": True, "noanalysis": True} or source["truncated"] is not False:
        raise RuntimeError("existing read-only edge artifact is not pinned")
    if normalize_picture_profile_export(source)["bounded_export_summary"]["artifact_sha256"] != "b69c884743e25d10fabdc6984d46ec4120755d4c9c8657f4773ae009d435ea32":
        raise RuntimeError("existing read-only edge artifact digest differs")
    clone = [item for item in source["direct_calls"] if item.get("caller") == CLONE_OWNER["address"]]
    expected = [
        {"caller": CLONE_OWNER["address"], "owner": "CmnViewSettingNodePictureProfile::clone", "site": edge["site"], "target": edge["target"]}
        for edge in CLONE_EDGES
    ]
    if clone != expected:
        raise RuntimeError("existing clone edge evidence is incomplete or differs")
    return CLONE_EDGES


def _decoded_plt_stubs(binary, metadata):
    """Bind every relocation to an ARM PLT stub by its decoded GOT calculation."""
    try:
        from capstone import CS_ARCH_ARM, CS_MODE_ARM, Cs
    except ImportError as exc:
        dependency_root = ROOT / ".artifacts" / "python-packages"
        if dependency_root.is_dir():
            sys.path.insert(0, str(dependency_root))
        try:
            from capstone import CS_ARCH_ARM, CS_MODE_ARM, Cs
        except ImportError:
            raise RuntimeError("Capstone ARM decoder is required for PLT binding") from exc
    plt_address, plt_offset, plt_size = metadata["plt"][3], metadata["plt"][4], metadata["plt"][5]
    relocation_by_got = {item["offset"]: item for item in metadata["relocations"]}
    if len(relocation_by_got) != len(metadata["relocations"]):
        raise RuntimeError("duplicate .rel.plt GOT offsets")
    decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    decoder.detail = True
    bindings = {}
    for start in range(plt_address, plt_address + plt_size - ARM_PLT_STUB_SIZE + 1, 4):
        source_offset = plt_offset + (start - plt_address)
        instructions = list(decoder.disasm(binary[source_offset:source_offset + ARM_PLT_STUB_SIZE], start))
        if len(instructions) != 3 or [item.mnemonic for item in instructions] != ["add", "add", "ldr"]:
            continue
        try:
            immediate0 = instructions[0].operands[2].imm
            immediate1 = instructions[1].operands[2].imm
            displacement = instructions[2].operands[1].mem.disp
        except (AttributeError, IndexError):
            continue
        got_address = (start + 8) + immediate0 + immediate1 + displacement
        relocation = relocation_by_got.get(got_address)
        if relocation is None:
            continue
        if got_address in bindings:
            raise RuntimeError("one .rel.plt GOT offset has multiple decoded PLT stubs")
        bindings[got_address] = {"relocation": relocation, "stub": start}
    return bindings


def _map_target_to_relocation(analysis_target, bindings):
    """Require a direct edge target to equal one decoded ARM PLT stub exactly."""
    target = int(analysis_target, 16) - ANALYSIS_LOAD_BIAS
    matches = [item for item in bindings.values() if item["stub"] == target]
    if len(matches) != 1:
        raise RuntimeError("direct edge target is not one exact decoded PLT stub")
    relocation = matches[0]["relocation"]
    if relocation["type"] != 22:
        raise RuntimeError("bound PLT relocation is not R_ARM_JUMP_SLOT")
    return {
        "analysis_target": analysis_target,
        "plt_elf_address": "0x%x" % target,
        "relocation_index": relocation["index"],
        "got_address": "0x%x" % relocation["offset"],
        "intra_entry_offset": 0,
        "relocation_type": "R_ARM_JUMP_SLOT",
        "symbol": relocation["symbol"]["name"],
    }


def build_raw_export(source=SOURCE):
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    if before != CAUTION_CONFIG_SHA256 or source.stat().st_size != CAUTION_CONFIG_SIZE:
        raise RuntimeError("source identity differs")
    metadata = _elf_metadata(source.read_bytes())
    _edge_evidence()
    bindings = _decoded_plt_stubs(source.read_bytes(), metadata)
    for expected_got in (0xB0CC64, 0xB0E1AC):
        if expected_got not in bindings:
            raise RuntimeError("targeted .rel.plt GOT binding is absent")
    mapped_copy = _map_target_to_relocation(CLONE_EDGES[1]["target"], bindings)
    copy_relocation = {"edge_site": CLONE_EDGES[1]["site"], "plt_address": CLONE_EDGES[1]["target"], **{key: mapped_copy[key] for key in ("plt_elf_address", "relocation_index", "got_address", "intra_entry_offset", "relocation_type", "symbol")}}
    if copy_relocation != COPY_CONSTRUCTOR_RELOCATION or mapped_copy["symbol"] != COPY_CONSTRUCTOR_SYMBOL:
        raise RuntimeError("copy constructor direct edge does not bind exactly")
    mapped_other = _map_target_to_relocation(CLONE_EDGES[0]["target"], bindings)
    other_import = {"edge_site": CLONE_EDGES[0]["site"], "plt_address": CLONE_EDGES[0]["target"], **{key: mapped_other[key] for key in ("plt_elf_address", "relocation_index", "got_address", "intra_entry_offset", "relocation_type", "symbol")}, "semantic_classification": "allocation"}
    if other_import != OTHER_IMPORT or mapped_other["symbol"] != OTHER_IMPORT_SYMBOL:
        raise RuntimeError("other direct edge does not bind exactly")
    vtables = [item for item in metadata["symbols"] if item["name"] == COPY_CONSTRUCTOR_VTABLE]
    if len(vtables) != 1 or vtables[0]["type"] != 1 or vtables[0]["size"] != 268:
        raise RuntimeError("typed Picture Profile vtable symbol is not exact")
    typed_vtable = {"address": "0x%x" % (vtables[0]["value"] + ANALYSIS_LOAD_BIAS), "elf_address": "0x%x" % vtables[0]["value"], "evidence_type": "dynamic-symbol", "symbol": COPY_CONSTRUCTOR_VTABLE, "elf_symbol_type": "STT_OBJECT", "size": vtables[0]["size"]}
    if typed_vtable != TYPED_VTABLE:
        raise RuntimeError("typed Picture Profile vtable mapping differs")
    document = {
        "program": "CautionConfig.so", "sha256": CAUTION_CONFIG_SHA256, "file_size": CAUTION_CONFIG_SIZE,
        "analysis_mode": {"read_only": True, "static_elf_metadata": True}, "program_changed": False,
        "clone_owner": CLONE_OWNER, "clone_edges": CLONE_EDGES, "plt_binding_scope": "targeted-exact", "copy_constructor_relocation": copy_relocation,
        "other_import": other_import, "typed_interface_registrations": [typed_vtable],
        "property_list_evidence": {"classification": "construction-only", "slots": ["PP%d" % number for number in range(1, 10)]},
        "selected_slot_paths": [], "persistence_paths": [], "processing_paths": [], "output_paths": [], "truncated": False,
    }
    normalize_picture_profile_clone_boundary_export(document)
    after = hashlib.sha256(source.read_bytes()).hexdigest()
    if after != before:
        raise RuntimeError("source changed during read-only export")
    return document


def write_json_atomic(output, document, approved_root=OUTPUT_ROOT):
    output = Path(output)
    root = Path(approved_root).resolve(strict=True)
    if output.name != "raw-picture-profile-clone-boundary.json" or output.parent.resolve(strict=True) != root or (output.exists() and (output.is_symlink() or not output.is_file())):
        raise RuntimeError("output containment is invalid")
    descriptor, temporary = tempfile.mkstemp(dir=str(root), prefix=".pp-clone-", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


if __name__ == "__main__":
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    document = build_raw_export()
    write_json_atomic(OUTPUT_ROOT / "raw-picture-profile-clone-boundary.json", document)
    print("PICTURE_PROFILE_CLONE_BOUNDARY_EXPORT|edges=2|typed_vtables=1|selected_slot=0|persistence=0|processing=0|output=0")
