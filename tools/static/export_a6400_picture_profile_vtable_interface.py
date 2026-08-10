"""Deterministic static α6400 Picture Profile typed-vtable metadata exporter."""
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
from pmca.analysis.picture_profile_handoff import normalize_picture_profile_handoff_export
from pmca.analysis.picture_profile_vtable_interface import (
    ADJACENT_SLOTS, ANALYSIS_LOAD_BIAS, CAUTION_CONFIG_SHA256, CAUTION_CONFIG_SIZE, CLONE_SLOT,
    CONSTRUCTOR_ALIASES, INHERITED_SLOT_GROUPS, PRIOR_ARTIFACTS, VTABLE,
    VTABLE_GLOB_DAT, normalize_picture_profile_vtable_interface_export,
)

SOURCE = ROOT / ".artifacts" / "decrypted" / "a6400-tw-v2.00" / "ma1co" / "firmware.tar_unpacked" / "0700_part_image" / "dev" / "nflasha15_unpacked" / "lib" / "CautionConfig.so"
CLONE_ARTIFACT = ROOT / ".artifacts" / "picture-profile-clone-boundary-trace" / "a6400-v2.00" / "raw-picture-profile-clone-boundary.json"
HANDOFF_ARTIFACT = ROOT / ".artifacts" / "picture-profile-handoff-trace" / "a6400-v2.00" / "raw-picture-profile-handoff.json"
OUTPUT_ROOT = ROOT / ".artifacts" / "picture-profile-vtable-interface-trace" / "a6400-v2.00"
VTABLE_ADDRESS = int(VTABLE["elf_address"], 16)
VTABLE_END = VTABLE_ADDRESS + VTABLE["size"]


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
    for required in (".dynsym", ".dynstr", ".rel.dyn"):
        if required not in by_name:
            raise RuntimeError("required ELF metadata section is absent")
    dynsym, dynstr, reldyn = (by_name[item] for item in (".dynsym", ".dynstr", ".rel.dyn"))
    if dynsym[9] != 16 or reldyn[9] != 8:
        raise RuntimeError("unexpected ELF metadata entry size")
    strings = binary[dynstr[4]:dynstr[4] + dynstr[5]]

    def symbol(index):
        offset = dynsym[4] + index * dynsym[9]
        name_offset, value, size, info, _other, section = struct.unpack_from("<IIIBBH", binary, offset)
        end = strings.find(b"\0", name_offset)
        if end < 0:
            raise RuntimeError("dynamic symbol name is unterminated")
        return {"name": strings[name_offset:end].decode("ascii", "strict"), "value": value, "size": size, "bind": info >> 4, "type": info & 15, "section": section}

    symbols = [symbol(index) for index in range(dynsym[5] // dynsym[9])]
    relocs = []
    for index in range(reldyn[5] // reldyn[9]):
        offset, info = struct.unpack_from("<II", binary, reldyn[4] + index * reldyn[9])
        symbol_index = info >> 8
        if symbol_index >= len(symbols):
            raise RuntimeError("relocation dynamic symbol index is invalid")
        relocs.append({"index": index, "offset": offset, "type": info & 255, "symbol": symbols[symbol_index]})
    return {"symbols": symbols, "relocations": relocs}


def _prior_artifacts():
    clone = json.loads(CLONE_ARTIFACT.read_text(encoding="utf-8"))
    handoff = json.loads(HANDOFF_ARTIFACT.read_text(encoding="utf-8"))
    clone_digest = normalize_picture_profile_clone_boundary_export(clone)["artifact_sha256"]
    handoff_digest = normalize_picture_profile_handoff_export(handoff)["artifact_sha256"]
    evidence = {"clone_boundary_sha256": clone_digest, "handoff_sha256": handoff_digest}
    if evidence != PRIOR_ARTIFACTS:
        raise RuntimeError("prior Picture Profile artifact digest differs")
    return evidence


def _typed_slot(relocation_by_offset, slot, expected_symbol):
    offset = VTABLE_ADDRESS + slot * 4
    record = relocation_by_offset.get(offset)
    if record is None or record["type"] != 2 or record["symbol"]["type"] != 2 or record["symbol"]["name"] != expected_symbol:
        raise RuntimeError("typed vtable slot differs")
    return record


def _slot_record(relocation_by_offset, expected):
    record = _typed_slot(relocation_by_offset, expected["slot"], expected["symbol"])
    candidate = {
        "relocation_index": record["index"], "relocation_type": "R_ARM_ABS32", "slot": expected["slot"],
        "offset": record["offset"] - VTABLE_ADDRESS, "virtual_index": expected["slot"] - 2,
        "vtable_offset": "0x%x" % (record["offset"] - VTABLE_ADDRESS), "symbol": record["symbol"]["name"],
        "elf_thumb_target": "0x%x" % record["symbol"]["value"],
        "elf_owner": "0x%x" % (record["symbol"]["value"] & ~1),
        "analysis_owner": "0x%x" % ((record["symbol"]["value"] & ~1) + ANALYSIS_LOAD_BIAS),
        "function_size": record["symbol"]["size"],
    }
    if candidate != {key: value for key, value in expected.items() if key != "role"}:
        raise RuntimeError("typed vtable slot evidence differs")
    return candidate


def _build_raw_export(source=SOURCE):
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    if before != CAUTION_CONFIG_SHA256 or source.stat().st_size != CAUTION_CONFIG_SIZE:
        raise RuntimeError("source identity differs")
    metadata = _elf_metadata(source.read_bytes())
    vtables = [item for item in metadata["symbols"] if item["name"] == VTABLE["symbol"]]
    if len(vtables) != 1 or vtables[0]["value"] != VTABLE_ADDRESS or vtables[0]["size"] != VTABLE["size"] or vtables[0]["type"] != 1:
        raise RuntimeError("typed Picture Profile vtable symbol differs")
    table_relocations = sorted(
        (item for item in metadata["relocations"] if VTABLE_ADDRESS <= item["offset"] < VTABLE_END),
        key=lambda item: item["offset"],
    )
    if len(table_relocations) != VTABLE["typed_relocation_count"] or [item["offset"] for item in table_relocations] != list(range(VTABLE_ADDRESS + 4, VTABLE_END, 4)):
        raise RuntimeError("vtable relocation coverage is incomplete")
    if any(item["type"] != 2 for item in table_relocations):
        raise RuntimeError("vtable relocation type is not typed ABS32")
    relocation_by_offset = {item["offset"]: item for item in table_relocations}
    if len(relocation_by_offset) != len(table_relocations):
        raise RuntimeError("vtable relocation offsets are duplicated")
    clone_slot = _slot_record(relocation_by_offset, CLONE_SLOT)
    adjacent_slots = []
    for expected in ADJACENT_SLOTS:
        shaped = _slot_record(relocation_by_offset, expected)
        adjacent_slots.append({"role": expected["role"], **{key: shaped[key] for key in shaped}})
    if adjacent_slots != ADJACENT_SLOTS:
        raise RuntimeError("adjacent vtable slots differ")
    inherited = {}
    for group, expected_entries in INHERITED_SLOT_GROUPS.items():
        entries = []
        for expected in expected_entries:
            record = _typed_slot(relocation_by_offset, expected["slot"], expected["symbol"])
            entries.append({"slot": (record["offset"] - VTABLE_ADDRESS) // 4, "symbol": record["symbol"]["name"]})
        inherited[group] = entries
    if inherited != INHERITED_SLOT_GROUPS:
        raise RuntimeError("inherited generic slot groups differ")
    glob_dat = [item for item in metadata["relocations"] if item["symbol"]["name"] == VTABLE["symbol"]]
    if len(glob_dat) != 1 or glob_dat[0]["type"] != 21:
        raise RuntimeError("vtable GLOB_DAT relocation is not exact")
    vtable_glob_dat = {"relocation_index": glob_dat[0]["index"], "got_address": "0x%x" % glob_dat[0]["offset"], "relocation_type": "R_ARM_GLOB_DAT", "symbol": glob_dat[0]["symbol"]["name"]}
    if vtable_glob_dat != VTABLE_GLOB_DAT:
        raise RuntimeError("vtable GLOB_DAT metadata differs")
    aliases = []
    for expected in CONSTRUCTOR_ALIASES:
        members = [item for item in metadata["symbols"] if item["name"] in expected["symbols"]]
        members.sort(key=lambda item: expected["symbols"].index(item["name"]))
        if len(members) != 2 or any(item["type"] != 2 for item in members) or members[0]["value"] != members[1]["value"] or members[0]["size"] != members[1]["size"]:
            raise RuntimeError("constructor alias membership differs")
        candidate = {"role": expected["role"], "symbols": [item["name"] for item in members], "elf_thumb_target": "0x%x" % members[0]["value"], "elf_owner": "0x%x" % (members[0]["value"] & ~1), "analysis_owner": "0x%x" % ((members[0]["value"] & ~1) + ANALYSIS_LOAD_BIAS), "function_size": members[0]["size"]}
        if candidate != expected:
            raise RuntimeError("constructor alias metadata differs")
        aliases.append(candidate)
    evidence = _prior_artifacts()
    document = {
        "program": "CautionConfig.so", "sha256": CAUTION_CONFIG_SHA256, "file_size": CAUTION_CONFIG_SIZE,
        "analysis_mode": {"read_only": True, "static_elf_metadata": True}, "program_changed": False,
        "analysis_load_bias": "0x%x" % ANALYSIS_LOAD_BIAS,
        "vtable": VTABLE, "clone_slot": clone_slot, "adjacent_slots": adjacent_slots,
        "inherited_slot_groups": inherited, "vtable_glob_dat": vtable_glob_dat, "constructor_aliases": aliases,
        "prior_artifacts": evidence, "pp1_pp9_bindings": [], "selected_slot_paths": [],
        "persistence_paths": [], "processing_paths": [], "output_paths": [], "truncated": False,
    }
    normalize_picture_profile_vtable_interface_export(document)
    after = hashlib.sha256(source.read_bytes()).hexdigest()
    if after != before:
        raise RuntimeError("source changed during read-only export")
    return document


build_raw_export = _build_raw_export


def write_json_atomic(output, document, approved_root=OUTPUT_ROOT):
    output = Path(output)
    root = Path(approved_root).resolve(strict=True)
    if output.name != "raw-picture-profile-vtable-interface.json" or output.parent.resolve(strict=True) != root or (output.exists() and (output.is_symlink() or not output.is_file())):
        raise RuntimeError("output containment is invalid")
    descriptor, temporary = tempfile.mkstemp(dir=str(root), prefix=".pp-vtable-", suffix=".tmp")
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
    write_json_atomic(OUTPUT_ROOT / "raw-picture-profile-vtable-interface.json", build_raw_export())
    print("PICTURE_PROFILE_VTABLE_INTERFACE_EXPORT|relocations=66|pp1_pp9=0|selected=0|persistence=0|processing=0|output=0")
