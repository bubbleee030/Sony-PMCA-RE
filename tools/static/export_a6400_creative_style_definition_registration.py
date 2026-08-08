"""Read-only deterministic exporter for α6400 Creative Style definition metadata."""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from pmca.analysis.creative_style_definition_registration import (
    CAUTION_CONFIG_SHA256, CAUTION_CONFIG_SIZE, CONSTRUCTOR_ALIASES, EXPECTED_RAW_EXPORT,
    GOT_BINDINGS, INITIALIZER, NEGATIVE_SCAN, PARITY_SLOTS, PLT_BINDINGS, PRIOR_ARTIFACTS,
    PROPERTY_LIST, PROPERTY_ROOT, PUBLICATION, ROOT as CREATIVE_ROOT,
    ROOT_CONSTRUCTOR_BINDINGS, SELECTOR, VTABLE,
    normalize_creative_style_definition_registration_export,
)


SOURCE = ROOT / ".artifacts" / "decrypted" / "a6400-tw-v2.00" / "ma1co" / "firmware.tar_unpacked" / "0700_part_image" / "dev" / "nflasha15_unpacked" / "lib" / "CautionConfig.so"
ARTIFACT_BASE = ROOT / ".artifacts"
OUTPUT_ROOT = ARTIFACT_BASE / "creative-style-definition-registration-trace" / "a6400-v2.00"
OUTPUT_NAME = "raw-creative-style-definition-registration.json"
REPORTS = {
    "picture_profile_vtable_interface_sha256": ROOT / "analysis" / "a6400-picture-profile-vtable-interface.json",
    "picture_profile_generic_consumers_sha256": ROOT / "analysis" / "a6400-picture-profile-generic-consumers.json",
    "picture_profile_initializer_registration_sha256": ROOT / "analysis" / "a6400-picture-profile-initializer-registration.json",
}


def _deps():
    try:
        from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_OP_MEM, Cs
        from elftools.elf.elffile import ELFFile
    except ImportError:
        for package_root in (ROOT / ".artifacts" / "pydeps", ROOT / ".artifacts" / "pydeps_vlf", ROOT / ".artifacts" / "python-packages"):
            if package_root.is_dir() and str(package_root) not in sys.path:
                sys.path.insert(0, str(package_root))
        try:
            from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_OP_MEM, Cs
            from elftools.elf.elffile import ELFFile
        except ImportError as exc:
            raise RuntimeError("local Capstone and pyelftools are required for static metadata export") from exc
    return CS_ARCH_ARM, CS_MODE_ARM, CS_OP_MEM, Cs, ELFFile


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _symbol_record(elf, index, expected):
    symbol = elf.get_section_by_name(".dynsym").get_symbol(index)
    section = elf.get_section(symbol["st_shndx"])
    candidate = {
        "symbol_index": index, "symbol": symbol.name, "elf_address": hex(symbol["st_value"]),
        "analysis_address": hex(symbol["st_value"] + 0x10000), "size": symbol["st_size"],
        "section": section.name, "elf_symbol_type": symbol["st_info"]["type"],
    }
    if symbol["st_info"]["bind"] != "STB_GLOBAL" or symbol["st_other"]["visibility"] != "STV_DEFAULT" or candidate != expected:
        raise RuntimeError("Creative Style object symbol metadata differs")
    return candidate


def _relocation_record(relocations, index, expected, expected_symbol_index):
    relocation = relocations[index]
    candidate = {"relocation_index": index, "relocation_type": {2: "R_ARM_ABS32", 21: "R_ARM_GLOB_DAT", 22: "R_ARM_JUMP_SLOT"}.get(relocation.entry.r_info_type), "site": hex(relocation.entry.r_offset), "symbol_index": relocation.entry.r_info_sym}
    if "role" in expected:
        candidate["role"] = expected["role"]
    if candidate != {**{key: value for key, value in expected.items() if key in candidate}, "symbol_index": expected_symbol_index}:
        raise RuntimeError("Creative Style relocation metadata differs")
    return candidate


def _load_mappings(elf):
    return [(segment["p_vaddr"], segment["p_vaddr"] + segment["p_filesz"], segment["p_offset"]) for segment in elf.iter_segments() if segment["p_type"] == "PT_LOAD"]


def _bytes_at_va(binary, mappings, address, length):
    offsets = [file_offset + address - start for start, end, file_offset in mappings if start <= address and address + length <= end]
    if len(offsets) != 1:
        raise RuntimeError("PLT stub does not map through exactly one load segment")
    return binary[offsets[0]:offsets[0] + length]


def _decoded_plt_addresses(elf, binary, mappings):
    CS_ARCH_ARM, CS_MODE_ARM, CS_OP_MEM, Cs, _ELFFile = _deps()
    plt = elf.get_section_by_name(".plt")
    decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    decoder.detail = True
    decoded = {}
    for address in range(plt["sh_addr"], plt["sh_addr"] + plt["sh_size"] - 11, 4):
        instructions = list(decoder.disasm(_bytes_at_va(binary, mappings, address, 12), address))
        if len(instructions) != 3 or [item.mnemonic for item in instructions] != ["add", "add", "ldr"]:
            continue
        if instructions[2].operands[1].type != CS_OP_MEM:
            continue
        got = address + 8 + instructions[0].operands[2].imm + instructions[1].operands[2].imm + instructions[2].operands[1].mem.disp
        if got in decoded:
            raise RuntimeError("multiple decoded PLT stubs map to one GOT entry")
        decoded[got] = address
    return decoded


def _plt_bindings(elf, binary, mappings):
    dynsym, relplt = elf.get_section_by_name(".dynsym"), list(elf.get_section_by_name(".rel.plt").iter_relocations())
    decoded = _decoded_plt_addresses(elf, binary, mappings)
    result = []
    for expected in PLT_BINDINGS:
        relocation = relplt[expected["relocation_index"]]
        candidate = {
            "role": expected["role"], "relocation_index": expected["relocation_index"],
            "relocation_type": "R_ARM_JUMP_SLOT", "got_address": hex(relocation.entry.r_offset),
            "plt_address": hex(decoded.get(relocation.entry.r_offset, 0)), "symbol_index": relocation.entry.r_info_sym,
            "decoded_stub": relocation.entry.r_offset in decoded,
        }
        if relocation.entry.r_info_type != 22 or dynsym.get_symbol(relocation.entry.r_info_sym).name not in (SELECTOR["symbol"], CONSTRUCTOR_ALIASES["symbols"][0]) or candidate != expected:
            raise RuntimeError("Creative Style PLT binding differs")
        result.append(candidate)
    return result


def _prior_artifacts():
    from pmca.analysis.picture_profile_generic_consumers import validate_picture_profile_generic_consumer_report
    from pmca.analysis.picture_profile_initializer_registration import validate_picture_profile_initializer_registration_report
    from pmca.analysis.picture_profile_vtable_interface import validate_picture_profile_vtable_interface_report

    validators = {
        "picture_profile_vtable_interface_sha256": validate_picture_profile_vtable_interface_report,
        "picture_profile_generic_consumers_sha256": validate_picture_profile_generic_consumer_report,
        "picture_profile_initializer_registration_sha256": validate_picture_profile_initializer_registration_report,
    }
    result = {}
    for key, path in REPORTS.items():
        document = validators[key](json.loads(path.read_text(encoding="utf-8")))
        result[key] = document["summary"]["artifact_sha256"]
    if result != PRIOR_ARTIFACTS:
        raise RuntimeError("prior Picture Profile linkage differs")
    return result


def _slot_record(relocation, relocation_index, dynsym, slot):
    symbol = dynsym.get_symbol(relocation.entry.r_info_sym)
    if symbol["st_info"]["type"] != "STT_FUNC":
        raise RuntimeError("required Creative Style interface slot is not a typed function")
    return {
        "slot": slot, "relocation_index": relocation_index, "relocation_type": "R_ARM_ABS32", "symbol": symbol.name,
        "elf_thumb_target": hex(symbol["st_value"]), "elf_owner": hex(symbol["st_value"] & ~1),
        "analysis_owner": hex((symbol["st_value"] & ~1) + 0x10000), "function_size": symbol["st_size"],
    }


def _vtable_and_parity(elf, rel_dyn):
    dynsym = elf.get_section_by_name(".dynsym")
    vtable = _symbol_record(elf, VTABLE["symbol_index"], {
        "symbol_index": VTABLE["symbol_index"], "symbol": VTABLE["symbol"], "elf_address": VTABLE["elf_address"],
        "analysis_address": VTABLE["analysis_address"], "size": VTABLE["size"], "section": ".data.rel.ro",
        "elf_symbol_type": "STT_OBJECT",
    })
    vtable = {**vtable, "address_point": VTABLE["address_point"], "word_count": VTABLE["word_count"],
              "typed_relocation_count": VTABLE["typed_relocation_count"], "glob_dat": VTABLE["glob_dat"]}
    if vtable != VTABLE:
        raise RuntimeError("Creative Style vtable symbol differs")
    start, end = int(VTABLE["elf_address"], 16), int(VTABLE["elf_address"], 16) + VTABLE["size"]
    typed = sorted(((index, relocation) for index, relocation in enumerate(rel_dyn) if start <= relocation.entry.r_offset < end), key=lambda item: item[1].entry.r_offset)
    if len(typed) != 66 or [relocation.entry.r_offset for _index, relocation in typed] != list(range(start + 4, end, 4)):
        raise RuntimeError("Creative Style vtable relocation coverage differs")
    by_slot = {}
    for index, relocation in typed:
        if relocation.entry.r_info_type != 2:
            raise RuntimeError("Creative Style vtable slot is not a typed ABS32 relocation")
        by_slot[(relocation.entry.r_offset - start) // 4] = (index, relocation)
    parity = {group: [_slot_record(by_slot[slot][1], by_slot[slot][0], dynsym, slot) for slot in slots] for group, slots in PARITY_SLOTS.items()}
    expected = EXPECTED_RAW_EXPORT["structural_parity_slots"]
    if parity != expected:
        raise RuntimeError("Creative Style structural vtable parity differs")
    glob_dat = rel_dyn[VTABLE["glob_dat"]["relocation_index"]]
    if glob_dat.entry.r_info_type != 21 or glob_dat.entry.r_info_sym != VTABLE["symbol_index"] or hex(glob_dat.entry.r_offset) != VTABLE["glob_dat"]["got_address"]:
        raise RuntimeError("Creative Style vtable GLOB_DAT differs")
    return VTABLE, parity


def _init_owner(elf, binary):
    init = elf.get_section_by_name(".init_array")
    if init is None or init["sh_addr"] + 12 != int(INITIALIZER["array_site"], 16) or init["sh_size"] != 24:
        raise RuntimeError("initializer array layout differs")
    target = int.from_bytes(binary[init["sh_offset"] + 12:init["sh_offset"] + 16], "little")
    if target != int(INITIALIZER["elf_thumb_target"], 16):
        raise RuntimeError("Creative Style broad initializer target differs")
    exidx = elf.get_section_by_name(".ARM.exidx")
    starts = []
    for index in range(exidx["sh_size"] // 8):
        address = exidx["sh_addr"] + index * 8
        value = int.from_bytes(binary[exidx["sh_offset"] + index * 8:exidx["sh_offset"] + index * 8 + 4], "little")
        offset = value & 0x7FFFFFFF
        if offset & 0x40000000:
            offset -= 0x80000000
        starts.append(address + offset)
    if starts.count(int(INITIALIZER["elf_owner"], 16)) != 1:
        raise RuntimeError("initializer target lacks an exact exidx owner")
    return INITIALIZER


def _negative_symbol_scan(dynsym):
    matches = []
    for symbol in dynsym.iter_symbols():
        name = symbol.name.casefold()
        if any(fragment in name for fragment in NEGATIVE_SCAN["name_fragments"]) and any(verb in name for verb in NEGATIVE_SCAN["verbs"]):
            matches.append(symbol.name)
    result = {"name_fragments": NEGATIVE_SCAN["name_fragments"], "verbs": NEGATIVE_SCAN["verbs"], "matches": sorted(matches)}
    if result != NEGATIVE_SCAN:
        raise RuntimeError("Creative Style persistence-like dynamic symbol scan is non-empty")
    return result


def _root_constructor_bindings(elf, binary, mappings):
    from capstone import CS_ARCH_ARM, CS_MODE_THUMB, CS_OP_IMM, CS_OP_MEM, CS_OP_REG, Cs
    from capstone.arm import (
        ARM_INS_ADD,
        ARM_INS_BLX,
        ARM_INS_LDR,
        ARM_INS_MOV,
        ARM_REG_PC,
        ARM_REG_R0,
        ARM_REG_R1,
        ARM_REG_R2,
        ARM_REG_R3,
        ARM_REG_R4,
        ARM_REG_R8,
    )

    expected = ROOT_CONSTRUCTOR_BINDINGS[0]
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True

    def instruction(address, size=4):
        items = list(decoder.disasm(_bytes_at_va(binary, mappings, address, size), address, 1))
        if len(items) != 1 or items[0].address != address:
            raise RuntimeError("Creative Style root constructor instruction is absent")
        return items[0]

    def word(address):
        return int.from_bytes(_bytes_at_va(binary, mappings, address, 4), "little")

    def literal_address(item):
        if (
            item.id != ARM_INS_LDR
            or len(item.operands) != 2
            or item.operands[1].type != CS_OP_MEM
            or item.operands[1].mem.base != ARM_REG_PC
            or item.operands[1].mem.index != 0
        ):
            return None
        return ((item.address + 4) & ~3) + item.operands[1].mem.disp

    init = elf.get_section_by_name(".init_array")
    if init is None or init["sh_size"] != 24:
        raise RuntimeError("Creative Style root constructor init-array differs")
    init_values = [
        int.from_bytes(binary[init["sh_offset"] + index * 4:init["sh_offset"] + index * 4 + 4], "little")
        for index in range(init["sh_size"] // 4)
    ]
    if (
        [init_values[index] for index in expected["init_array_indices"]]
        != [int(value, 16) for value in expected["init_array_targets"]]
        or [hex(init["sh_addr"] + index * 4) for index in expected["init_array_indices"]]
        != expected["init_array_sites"]
    ):
        raise RuntimeError("Creative Style root constructor init-array targets differ")

    exidx = elf.get_section_by_name(".ARM.exidx")
    starts = []
    for index in range(exidx["sh_size"] // 8):
        place = exidx["sh_addr"] + index * 8
        value = int.from_bytes(
            binary[exidx["sh_offset"] + index * 8:exidx["sh_offset"] + index * 8 + 4],
            "little",
        )
        offset = value & 0x7FFFFFFF
        if offset & 0x40000000:
            offset -= 0x80000000
        starts.append(place + offset)
    owner_start = int(expected["owner_start"], 16)
    owner_index = starts.index(owner_start) if starts.count(owner_start) == 1 else -1
    if owner_index < 0 or starts[owner_index + 1] != int(expected["owner_end"], 16):
        raise RuntimeError("Creative Style root constructor owner differs")
    from tools.static.export_a6400_creative_style_menu_list_construction import (
        _cfg_distance,
    )

    owner_items = list(
        decoder.disasm(
            _bytes_at_va(
                binary,
                mappings,
                owner_start,
                int(expected["owner_end"], 16) - owner_start,
            ),
            owner_start,
        )
    )
    decoded_end = owner_items[-1].address + owner_items[-1].size if owner_items else 0
    reachable_entry = int(expected["reachable_entry_normalized"], 16)
    entry_distance = _cfg_distance(
        owner_items, reachable_entry, int(expected["call_site"], 16)
    )
    if (
        expected["reachable_init_array_indices"] != [5]
        or (int(expected["init_array_targets"][5 - expected["init_array_indices"][0]], 16) & ~1)
        != reachable_entry
        or entry_distance != expected["entry_to_call_edge_count"]
        or (decoded_end == int(expected["owner_end"], 16))
        != expected["owner_decode_complete"]
        or decoded_end != int(expected["bounded_decoded_end"], 16)
    ):
        raise RuntimeError("Creative Style root constructor CFG reachability differs")

    pic_load = instruction(0x93AFFA)
    pic_add = instruction(0x93B000)
    if (
        literal_address(pic_load) != 0x93B050
        or pic_load.operands[0].reg != ARM_REG_R4
        or pic_add.id != ARM_INS_ADD
        or pic_add.operands[0].reg != ARM_REG_R4
        or pic_add.operands[1].reg != ARM_REG_PC
        or word(0x93B050) + 0x93B004 != int(expected["pic_base"], 16)
    ):
        raise RuntimeError("Creative Style root constructor PIC base differs")

    root_offset = instruction(0x93B330)
    root_load = instruction(0x93B338)
    properties_offset = instruction(0x93B33C)
    receiver_move = instruction(0x93B340)
    properties_load = instruction(0x93B342)
    call = instruction(0x93B344)
    zero = instruction(0x93B334)
    count = instruction(0x93B336)
    root_cell = int(expected["pic_base"], 16) + word(0x93BD34)
    properties_cell = int(expected["pic_base"], 16) + word(0x93BD38)
    if (
        literal_address(root_offset) != 0x93BD34
        or literal_address(properties_offset) != 0x93BD38
        or root_cell != int(expected["root_got_cell"], 16)
        or properties_cell != int(expected["properties_got_cell"], 16)
        or root_load.id != ARM_INS_LDR
        or root_load.operands[0].reg != ARM_REG_R8
        or root_load.operands[1].mem.base != ARM_REG_R4
        or root_load.operands[1].mem.index != ARM_REG_R3
        or properties_load.id != ARM_INS_LDR
        or properties_load.operands[0].reg != ARM_REG_R3
        or properties_load.operands[1].mem.base != ARM_REG_R4
        or properties_load.operands[1].mem.index != ARM_REG_R3
        or receiver_move.id != ARM_INS_MOV
        or receiver_move.operands[0].reg != ARM_REG_R0
        or receiver_move.operands[1].reg != ARM_REG_R8
        or zero.id != ARM_INS_MOV
        or zero.operands[0].reg != ARM_REG_R1
        or zero.operands[1].type != CS_OP_IMM
        or zero.operands[1].imm != 0
        or count.id != ARM_INS_MOV
        or count.operands[0].reg != ARM_REG_R2
        or count.operands[1].type != CS_OP_REG
        or count.operands[1].reg != ARM_REG_R1
        or call.id != ARM_INS_BLX
        or call.operands[0].type != CS_OP_IMM
        or (call.operands[0].imm & ~1) != int(expected["plt_address"], 16)
    ):
        raise RuntimeError("Creative Style root/properties constructor dataflow differs")

    rel_dyn = list(elf.get_section_by_name(".rel.dyn").iter_relocations())
    dynsym = elf.get_section_by_name(".dynsym")
    for index, site, symbol_index, symbol_name, symbol_value in (
        (
            expected["root_relocation_index"],
            root_cell,
            CREATIVE_ROOT["symbol_index"],
            CREATIVE_ROOT["symbol"],
            int(expected["root_object"], 16),
        ),
        (
            expected["properties_relocation_index"],
            properties_cell,
            PROPERTY_ROOT["symbol_index"],
            PROPERTY_ROOT["symbol"],
            int(expected["properties_object"], 16),
        ),
    ):
        relocation = rel_dyn[index]
        symbol = dynsym.get_symbol(symbol_index)
        if (
            relocation.entry.r_offset != site
            or relocation.entry.r_info_type != 21
            or relocation.entry.r_info_sym != symbol_index
            or symbol.name != symbol_name
            or symbol["st_value"] != symbol_value
        ):
            raise RuntimeError("Creative Style root constructor relocation differs")

    relplt = list(elf.get_section_by_name(".rel.plt").iter_relocations())
    constructor_relocation = relplt[PLT_BINDINGS[1]["relocation_index"]]
    constructor_symbol = dynsym.get_symbol(constructor_relocation.entry.r_info_sym)
    if (
        constructor_relocation.entry.r_info_type != 22
        or constructor_symbol.name != expected["constructor_symbol"]
        or constructor_symbol["st_value"] != int(CONSTRUCTOR_ALIASES["elf_thumb_target"], 16)
    ):
        raise RuntimeError("Creative Style root constructor PLT symbol differs")
    return copy.deepcopy(ROOT_CONSTRUCTOR_BINDINGS)


def _metadata_from_file(source=SOURCE):
    source = Path(source)
    before = _sha256(source)
    if source.name != "CautionConfig.so" or before != CAUTION_CONFIG_SHA256 or source.stat().st_size != CAUTION_CONFIG_SIZE:
        raise RuntimeError("pinned Creative Style source identity differs")
    _CS_ARCH_ARM, _CS_MODE_ARM, _CS_OP_MEM, _Cs, ELFFile = _deps()
    binary = source.read_bytes()
    with io.BytesIO(binary) as stream:
        elf = ELFFile(stream)
        dynsym = elf.get_section_by_name(".dynsym")
        rel_dyn = list(elf.get_section_by_name(".rel.dyn").iter_relocations())
        if dynsym is None or elf.get_section_by_name(".rel.plt") is None:
            raise RuntimeError("required dynamic ELF metadata is absent")
        root = _symbol_record(elf, CREATIVE_ROOT["symbol_index"], CREATIVE_ROOT)
        property_root = _symbol_record(elf, PROPERTY_ROOT["symbol_index"], PROPERTY_ROOT)
        property_list = _symbol_record(elf, PROPERTY_LIST["symbol_index"], PROPERTY_LIST)
        container = _symbol_record(elf, PUBLICATION["container_symbol_index"], {
            "symbol_index": PUBLICATION["container_symbol_index"], "symbol": PUBLICATION["container_symbol"],
            "elf_address": PUBLICATION["container_address"], "analysis_address": "0xb9a380", "size": PUBLICATION["container_size"],
            "section": PUBLICATION["container_section"], "elf_symbol_type": "STT_OBJECT",
        })
        publication = _relocation_record(rel_dyn, PUBLICATION["relocation_index"], PUBLICATION, CREATIVE_ROOT["symbol_index"])
        publication.pop("symbol_index")
        publication.update({key: PUBLICATION[key] for key in PUBLICATION if key not in publication})
        if not int(container["elf_address"], 16) <= int(publication["site"], 16) < int(container["elf_address"], 16) + container["size"] or hex(int(publication["site"], 16) - int(container["elf_address"], 16)) != publication["object_offset"] or publication != PUBLICATION:
            raise RuntimeError("Creative Style default-root publication containment differs")
        got = []
        for expected in GOT_BINDINGS:
            record = _relocation_record(rel_dyn, expected["relocation_index"], expected, expected["symbol_index"])
            if record != expected:
                raise RuntimeError("Creative Style GOT binding differs")
            got.append(record)
        aliases = [dynsym.get_symbol(index) for index in (34548, 21460)]
        alias_candidate = {"symbols": [item.name for item in aliases], "elf_thumb_target": hex(aliases[0]["st_value"]), "elf_owner": hex(aliases[0]["st_value"] & ~1), "analysis_owner": hex((aliases[0]["st_value"] & ~1) + 0x10000), "function_size": aliases[0]["st_size"]}
        if any(item["st_info"]["type"] != "STT_FUNC" for item in aliases) or aliases[0]["st_value"] != aliases[1]["st_value"] or aliases[0]["st_size"] != aliases[1]["st_size"] or alias_candidate != CONSTRUCTOR_ALIASES:
            raise RuntimeError("Creative Style C1/C2 alias metadata differs")
        selector_symbol = dynsym.get_symbol(SELECTOR["symbol_index"])
        selector = {"symbol_index": SELECTOR["symbol_index"], "symbol": selector_symbol.name, "elf_thumb_target": hex(selector_symbol["st_value"]), "elf_owner": hex(selector_symbol["st_value"] & ~1), "analysis_owner": hex((selector_symbol["st_value"] & ~1) + 0x10000), "function_size": selector_symbol["st_size"]}
        if selector_symbol["st_info"]["type"] != "STT_FUNC" or selector != SELECTOR:
            raise RuntimeError("Creative Style selector metadata differs")
        plt_bindings = _plt_bindings(elf, binary, _load_mappings(elf))
        vtable, parity = _vtable_and_parity(elf, rel_dyn)
        initializer = _init_owner(elf, binary)
        root_constructor_bindings = _root_constructor_bindings(
            elf, binary, _load_mappings(elf)
        )
        negative = _negative_symbol_scan(dynsym)
    if _sha256(source) != before:
        raise RuntimeError("pinned source changed during read-only metadata export")
    result = copy.deepcopy(EXPECTED_RAW_EXPORT)
    result.update({"root": root, "property_root": property_root, "property_list": property_list, "publication": publication,
                   "got_bindings": got, "constructor_aliases": alias_candidate, "selector": selector, "plt_bindings": plt_bindings,
                   "vtable": vtable, "structural_parity_slots": parity, "prior_artifacts": _prior_artifacts(),
                   "initializer": initializer, "root_constructor_bindings": root_constructor_bindings,
                   "negative_symbol_scan": negative})
    return result


class FileAdapter:
    def __init__(self, source=SOURCE):
        self.source = Path(source)

    def metadata(self):
        return _metadata_from_file(self.source)


def build_raw_export(adapter):
    try:
        document = adapter.metadata()
        normalize_creative_style_definition_registration_export(document)
        return document
    except Exception as error:
        raise RuntimeError("Creative Style definition metadata differs from the exact bounded contract") from error


def prepare_output_root(approved_root=OUTPUT_ROOT, artifact_base=ARTIFACT_BASE):
    """Create only literal directory components beneath the fixed artifact base."""
    base = Path(os.path.abspath(os.fspath(artifact_base)))
    target = Path(os.path.abspath(os.fspath(approved_root)))
    if base.is_symlink() or not base.is_dir():
        raise RuntimeError("artifact base is not a literal directory")
    try:
        relative = target.relative_to(base)
    except ValueError as error:
        raise RuntimeError("approved output root is not beneath the artifact base") from error
    current = base
    if current.resolve(strict=True) != current:
        raise RuntimeError("artifact base resolves through a link")
    for part in relative.parts:
        current = current / part
        if current.exists() or current.is_symlink():
            if current.is_symlink() or not current.is_dir() or current.resolve(strict=True) != current:
                raise RuntimeError("approved output root escapes through a symlink")
        else:
            current.mkdir()
            if current.is_symlink() or not current.is_dir() or current.resolve(strict=True) != current:
                raise RuntimeError("approved output root is not a literal directory")
    return current


def write_json_atomic(output, document, approved_root=OUTPUT_ROOT, artifact_base=ARTIFACT_BASE):
    root = prepare_output_root(approved_root, artifact_base)
    output = Path(os.path.abspath(os.fspath(output)))
    expected = root / OUTPUT_NAME
    if output != expected or output.parent != root or (output.exists() and (output.is_symlink() or not output.is_file())):
        raise RuntimeError("output path escapes the fixed artifact root")
    descriptor, temporary = tempfile.mkstemp(dir=str(root), prefix=".creative-style-definition-", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(document, stream, sort_keys=True, separators=(",", ":"))
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
    args = list(sys.argv[1:] if args is None else args)
    if args:
        raise SystemExit("usage: no arguments; the source and output locations are pinned")
    write_json_atomic(OUTPUT_ROOT / OUTPUT_NAME, build_raw_export(FileAdapter()))
    print("CREATIVE_STYLE_DEFINITION_REGISTRATION_EXPORT|publication=1|vtable_relocations=66|constructor_static=1|constructor_runtime=0|selected=0|persistence=0|processing=0|output=0")


if __name__ == "__main__":
    main()
