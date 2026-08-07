"""Deterministically export bounded α6400 vertical-layout factory metadata."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile


EXPECTED_PROGRAM = "viewUnified7.so"
EXPECTED_SHA256 = "c48cde43ff22d808ad23c42019ddae516fff7da060004eb81ed2bb85012aa538"
EXPECTED_IMAGE_SIZE = 541_024
VIEW_UNIFIED2_SHA256 = "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2"
VIEW_UNIFIED2_IMAGE_SIZE = 11_530_552
FACTORY_ROOT = 0x52840
FACTORY_OWNER = {"start": 0x52840, "end": 0x529B8}
FACTORY_GROUP_ID = 0x1B906244
TOTAL_CONSTRUCTOR_ARM_COUNT = 12
VERTICAL_CLASSICAL_ARMS = (
    {"id": "info", "class_id": 0x61DC811C, "site": 0x52934, "target": 0x14E9C},
    {"id": "footer", "class_id": 0x186C17F6, "site": 0x52944, "target": 0x14028},
    {"id": "header-manual-info", "class_id": 0x8E7FDF88, "site": 0x52914, "target": 0x14148},
    {"id": "manual", "class_id": 0x7BE1C309, "site": 0x52954, "target": 0x14D64},
    {"id": "error", "class_id": 0xBDBC36BD, "site": 0x52924, "target": 0x14B04},
)
INVALID_OFFSET_CLASSIFICATIONS = (
    {"offset": 0x181F18, "classification": "internal-conditional-branch"},
    {"offset": 0x24222C, "classification": "non-instruction-boundary-second-halfword"},
    {"offset": 0x3BA6DC, "classification": "non-instruction-boundary-second-halfword"},
    {"offset": 0x651684, "classification": "non-instruction-boundary-second-halfword"},
)
FALSE_CLASS_ID_PATHS = tuple(
    {"offset": offset, "classification": "constructor-vptr-material-path", "class_id_load": False}
    for offset in (0x37B614, 0x37AA18, 0x37B5E0, 0x37B648, 0x37B578)
)
CONSTRUCTORS = (
    {"id": "header-manual-info", "caller": FACTORY_ROOT, "site": 0x52914, "target": 0x14148, "kind": "direct"},
    {"id": "error", "caller": FACTORY_ROOT, "site": 0x52924, "target": 0x14B04, "kind": "direct"},
    {"id": "info", "caller": FACTORY_ROOT, "site": 0x52934, "target": 0x14E9C, "kind": "direct"},
    {"id": "footer", "caller": FACTORY_ROOT, "site": 0x52944, "target": 0x14028, "kind": "direct"},
    {"id": "manual", "caller": FACTORY_ROOT, "site": 0x52954, "target": 0x14D64, "kind": "direct"},
)
REVERSE_CALLERS = ({"caller": 0x529CC, "site": 0x529D6, "target": FACTORY_ROOT, "kind": "direct"},)
UPSTREAM_ROOTS = {
    "camera_orientation_owners": (0x2D2C6, 0x30750),
    "status_orientation_owners": (0x189DC, 0x1B070, 0x1C56C),
    "layout_mode": {"site_count": 28, "owner_count": 15, "owner_overlap_with_factory": False},
}

DECISION_SPECS = (
    (0x52844, 0x52980, 0x1B906244, 0x52846, ((0x52848, 0x528BC, "eq"),)),
    (0x5284A, 0x52984, 0xE66E6CA4, 0x5284C, ((0x5284E, 0x5297A, "ne"),)),
    (0x52852, 0x52988, 0x1CF3C888, 0x52854, ((0x52856, 0x52874, "eq"), (0x52858, 0x52864, "hi"))),
    (0x5285A, 0x5298C, 0x11BFB8FE, 0x5285C, ((0x5285E, 0x5297A, "ne"), (0x52862, 0x528AA, "al"))),
    (0x52864, 0x52990, 0x30302FDC, 0x52866, ((0x52868, 0x52886, "eq"),)),
    (0x5286A, 0x52994, 0xCE5C071A, 0x5286C, ((0x5286E, 0x5297A, "ne"), (0x52872, 0x52898, "al"))),
    (0x528BC, 0x52998, 0x61DC811C, 0x528BE, ((0x528C0, 0x5292A, "eq"), (0x528C2, 0x528D8, "hi"))),
    (0x528C4, 0x5299C, 0x186C17F6, 0x528C6, ((0x528C8, 0x5293A, "eq"),)),
    (0x528CA, 0x529A0, 0x404BE01F, 0x528CC, ((0x528CE, 0x5295A, "eq"),)),
    (0x528D0, 0x529A4, 0x064A2EF8, 0x528D2, ((0x528D4, 0x5297A, "ne"), (0x528D6, 0x528F6, "al"))),
    (0x528D8, 0x529A8, 0x8E7FDF88, 0x528DA, ((0x528DC, 0x52908, "eq"), (0x528DE, 0x528E8, "hi"))),
    (0x528E0, 0x529AC, 0x7BE1C309, 0x528E2, ((0x528E4, 0x5297A, "ne"), (0x528E6, 0x5294A, "al"))),
    (0x528E8, 0x529B0, 0xBDBC36BD, 0x528EA, ((0x528EC, 0x5291A, "eq"),)),
    (0x528EE, 0x529B4, 0xFE6E20C3, 0x528F0, ((0x528F2, 0x5297A, "ne"), (0x528F4, 0x5296A, "al"))),
)

FACTORY_ARMS = (
    (0x52874, 0x52876, 0x52880, 0x52774),
    (0x52886, 0x52888, 0x52892, 0x52798),
    (0x52898, 0x5289A, 0x528A4, 0x527BC),
    (0x528AA, 0x528AC, 0x528B6, 0x527E0),
    (0x528F6, 0x528F8, 0x52902, 0x147EC),
    (0x52908, 0x5290A, 0x52914, 0x14148),
    (0x5291A, 0x5291C, 0x52924, 0x14B04),
    (0x5292A, 0x5292C, 0x52934, 0x14E9C),
    (0x5293A, 0x5293C, 0x52944, 0x14028),
    (0x5294A, 0x5294C, 0x52954, 0x14D64),
    (0x5295A, 0x5295C, 0x52964, 0x14B48),
    (0x5296A, 0x5296C, 0x52974, 0x13D1C),
)

VIEW_UNIFIED2_CLASSIFICATION_SPECS = (
    (0x181F18, (0x1729E8, 0x184AC4), "conditional-branch", 0x183FA8),
    (0x24222C, (0x23A8C0, 0x2A3680), "second-halfword", 0x24222A),
    (0x3BA6DC, (0x3B6940, 0x3BBED8), "second-halfword", 0x3BA6DA),
    (0x651684, (0x64DA44, 0x6549E4), "second-halfword", 0x651682),
    (0x37B614, (0x37B60C, 0x37B630), "vptr-material", (0x37B62C, 0x9D30)),
    (0x37AA18, (0x37AA10, 0x37AA34), "vptr-material", (0x37AA30, 0xA0D0)),
    (0x37B5E0, (0x37B5D8, 0x37B5FC), "vptr-material", (0x37B5F8, 0x60B0)),
    (0x37B648, (0x37B640, 0x37B664), "vptr-material", (0x37B660, 0xA524)),
    (0x37B578, (0x37B570, 0x37B594), "vptr-material", (0x37B590, 0xB034)),
)


def _at(blob, mappings, address, width):
    for start, end, file_offset in mappings:
        if start <= address and address + width <= end:
            return blob[file_offset + address - start:file_offset + address - start + width]
    raise RuntimeError("address is outside a file-backed PT_LOAD mapping")


def _word(blob, mappings, address):
    return int.from_bytes(_at(blob, mappings, address, 4), "little")


def _decoder(deps):
    decoder = deps["Cs"](deps["arch"], deps["thumb_mode"])
    decoder.detail = True
    return decoder


def _decode(blob, mappings, deps, start, end, *, complete=True):
    items = list(_decoder(deps).disasm(_at(blob, mappings, start, end - start), start))
    if complete and (not items or items[0].address != start or items[-1].address + items[-1].size != end):
        raise RuntimeError("bounded Thumb range is incomplete")
    return items


def _instruction(blob, mappings, deps, site):
    items = _decode(blob, mappings, deps, site, site + 4, complete=False)
    if not items or items[0].address != site:
        raise RuntimeError("instruction site does not decode")
    return items[0]


def _direct_target(item, deps):
    targets = [operand.imm & ~1 for operand in item.operands if operand.type == deps["imm"]]
    return targets[0] if len(targets) == 1 else None


def _owner(exidx, address):
    matches = [item for item in exidx if item[0] <= address < item[1]]
    if len(matches) != 1:
        raise RuntimeError("exception-index owner is not exact")
    return matches[0]


def _validate_factory(blob, mappings, deps, exidx, plt_symbols):
    """Validate exact owners, decisions, allocations, and constructor arms."""
    if not isinstance(blob, (bytes, bytearray)) or not mappings or not isinstance(deps, dict):
        raise RuntimeError("factory validation inputs are incomplete")
    if _owner(exidx, FACTORY_ROOT) != (FACTORY_OWNER["start"], FACTORY_OWNER["end"]):
        raise RuntimeError("factory ARM.exidx owner differs")
    if _owner(exidx, 0x529CC) != (0x529CC, 0x529E8):
        raise RuntimeError("factory wrapper ARM.exidx owner differs")

    for load_site, literal_site, value, compare_site, branches in DECISION_SPECS:
        load = _instruction(blob, mappings, deps, load_site)
        if (
            load.id != deps["ldr"]
            or len(load.operands) != 2
            or load.operands[0].type != deps["reg"]
            or load.operands[1].type != deps["mem"]
            or load.operands[1].mem.base != deps["pc"]
            or ((load.address + 4) & ~3) + load.operands[1].mem.disp != literal_site
            or _word(blob, mappings, literal_site) != value
        ):
            raise RuntimeError("factory group/class literal load differs")
        compare = _instruction(blob, mappings, deps, compare_site)
        input_register = deps["r0"] if compare_site in {0x52846, 0x5284C} else deps["r1"]
        if (
            compare.id != deps["cmp"]
            or len(compare.operands) != 2
            or any(operand.type != deps["reg"] for operand in compare.operands)
            or load.operands[0].reg != deps["r3"]
            or compare.operands[0].reg != input_register
            or compare.operands[1].reg != load.operands[0].reg
            or compare.operands[0].reg == compare.operands[1].reg
        ):
            raise RuntimeError("factory group/class comparison differs")
        for branch_site, branch_target, condition in branches:
            branch = _instruction(blob, mappings, deps, branch_site)
            if (
                not branch.group(deps["jump_group"])
                or branch.group(deps["call_group"])
                or branch.cc != deps[condition]
                or _direct_target(branch, deps) != branch_target
            ):
                raise RuntimeError("factory decision branch differs")

    owner_items = _decode(blob, mappings, deps, FACTORY_OWNER["start"], 0x52980)
    allocation_target = plt_symbols.get("malloc")
    if allocation_target != 0x14A08:
        raise RuntimeError("factory allocation PLT binding differs")
    direct_calls = {
        item.address: _direct_target(item, deps)
        for item in owner_items if item.group(deps["call_group"])
    }
    expected_call_sites = set()
    for size_site, allocation_site, constructor_site, constructor_target in FACTORY_ARMS:
        expected_call_sites.update((allocation_site, constructor_site))
        size = _instruction(blob, mappings, deps, size_site)
        if (
            size.id != deps["mov"]
            or len(size.operands) != 2
            or size.operands[0].type != deps["reg"]
            or size.operands[0].reg != deps["r0"]
            or size.operands[1].type != deps["imm"]
            or size.operands[1].imm != 0x18
        ):
            raise RuntimeError("factory allocation size differs")
        if direct_calls.get(allocation_site) != allocation_target:
            raise RuntimeError("factory allocation arm differs")
        if direct_calls.get(constructor_site) != constructor_target:
            raise RuntimeError("factory constructor arm differs")
    if (
        len(FACTORY_ARMS) != TOTAL_CONSTRUCTOR_ARM_COUNT
        or set(direct_calls) != expected_call_sites
        or sum(target == allocation_target for target in direct_calls.values()) != TOTAL_CONSTRUCTOR_ARM_COUNT
    ):
        raise RuntimeError("factory constructor arm count differs")

    wrapper_call = _instruction(blob, mappings, deps, 0x529D6)
    if not wrapper_call.group(deps["call_group"]) or _direct_target(wrapper_call, deps) != FACTORY_ROOT:
        raise RuntimeError("factory wrapper forwarding call differs")

    return {
        "constructors": CONSTRUCTORS, "reverse_callers": REVERSE_CALLERS,
        "unresolved_indirect_terminals": (), "owner": FACTORY_OWNER,
        "total_constructor_arm_count": len(FACTORY_ARMS),
        "group_id": FACTORY_GROUP_ID, "vertical_classical_arms": VERTICAL_CLASSICAL_ARMS,
        "invalid_offset_classifications": INVALID_OFFSET_CLASSIFICATIONS,
        "false_class_id_paths": FALSE_CLASS_ID_PATHS,
    }


def _validate_invalid_offset_classifications(blob, mappings, deps, exidx):
    """Validate only the sibling viewUnified2 instruction/owner classifications."""
    for offset, expected_owner, classification, evidence in VIEW_UNIFIED2_CLASSIFICATION_SPECS:
        if _owner(exidx, offset) != expected_owner:
            raise RuntimeError("viewUnified2 invalid-offset owner differs")
        if classification == "conditional-branch":
            item = _instruction(blob, mappings, deps, offset)
            if (
                item.size != 4
                or not item.group(deps["jump_group"])
                or item.group(deps["call_group"])
                or item.cc != deps["eq"]
                or _direct_target(item, deps) != evidence
            ):
                raise RuntimeError("viewUnified2 internal branch classification differs")
        elif classification == "second-halfword":
            item = _instruction(blob, mappings, deps, evidence)
            if item.address + 2 != offset or item.size != 4:
                raise RuntimeError("viewUnified2 second-halfword classification differs")
            if offset == 0x24222C:
                operands = item.operands
                if (
                    item.id != deps["add"]
                    or len(operands) != 3
                    or operands[0].type != deps["reg"] or operands[0].reg != deps["r5"]
                    or operands[1].type != deps["reg"] or operands[1].reg != deps["r7"]
                    or operands[2].type != deps["imm"] or operands[2].imm != 0x2B800
                ):
                    raise RuntimeError("viewUnified2 add second-halfword evidence differs")
            elif offset == 0x3BA6DC:
                if item.id != deps["blx"] or _direct_target(item, deps) != 0x14EDA8:
                    raise RuntimeError("viewUnified2 call second-halfword evidence differs")
            elif item.id != deps["b"] or _direct_target(item, deps) != 0x651EA0:
                raise RuntimeError("viewUnified2 branch second-halfword evidence differs")
        else:
            literal_site, literal_value = evidence
            item = _instruction(blob, mappings, deps, offset)
            if (
                item.id != deps["ldr"]
                or item.size != 2
                or len(item.operands) != 2
                or item.operands[0].type != deps["reg"]
                or item.operands[0].reg != deps["r2"]
                or item.operands[1].type != deps["mem"]
                or item.operands[1].mem.base != deps["pc"]
                or ((item.address + 4) & ~3) + item.operands[1].mem.disp != literal_site
                or _word(blob, mappings, literal_site) != literal_value
            ):
                raise RuntimeError("viewUnified2 constructor vptr-material evidence differs")
    return INVALID_OFFSET_CLASSIFICATIONS


def _require_dependencies():
    try:
        from capstone import (
            Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB,
            CS_GRP_CALL, CS_GRP_JUMP, CS_OP_IMM,
        )
        from capstone.arm import (
            ARM_CC_AL, ARM_CC_EQ, ARM_CC_HI, ARM_CC_NE,
            ARM_INS_ADD, ARM_INS_B, ARM_INS_BLX, ARM_INS_CMP, ARM_INS_LDR, ARM_INS_MOV,
            ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC, ARM_REG_R0, ARM_REG_R1, ARM_REG_R2,
            ARM_REG_R3, ARM_REG_R4, ARM_REG_R5, ARM_REG_R7,
        )
        from elftools.elf.elffile import ELFFile
    except (ImportError, AttributeError) as error:
        raise RuntimeError("vertical factory export requires capstone and pyelftools") from error
    return {
        "Cs": Cs, "arch": CS_ARCH_ARM, "arm_mode": CS_MODE_ARM,
        "thumb_mode": CS_MODE_THUMB, "call_group": CS_GRP_CALL,
        "jump_group": CS_GRP_JUMP, "imm": CS_OP_IMM,
        "al": ARM_CC_AL, "eq": ARM_CC_EQ, "hi": ARM_CC_HI, "ne": ARM_CC_NE,
        "add": ARM_INS_ADD, "b": ARM_INS_B, "blx": ARM_INS_BLX,
        "cmp": ARM_INS_CMP, "ldr": ARM_INS_LDR, "mov": ARM_INS_MOV, "mem": ARM_OP_MEM,
        "reg": ARM_OP_REG, "pc": ARM_REG_PC, "r0": ARM_REG_R0, "r1": ARM_REG_R1,
        "r2": ARM_REG_R2, "r3": ARM_REG_R3, "r4": ARM_REG_R4,
        "r5": ARM_REG_R5, "r7": ARM_REG_R7, "ELFFile": ELFFile,
    }


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _prel31(value, place):
    value &= 0x7fffffff
    return place + (value - 0x80000000 if value & 0x40000000 else value)


def _mappings(elf):
    return tuple(
        (segment["p_vaddr"], segment["p_vaddr"] + segment["p_filesz"], segment["p_offset"])
        for segment in elf.iter_segments() if segment["p_type"] == "PT_LOAD"
    )


def _exidx_ranges(blob, exidx):
    starts = sorted(
        _prel31(
            int.from_bytes(blob[offset:offset + 4], "little"),
            exidx["sh_addr"] + index * 8,
        )
        for index, offset in enumerate(
            range(exidx["sh_offset"], exidx["sh_offset"] + exidx["sh_size"], 8)
        )
    )
    return tuple(zip(starts, starts[1:])), starts


def _validate_view_unified2_classifications(source_path):
    path = Path(source_path)
    before = _sha256(path)
    if (
        path.name != "viewUnified2.so"
        or path.is_symlink()
        or path.stat().st_size != VIEW_UNIFIED2_IMAGE_SIZE
        or before != VIEW_UNIFIED2_SHA256
    ):
        raise RuntimeError("sibling viewUnified2 source identity differs")
    deps = _require_dependencies()
    blob = path.read_bytes()
    with path.open("rb") as stream:
        elf = deps["ELFFile"](stream)
        exidx_section = elf.get_section_by_name(".ARM.exidx")
        if exidx_section is None:
            raise RuntimeError("sibling viewUnified2 exception index is missing")
        ranges, _starts = _exidx_ranges(blob, exidx_section)
        result = _validate_invalid_offset_classifications(
            blob, _mappings(elf), deps, ranges
        )
    if _sha256(path) != before:
        raise RuntimeError("sibling viewUnified2 source changed during read-only validation")
    return result


def _metadata_from_file(source_path):
    deps = _require_dependencies()
    Cs, arch = deps["Cs"], deps["arch"]
    arm_mode, thumb_mode = deps["arm_mode"], deps["thumb_mode"]
    call_group, imm_type, ELFFile = deps["call_group"], deps["imm"], deps["ELFFile"]
    path = Path(source_path)
    before = _sha256(path)
    if path.name != EXPECTED_PROGRAM or before != EXPECTED_SHA256 or path.stat().st_size != EXPECTED_IMAGE_SIZE:
        raise RuntimeError("vertical factory source identity is not pinned")
    blob = path.read_bytes()
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        relplt = elf.get_section_by_name(".rel.plt")
        dynsym = elf.get_section(relplt["sh_link"])
        plt = elf.get_section_by_name(".plt")
        text = elf.get_section_by_name(".text")
        exidx = elf.get_section_by_name(".ARM.exidx")
        if None in (relplt, dynsym, plt, text, exidx):
            raise RuntimeError("vertical factory ELF sections are missing")
        mappings = _mappings(elf)
        got_to_symbol = {entry["r_offset"]: dynsym.get_symbol(entry["r_info_sym"]).name for entry in relplt.iter_relocations()}
        arm = Cs(arch, arm_mode); arm.detail = True
        got_to_plt = {}
        plt_data = plt.data()
        for offset in range(0, plt["sh_size"] - 11, 4):
            start = plt["sh_addr"] + offset
            decoded = list(arm.disasm(plt_data[offset:offset + 12], start))
            if len(decoded) != 3 or [item.mnemonic for item in decoded] != ["add", "add", "ldr"]:
                continue
            if not decoded[0].op_str.startswith("ip, pc") or not decoded[1].op_str.startswith("ip, ip") or not decoded[2].op_str.startswith("pc, [ip,"):
                continue
            got_to_plt[(start + 8) + decoded[1].operands[2].imm + decoded[2].operands[1].mem.disp] = start
        expected_symbols = {
            "header-manual-info": "_ZN16LG_master_camera62Layoutlayout_CMN_M_REC_VERTICAL_CLASSICAL_HEADER_MANUALINFO_LRC1Ev",
            "error": "_ZN16LG_master_camera50Layoutlayout_CMN_M_REC_VERTICAL_CLASSICAL_ERROR_LRC1Ev",
            "info": "_ZN16LG_master_camera49Layoutlayout_CMN_M_REC_VERTICAL_CLASSICAL_INFO_LRC1Ev",
            "footer": "_ZN16LG_master_camera51Layoutlayout_CMN_M_REC_FOOTER_VERTICAL_CLASSICAL_LRC1Ev",
            "manual": "_ZN16LG_master_camera51Layoutlayout_CMN_M_REC_VERTICAL_CLASSICAL_MANUAL_LRC1Ev",
        }
        upstream_symbols = {
            "layout_mode": ("_ZN15ViewBaseProduct17UserGetLayoutModeEi", 0x13D34),
            "camera_orientation": ("_ZN27CmnWrpOrientationRegisterAF20getCameraOrientationEv", 0x14958),
            "status_orientation": ("_ZN27CmnWrpOrientationRegisterAF23getStsCameraOrientationEv", 0x15008),
        }
        wanted_names = set(expected_symbols.values()) | {item[0] for item in upstream_symbols.values()} | {"malloc"}
        symbol_to_plt = {name: got_to_plt[got] for got, name in got_to_symbol.items() if name in wanted_names and got in got_to_plt}
        for edge in CONSTRUCTORS:
            if symbol_to_plt.get(expected_symbols[edge["id"]]) != edge["target"]:
                raise RuntimeError("vertical constructor PLT mapping is not pinned")
        if any(symbol_to_plt.get(name) != target for name, target in upstream_symbols.values()):
            raise RuntimeError("vertical upstream PLT mapping is not pinned")
        exidx_ranges, exidx_starts = _exidx_ranges(blob, exidx)
        if FACTORY_ROOT not in exidx_starts:
            raise RuntimeError("factory root is not an exact ARM.exidx owner")
        thumb = Cs(arch, thumb_mode); thumb.detail = True; thumb.skipdata = True
        text_start = text["sh_addr"]
        text_end = text_start + text["sh_size"]
        text_data = text.data()
        function_starts = sorted({value for value in exidx_starts if text_start <= value < text_end})
        local_calls = []
        all_calls = []
        for index, owner in enumerate(function_starts):
            end = function_starts[index + 1] if index + 1 < len(function_starts) else text_end
            code = text_data[owner - text_start:end - text_start]
            for instruction in thumb.disasm(code, owner):
                if instruction.id == 0 or not instruction.group(call_group):
                    continue
                if not instruction.operands or instruction.operands[0].type != imm_type:
                    if owner == FACTORY_ROOT:
                        local_calls.append({"site": instruction.address, "kind": "unresolved-indirect"})
                    continue
                call = {"caller": owner, "site": instruction.address, "target": instruction.operands[0].imm & ~1}
                if owner == FACTORY_ROOT:
                    local_calls.append({"site": call["site"], "target": call["target"]})
                all_calls.append(call)
        observed = tuple({"id": edge["id"], "caller": FACTORY_ROOT, "site": edge["site"], "target": edge["target"], "kind": "direct"} for edge in CONSTRUCTORS if {"site": edge["site"], "target": edge["target"]} in local_calls)
        if observed != CONSTRUCTORS:
            raise RuntimeError("factory local direct calls are not exact")
        reverse = tuple({"caller": item["caller"], "site": item["site"], "target": FACTORY_ROOT, "kind": "direct"} for item in all_calls if item["target"] == FACTORY_ROOT)
        unresolved = tuple(item for item in local_calls if item.get("kind") == "unresolved-indirect")
        def calls_to(label):
            target = upstream_symbols[label][1]
            return tuple(item for item in all_calls if item["target"] == target)
        camera_calls = calls_to("camera_orientation")
        status_calls = calls_to("status_orientation")
        layout_calls = calls_to("layout_mode")
        upstream = {
            "camera_orientation_owners": tuple(sorted({item["caller"] for item in camera_calls})),
            "status_orientation_owners": tuple(sorted({item["caller"] for item in status_calls})),
            "layout_mode": {
                "site_count": len(layout_calls),
                "owner_count": len({item["caller"] for item in layout_calls}),
                "owner_overlap_with_factory": any(item["caller"] == FACTORY_ROOT for item in layout_calls),
            },
        }
        if upstream != UPSTREAM_ROOTS:
            raise RuntimeError("vertical upstream owner inventory is not exact")
    after = _sha256(path)
    if after != before:
        raise RuntimeError("vertical factory source changed during read-only export")
    return {
        **_validate_factory(blob, mappings, deps, exidx_ranges, symbol_to_plt),
        "constructors": observed, "reverse_callers": reverse, "unresolved_indirect_terminals": unresolved,
        "upstream_roots": upstream,
    }


def build_raw_export(adapter):
    if adapter.program_name() != EXPECTED_PROGRAM or adapter.program_sha256() != EXPECTED_SHA256 or adapter.program_size() != EXPECTED_IMAGE_SIZE:
        raise RuntimeError("vertical factory adapter source identity is invalid")
    if adapter.analysis_mode() != {"engine": "elf-capstone-thumb", "read_only": True, "source_unchanged": True}:
        raise RuntimeError("vertical factory adapter is not a read-only ELF/Capstone export")
    observed = adapter.factory_metadata(FACTORY_ROOT)
    expected = {"constructors": CONSTRUCTORS, "reverse_callers": REVERSE_CALLERS, "unresolved_indirect_terminals": (), "owner": FACTORY_OWNER, "total_constructor_arm_count": TOTAL_CONSTRUCTOR_ARM_COUNT, "group_id": FACTORY_GROUP_ID, "vertical_classical_arms": VERTICAL_CLASSICAL_ARMS, "invalid_offset_classifications": INVALID_OFFSET_CLASSIFICATIONS, "false_class_id_paths": FALSE_CLASS_ID_PATHS}
    if observed != expected:
        raise RuntimeError("vertical factory owner, group/class, or boundary evidence is not exact")
    upstream = adapter.upstream_roots()
    if upstream != UPSTREAM_ROOTS:
        raise RuntimeError("vertical upstream root metadata differs from the exact bounded result")
    return {"schema_version": 1, "program": EXPECTED_PROGRAM, "sha256": EXPECTED_SHA256, "image_size": EXPECTED_IMAGE_SIZE, "analysis_mode": adapter.analysis_mode(), "factory": {"root": FACTORY_ROOT, "owner": dict(FACTORY_OWNER), "total_constructor_arm_count": TOTAL_CONSTRUCTOR_ARM_COUNT, "group_id": FACTORY_GROUP_ID, "vertical_classical_arms": [dict(item) for item in VERTICAL_CLASSICAL_ARMS], "branch_value_classification": "local-branching-observed", "constructors": [dict(item) for item in CONSTRUCTORS], "reverse_callers": [dict(item) for item in REVERSE_CALLERS], "unresolved_indirect_terminals": []}, "upstream_roots": {"camera_orientation_owners": list(UPSTREAM_ROOTS["camera_orientation_owners"]), "status_orientation_owners": list(UPSTREAM_ROOTS["status_orientation_owners"]), "layout_mode": dict(UPSTREAM_ROOTS["layout_mode"])}, "invalid_offset_classifications": [dict(item) for item in INVALID_OFFSET_CLASSIFICATIONS], "false_class_id_paths": [dict(item) for item in FALSE_CLASS_ID_PATHS], "truncated": False}


class FileAdapter:
    def __init__(self, source_path): self.source_path = Path(source_path); self._metadata = None
    def program_name(self): return self.source_path.name
    def program_sha256(self): return _sha256(self.source_path)
    def program_size(self): return self.source_path.stat().st_size
    def analysis_mode(self): return {"engine": "elf-capstone-thumb", "read_only": True, "source_unchanged": True}
    def factory_metadata(self, root):
        if root != FACTORY_ROOT: raise RuntimeError("factory root is not pinned")
        if self._metadata is None:
            classifications = _validate_view_unified2_classifications(
                self.source_path.with_name("viewUnified2.so")
            )
            if classifications != INVALID_OFFSET_CLASSIFICATIONS:
                raise RuntimeError("sibling viewUnified2 classifications differ")
            self._metadata = _metadata_from_file(self.source_path)
        return {key: self._metadata[key] for key in ("constructors", "reverse_callers", "unresolved_indirect_terminals", "owner", "total_constructor_arm_count", "group_id", "vertical_classical_arms", "invalid_offset_classifications", "false_class_id_paths")}
    def upstream_roots(self):
        if self._metadata is None:
            self.factory_metadata(FACTORY_ROOT)
        return self._metadata["upstream_roots"]


def write_json_atomic(output_path, document, approved_root):
    output, root = Path(output_path), Path(approved_root).resolve(strict=True)
    if output.name != "raw-vertical-layout-factory.json" or output.parent.resolve(strict=True) != root:
        raise RuntimeError("vertical factory output is outside the approved artifact root")
    handle, temporary = tempfile.mkstemp(dir=str(root), prefix=".vertical-factory-", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(document, stream, sort_keys=True, indent=2); stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, output)
    except BaseException:
        try: os.unlink(temporary)
        except FileNotFoundError: pass
        raise


def main(args=None):
    args = list(args if args is not None else __import__("sys").argv[1:])
    if len(args) != 2: raise SystemExit("usage: <source.so> <output.json>")
    document = build_raw_export(FileAdapter(args[0]))
    write_json_atomic(args[1], document, Path(args[1]).parent)
    print("VERTICAL_LAYOUT_FACTORY_EXPORT|constructors=5|reverse_callers=1|unresolved=0")


if __name__ == "__main__": main()
