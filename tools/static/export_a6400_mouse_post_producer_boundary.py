"""Read-only exporter for the bounded α6400 mouse-post producer boundary."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pmca.analysis.mouse_post_producer_boundary import (
    EXPECTED_EXPORT,
    FIRMWARE_INVENTORY,
    INTERACTION_DEPENDENCY,
    LIBOBJ_PUBLICATION_SCAN,
    PUBLIC_APIS,
    QUEUE_PROCESSOR,
    SOURCE,
    SYMBOL_UNIVERSE,
    normalize_mouse_post_producer_boundary_export,
)
from tools.static.export_a6400_creative_style_registry_consumers import (
    FIRMWARE_ROOT,
    _inventory,
)
from tools.static.export_a6400_generic_model_owner_provenance import (
    _at,
    _exidx_ranges,
    _mappings,
)


SOURCE_PATH = FIRMWARE_ROOT / SOURCE["module"]
INTERACTION_REPORT = ROOT / INTERACTION_DEPENDENCY["report"]
QUEUE_PROCESSOR_ENTRY = QUEUE_PROCESSOR["owner"]["start"]
TARGETS = {
    **{api["role"]: api["normalized_entry"] for api in PUBLIC_APIS},
    "queue_processor": QUEUE_PROCESSOR_ENTRY,
}
_LIBOBJ_SCAN_CACHE = {}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _dependencies():
    try:
        from capstone import (
            Cs,
            CS_ARCH_ARM,
            CS_GRP_CALL,
            CS_GRP_JUMP,
            CS_MODE_THUMB,
        )
        from capstone.arm import (
            ARM_INS_ADD,
            ARM_INS_ADR,
            ARM_INS_LDR,
            ARM_INS_MOVT,
            ARM_INS_MOVW,
            ARM_INS_SUB,
            ARM_OP_IMM,
            ARM_OP_MEM,
            ARM_OP_REG,
            ARM_REG_PC,
        )
        from elftools.common.exceptions import ELFError
        from elftools.elf.constants import SH_FLAGS
        from elftools.elf.elffile import ELFFile
    except (ImportError, AttributeError) as error:
        raise RuntimeError("local Capstone and pyelftools are required") from error
    return {
        "Cs": Cs,
        "arch": CS_ARCH_ARM,
        "mode": CS_MODE_THUMB,
        "call_group": CS_GRP_CALL,
        "jump_group": CS_GRP_JUMP,
        "add": ARM_INS_ADD,
        "adr": ARM_INS_ADR,
        "ldr": ARM_INS_LDR,
        "movt": ARM_INS_MOVT,
        "movw": ARM_INS_MOVW,
        "sub": ARM_INS_SUB,
        "imm": ARM_OP_IMM,
        "mem": ARM_OP_MEM,
        "reg": ARM_OP_REG,
        "pc": ARM_REG_PC,
        "ELFError": ELFError,
        "ELFFile": ELFFile,
        "alloc_flag": SH_FLAGS.SHF_ALLOC,
    }


def dependencies_available() -> bool:
    try:
        _dependencies()
    except RuntimeError:
        return False
    return True


def sources_available() -> bool:
    paths = (FIRMWARE_ROOT, SOURCE_PATH, INTERACTION_REPORT)
    return all(path.exists() and not path.is_symlink() for path in paths)


def _inventory_and_paths():
    inventory, elf_paths = _inventory()
    normalized = {
        "regular_file_count": inventory["regular_file_count"],
        "elf_file_count": inventory["elf_file_count"],
        "shared_object_count": inventory["shared_object_count"],
        "canonical_sha256": inventory["canonical_inventory_sha256"],
    }
    if normalized != FIRMWARE_INVENTORY:
        raise RuntimeError("firmware inventory identity differs")
    return normalized, tuple(elf_paths)


def _interaction_dependency():
    from pmca.analysis.creative_style_interaction_surface import (
        EXPECTED_EXPORT as INTERACTION_EXPORT,
        validate_creative_style_interaction_surface_report,
    )

    if INTERACTION_REPORT.is_symlink() or not INTERACTION_REPORT.is_file():
        raise RuntimeError("interaction dependency is unavailable or linked")
    report = validate_creative_style_interaction_surface_report(
        json.loads(INTERACTION_REPORT.read_text(encoding="utf-8"))
    )
    pipeline = INTERACTION_EXPORT["generic_belt_input_chain"][
        "candidate_widget_system_delivery"
    ]["static_mouse_post_pipeline"]
    result = {
        "report": INTERACTION_REPORT.relative_to(ROOT).as_posix(),
        "canonical_export_sha256": report["summary"]["canonical_export_sha256"],
        "static_post_api_to_widget_delivery_found": pipeline["status"]
        == "STATIC_POST_API_TO_WIDGET_DELIVERY_PROVEN__UPSTREAM_PRODUCER_UNRESOLVED",
        "raw_input_producer_found": False,
    }
    if (
        result != INTERACTION_DEPENDENCY
        or len(pipeline["public_entries"]) != len(PUBLIC_APIS)
        or pipeline["member_dispatch"]["processor_owner"]
        != QUEUE_PROCESSOR["owner"]
        or report["claims"]["runtime_execution_proven"] is not False
        or report["claims"]["creative_style_touch_route_found"] is not False
    ):
        raise RuntimeError("interaction dependency differs")
    return result


def scan_firmware_symbol_universe(elf_paths=None) -> dict:
    deps = _dependencies()
    if elf_paths is None:
        _inventory_result, elf_paths = _inventory_and_paths()
    found = {api["symbol"]: [] for api in PUBLIC_APIS}
    for relative in elf_paths:
        path = FIRMWARE_ROOT / relative
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("firmware symbol inventory contains a nonregular path")
        try:
            with path.open("rb") as stream:
                elf = deps["ELFFile"](stream)
                dynsym = elf.get_section_by_name(".dynsym")
                if dynsym is None:
                    continue
                for index, symbol in enumerate(dynsym.iter_symbols()):
                    if symbol.name not in found:
                        continue
                    api = next(item for item in PUBLIC_APIS if item["symbol"] == symbol.name)
                    found[symbol.name].append(
                        {
                            "role": api["role"],
                            "module": relative,
                            "dynsym_index": index,
                            "symbol": symbol.name,
                            "defined": symbol["st_shndx"] != "SHN_UNDEF",
                            "entry": symbol["st_value"],
                            "size": symbol["st_size"],
                            "binding": symbol["st_info"]["bind"],
                            "visibility": symbol["st_other"]["visibility"],
                        }
                    )
        except deps["ELFError"] as error:
            raise RuntimeError(f"inventory ELF became unparsable: {relative}") from error

    matches = []
    for api in PUBLIC_APIS:
        matches.extend(found[api["symbol"]])
    external_definitions = [
        record
        for record in matches
        if record["defined"] and record["module"] != SOURCE["module"]
    ]
    external_imports = [record for record in matches if not record["defined"]]

    occurrences = []
    for api in PUBLIC_APIS:
        needle = api["short_name"].encode("ascii")
        modules = []
        count = 0
        for path in sorted(FIRMWARE_ROOT.rglob("*")):
            if path.is_dir():
                continue
            if path.is_symlink() or not path.is_file():
                raise RuntimeError("firmware name inventory contains a nonregular path")
            hits = path.read_bytes().count(needle)
            if hits:
                modules.append(path.relative_to(FIRMWARE_ROOT).as_posix())
                count += hits
        occurrences.append(
            {
                "role": api["role"],
                "short_name": api["short_name"],
                "modules": modules,
                "occurrence_count": count,
            }
        )

    result = {
        "elf_file_count": len(elf_paths),
        "matches": matches,
        "external_definitions": external_definitions,
        "external_imports": external_imports,
        "short_name_occurrences": occurrences,
    }
    if result != SYMBOL_UNIVERSE:
        raise RuntimeError("firmware mouse-post symbol universe differs")
    return result


def _direct_target(instruction, deps):
    targets = [
        operand.imm & ~1
        for operand in instruction.operands
        if operand.type == deps["imm"]
    ]
    return targets[0] if len(targets) == 1 else None


def _target_role(value):
    normalized = value & ~1
    return next((role for role, target in TARGETS.items() if normalized == target), None)


def _decode_publications(elf, blob, mappings, ranges, deps):
    decoder = deps["Cs"](deps["arch"], deps["mode"])
    decoder.detail = True
    calls = copy.deepcopy({role: [] for role in TARGETS})
    materializations = copy.deepcopy({role: [] for role in TARGETS})
    complete_count = 0

    for start, end in ranges:
        instructions = list(decoder.disasm(_at(blob, mappings, start, end - start), start))
        complete = bool(
            instructions
            and instructions[0].address == start
            and instructions[-1].address + instructions[-1].size == end
        )
        complete_count += int(complete)
        literal_by_register = {}
        movw_by_register = {}
        for instruction in instructions:
            if instruction.group(deps["call_group"]) or instruction.group(deps["jump_group"]):
                role = _target_role(_direct_target(instruction, deps) or 0)
                if role is not None:
                    calls[role].append(
                        {
                            "owner_start": start,
                            "owner_end": end,
                            "owner_complete": complete,
                            "site": instruction.address,
                        }
                    )

            operands = instruction.operands
            candidate = None
            method = None
            if instruction.id == deps["adr"] and len(operands) >= 2 and operands[1].type == deps["imm"]:
                candidate = operands[1].imm
                method = "adr-or-pc-immediate"
            elif instruction.id in {deps["add"], deps["sub"]} and len(operands) >= 3:
                registers = [operand.reg for operand in operands[1:] if operand.type == deps["reg"]]
                immediates = [operand.imm for operand in operands[1:] if operand.type == deps["imm"]]
                if deps["pc"] in registers and len(immediates) == 1:
                    base = (instruction.address + 4) & ~3
                    candidate = base + (immediates[0] if instruction.id == deps["add"] else -immediates[0])
                    method = "adr-or-pc-immediate"
                elif instruction.id == deps["add"] and deps["pc"] in registers:
                    source_registers = [register for register in registers if register != deps["pc"]]
                    if len(source_registers) == 1 and source_registers[0] in literal_by_register:
                        literal = literal_by_register[source_registers[0]]
                        candidate = instruction.address + 4 + literal["value"]
                        method = "pc-literal-add"
            if candidate is not None:
                role = _target_role(candidate)
                if role is not None:
                    materializations[role].append(
                        {
                            "method": method,
                            "owner_start": start,
                            "owner_end": end,
                            "owner_complete": complete,
                            "site": instruction.address,
                        }
                    )

            written = set(instruction.regs_access()[1])
            for register in written:
                literal_by_register.pop(register, None)
                if instruction.id != deps["movt"]:
                    movw_by_register.pop(register, None)

            if (
                instruction.id == deps["ldr"]
                and len(operands) == 2
                and operands[0].type == deps["reg"]
                and operands[1].type == deps["mem"]
                and operands[1].mem.base == deps["pc"]
                and operands[1].mem.index == 0
            ):
                literal_site = ((instruction.address + 4) & ~3) + operands[1].mem.disp
                try:
                    value = int.from_bytes(_at(blob, mappings, literal_site, 4), "little")
                except RuntimeError:
                    pass
                else:
                    literal_by_register[operands[0].reg] = {
                        "value": value,
                        "site": instruction.address,
                    }
            elif (
                instruction.id == deps["movw"]
                and len(operands) == 2
                and operands[0].type == deps["reg"]
                and operands[1].type == deps["imm"]
            ):
                movw_by_register[operands[0].reg] = {
                    "value": operands[1].imm & 0xFFFF,
                    "site": instruction.address,
                }
            elif (
                instruction.id == deps["movt"]
                and len(operands) == 2
                and operands[0].type == deps["reg"]
                and operands[1].type == deps["imm"]
                and operands[0].reg in movw_by_register
            ):
                low = movw_by_register[operands[0].reg]
                role = _target_role((operands[1].imm << 16) | low["value"])
                if role is not None:
                    materializations[role].append(
                        {
                            "method": "movw-movt",
                            "owner_start": start,
                            "owner_end": end,
                            "owner_complete": complete,
                            "site": instruction.address,
                            "low_site": low["site"],
                        }
                    )

    return calls, materializations, complete_count


def _relocation_publications(elf, blob, mappings):
    result = copy.deepcopy({role: [] for role in TARGETS})
    dynsym = elf.get_section_by_name(".dynsym")
    section = elf.get_section_by_name(".rel.dyn")
    if dynsym is None or section is None:
        raise RuntimeError("libObj relocation metadata is unavailable")
    for index, relocation in enumerate(section.iter_relocations()):
        site = relocation["r_offset"]
        try:
            addend = int.from_bytes(_at(blob, mappings, site, 4), "little")
        except RuntimeError:
            continue
        symbol = dynsym.get_symbol(relocation["r_info_sym"])
        candidates = {addend}
        if symbol["st_shndx"] != "SHN_UNDEF" and symbol["st_value"]:
            candidates.add(symbol["st_value"])
            candidates.add((symbol["st_value"] + addend) & 0xFFFFFFFF)
            signed = addend if addend < 0x80000000 else addend - 0x100000000
            candidates.add((symbol["st_value"] + signed) & 0xFFFFFFFF)
            candidates.add((site + signed) & 0xFFFFFFFF)
        for candidate in candidates:
            role = _target_role(candidate)
            if role is not None:
                result[role].append(
                    {
                        "relocation_index": index,
                        "site": site,
                        "relocation_type": relocation["r_info_type"],
                        "symbol_index": relocation["r_info_sym"],
                    }
                )
    return result


def _aligned_pointer_publications(elf, blob):
    result = copy.deepcopy({role: [] for role in TARGETS})
    excluded = set()
    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym is None:
        raise RuntimeError("libObj dynamic symbol metadata is unavailable")
    for api in PUBLIC_APIS:
        excluded.add(dynsym["sh_offset"] + api["dynsym_index"] * dynsym["sh_entsize"] + 4)
    for section in elf.iter_sections():
        if (
            not section["sh_flags"] & 2
            or section["sh_type"] == "SHT_NOBITS"
            or section["sh_size"] < 4
        ):
            continue
        data = blob[section["sh_offset"] : section["sh_offset"] + section["sh_size"]]
        for offset in range(0, len(data) - 3, 4):
            file_offset = section["sh_offset"] + offset
            if file_offset in excluded:
                continue
            role = _target_role(int.from_bytes(data[offset : offset + 4], "little"))
            if role is not None:
                result[role].append(
                    {
                        "section": section.name,
                        "address": section["sh_addr"] + offset,
                    }
                )
    return result


def _queue_processor_symbols(elf):
    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym is None:
        raise RuntimeError("libObj dynamic symbol metadata is unavailable")
    return [
        {
            "dynsym_index": index,
            "symbol": symbol.name,
            "entry": symbol["st_value"],
            "size": symbol["st_size"],
        }
        for index, symbol in enumerate(dynsym.iter_symbols())
        if symbol["st_shndx"] != "SHN_UNDEF"
        and (symbol["st_value"] & ~1) == QUEUE_PROCESSOR_ENTRY
    ]


def scan_libobj_publications() -> dict:
    deps = _dependencies()
    if SOURCE_PATH.is_symlink() or not SOURCE_PATH.is_file():
        raise RuntimeError("pinned libObj source is unavailable or linked")
    before = _sha256(SOURCE_PATH)
    if SOURCE_PATH.stat().st_size != SOURCE["size"] or before != SOURCE["sha256"]:
        raise RuntimeError("pinned libObj source identity differs")
    cache_key = (FIRMWARE_INVENTORY["canonical_sha256"], before)
    if cache_key in _LIBOBJ_SCAN_CACHE:
        if _sha256(SOURCE_PATH) != before:
            raise RuntimeError("pinned libObj source changed before cached scan use")
        return copy.deepcopy(_LIBOBJ_SCAN_CACHE[cache_key])
    blob = SOURCE_PATH.read_bytes()
    with SOURCE_PATH.open("rb") as stream:
        elf = deps["ELFFile"](stream)
        mappings = _mappings(elf)
        ranges = _exidx_ranges(elf, blob)
        calls, materializations, complete_count = _decode_publications(
            elf,
            blob,
            mappings,
            ranges,
            deps,
        )
        relocations = _relocation_publications(elf, blob, mappings)
        aligned = _aligned_pointer_publications(elf, blob)
        queue_symbols = _queue_processor_symbols(elf)
    result = {
        "scan_methods": list(LIBOBJ_PUBLICATION_SCAN["scan_methods"]),
        "owner_count": len(ranges),
        "complete_owner_count": complete_count,
        "incomplete_owner_count": len(ranges) - complete_count,
        "direct_inbound_calls": calls,
        "relocation_publications": relocations,
        "aligned_pointer_publications": aligned,
        "address_materializations": materializations,
    }
    if _sha256(SOURCE_PATH) != before:
        raise RuntimeError("pinned libObj source changed during scan")
    if result != LIBOBJ_PUBLICATION_SCAN or queue_symbols:
        raise RuntimeError("libObj mouse-post publication inventory differs")
    _LIBOBJ_SCAN_CACHE[cache_key] = copy.deepcopy(result)
    return copy.deepcopy(result)


class FileAdapter:
    def inventory(self):
        return _inventory_and_paths()

    def interaction_dependency(self):
        return _interaction_dependency()

    def symbol_universe(self, elf_paths):
        return scan_firmware_symbol_universe(elf_paths)

    def libobj_publication_scan(self):
        return scan_libobj_publications()

    def queue_processor(self, publication_scan):
        return {
            "owner": copy.deepcopy(QUEUE_PROCESSOR["owner"]),
            "dynamic_symbol_definitions": [],
            "direct_inbound_calls": copy.deepcopy(
                publication_scan["direct_inbound_calls"]["queue_processor"]
            ),
            "relocation_publications": copy.deepcopy(
                publication_scan["relocation_publications"]["queue_processor"]
            ),
            "aligned_pointer_publications": copy.deepcopy(
                publication_scan["aligned_pointer_publications"]["queue_processor"]
            ),
            "address_materializations": copy.deepcopy(
                publication_scan["address_materializations"]["queue_processor"]
            ),
        }


def _validate_candidate_boundary(symbol_universe, publication_scan, queue_processor):
    if symbol_universe["external_definitions"] or symbol_universe["external_imports"]:
        raise RuntimeError("external-symbol-consumer scan differs")
    if symbol_universe["short_name_occurrences"] != SYMBOL_UNIVERSE["short_name_occurrences"]:
        raise RuntimeError("short-name-file scan differs")
    for field, label in (
        ("direct_inbound_calls", "decoded-direct-caller"),
        ("relocation_publications", "dynamic-relocation"),
        ("aligned_pointer_publications", "allocated-aligned-pointer"),
        ("address_materializations", "address-materialization"),
    ):
        for role, candidates in publication_scan[field].items():
            if candidates:
                raise RuntimeError(f"{label} scan differs for {role}")
    for field, label in (
        ("direct_inbound_calls", "queue-processor-direct-caller"),
        ("relocation_publications", "queue-processor-relocation"),
        ("aligned_pointer_publications", "queue-processor-aligned-pointer"),
        ("address_materializations", "queue-processor-address-materialization"),
    ):
        if queue_processor[field]:
            raise RuntimeError(f"{label} scan differs")


def build_raw_export(adapter=None) -> dict:
    adapter = FileAdapter() if adapter is None else adapter
    inventory, elf_paths = adapter.inventory()
    publication_scan = adapter.libobj_publication_scan()
    symbol_universe = adapter.symbol_universe(elf_paths)
    queue_processor = adapter.queue_processor(publication_scan)
    _validate_candidate_boundary(
        symbol_universe,
        publication_scan,
        queue_processor,
    )
    document = {
        "schema_version": 1,
        "analysis_mode": copy.deepcopy(EXPECTED_EXPORT["analysis_mode"]),
        "firmware_inventory": inventory,
        "source": copy.deepcopy(SOURCE),
        "interaction_dependency": adapter.interaction_dependency(),
        "public_apis": copy.deepcopy(list(PUBLIC_APIS)),
        "symbol_universe": symbol_universe,
        "libobj_publication_scan": publication_scan,
        "queue_processor": queue_processor,
        "first_unresolved_boundary": EXPECTED_EXPORT["first_unresolved_boundary"],
        "readiness": EXPECTED_EXPORT["readiness"],
        "claims": copy.deepcopy(EXPECTED_EXPORT["claims"]),
        "truncated": False,
    }
    try:
        return normalize_mouse_post_producer_boundary_export(document)
    except ValueError as error:
        raise RuntimeError("mouse-post producer boundary differs") from error


if __name__ == "__main__":
    document = build_raw_export()
    print(
        "A6400_MOUSE_POST_PRODUCER_BOUNDARY"
        f"|apis={len(document['public_apis'])}"
        "|external=0|publications=0|processor=0|runtime=0"
        "|camera_access=0|binary_execution=0"
    )
