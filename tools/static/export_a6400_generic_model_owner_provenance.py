"""Read-only exporter for anonymous α6400 generic model-owner provenance."""
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

from pmca.analysis.generic_model_owner_provenance import (
    CLAIMS,
    CREATIVE_STYLE_BOUNDARY,
    EXPECTED_EXPORT,
    INITIALIZER_CALLS,
    MODULES,
    VIEW_UNIFIED4,
    VIEW_UNIFIED7,
    normalize_generic_model_owner_provenance_export,
)
from tools.static.export_a6400_creative_style_model_cursor_boundary import (
    _decoded_plt_addresses_exact,
    _register_origin,
)


FIRMWARE_LIB = ROOT / ".artifacts" / "decrypted" / "a6400-tw-v2.00" / "ma1co" / "firmware.tar_unpacked" / "0700_part_image" / "dev" / "nflasha15_unpacked" / "lib"
SOURCES = {
    "lib/viewUnified4.so": FIRMWARE_LIB / "viewUnified4.so",
    "lib/viewUnified7.so": FIRMWARE_LIB / "viewUnified7.so",
}
ARTIFACT_BASE = ROOT / ".artifacts"
OUTPUT_ROOT = ARTIFACT_BASE / "generic-model-owner-provenance" / "a6400-v2.00"
OUTPUT_NAME = "generic-model-owner-provenance-export.json"


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _dependencies():
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_GRP_CALL, CS_GRP_JUMP, CS_MODE_THUMB
        from capstone.arm import (
            ARM_INS_LDR, ARM_INS_STR, ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG,
            ARM_REG_PC, ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3,
        )
        from elftools.elf.elffile import ELFFile
    except (ImportError, AttributeError) as exc:
        raise RuntimeError("local Capstone and pyelftools are required") from exc
    return {
        "Cs": Cs,
        "arch": CS_ARCH_ARM,
        "mode": CS_MODE_THUMB,
        "call_group": CS_GRP_CALL,
        "jump_group": CS_GRP_JUMP,
        "ldr": ARM_INS_LDR,
        "str": ARM_INS_STR,
        "imm": ARM_OP_IMM,
        "mem": ARM_OP_MEM,
        "reg": ARM_OP_REG,
        "pc": ARM_REG_PC,
        "r0": ARM_REG_R0,
        "r1": ARM_REG_R1,
        "caller_saved": {ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3},
        "ELFFile": ELFFile,
    }


def dependencies_available():
    try:
        _dependencies()
    except RuntimeError:
        return False
    return True


def sources_available():
    return all(path.is_file() and not path.is_symlink() for path in SOURCES.values())


def _mappings(elf):
    return [
        (segment["p_vaddr"], segment["p_vaddr"] + segment["p_filesz"], segment["p_offset"])
        for segment in elf.iter_segments()
        if segment["p_type"] == "PT_LOAD"
    ]


def _at(blob, mappings, address, length):
    offsets = [
        offset + address - start
        for start, end, offset in mappings
        if start <= address and address + length <= end
    ]
    if len(offsets) != 1:
        raise RuntimeError("virtual address does not map exactly once")
    return blob[offsets[0] : offsets[0] + length]


def _prel31(word, place):
    offset = word & 0x7FFFFFFF
    if offset & 0x40000000:
        offset -= 0x80000000
    return (place + offset) & 0xFFFFFFFF


def _exidx_ranges(elf, blob):
    section = elf.get_section_by_name(".ARM.exidx")
    if section is None or section["sh_size"] % 8:
        raise RuntimeError("ARM exidx metadata differs")
    starts = []
    for offset in range(0, section["sh_size"], 8):
        place = section["sh_addr"] + offset
        word = int.from_bytes(blob[section["sh_offset"] + offset : section["sh_offset"] + offset + 4], "little")
        starts.append(_prel31(word, place) & ~1)
    if starts != sorted(starts) or len(starts) != len(set(starts)):
        raise RuntimeError("ARM exidx order differs")
    executable_ends = [
        segment["p_vaddr"] + segment["p_filesz"]
        for segment in elf.iter_segments()
        if segment["p_type"] == "PT_LOAD"
        and segment["p_flags"] & 1
        and segment["p_vaddr"] <= starts[-1] < segment["p_vaddr"] + segment["p_filesz"]
    ]
    if len(executable_ends) != 1 or executable_ends[0] <= starts[-1] or executable_ends[0] & 1:
        raise RuntimeError("final ARM exidx range is not bounded by one executable mapping")
    return [(start, end) for start, end in zip(starts, starts[1:] + executable_ends)]


def _decode_range(blob, mappings, deps, start, end, require_complete=True):
    decoder = deps["Cs"](deps["arch"], deps["mode"])
    decoder.detail = True
    items = list(decoder.disasm(_at(blob, mappings, start, end - start), start))
    if require_complete and (not items or (items[0].address & ~1) != start or items[-1].address + items[-1].size != end):
        raise RuntimeError("bounded owner decode is incomplete")
    return items


def _instruction_at(blob, mappings, deps, site, length=4):
    items = _decode_range(blob, mappings, deps, site, site + length, require_complete=False)
    if not items or (items[0].address & ~1) != site:
        raise RuntimeError("expected instruction site does not decode")
    return items[0]


def _direct_target(item, deps):
    targets = [operand.imm & ~1 for operand in item.operands if operand.type == deps["imm"]]
    return targets[0] if len(targets) == 1 else None


def _validate_tail_dispatch(blob, mappings, deps, expected):
    item = _instruction_at(blob, mappings, deps, expected["site"])
    if item.mnemonic != "b.w" or not item.group(deps["jump_group"]) or _direct_target(item, deps) != expected["target"]:
        raise RuntimeError("table-dispatch tail transfer differs")
    table = expected["table_branch"]
    if (
        table["entry_width"] != 2
        or table["table_start"] != table["site"] + 4
        or table["entry_site"] != table["table_start"] + table["selector_index"] * table["entry_width"]
        or table["fallthrough_branch_site"] != expected["site"]
    ):
        raise RuntimeError("table-dispatch metadata is internally inconsistent")
    table_item = _instruction_at(blob, mappings, deps, table["site"])
    if table_item.mnemonic != "tbh" or not table_item.group(deps["jump_group"]):
        raise RuntimeError("table-dispatch selector differs")
    entry_value = int.from_bytes(_at(blob, mappings, table["entry_site"], table["entry_width"]), "little")
    if entry_value != table["entry_value"] or table["landing"] != table["table_start"] + 2 * entry_value:
        raise RuntimeError("table-dispatch entry relation differs")
    landing = _instruction_at(blob, mappings, deps, table["landing"])
    if (
        not (landing.mnemonic.startswith("pop") or landing.mnemonic == "bx")
        or landing.address + landing.size != expected["site"]
    ):
        raise RuntimeError("table-dispatch landing does not fall through to the target branch")
    start, end = expected["owner"]["start"], expected["owner"]["end"]
    owner_items = _decode_range(blob, mappings, deps, start, end, require_complete=False)
    candidates = [entry.address & ~1 for entry in owner_items if entry.mnemonic == "tbh"]
    if len(candidates) != 1:
        raise RuntimeError("table-dispatch form differs")
    if candidates[0] != table["site"]:
        raise RuntimeError("table-dispatch site differs")
    if (
        not expected["receiver_r0_preserved_case_path"]
        or expected["receiver_type_proven"]
        or expected["path_sensitive_receiver_proof"]
    ):
        raise RuntimeError("table-dispatch receiver claim differs")
    case_path = _decode_range(blob, mappings, deps, start, table["table_start"])
    case_path.extend((landing, item))
    if _register_origin(case_path, len(case_path) - 1, deps["r0"], deps) != "this":
        raise RuntimeError("table-dispatch case path does not preserve entry r0")
    return copy.deepcopy(expected)


def _relative_record(elf, blob, expected):
    relocations = list(elf.get_section_by_name(".rel.dyn").iter_relocations())
    relocation = relocations[expected["relocation_index"]]
    site = relocation["r_offset"]
    addend = int.from_bytes(_at(blob, _mappings(elf), site, 4), "little") & ~1
    record = {
        "relocation_index": expected["relocation_index"],
        "site": site,
        "relocation_type": relocation["r_info_type"],
        "section": _section_name(elf, site),
        "target": addend,
    }
    if relocation["r_info_sym"] != 0 or record != expected:
        raise RuntimeError("address-taken relative relocation differs")
    return record


def _section_name(elf, address):
    matches = [
        section.name
        for section in elf.iter_sections()
        if section["sh_addr"] <= address < section["sh_addr"] + section["sh_size"]
    ]
    if len(matches) != 1:
        raise RuntimeError("section ownership differs")
    return matches[0]


def _all_relative_targets(elf, blob):
    mappings = _mappings(elf)
    result = []
    for index, relocation in enumerate(elf.get_section_by_name(".rel.dyn").iter_relocations()):
        if relocation["r_info_type"] != 23 or relocation["r_info_sym"] != 0:
            continue
        result.append((index, relocation["r_offset"], int.from_bytes(_at(blob, mappings, relocation["r_offset"], 4), "little") & ~1))
    return result


def _global_direct_inbound(blob, mappings, deps, exidx_ranges, target):
    decoder = deps["Cs"](deps["arch"], deps["mode"])
    decoder.detail = True
    matches = []
    complete = True
    for start, end in exidx_ranges:
        items = list(decoder.disasm(_at(blob, mappings, start, end - start), start))
        if not items or (items[0].address & ~1) != start or items[-1].address + items[-1].size != end:
            complete = False
        for item in items:
            if (
                _direct_target(item, deps) == target
                and (item.group(deps["jump_group"]) or item.group(deps["call_group"]))
            ):
                matches.append((item.address & ~1, start, end, item.mnemonic))
    return list(dict.fromkeys(matches)), complete


def _literal_targets(items, blob, mappings, deps):
    targets = []
    for item in items:
        if item.id != deps["ldr"] or len(item.operands) < 2 or item.operands[1].type != deps["mem"]:
            continue
        memory = item.operands[1].mem
        if memory.base != deps["pc"] or memory.index != 0:
            continue
        literal = ((item.address + 4) & ~3) + memory.disp
        try:
            targets.append(int.from_bytes(_at(blob, mappings, literal, 4), "little"))
        except RuntimeError:
            continue
    return targets


def _vu4_record(blob, elf, deps):
    mappings = _mappings(elf)
    exidx = _exidx_ranges(elf, blob)
    expected = VIEW_UNIFIED4
    targets = []
    creative_cells = {0x282534, 0x282DBC, 0x282F1C, 0x284D74, 0x284ECC, 0x285034}
    relative_targets = _all_relative_targets(elf, blob)
    for item_expected in expected["targets"]:
        interval = item_expected["exidx_interval"]
        if (interval["start"], interval["end"]) not in exidx:
            raise RuntimeError("VU4 target EXIDX interval differs")
        dispatch = _validate_tail_dispatch(blob, mappings, deps, item_expected["inbound_dispatch"])
        inbound, direct_scan_complete = _global_direct_inbound(blob, mappings, deps, exidx, item_expected["entry"])
        if [(site, start, end) for site, start, end, _mnemonic in inbound] != [
            (dispatch["site"], dispatch["owner"]["start"], dispatch["owner"]["end"])
        ]:
            raise RuntimeError("VU4 direct inbound inventory differs")
        if item_expected["entry_address_taken"] is None and any(target == item_expected["entry"] for _index, _site, target in relative_targets):
            raise RuntimeError("VU4 target unexpectedly address-taken")
        target_items = _decode_range(blob, mappings, deps, interval["start"], interval["end"])
        by_address = {entry.address & ~1: entry for entry in target_items}
        entry_items = [entry for entry in target_items if (entry.address & ~1) >= item_expected["entry"]]
        entry_by_address = {entry.address & ~1: entry for entry in entry_items}
        for call_expected in item_expected["sequence_calls"]:
            call = entry_by_address.get(call_expected["site"])
            if call is None or call.mnemonic != "blx" or not call.group(deps["call_group"]):
                raise RuntimeError("VU4 sequence call differs")
            call_index = entry_items.index(call)
            origin = _register_origin(entry_items, call_index, deps["r0"], deps)
            expected_origin = f"this+0x{item_expected['utility_member_offset']:02x}"
            if origin != expected_origin:
                raise RuntimeError(
                    f"VU4 utility receiver field differs at {call_expected['site']:#x}: "
                    f"expected {expected_origin}, observed {origin}"
                )
        dispatcher_items = _decode_range(
            blob,
            mappings,
            deps,
            dispatch["owner"]["start"],
            dispatch["owner"]["end"],
            require_complete=False,
        )
        if any(value in creative_cells for value in _literal_targets(target_items + dispatcher_items, blob, mappings, deps)):
            raise RuntimeError("VU4 target unexpectedly has a Creative Style PC-literal reference")
        record = copy.deepcopy(item_expected)
        if (
            direct_scan_complete != item_expected["direct_scan_complete"]
            or item_expected["direct_inventory_exhaustive"] != direct_scan_complete
        ):
            raise RuntimeError("VU4 canonical direct-scan scope differs")
        record["inbound_dispatch"] = dispatch
        record["dispatcher_address_taken"] = _relative_record(elf, blob, item_expected["dispatcher_address_taken"])
        if "interval_first_entry_address_taken" in item_expected:
            record["interval_first_entry_address_taken"] = _relative_record(elf, blob, item_expected["interval_first_entry_address_taken"])
            prior = by_address.get(item_expected["prior_return_site"])
            if prior is None or not (prior.mnemonic.startswith("pop") or prior.mnemonic == "bx"):
                raise RuntimeError("split EXIDX prior return differs")
        targets.append(record)
    result = copy.deepcopy(expected)
    result["targets"] = targets
    return result


def _binding_records(elf, blob, dynsym, expected_calls):
    mappings = _mappings(elf)
    relplt = list(elf.get_section_by_name(".rel.plt").iter_relocations())
    decoded = _decoded_plt_addresses_exact(elf, blob, mappings)
    records = []
    for expected in expected_calls:
        relocation = relplt[expected["relocation_index"]]
        symbol = dynsym.get_symbol(relocation["r_info_sym"])
        record = {
            "role": expected["role"],
            "site": expected["site"],
            "symbol": symbol.name,
            "symbol_index": relocation["r_info_sym"],
            "symbol_defined": symbol["st_shndx"] != "SHN_UNDEF",
            "relocation_index": expected["relocation_index"],
            "relocation_type": relocation["r_info_type"],
            "got": relocation["r_offset"],
            "plt": decoded.get(relocation["r_offset"]),
        }
        if record != expected:
            raise RuntimeError("initializer PLT binding differs")
        records.append(record)
    return records


def _mapped_pointer_count(elf, blob, target):
    count = 0
    for section in elf.iter_sections():
        if section["sh_type"] == "SHT_NOBITS" or section["sh_size"] < 4:
            continue
        data = blob[section["sh_offset"] : section["sh_offset"] + section["sh_size"]]
        for offset in range(0, len(data) - 3, 4):
            if int.from_bytes(data[offset : offset + 4], "little") in (target, target | 1):
                count += 1
    return count


def _vu7_record(blob, elf, deps):
    mappings = _mappings(elf)
    exidx = _exidx_ranges(elf, blob)
    dynsym = elf.get_section_by_name(".dynsym")
    symbols = list(dynsym.iter_symbols())
    expected = VIEW_UNIFIED7
    target_expected = expected["target"]
    start, end = target_expected["range"]["start"], target_expected["range"]["end"]
    target_items = _decode_range(blob, mappings, deps, start, end)
    if len(target_items) != target_expected["decoded_instruction_count"]:
        raise RuntimeError("VU7 target instruction count differs")
    by_address = {item.address & ~1: item for item in target_items}
    for site in target_expected["receiver_sites"]:
        call = by_address.get(site)
        if call is None or call.mnemonic != "blx" or not call.group(deps["call_group"]):
            raise RuntimeError("VU7 target helper call differs")
        if _register_origin(target_items, target_items.index(call), deps["r0"], deps) != "this+0x14c":
            raise RuntimeError("VU7 utility receiver field differs")
    dispatch_expected = target_expected["inbound_dispatch"]
    dispatch = _validate_tail_dispatch(blob, mappings, deps, dispatch_expected)
    direct, direct_scan_complete = _global_direct_inbound(blob, mappings, deps, exidx, start)
    if direct != [(
        dispatch["site"],
        dispatch["owner"]["start"],
        dispatch["owner"]["end"],
        "b.w",
    )]:
        raise RuntimeError("VU7 direct inbound inventory differs")
    relatives = _all_relative_targets(elf, blob)
    relocation_reference_count = sum(target in (start, start | 1) for _index, _site, target in relatives)
    dynsym_owner_count = sum(
        symbol["st_shndx"] != "SHN_UNDEF"
        and symbol["st_info"]["type"] == "STT_FUNC"
        and symbol["st_size"] > 0
        and (symbol["st_value"] & ~1) <= start < (symbol["st_value"] & ~1) + symbol["st_size"]
        for symbol in symbols
    )
    inventory = {
        "bounded_direct_transfer_count": len(direct),
        "canonical_direct_scan_complete": direct_scan_complete,
        "direct_inventory_exhaustive": direct_scan_complete,
        "mapped_pointer_word_count": _mapped_pointer_count(elf, blob, start),
        "relocation_reference_count": relocation_reference_count,
        "dynsym_owner_count": dynsym_owner_count,
        "address_taken_table_count": sum(target == start for _index, _site, target in relatives),
    }
    if inventory != target_expected["static_inbound_inventory"]:
        raise RuntimeError(
            f"VU7 static inbound inventory differs: expected {target_expected['static_inbound_inventory']}, "
            f"observed {inventory}; direct matches {direct}"
        )
    dispatcher_refs = [record for record in relatives if record[2] == dispatch["owner"]["start"]]
    if len(dispatcher_refs) != 1:
        raise RuntimeError("VU7 dispatcher address-taking inventory differs")
    dispatcher_address_taken = _relative_record(elf, blob, target_expected["dispatcher_address_taken"])
    dispatcher_items = _decode_range(
        blob,
        mappings,
        deps,
        dispatch["owner"]["start"],
        dispatch["owner"]["end"],
        require_complete=False,
    )
    creative_cells = {0x72434, 0x8056C}
    if any(value in creative_cells for value in _literal_targets(target_items + dispatcher_items, blob, mappings, deps)):
        raise RuntimeError("VU7 target unexpectedly has a Creative Style PC-literal reference")

    candidate_expected = expected["initializer_candidate"]
    candidate_start, candidate_end = candidate_expected["range"]["start"], candidate_expected["range"]["end"]
    if (candidate_start, candidate_end) not in exidx:
        raise RuntimeError("initializer candidate EXIDX range differs")
    candidate_items = _decode_range(blob, mappings, deps, candidate_start, candidate_end)
    candidate_by_address = {item.address & ~1: item for item in candidate_items}
    calls = _binding_records(elf, blob, dynsym, candidate_expected["calls"])
    for binding in calls:
        item = candidate_by_address.get(binding["site"])
        if item is None or item.mnemonic != "blx" or _direct_target(item, deps) != binding["plt"]:
            raise RuntimeError("initializer candidate call site differs")
    for access_expected in candidate_expected["field_accesses"]:
        item = candidate_by_address.get(access_expected["site"])
        expected_id = deps["ldr"] if access_expected["access"] == "read" else deps["str"]
        if item is None or item.id != expected_id or len(item.operands) < 2 or item.operands[1].type != deps["mem"] or item.operands[1].mem.disp != access_expected["offset"]:
            raise RuntimeError("initializer field access differs")
        base_origin = _register_origin(candidate_items, candidate_items.index(item), item.operands[1].mem.base, deps)
        if base_origin != "this":
            raise RuntimeError("initializer field base is not entry receiver")
    if any(_direct_target(item, deps) == start for item in candidate_items):
        raise RuntimeError("initializer unexpectedly has a direct target path")
    if any(value in creative_cells for value in _literal_targets(candidate_items, blob, mappings, deps)):
        raise RuntimeError("initializer unexpectedly has a Creative Style PC-literal reference")
    candidate = copy.deepcopy(candidate_expected)
    candidate["calls"] = calls
    target = copy.deepcopy(target_expected)
    target["inbound_dispatch"] = dispatch
    target["dispatcher_address_taken"] = dispatcher_address_taken
    result = copy.deepcopy(expected)
    result["target"] = target
    result["initializer_candidate"] = candidate
    return result


def _metadata_from_files(sources=SOURCES):
    deps = _dependencies()
    identities = {item["module"]: item for item in MODULES}
    before = {}
    results = {}
    for module in ("lib/viewUnified4.so", "lib/viewUnified7.so"):
        source = Path(sources[module])
        if source.is_symlink() or not source.is_file():
            raise RuntimeError("source must be a literal regular file")
        before[module] = _sha256(source)
        identity = identities[module]
        if source.name != Path(module).name or source.stat().st_size != identity["size"] or before[module] != identity["sha256"]:
            raise RuntimeError("source identity differs")
        blob = source.read_bytes()
        with io.BytesIO(blob) as stream:
            elf = deps["ELFFile"](stream)
            results[module] = _vu4_record(blob, elf, deps) if module.endswith("viewUnified4.so") else _vu7_record(blob, elf, deps)
    document = copy.deepcopy(EXPECTED_EXPORT)
    document.update({
        "view_unified4": results["lib/viewUnified4.so"],
        "view_unified7": results["lib/viewUnified7.so"],
        "creative_style_boundary": copy.deepcopy(CREATIVE_STYLE_BOUNDARY),
        "claims": copy.deepcopy(CLAIMS),
    })
    normalize_generic_model_owner_provenance_export(document)
    if any(_sha256(sources[module]) != before[module] for module in before):
        raise RuntimeError("source changed during static export")
    return document


class FileAdapter:
    def __init__(self, sources=SOURCES):
        self.sources = sources

    def metadata(self):
        return _metadata_from_files(self.sources)


def build_raw_export(adapter=None):
    try:
        return normalize_generic_model_owner_provenance_export((adapter or FileAdapter()).metadata())
    except Exception as exc:
        raise RuntimeError("generic model-owner provenance differs from the exact bounded static result") from exc


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
    handle, temporary = tempfile.mkstemp(dir=str(root), prefix=".owner-provenance-", suffix=".tmp")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
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
    print("GENERIC_MODEL_OWNER_PROVENANCE_EXPORT|vu4_targets=2|vu7_targets=1|creative_binding=0|persistence=0")
