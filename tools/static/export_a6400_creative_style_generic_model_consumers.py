"""Read-only exporter for generic model consumers near Creative Style data."""
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

from pmca.analysis.creative_style_generic_model_consumers import (
    BINDINGS,
    CLAIMS,
    CREATIVE_STYLE_PUBLICATIONS,
    EXPECTED_EXPORT,
    GENERIC_MODEL_SEQUENCES,
    MODULES,
    OWNERSHIP_BOUNDARY,
    normalize_creative_style_generic_model_consumers_export,
)
from tools.static.export_a6400_creative_style_model_cursor_boundary import (
    _decoded_plt_addresses_exact,
)


FIRMWARE_LIB = ROOT / ".artifacts" / "decrypted" / "a6400-tw-v2.00" / "ma1co" / "firmware.tar_unpacked" / "0700_part_image" / "dev" / "nflasha15_unpacked" / "lib"
SOURCES = {
    "lib/viewUnified4.so": FIRMWARE_LIB / "viewUnified4.so",
    "lib/viewUnified7.so": FIRMWARE_LIB / "viewUnified7.so",
}
ARTIFACT_BASE = ROOT / ".artifacts"
OUTPUT_ROOT = ARTIFACT_BASE / "creative-style-generic-model-consumers" / "a6400-v2.00"
OUTPUT_NAME = "generic-model-consumers-export.json"


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _dependencies():
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_GRP_CALL, CS_MODE_THUMB
        from capstone.arm import ARM_OP_IMM
        from elftools.elf.elffile import ELFFile
    except (ImportError, AttributeError) as exc:
        raise RuntimeError("local Capstone and pyelftools are required") from exc
    return {
        "Cs": Cs,
        "arch": CS_ARCH_ARM,
        "mode": CS_MODE_THUMB,
        "call_group": CS_GRP_CALL,
        "imm": ARM_OP_IMM,
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
        raise RuntimeError("ARM exidx owner order differs")
    return {(start, end) for start, end in zip(starts, starts[1:])}


def _binding_records(elf, blob, mappings, dynsym, module):
    relplt = list(elf.get_section_by_name(".rel.plt").iter_relocations())
    decoded = _decoded_plt_addresses_exact(elf, blob, mappings)
    records = []
    for expected in BINDINGS[module]:
        relocation = relplt[expected["relocation_index"]]
        symbol = dynsym.get_symbol(relocation["r_info_sym"])
        record = {
            "role": expected["role"],
            "symbol": symbol.name,
            "symbol_index": relocation["r_info_sym"],
            "symbol_defined": symbol["st_shndx"] != "SHN_UNDEF",
            "relocation_index": expected["relocation_index"],
            "relocation_type": relocation["r_info_type"],
            "got": relocation["r_offset"],
            "plt": decoded.get(relocation["r_offset"]),
        }
        if record != expected:
            raise RuntimeError("generic helper PLT binding differs")
        records.append(record)
    return records


def _sequence_records(blob, mappings, elf, dynsym, deps, module):
    expected_sequences = [item for item in GENERIC_MODEL_SEQUENCES if item["module"] == module]
    exidx = _exidx_ranges(elf, blob)
    decoder = deps["Cs"](deps["arch"], deps["mode"])
    decoder.detail = True
    symbols = list(dynsym.iter_symbols())
    result = []
    for expected in expected_sequences:
        start, end = expected["owner"]["start"], expected["owner"]["end"]
        if (start, end) not in exidx:
            raise RuntimeError("generic sequence owner is not an exact exidx range")
        dynsym_owners = [
            symbol.name
            for symbol in symbols
            if symbol["st_shndx"] != "SHN_UNDEF"
            and symbol["st_info"]["type"] == "STT_FUNC"
            and symbol["st_size"] > 0
            and (symbol["st_value"] & ~1) == start
        ]
        if dynsym_owners:
            raise RuntimeError("generic sequence unexpectedly has a nonzero dynsym owner")
        items = list(decoder.disasm(_at(blob, mappings, start, end - start), start))
        if not items or (items[0].address & ~1) != start or items[-1].address + items[-1].size != end:
            raise RuntimeError("generic sequence owner decode is incomplete")
        by_address = {item.address & ~1: item for item in items}
        calls = []
        for call_expected in expected["calls"]:
            item = by_address.get(call_expected["site"])
            if (
                item is None
                or not item.group(deps["call_group"])
                or item.mnemonic != "blx"
                or len(item.operands) != 1
                or item.operands[0].type != deps["imm"]
            ):
                raise RuntimeError("generic sequence call site differs")
            targets = [operand.imm & ~1 for operand in item.operands if operand.type == deps["imm"]]
            if targets != [call_expected["target"]]:
                raise RuntimeError("generic sequence direct target differs")
            calls.append(copy.deepcopy(call_expected))
        record = copy.deepcopy(expected)
        record["calls"] = calls
        result.append(record)
    return result


def _section_name(elf, address):
    matches = [
        section.name
        for section in elf.iter_sections()
        if section["sh_addr"] <= address < section["sh_addr"] + section["sh_size"]
    ]
    if len(matches) != 1:
        raise RuntimeError("relocation section ownership differs")
    return matches[0]


def _publication_record(elf, dynsym, module, owners):
    expected = next(item for item in CREATIVE_STYLE_PUBLICATIONS if item["module"] == module)
    symbol = dynsym.get_symbol(expected["symbol_index"])
    if symbol.name != expected["symbol"] or (symbol["st_shndx"] != "SHN_UNDEF") != expected["symbol_defined"]:
        raise RuntimeError("Creative Style publication symbol differs")
    rel_dyn = list(elf.get_section_by_name(".rel.dyn").iter_relocations())
    matching = [
        (index, relocation)
        for index, relocation in enumerate(rel_dyn)
        if relocation["r_info_sym"] == expected["symbol_index"]
    ]
    expected_indices = [item["relocation_index"] for item in expected["relocations"]]
    if [index for index, _relocation in matching] != expected_indices:
        raise RuntimeError("Creative Style publication inventory differs")
    records = []
    for item_expected, (relocation_index, relocation) in zip(expected["relocations"], matching):
        site = relocation["r_offset"]
        inside = any(start <= site < end for start, end in owners)
        record = {
            "relocation_index": relocation_index,
            "site": site,
            "relocation_type": relocation["r_info_type"],
            "section": _section_name(elf, site),
            "inside_any_sequence_owner": inside,
        }
        if relocation["r_info_sym"] != expected["symbol_index"] or record != item_expected:
            raise RuntimeError("Creative Style publication relocation differs")
        records.append(record)
    result = copy.deepcopy(expected)
    result["relocations"] = records
    return result


def _metadata_from_files(sources=SOURCES):
    deps = _dependencies()
    expected_modules = {item["module"]: item for item in MODULES}
    before = {}
    bindings = {}
    sequences = []
    publications = []
    for module in ("lib/viewUnified4.so", "lib/viewUnified7.so"):
        source = Path(sources[module])
        if source.is_symlink() or not source.is_file():
            raise RuntimeError("source must be a literal regular file")
        identity = expected_modules[module]
        before[module] = _sha256(source)
        if source.name != Path(module).name or source.stat().st_size != identity["size"] or before[module] != identity["sha256"]:
            raise RuntimeError("source identity differs")
        blob = source.read_bytes()
        with io.BytesIO(blob) as stream:
            elf = deps["ELFFile"](stream)
            mappings = _mappings(elf)
            dynsym = elf.get_section_by_name(".dynsym")
            if dynsym is None:
                raise RuntimeError("dynamic symbols are unavailable")
            bindings[module] = _binding_records(elf, blob, mappings, dynsym, module)
            module_sequences = _sequence_records(blob, mappings, elf, dynsym, deps, module)
            sequences.extend(module_sequences)
            owners = [(item["owner"]["start"], item["owner"]["end"]) for item in module_sequences]
            publications.append(_publication_record(elf, dynsym, module, owners))
    document = copy.deepcopy(EXPECTED_EXPORT)
    document.update({
        "bindings": bindings,
        "generic_model_sequences": sequences,
        "creative_style_publications": publications,
        "ownership_boundary": copy.deepcopy(OWNERSHIP_BOUNDARY),
        "claims": copy.deepcopy(CLAIMS),
    })
    normalize_creative_style_generic_model_consumers_export(document)
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
        return normalize_creative_style_generic_model_consumers_export((adapter or FileAdapter()).metadata())
    except Exception as exc:
        raise RuntimeError("generic model-consumer metadata differs from the exact bounded static result") from exc


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
    handle, temporary = tempfile.mkstemp(dir=str(root), prefix=".generic-model-consumers-", suffix=".tmp")
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
    print("CREATIVE_STYLE_GENERIC_MODEL_CONSUMERS_EXPORT|modules=2|sequences=3|calls=7|creative_binding=0|persistence=0")
