"""Read-only typed α6400 Picture Profile initializer-registration exporter."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pmca.analysis.picture_profile_generic_consumers import normalize_picture_profile_generic_consumer_export
from pmca.analysis.picture_profile_handoff import normalize_picture_profile_handoff_export
from pmca.analysis.picture_profile_initializer_registration import (
    ANALYSIS_LOAD_BIAS,
    CAUTION_CONFIG_SHA256,
    CAUTION_CONFIG_SIZE,
    ELF_INVENTORY,
    INIT_ARRAY_ENTRIES,
    INITIALIZER_OWNER,
    NAME_FRAGMENTS,
    PRIOR_ARTIFACTS,
    SYSTEM_DT_NEEDED,
    normalize_picture_profile_initializer_registration_export,
)


FIRMWARE_ROOT = ROOT / ".artifacts" / "decrypted" / "a6400-tw-v2.00" / "ma1co" / "firmware.tar_unpacked" / "0700_part_image" / "dev" / "nflasha15_unpacked"
SOURCE = FIRMWARE_ROOT / "lib" / "CautionConfig.so"
HANDOFF_ARTIFACT = ROOT / ".artifacts" / "picture-profile-handoff-trace" / "a6400-v2.00" / "raw-picture-profile-handoff.json"
GENERIC_ARTIFACT = ROOT / ".artifacts" / "picture-profile-generic-consumer-trace" / "a6400-v2.00" / "raw-picture-profile-generic-consumers.json"
OUTPUT_ROOT = ROOT / ".artifacts" / "picture-profile-initializer-registration-trace" / "a6400-v2.00"
RAW_FILENAME = "raw-picture-profile-initializer-registration.json"


def _dependencies():
    try:
        from elftools.common.exceptions import ELFError
        from elftools.elf.elffile import ELFFile
    except ImportError:
        dependency_root = ROOT / ".artifacts" / "pydeps_vlf"
        if not dependency_root.is_dir() or dependency_root.is_symlink():
            raise RuntimeError("local pyelftools dependency is unavailable")
        sys.path.insert(0, str(dependency_root))
        try:
            from elftools.common.exceptions import ELFError
            from elftools.elf.elffile import ELFFile
        except ImportError as error:
            raise RuntimeError("local pyelftools dependency is unavailable") from error
    return ELFError, ELFFile


def pyelftools_available():
    """Whether the exporter can resolve its own required local ELF parser."""
    try:
        _dependencies()
    except RuntimeError:
        return False
    return True


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical_inventory_digest(records):
    """Return the global-lexical-path inventory identity, independent of root order."""
    return hashlib.sha256(json.dumps(sorted(records, key=lambda record: record["path"]), sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _prel31(value, place):
    value &= 0x7FFFFFFF
    return place + (value - 0x80000000 if value & 0x40000000 else value)


def _prior_artifacts():
    result = {}
    for key, path, normalizer in (
        ("handoff_sha256", HANDOFF_ARTIFACT, normalize_picture_profile_handoff_export),
        ("generic_consumer_sha256", GENERIC_ARTIFACT, normalize_picture_profile_generic_consumer_export),
    ):
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("prior evidence must be a regular JSON file")
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise RuntimeError("prior evidence is invalid JSON") from error
        result[key] = normalizer(document)["artifact_sha256"]
    if result != PRIOR_ARTIFACTS:
        raise RuntimeError("prior artifact digest differs")
    return result


def _init_array(elf, blob):
    section = elf.get_section_by_name(".init_array")
    rel_dyn = elf.get_section_by_name(".rel.dyn")
    if section is None or rel_dyn is None:
        raise RuntimeError("initializer metadata sections are absent")
    if section["sh_addr"] != int("0xaa6290", 16) or section["sh_size"] != 24:
        raise RuntimeError("initializer array identity differs")
    entries = []
    for index, relocation in enumerate(rel_dyn.iter_relocations()):
        address = relocation["r_offset"]
        if not section["sh_addr"] <= address < section["sh_addr"] + section["sh_size"]:
            continue
        offset = section["sh_offset"] + address - section["sh_addr"]
        target = int.from_bytes(blob[offset:offset + 4], "little")
        entries.append({
            "relocation_index": index, "relocation_address": "0x%x" % address,
            "relocation_type": "R_ARM_RELATIVE", "symbol_index": relocation["r_info_sym"],
            "thumb_target": "0x%x" % target, "elf_owner": "0x%x" % (target & ~1),
            "analysis_owner": "0x%x" % ((target & ~1) + ANALYSIS_LOAD_BIAS),
        })
        if relocation["r_info_type"] != 23 or relocation["r_info_sym"] != 0:
            raise RuntimeError("initializer relocation is not typed R_ARM_RELATIVE")
    result = {"elf_address": "0x%x" % section["sh_addr"], "size": section["sh_size"], "entries": entries}
    if result["entries"] != INIT_ARRAY_ENTRIES:
        raise RuntimeError("initializer relocation records differ")
    return result


def _initializer_owner(elf, blob):
    text = elf.get_section_by_name(".text")
    exidx = elf.get_section_by_name(".ARM.exidx")
    if text is None or exidx is None or exidx["sh_size"] % 8:
        raise RuntimeError("ARM exception-index metadata is absent")
    starts = sorted({
        _prel31(int.from_bytes(blob[offset:offset + 4], "little"), exidx["sh_addr"] + index * 8)
        for index, offset in enumerate(range(exidx["sh_offset"], exidx["sh_offset"] + exidx["sh_size"], 8))
    })
    owner = int("0x8251f8", 16)
    if owner not in starts or starts.index(owner) + 1 >= len(starts):
        raise RuntimeError("initializer owner is not an ARM.exidx function")
    result = {
        "elf_range_start": "0x%x" % owner,
        "elf_range_end": "0x%x" % starts[starts.index(owner) + 1],
        "analysis_range_start": "0x%x" % (owner + ANALYSIS_LOAD_BIAS),
        "analysis_range_end": "0x%x" % (starts[starts.index(owner) + 1] + ANALYSIS_LOAD_BIAS),
        "evidence": "ARM.exidx-function",
    }
    if result != INITIALIZER_OWNER:
        raise RuntimeError("initializer ARM.exidx range differs")
    return result


def _regular_elf_inventory():
    ELFError, ELFFile = _dependencies()
    records, definitions, imports, persistence = [], set(), [], []
    for root_name in ELF_INVENTORY["roots"]:
        directory = FIRMWARE_ROOT / root_name
        if directory.is_symlink() or not directory.is_dir():
            raise RuntimeError("bounded ELF scan root is unavailable or linked")
        # Only regular file entries are considered; exact paths are canonicalized
        # globally below, so the identity does not depend on root traversal order.
        for path in sorted(directory.rglob("*")):
            if path.is_dir():
                continue
            if path.is_symlink() or not path.is_file():
                continue
            try:
                with path.open("rb") as stream:
                    elf = ELFFile(stream)
                    dynsym = elf.get_section_by_name(".dynsym")
                    if dynsym is None:
                        continue
                    symbols = list(dynsym.iter_symbols())
            except ELFError:
                continue
            relative = path.relative_to(FIRMWARE_ROOT).as_posix()
            records.append({"path": relative, "size": path.stat().st_size, "sha256": _sha256(path)})
            for symbol in symbols:
                name = symbol.name
                if not name or not any(fragment in name for fragment in NAME_FRAGMENTS):
                    continue
                if any(verb in name.casefold() for verb in ("save", "load", "store", "persist", "read", "write")):
                    persistence.append(name)
                if symbol["st_shndx"] == "SHN_UNDEF":
                    imports.append({"module": relative, "symbol": name})
                else:
                    definitions.add(relative)
    digest = canonical_inventory_digest(records)
    inventory = {"roots": list(ELF_INVENTORY["roots"]), "elf_file_count": len(records), "canonical_inventory_sha256": digest}
    if inventory != ELF_INVENTORY:
        raise RuntimeError("bounded ELF inventory differs")
    scan = {
        "exact_name_fragments": list(NAME_FRAGMENTS),
        "defining_modules": sorted(definitions),
        "direct_named_cross_module_imports": sorted(imports, key=lambda item: (item["module"], item["symbol"])),
        "persistence_verb_symbols": sorted(set(persistence)),
    }
    if scan != {"exact_name_fragments": NAME_FRAGMENTS, "defining_modules": ["lib/CautionConfig.so"], "direct_named_cross_module_imports": [], "persistence_verb_symbols": []}:
        raise RuntimeError("named Picture Profile cross-module scan differs")
    return inventory, scan


def _needed(elf):
    dynamic = elf.get_section_by_name(".dynamic")
    if dynamic is None:
        raise RuntimeError("dynamic metadata is absent")
    result = [tag.needed for tag in dynamic.iter_tags() if tag.entry.d_tag == "DT_NEEDED"]
    if result != SYSTEM_DT_NEEDED:
        raise RuntimeError("dynamic dependency set differs")
    return result


def build_raw_export(source=SOURCE):
    """Build the exact static registration result without executing the source."""

    _ELFError, ELFFile = _dependencies()
    source = Path(source)
    if source.is_symlink() or not source.is_file():
        raise RuntimeError("source must be a regular firmware file")
    before = _sha256(source)
    if source.name != "CautionConfig.so" or before != CAUTION_CONFIG_SHA256 or source.stat().st_size != CAUTION_CONFIG_SIZE:
        raise RuntimeError("source identity differs")
    blob = source.read_bytes()
    with source.open("rb") as stream:
        elf = ELFFile(stream)
        init_array = _init_array(elf, blob)
        owner = _initializer_owner(elf, blob)
        needed = _needed(elf)
    inventory, named = _regular_elf_inventory()
    document = {
        "program": "CautionConfig.so", "sha256": CAUTION_CONFIG_SHA256, "file_size": CAUTION_CONFIG_SIZE,
        "analysis_mode": {"read_only": True, "static_elf_metadata": True, "source_unchanged": True}, "program_changed": False,
        "init_array": init_array, "initializer_owner": owner, "prior_artifacts": _prior_artifacts(),
        "pp1_pp9_construction": {"constructor_parameter_reference_count": 18, "analysis_owner": "0x8351f8"},
        "bounded_elf_inventory": inventory, "named_symbol_scan": named, "dt_needed": needed,
        "selected_state_paths": [], "ui_dispatch_paths": [], "persistence_paths": [], "processing_paths": [], "output_paths": [], "truncated": False,
    }
    normalize_picture_profile_initializer_registration_export(document)
    if _sha256(source) != before:
        raise RuntimeError("source changed during read-only export")
    return document


def write_json_atomic(output, document, approved_root=OUTPUT_ROOT):
    """Write only the fixed ignored JSON filename inside a literal safe root."""

    output, root = Path(output), Path(approved_root)
    literal = root.absolute()
    if root.is_symlink() or not root.is_dir() or root.resolve(strict=True) != literal:
        raise RuntimeError("approved output root is not a literal directory")
    expected = literal / RAW_FILENAME
    if output.absolute() != expected or output.parent.absolute() != literal or output.is_symlink() or (output.exists() and not output.is_file()):
        raise RuntimeError("output containment is invalid")
    descriptor, temporary = tempfile.mkstemp(dir=str(literal), prefix=".pp-initializer-", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(document, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, expected)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main():
    if OUTPUT_ROOT.is_symlink():
        raise RuntimeError("fixed output root is linked")
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    write_json_atomic(OUTPUT_ROOT / RAW_FILENAME, build_raw_export())
    print("PICTURE_PROFILE_INITIALIZER_REGISTRATION_EXPORT|entries=6|pp_constructor_refs=18|named_imports=0")


if __name__ == "__main__":
    main()
