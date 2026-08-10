"""Read-only α6400 Creative Style default-root registry exporter."""

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
from pmca.analysis.creative_style_registry_consumers import (
    CAUTION_CONFIG, FIRMWARE_ELF_FILE_COUNT, FIRMWARE_INVENTORY_SHA256, FIRMWARE_REGULAR_FILE_COUNT,
    FIRMWARE_SHARED_OBJECT_COUNT, MODULES, PRIOR_ARTIFACTS, normalize_creative_style_registry_consumers_export,
)

FIRMWARE_ROOT = ROOT / ".artifacts" / "decrypted" / "a6400-tw-v2.00" / "ma1co" / "firmware.tar_unpacked" / "0700_part_image" / "dev" / "nflasha15_unpacked"
OUTPUT_ROOT = ROOT / ".artifacts" / "creative-style-registry-consumer-trace" / "a6400-v2.00"
OUTPUT_NAME = "raw-creative-style-registry-consumers.json"
REPORTS = {
    "creative_style_definition_registration_sha256": ROOT / "analysis" / "a6400-creative-style-definition-registration.json",
    "creative_style_root_consumers_sha256": ROOT / "analysis" / "a6400-creative-style-root-consumers.json",
}


def _dependencies():
    try:
        from elftools.common.exceptions import ELFError
        from elftools.elf.elffile import ELFFile
    except ImportError:
        dependency_root = ROOT / ".artifacts" / "pydeps_vlf"
        if dependency_root.is_symlink() or not dependency_root.is_dir():
            raise RuntimeError("local pyelftools dependency is unavailable")
        sys.path.insert(0, str(dependency_root))
        try:
            from elftools.common.exceptions import ELFError
            from elftools.elf.elffile import ELFFile
        except ImportError as error:
            raise RuntimeError("local pyelftools dependency is unavailable") from error
    return ELFError, ELFFile


def pyelftools_available():
    """Whether the exporter can resolve the same parser used by live export."""
    try:
        _dependencies()
    except (RuntimeError, ImportError):
        return False
    return True


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical_inventory_digest(records):
    return hashlib.sha256(json.dumps(sorted(records, key=lambda item: item["path"]), sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _registry_digest(entries):
    return hashlib.sha256((json.dumps(entries, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")).hexdigest()


def _inventory():
    ELFError, ELFFile = _dependencies()
    if FIRMWARE_ROOT.is_symlink() or not FIRMWARE_ROOT.is_dir():
        raise RuntimeError("firmware root is unavailable or linked")
    records, elf_paths, shared_objects = [], [], []
    for path in sorted(FIRMWARE_ROOT.rglob("*")):
        if path.is_dir():
            continue
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("firmware inventory contains a nonregular path")
        record = {"path": path.relative_to(FIRMWARE_ROOT).as_posix(), "size": path.stat().st_size, "sha256": _sha256(path)}
        records.append(record)
        try:
            with path.open("rb") as stream:
                ELFFile(stream)
        except ELFError:
            continue
        elf_paths.append(record["path"])
        if path.suffix == ".so":
            shared_objects.append(record["path"])
    result = {"regular_file_count": len(records), "elf_file_count": len(elf_paths), "shared_object_count": len(shared_objects), "canonical_inventory_sha256": canonical_inventory_digest(records)}
    expected = {"regular_file_count": FIRMWARE_REGULAR_FILE_COUNT, "elf_file_count": FIRMWARE_ELF_FILE_COUNT, "shared_object_count": FIRMWARE_SHARED_OBJECT_COUNT, "canonical_inventory_sha256": FIRMWARE_INVENTORY_SHA256}
    if result != expected:
        raise RuntimeError("firmware inventory differs")
    return result, elf_paths


def _section_name(elf, symbol):
    if symbol["st_shndx"] == "SHN_UNDEF":
        return "SHN_UNDEF"
    return elf.get_section(symbol["st_shndx"]).name


def _coverage(symbol_table, cells):
    if symbol_table is None:
        return False, [], []
    exact, covering = [], []
    for cell in cells:
        for symbol in symbol_table.iter_symbols():
            if symbol["st_value"] == cell:
                exact.append(cell)
            elif symbol["st_size"] and symbol["st_value"] < cell < symbol["st_value"] + symbol["st_size"]:
                covering.append(cell)
    return True, sorted(set(exact)), sorted(set(covering))


def _registry_reference_metadata(elf):
    """Collect named symbol scope before treating absent relocation tables as empty."""
    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym is None:
        return {"symbol_indexes": {}, "plt_reference_indices": []}
    symbol_indexes = {
        symbol.name: index
        for index, symbol in enumerate(dynsym.iter_symbols())
        if symbol.name in {"cmnViewSettingNodesRootDefault", "cmnViewSettingNodeRootCreativeStyle"}
    }
    rel_plt = elf.get_section_by_name(".rel.plt")
    plt_relocations = [] if rel_plt is None else list(rel_plt.iter_relocations())
    return {
        "symbol_indexes": symbol_indexes,
        "plt_reference_indices": [
            index for index, relocation in enumerate(plt_relocations)
            if relocation["r_info_sym"] in symbol_indexes.values()
        ],
    }


def _registry_and_references(elf_paths):
    _ELFError, ELFFile = _dependencies()
    reference_modules, plt_reference_modules, consumer_relocations, coverage = [], [], {}, []
    registry_entries = None
    expected_modules = {item["module"]: item for item in MODULES}
    for relative in elf_paths:
        path = FIRMWARE_ROOT / relative
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            dynsym, rel_dyn = elf.get_section_by_name(".dynsym"), elf.get_section_by_name(".rel.dyn")
            if dynsym is None:
                continue
            reference = _registry_reference_metadata(elf)
            symbol_indexes = reference["symbol_indexes"]
            if symbol_indexes:
                reference_modules.append(relative)
                if reference["plt_reference_indices"]:
                    plt_reference_modules.append(relative)
            if rel_dyn is None:
                continue
            if relative == "lib/CautionConfig.so":
                container = dynsym.get_symbol(11778)
                if container.name != "cmnViewSettingNodesRootDefault" or container["st_value"] != 0xB8A380 or container["st_size"] != 1660 or container["st_info"]["type"] != "STT_OBJECT" or _section_name(elf, container) != ".data":
                    raise RuntimeError("registry container differs")
                entries = []
                for relocation_index, relocation in enumerate(rel_dyn.iter_relocations()):
                    site = relocation["r_offset"]
                    if not container["st_value"] <= site < container["st_value"] + container["st_size"]:
                        continue
                    target = dynsym.get_symbol(relocation["r_info_sym"])
                    entries.append({"slot": (site - container["st_value"]) // 4, "offset": hex(site - container["st_value"]), "relocation_index": relocation_index, "site": hex(site), "relocation_type": "R_ARM_ABS32" if relocation["r_info_type"] == 2 else None, "target_dynsym_index": relocation["r_info_sym"], "target_symbol": target.name, "target_size": target["st_size"], "target_section": _section_name(elf, target), "target_symbol_type": target["st_info"]["type"], "target_binding": target["st_info"]["bind"], "target_defined": target["st_shndx"] != "SHN_UNDEF"})
                registry_entries = sorted(entries, key=lambda item: item["site"])
                continue
            if relative not in {"lib/viewUnified2.so", "lib/viewUnified4.so", "lib/viewUnified7.so"}:
                continue
            registry_index = symbol_indexes.get("cmnViewSettingNodesRootDefault")
            creative_index = symbol_indexes.get("cmnViewSettingNodeRootCreativeStyle")
            records = list(rel_dyn.iter_relocations())
            def _record(index, section):
                relocation = records[index]
                return {"relocation_index": index, "site": hex(relocation["r_offset"]), "relocation_type": "R_ARM_GLOB_DAT" if relocation["r_info_type"] == 21 else "R_ARM_ABS32" if relocation["r_info_type"] == 2 else None, "section": section}
            registry_got = [index for index, relocation in enumerate(records) if registry_index is not None and relocation["r_info_sym"] == registry_index and relocation["r_info_type"] == 21]
            creative_got = [index for index, relocation in enumerate(records) if creative_index is not None and relocation["r_info_sym"] == creative_index and relocation["r_info_type"] == 21]
            creative_data = [index for index, relocation in enumerate(records) if creative_index is not None and relocation["r_info_sym"] == creative_index and relocation["r_info_type"] == 2]
            got = elf.get_section_by_name(".got")
            data = elf.get_section_by_name(".data")
            if any(not got["sh_addr"] <= records[index]["r_offset"] < got["sh_addr"] + got["sh_size"] for index in registry_got + creative_got) or any(not data["sh_addr"] <= records[index]["r_offset"] < data["sh_addr"] + data["sh_size"] for index in creative_data):
                raise RuntimeError("consumer relocation section differs")
            consumer_relocations[relative] = {"registry_dynsym_index": registry_index, "creative_style_dynsym_index": creative_index, "registry_glob_dat": _record(registry_got[0], ".got") if len(registry_got) == 1 else None, "creative_style_glob_dat": _record(creative_got[0], ".got") if len(creative_got) == 1 else None, "creative_style_abs32": [_record(index, ".data") for index in creative_data]}
            cells = [records[index]["r_offset"] for index in creative_data]
            dynamic_present, dynamic_exact, dynamic_covering = _coverage(dynsym, cells)
            static_present, static_exact, static_covering = _coverage(elf.get_section_by_name(".symtab"), cells)
            if not dynamic_present or dynamic_exact or dynamic_covering or static_present or static_exact or static_covering:
                raise RuntimeError("consumer data-cell symbol coverage differs")
            coverage.append({"module": relative, "cell_count": len(cells), "dynamic_exact": dynamic_exact, "dynamic_covering": dynamic_covering, "static_table_present": static_present, "static_exact": static_exact, "static_covering": static_covering})
    if registry_entries is None or set(reference_modules) != set(expected_modules) or set(consumer_relocations) != {"lib/viewUnified2.so", "lib/viewUnified4.so", "lib/viewUnified7.so"}:
        raise RuntimeError("registry reference scope differs")
    return registry_entries, sorted(reference_modules), sorted(plt_reference_modules), consumer_relocations, sorted(coverage, key=lambda item: item["module"])


def _prior_artifacts():
    from pmca.analysis.creative_style_definition_registration import validate_creative_style_definition_registration_report
    from pmca.analysis.creative_style_root_consumers import validate_creative_style_root_consumers_report
    validators = {"creative_style_definition_registration_sha256": lambda value: validate_creative_style_definition_registration_report(value)["summary"]["artifact_sha256"], "creative_style_root_consumers_sha256": lambda value: validate_creative_style_root_consumers_report(value)["export_summary"]["canonical_export_sha256"]}
    result = {}
    for key, path in REPORTS.items():
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("prior evidence must be a regular file")
        result[key] = validators[key](json.loads(path.read_text(encoding="utf-8")))
    if result != PRIOR_ARTIFACTS:
        raise RuntimeError("prior evidence digest differs")
    return result


def build_raw_export():
    inventory, elf_paths = _inventory()
    paths = {item["module"]: FIRMWARE_ROOT / item["module"] for item in MODULES}
    before = {module: _sha256(path) for module, path in paths.items()}
    if any(before[item["module"]] != item["sha256"] or paths[item["module"]].stat().st_size != item["size"] for item in MODULES):
        raise RuntimeError("pinned module identity differs")
    entries, reference_modules, plt_reference_modules, consumers, coverage = _registry_and_references(elf_paths)
    document = {"schema_version": 1, "analysis_mode": {"read_only": True, "static_elf_metadata": True, "source_unchanged": True}, "firmware_inventory": inventory, "modules": list(MODULES), "registry": {"dynsym_index": 11778, "symbol": "cmnViewSettingNodesRootDefault", "elf_address": "0xb8a380", "size": 1660, "section": ".data", "symbol_type": "STT_OBJECT", "slot_count": 415}, "registry_entries": entries, "registry_entries_sha256": _registry_digest(entries), "creative_style": {"slot": 15, "offset": "0x3c", "relocation_index": 87605, "site": "0xb8a3bc", "target_dynsym_index": 31507, "target_symbol": "cmnViewSettingNodeRootCreativeStyle"}, "reference_modules": reference_modules, "consumer_relocations": consumers, "data_cell_symbol_coverage": coverage, "plt_reference_modules": plt_reference_modules, "prior_artifacts": _prior_artifacts(), "claims": {"typed_default_registry_found": True, "creative_style_registry_slot_found": True, "cross_module_data_publication_found": True, "indirect_data_consumers_found": False, "selected_state_found": False, "persistence_found": False, "creative_look_found": False}, "truncated": False}
    normalize_creative_style_registry_consumers_export(document)
    if any(_sha256(path) != before[module] for module, path in paths.items()):
        raise RuntimeError("source changed during read-only export")
    return document


def prepare_output_root(approved_root=OUTPUT_ROOT, artifact_base=ROOT / ".artifacts"):
    base, target = Path(os.path.abspath(artifact_base)), Path(os.path.abspath(approved_root))
    if base.is_symlink() or not base.is_dir() or base.resolve(strict=True) != base:
        raise RuntimeError("artifact base is not a literal directory")
    try:
        relative = target.relative_to(base)
    except ValueError as error:
        raise RuntimeError("output root is not beneath the artifact base") from error
    current = base
    for part in relative.parts:
        current = current / part
        if current.exists() or current.is_symlink():
            if current.is_symlink() or not current.is_dir() or current.resolve(strict=True) != current:
                raise RuntimeError("output root escapes through a link")
        else:
            current.mkdir()
            if current.is_symlink() or current.resolve(strict=True) != current:
                raise RuntimeError("output root is not literal")
    return current


def write_json_atomic(output, document, approved_root=OUTPUT_ROOT, artifact_base=ROOT / ".artifacts"):
    root = prepare_output_root(approved_root, artifact_base)
    output, expected = Path(os.path.abspath(output)), root / OUTPUT_NAME
    if output != expected or output.parent != root or output.is_symlink() or (output.exists() and not output.is_file()):
        raise RuntimeError("output path escapes the fixed artifact root")
    descriptor, temporary = tempfile.mkstemp(dir=str(root), prefix=".creative-style-registry-", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(document, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, output)
    except BaseException:
        try: os.unlink(temporary)
        except FileNotFoundError: pass
        raise


def main():
    write_json_atomic(OUTPUT_ROOT / OUTPUT_NAME, build_raw_export())
    print("CREATIVE_STYLE_REGISTRY_CONSUMERS_EXPORT|slots=415|modules=4|data_cells=58|plt=0|selected=0|persistence=0|creative_look=0")


if __name__ == "__main__":
    main()
