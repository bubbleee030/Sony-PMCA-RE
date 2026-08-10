"""Read-only α6400 UI layout-header loader/GOT metadata exporter."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile

from pmca.analysis.ui_layout_header_got_boundary import (
    EXPECTED_RAW_EXPORT,
    SLOT34_DISPATCH_DIGEST,
    VIEW_UNIFIED7_SHA256,
    VIEW_UNIFIED7_SIZE,
    VTABLE_DIGEST,
    normalize_ui_layout_header_got_boundary_export,
)
from pmca.analysis.ui_layout_vtable_interface import (
    normalize_ui_layout_vtable_interface_export,
    summarize_ui_layout_vtable_interface_export,
)
from pmca.analysis.ui_slot34_dispatch import (
    normalize_ui_slot34_dispatch_export,
    summarize_ui_slot34_dispatch_export,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_ROOT = REPOSITORY_ROOT / ".artifacts" / "ui-layout-header-got-boundary-trace" / "a6400-v2.00"
EXPECTED_PROGRAM = "viewUnified7.so"


def _dependencies():
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError as error:
        raise RuntimeError("UI layout-header GOT export requires local pyelftools") from error
    return ELFFile


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _file_offset(elf, address, width):
    matches = []
    for segment in elf.iter_segments():
        if segment["p_type"] == "PT_LOAD" and segment["p_vaddr"] <= address and address + width <= segment["p_vaddr"] + segment["p_filesz"]:
            matches.append(segment["p_offset"] + address - segment["p_vaddr"])
    if len(matches) != 1:
        raise RuntimeError("relocation site is not uniquely file-backed")
    return matches[0]


def _prior(path, normalizer, summarizer, contract, digest):
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file():
        raise RuntimeError("prior evidence must be a regular JSON file")
    try:
        document = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError("prior evidence is invalid JSON") from error
    normalizer(document)
    result = {"analysis_contract": contract, "canonical_export_sha256": summarizer(document)["canonical_export_sha256"]}
    if result["canonical_export_sha256"] != digest:
        raise RuntimeError("prior evidence digest is not pinned")
    return result


def _dynamic_symbol_coverage(dynsym, address):
    exact, covering = [], []
    for symbol in dynsym.iter_symbols():
        value, size = symbol["st_value"], symbol["st_size"]
        if value == address:
            exact.append(symbol.name)
        elif size and value < address < value + size:
            covering.append(symbol.name)
    return {"exact": sorted(exact), "covering": sorted(covering)}


def _metadata_from_file(source_path, vtable_path, slot34_path):
    ELFFile = _dependencies()
    source = Path(source_path)
    before = _sha256(source)
    if source.name != EXPECTED_PROGRAM or source.stat().st_size != VIEW_UNIFIED7_SIZE or before != VIEW_UNIFIED7_SHA256:
        raise RuntimeError("layout-header source identity is not pinned")
    vtable = _prior(vtable_path, normalize_ui_layout_vtable_interface_export, summarize_ui_layout_vtable_interface_export, "ui_layout_vtable_interface", VTABLE_DIGEST)
    slot34 = _prior(slot34_path, normalize_ui_slot34_dispatch_export, summarize_ui_slot34_dispatch_export, "ui_slot34_dispatch", SLOT34_DISPATCH_DIGEST)
    blob = source.read_bytes()
    with source.open("rb") as stream:
        elf = ELFFile(stream)
        got, rel, dynsym = (elf.get_section_by_name(name) for name in (".got", ".rel.dyn", ".dynsym"))
        if got is None or rel is None or dynsym is None:
            raise RuntimeError("required ELF metadata sections are missing")
        if (got["sh_addr"], got["sh_addr"] + got["sh_size"]) != (0x71B0C, 0x724F0):
            raise RuntimeError("GOT bounds differ from the pinned source result")
        relocs = list(rel.iter_relocations())
        records = []
        for index, site, header in ((item["relocation_index"], item["site"], item["header"]) for item in EXPECTED_RAW_EXPORT["layout_header_relocations"]):
            relocation = relocs[index]
            if relocation["r_offset"] != site or relocation["r_info_type"] != 23 or relocation["r_info_sym"] != 0:
                raise RuntimeError("layout-header relocation is not the pinned unsymbolized R_ARM_RELATIVE record")
            addend = int.from_bytes(blob[_file_offset(elf, site, 4):_file_offset(elf, site, 4) + 4], "little")
            site_coverage = _dynamic_symbol_coverage(dynsym, site)
            header_coverage = _dynamic_symbol_coverage(dynsym, header)
            if addend != header or site_coverage != {"exact": [], "covering": []} or header_coverage != {"exact": [], "covering": []}:
                raise RuntimeError("layout-header relocation is symbolized or differs from pinned metadata")
            records.append({"relocation_index": index, "site": site, "relocation_type": "R_ARM_RELATIVE", "symbol_index": 0, "addend": addend, "header": header, "site_symbol_coverage": site_coverage, "header_symbol_coverage": header_coverage})
        relative_count = sum(1 for relocation in relocs if got["sh_addr"] <= relocation["r_offset"] < got["sh_addr"] + got["sh_size"] and relocation["r_info_type"] == 23 and relocation["r_info_sym"] == 0)
        named = relocs[3858]
        if named["r_offset"] != 0x72434 or named["r_info_type"] != 21 or named["r_info_sym"] != 544 or dynsym.get_symbol(544).name != "cmnViewSettingNodeRootCreativeStyle":
            raise RuntimeError("Creative Style import is not the independently pinned GLOB_DAT record")
    if _sha256(source) != before:
        raise RuntimeError("source changed during read-only static export")
    result = copy.deepcopy(EXPECTED_RAW_EXPORT)
    result["prior_vtable_interface"] = vtable
    result["prior_slot34_dispatch"] = slot34
    result["layout_header_relocations"] = records
    result["unsymbolized_relative_got_count"] = relative_count
    return result


def build_raw_export(adapter):
    try:
        return normalize_ui_layout_header_got_boundary_export(adapter.metadata())
    except Exception as error:
        raise RuntimeError("layout-header GOT metadata differs from the exact bounded result") from error


class FileAdapter:
    def __init__(self, source_path, vtable_path, slot34_path):
        self.source_path = Path(source_path)
        self.vtable_path = Path(vtable_path)
        self.slot34_path = Path(slot34_path)

    def metadata(self):
        return _metadata_from_file(self.source_path, self.vtable_path, self.slot34_path)


def write_json_atomic(output_path, document):
    output = Path(output_path)
    literal = Path(OUTPUT_ROOT).absolute()
    root = literal.resolve(strict=True)
    expected = root / "raw-ui-layout-header-got-boundary.json"
    if root != literal or root.is_symlink() or Path(os.path.abspath(output)) != expected or output.parent.resolve(strict=True) != root or output.is_symlink() or (output.exists() and not output.is_file()):
        raise RuntimeError("layout-header GOT output escapes the pinned artifact root")
    handle, temporary = tempfile.mkstemp(dir=str(root), prefix=".ui-layout-header-got-", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(document, stream, sort_keys=True, indent=2)
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
    args = list(args if args is not None else __import__("sys").argv[1:])
    if len(args) != 4:
        raise SystemExit("usage: <source.so> <vtable.json> <slot34.json> <output.json>")
    output = Path(args[3])
    if Path(os.path.abspath(output)) != Path(os.path.abspath(OUTPUT_ROOT / "raw-ui-layout-header-got-boundary.json")):
        raise RuntimeError("layout-header GOT main output is not the pinned artifact path")
    write_json_atomic(output, build_raw_export(FileAdapter(args[0], args[1], args[2])))
    print("UI_LAYOUT_HEADER_GOT_EXPORT|headers=5|unsymbolized_relative_got=194|selector=0|touch=0")


if __name__ == "__main__":
    main()
