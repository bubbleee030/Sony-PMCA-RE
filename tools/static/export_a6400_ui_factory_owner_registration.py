"""Export only typed static evidence for the α6400 UI factory forwarding owner."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile


EXPECTED_PROGRAM = "viewUnified7.so"
EXPECTED_SHA256 = "c48cde43ff22d808ad23c42019ddae516fff7da060004eb81ed2bb85012aa538"
EXPECTED_IMAGE_SIZE = 541_024
EXPECTED_ANALYSIS_MODE = {"engine": "elf-capstone-thumb-metadata", "read_only": True, "source_unchanged": True}
EXPECTED_OWNER = {
    "range": {"start": 0x529CC, "end": 0x529E8},
    "forwarding_edge": {"caller": 0x529CC, "site": 0x529D6, "target": 0x52840, "kind": "direct"},
    "direct_callers": (),
}
EXPECTED_TYPED_REGISTRATIONS = (
    {"index": 1268, "address": 0x70EE8, "target": 0x529CC, "thumb_pointer": 0x529CD, "evidence_kind": "relocation", "relocation_type": "R_ARM_RELATIVE", "section_name": ".rel.dyn"},
    {"index": 1286, "address": 0x70FA0, "target": 0x529CC, "thumb_pointer": 0x529CD, "evidence_kind": "relocation", "relocation_type": "R_ARM_RELATIVE", "section_name": ".rel.dyn"},
    {"index": 1305, "address": 0x71040, "target": 0x529CC, "thumb_pointer": 0x529CD, "evidence_kind": "relocation", "relocation_type": "R_ARM_RELATIVE", "section_name": ".rel.dyn"},
    {"index": 1327, "address": 0x710F0, "target": 0x529CC, "thumb_pointer": 0x529CD, "evidence_kind": "relocation", "relocation_type": "R_ARM_RELATIVE", "section_name": ".rel.dyn"},
    {"index": 1349, "address": 0x711A0, "target": 0x529CC, "thumb_pointer": 0x529CD, "evidence_kind": "relocation", "relocation_type": "R_ARM_RELATIVE", "section_name": ".rel.dyn"},
)
EXPECTED_ORIENTATION_IMPORTS = (
    {"id": "camera_orientation", "symbol": "_ZN27CmnWrpOrientationRegisterAF20getCameraOrientationEv", "plt": 0x14958, "owners": ({"owner": 0x2D2C6, "site": 0x2D2CC}, {"owner": 0x30750, "site": 0x30934})},
    {"id": "status_orientation", "symbol": "_ZN27CmnWrpOrientationRegisterAF23getStsCameraOrientationEv", "plt": 0x15008, "owners": ({"owner": 0x189DC, "site": 0x189EE}, {"owner": 0x1B070, "site": 0x1B08C}, {"owner": 0x1C56C, "site": 0x1C584}, {"owner": 0x1C56C, "site": 0x1C5E4})},
)
EXPECTED_PATH_SUMMARY = {
    "max_depth": 32,
    "orientation_roots": (0x2D2C6, 0x30750, 0x189DC, 0x1B070, 0x1C56C),
    "layout_mode_roots": (0x193E0, 0x27458, 0x27540, 0x29660, 0x2D68C, 0x2D770, 0x2D82C, 0x3260C, 0x53598, 0x53B9C, 0x54440, 0x56CCC, 0x56D8C, 0x56E4C, 0x56F0C),
    "paths_to_owner": (),
    "paths_to_factory": (),
}


def _validate_wrapper_registrations(elf, blob, mappings, deps, rels):
    """Validate the five typed address-taken wrapper registrations, not invocation."""
    del elf, blob, mappings, deps
    if tuple(rels) != EXPECTED_TYPED_REGISTRATIONS:
        raise RuntimeError("wrapper relocation index, type, site, or target is not exact")
    return tuple(rels)


def _require_dependencies():
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_GRP_CALL, CS_OP_IMM
        from elftools.elf.elffile import ELFFile
    except ImportError as error:
        raise RuntimeError("UI owner registration export requires capstone and pyelftools") from error
    return Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_GRP_CALL, CS_OP_IMM, ELFFile


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _prel31(value, place):
    value &= 0x7FFFFFFF
    return place + (value - 0x80000000 if value & 0x40000000 else value)


def _find_paths(edges, roots, targets, max_depth):
    adjacency = {}
    for edge in edges:
        adjacency.setdefault(edge["caller"], set()).add(edge["target"])
    found = []
    for root in roots:
        frontier = [(root, (root,))]
        visited = {root}
        while frontier:
            current, path = frontier.pop(0)
            if len(path) - 1 >= max_depth:
                continue
            for target in sorted(adjacency.get(current, ())):
                candidate = path + (target,)
                if target in targets:
                    found.append(candidate)
                    continue
                if target not in visited:
                    visited.add(target)
                    frontier.append((target, candidate))
    return tuple(found)


def _virtual_to_file_offset(elf, address, width):
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD":
            continue
        start, size = segment["p_vaddr"], segment["p_filesz"]
        if start <= address and address + width <= start + size:
            return segment["p_offset"] + (address - start)
    raise RuntimeError("relative relocation offset is outside a file-backed PT_LOAD segment")


def _metadata_from_file(source_path):
    Cs, arch, arm_mode, thumb_mode, call_group, imm_type, ELFFile = _require_dependencies()
    path = Path(source_path)
    before = _sha256(path)
    if path.name != EXPECTED_PROGRAM or before != EXPECTED_SHA256 or path.stat().st_size != EXPECTED_IMAGE_SIZE:
        raise RuntimeError("UI owner registration source identity is not pinned")
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        text = elf.get_section_by_name(".text")
        exidx = elf.get_section_by_name(".ARM.exidx")
        if text is None or exidx is None:
            raise RuntimeError("UI owner registration ELF sections are missing")
        relplt = elf.get_section_by_name(".rel.plt")
        plt = elf.get_section_by_name(".plt")
        if relplt is None or plt is None:
            raise RuntimeError("UI owner registration PLT relocation sections are missing")
        dynsym = elf.get_section(relplt["sh_link"])
        got_to_symbol = {entry["r_offset"]: dynsym.get_symbol(entry["r_info_sym"]).name for entry in relplt.iter_relocations()}
        arm = Cs(arch, arm_mode)
        arm.detail = True
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
        symbol_to_plt = {symbol: got_to_plt[got] for got, symbol in got_to_symbol.items() if got in got_to_plt}
        for item in EXPECTED_ORIENTATION_IMPORTS:
            if symbol_to_plt.get(item["symbol"]) != item["plt"]:
                raise RuntimeError("orientation dynsym-to-GOT-to-PLT mapping is not exact")
        blob = path.read_bytes()
        starts = sorted(_prel31(int.from_bytes(blob[offset:offset + 4], "little"), exidx["sh_addr"] + index * 8) for index, offset in enumerate(range(exidx["sh_offset"], exidx["sh_offset"] + exidx["sh_size"], 8)))
        text_start, text_end = text["sh_addr"], text["sh_addr"] + text["sh_size"]
        starts = sorted({start for start in starts if text_start <= start < text_end})
        owner_index = starts.index(EXPECTED_OWNER["range"]["start"]) if EXPECTED_OWNER["range"]["start"] in starts else -1
        if owner_index < 0 or owner_index + 1 >= len(starts) or starts[owner_index + 1] != EXPECTED_OWNER["range"]["end"]:
            raise RuntimeError("forwarding owner ARM.exidx range is not exact")
        thumb = Cs(arch, thumb_mode)
        thumb.detail = True
        thumb.skipdata = True
        text_data = text.data()
        calls = []
        for index, owner in enumerate(starts):
            end = starts[index + 1] if index + 1 < len(starts) else text_end
            for instruction in thumb.disasm(text_data[owner - text_start:end - text_start], owner):
                if instruction.id and instruction.group(call_group) and instruction.operands and instruction.operands[0].type == imm_type:
                    calls.append({"caller": owner, "site": instruction.address, "target": instruction.operands[0].imm & ~1, "kind": "direct"})
        forwarding = [edge for edge in calls if edge["caller"] == EXPECTED_OWNER["range"]["start"] and edge["site"] == EXPECTED_OWNER["forwarding_edge"]["site"]]
        if forwarding != [EXPECTED_OWNER["forwarding_edge"]]:
            raise RuntimeError("forwarding edge is not exact")
        direct_callers = tuple(edge for edge in calls if edge["target"] == EXPECTED_OWNER["range"]["start"])
        if direct_callers:
            raise RuntimeError("direct owner caller result changed from pinned zero")
        orientation_imports = []
        for item in EXPECTED_ORIENTATION_IMPORTS:
            owners = tuple({"owner": edge["caller"], "site": edge["site"]} for edge in calls if edge["target"] == item["plt"])
            actual = {"id": item["id"], "symbol": item["symbol"], "plt": item["plt"], "owners": owners}
            if actual != item:
                raise RuntimeError("orientation direct-call owner/site set is not exact")
            orientation_imports.append(actual)
        orientation_imports = tuple(orientation_imports)
        orientation_roots = tuple(dict.fromkeys(owner["owner"] for item in orientation_imports for owner in item["owners"]))
        if orientation_roots != EXPECTED_PATH_SUMMARY["orientation_roots"]:
            raise RuntimeError("derived orientation owners are not exact")
        layout_owners = tuple(sorted({edge["caller"] for edge in calls if edge["target"] == 0x13D34}))
        if layout_owners != EXPECTED_PATH_SUMMARY["layout_mode_roots"]:
            raise RuntimeError("layout-mode owner inventory is not exact")
        roots = tuple(sorted(set(orientation_roots) | set(layout_owners)))
        paths_to_owner = _find_paths(calls, roots, {EXPECTED_OWNER["range"]["start"]}, 32)
        paths_to_factory = _find_paths(calls, roots, {EXPECTED_OWNER["forwarding_edge"]["target"]}, 32)
        if paths_to_owner or paths_to_factory:
            raise RuntimeError("direct orientation path result changed from pinned zero")
        references = []
        for section in elf.iter_sections():
            if section["sh_type"] not in ("SHT_REL", "SHT_RELA"):
                continue
            for index, relocation in enumerate(section.iter_relocations()):
                if section.name != ".rel.dyn" or relocation["r_info_type"] != 23:
                    continue
                file_offset = _virtual_to_file_offset(elf, relocation["r_offset"], 4)
                thumb_pointer = int.from_bytes(blob[file_offset:file_offset + 4], "little")
                target = thumb_pointer & ~1
                if target == EXPECTED_OWNER["range"]["start"]:
                    references.append({"index": index, "address": relocation["r_offset"], "target": target, "thumb_pointer": thumb_pointer, "evidence_kind": "relocation", "relocation_type": "R_ARM_RELATIVE", "section_name": section.name})
        references = tuple(sorted(references, key=lambda item: item["address"]))
        references = _validate_wrapper_registrations(elf, blob, None, None, references)
    after = _sha256(path)
    if after != before:
        raise RuntimeError("UI owner registration source changed during read-only export")
    return {"owner": EXPECTED_OWNER, "typed_registration_references": EXPECTED_TYPED_REGISTRATIONS, "orientation_imports": orientation_imports, "direct_path_summary": EXPECTED_PATH_SUMMARY}


def build_raw_export(adapter):
    if adapter.program_name() != EXPECTED_PROGRAM or adapter.program_sha256() != EXPECTED_SHA256 or adapter.program_size() != EXPECTED_IMAGE_SIZE:
        raise RuntimeError("UI owner registration adapter source identity is invalid")
    if adapter.analysis_mode() != EXPECTED_ANALYSIS_MODE:
        raise RuntimeError("UI owner registration adapter is not read-only static metadata")
    if adapter.owner_metadata() != EXPECTED_OWNER or adapter.typed_registration_references() != EXPECTED_TYPED_REGISTRATIONS or adapter.orientation_imports() != EXPECTED_ORIENTATION_IMPORTS or adapter.direct_path_summary() != EXPECTED_PATH_SUMMARY:
        raise RuntimeError("UI owner registration metadata differs from the exact bounded result")
    return {
        "schema_version": 1, "program": EXPECTED_PROGRAM, "sha256": EXPECTED_SHA256,
        "image_size": EXPECTED_IMAGE_SIZE, "analysis_mode": dict(EXPECTED_ANALYSIS_MODE),
        "owner": {"range": dict(EXPECTED_OWNER["range"]), "forwarding_edge": dict(EXPECTED_OWNER["forwarding_edge"]), "direct_callers": []},
        "typed_registration_references": [dict(item) for item in EXPECTED_TYPED_REGISTRATIONS],
        "orientation_imports": [{"id": item["id"], "symbol": item["symbol"], "plt": item["plt"], "owners": [dict(owner) for owner in item["owners"]]} for item in EXPECTED_ORIENTATION_IMPORTS],
        "direct_path_summary": {key: list(value) if isinstance(value, tuple) else value for key, value in EXPECTED_PATH_SUMMARY.items()},
        "truncated": False,
    }


class FileAdapter:
    def __init__(self, source_path):
        self.source_path = Path(source_path)
        self._metadata = None
    def _read(self):
        if self._metadata is None:
            self._metadata = _metadata_from_file(self.source_path)
        return self._metadata
    def program_name(self): return self.source_path.name
    def program_sha256(self): return _sha256(self.source_path)
    def program_size(self): return self.source_path.stat().st_size
    def analysis_mode(self): return dict(EXPECTED_ANALYSIS_MODE)
    def owner_metadata(self): return self._read()["owner"]
    def typed_registration_references(self): return self._read()["typed_registration_references"]
    def orientation_imports(self): return self._read()["orientation_imports"]
    def direct_path_summary(self): return self._read()["direct_path_summary"]


def write_json_atomic(output_path, document, approved_root):
    output, root = Path(output_path), Path(approved_root).resolve(strict=True)
    if output.name != "raw-ui-factory-owner-registration.json" or output.parent.resolve(strict=True) != root:
        raise RuntimeError("UI owner registration output is outside the approved artifact root")
    handle, temporary = tempfile.mkstemp(dir=str(root), prefix=".ui-owner-registration-", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(document, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    except BaseException:
        try: os.unlink(temporary)
        except FileNotFoundError: pass
        raise


def main(args=None):
    args = list(args if args is not None else __import__("sys").argv[1:])
    if len(args) != 2:
        raise SystemExit("usage: <source.so> <output.json>")
    document = build_raw_export(FileAdapter(args[0]))
    write_json_atomic(args[1], document, Path(args[1]).parent)
    print("UI_FACTORY_OWNER_REGISTRATION_EXPORT|typed_references=5|direct_callers=0|paths=0")


if __name__ == "__main__":
    main()
