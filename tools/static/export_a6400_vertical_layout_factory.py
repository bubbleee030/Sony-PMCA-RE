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
FACTORY_ROOT = 0x52840
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


def _require_dependencies():
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_GRP_CALL, CS_OP_IMM
        from elftools.elf.elffile import ELFFile
    except ImportError as error:
        raise RuntimeError("vertical factory export requires capstone and pyelftools") from error
    return Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_GRP_CALL, CS_OP_IMM, ELFFile


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _prel31(value, place):
    value &= 0x7fffffff
    return place + (value - 0x80000000 if value & 0x40000000 else value)


def _metadata_from_file(source_path):
    Cs, arch, arm_mode, thumb_mode, call_group, imm_type, ELFFile = _require_dependencies()
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
        wanted_names = set(expected_symbols.values()) | {item[0] for item in upstream_symbols.values()}
        symbol_to_plt = {name: got_to_plt[got] for got, name in got_to_symbol.items() if name in wanted_names and got in got_to_plt}
        for edge in CONSTRUCTORS:
            if symbol_to_plt.get(expected_symbols[edge["id"]]) != edge["target"]:
                raise RuntimeError("vertical constructor PLT mapping is not pinned")
        if any(symbol_to_plt.get(name) != target for name, target in upstream_symbols.values()):
            raise RuntimeError("vertical upstream PLT mapping is not pinned")
        exidx_starts = sorted(_prel31(int.from_bytes(blob[offset:offset + 4], "little"), exidx["sh_addr"] + index * 8) for index, offset in enumerate(range(exidx["sh_offset"], exidx["sh_offset"] + exidx["sh_size"], 8)))
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
    return {"constructors": observed, "reverse_callers": reverse, "unresolved_indirect_terminals": unresolved, "upstream_roots": upstream}


def build_raw_export(adapter):
    if adapter.program_name() != EXPECTED_PROGRAM or adapter.program_sha256() != EXPECTED_SHA256 or adapter.program_size() != EXPECTED_IMAGE_SIZE:
        raise RuntimeError("vertical factory adapter source identity is invalid")
    if adapter.analysis_mode() != {"engine": "elf-capstone-thumb", "read_only": True, "source_unchanged": True}:
        raise RuntimeError("vertical factory adapter is not a read-only ELF/Capstone export")
    observed = adapter.factory_metadata(FACTORY_ROOT)
    if observed != {"constructors": CONSTRUCTORS, "reverse_callers": REVERSE_CALLERS, "unresolved_indirect_terminals": ()}:
        raise RuntimeError("vertical factory metadata differs from the exact bounded result")
    upstream = adapter.upstream_roots()
    if upstream != UPSTREAM_ROOTS:
        raise RuntimeError("vertical upstream root metadata differs from the exact bounded result")
    return {"schema_version": 1, "program": EXPECTED_PROGRAM, "sha256": EXPECTED_SHA256, "image_size": EXPECTED_IMAGE_SIZE, "analysis_mode": adapter.analysis_mode(), "factory": {"root": FACTORY_ROOT, "branch_value_classification": "local-branching-observed", "constructors": [dict(item) for item in CONSTRUCTORS], "reverse_callers": [dict(item) for item in REVERSE_CALLERS], "unresolved_indirect_terminals": []}, "upstream_roots": {"camera_orientation_owners": list(UPSTREAM_ROOTS["camera_orientation_owners"]), "status_orientation_owners": list(UPSTREAM_ROOTS["status_orientation_owners"]), "layout_mode": dict(UPSTREAM_ROOTS["layout_mode"])}, "truncated": False}


class FileAdapter:
    def __init__(self, source_path): self.source_path = Path(source_path); self._metadata = None
    def program_name(self): return self.source_path.name
    def program_sha256(self): return _sha256(self.source_path)
    def program_size(self): return self.source_path.stat().st_size
    def analysis_mode(self): return {"engine": "elf-capstone-thumb", "read_only": True, "source_unchanged": True}
    def factory_metadata(self, root):
        if root != FACTORY_ROOT: raise RuntimeError("factory root is not pinned")
        if self._metadata is None: self._metadata = _metadata_from_file(self.source_path)
        return {key: self._metadata[key] for key in ("constructors", "reverse_callers", "unresolved_indirect_terminals")}
    def upstream_roots(self):
        if self._metadata is None: self._metadata = _metadata_from_file(self.source_path)
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
