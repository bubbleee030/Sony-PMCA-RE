"""Export only typed ELF evidence for α6400 UI layout virtual dispatch."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile

from pmca.analysis.ui_layout_vtable_interface import (
    EXPECTED_OWNER,
    EXPECTED_PRIOR_OWNER_REGISTRATION,
    EXPECTED_TABLES,
    TYPEINFO_SYMBOL,
    VIEW_UNIFIED7_SHA256,
    VIEW_UNIFIED7_SIZE,
)
from pmca.analysis.ui_factory_owner_registration import (
    normalize_ui_factory_owner_registration_export,
    summarize_ui_factory_owner_registration_export,
)


EXPECTED_PROGRAM = "viewUnified7.so"
EXPECTED_SHA256 = VIEW_UNIFIED7_SHA256
EXPECTED_IMAGE_SIZE = VIEW_UNIFIED7_SIZE
EXPECTED_ANALYSIS_MODE = {"engine": "elf-relocation-rtti", "read_only": True, "source_unchanged": True}
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_ROOT = REPOSITORY_ROOT / ".artifacts" / "ui-layout-vtable-interface-trace" / "a6400-v2.00"


def _require_dependencies():
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_GRP_CALL, CS_OP_IMM
        from elftools.elf.elffile import ELFFile
    except ImportError as error:
        raise RuntimeError("UI layout vtable export requires capstone and pyelftools") from error
    return Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_GRP_CALL, CS_OP_IMM, ELFFile


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _file_offset(elf, address, width):
    for segment in elf.iter_segments():
        if segment["p_type"] == "PT_LOAD" and segment["p_vaddr"] <= address and address + width <= segment["p_vaddr"] + segment["p_filesz"]:
            return segment["p_offset"] + address - segment["p_vaddr"]
    raise RuntimeError("typed relocation is not backed by PT_LOAD")


def _word(elf, blob, address):
    return int.from_bytes(blob[_file_offset(elf, address, 4):_file_offset(elf, address, 4) + 4], "little")


def _prel31(value, place):
    value &= 0x7FFFFFFF
    return place + (value - 0x80000000 if value & 0x40000000 else value)


def _cstring(elf, blob, address):
    offset = _file_offset(elf, address, 1)
    end = blob.find(b"\0", offset)
    if end < 0:
        raise RuntimeError("RTTI name is not null terminated")
    try:
        return blob[offset:end].decode("ascii")
    except UnicodeDecodeError as error:
        raise RuntimeError("RTTI name is not ASCII") from error


def _relocation_map(elf):
    rel = elf.get_section_by_name(".rel.dyn")
    if rel is None:
        raise RuntimeError(".rel.dyn is missing")
    symbols = elf.get_section(rel["sh_link"])
    if symbols is None:
        raise RuntimeError(".rel.dyn symbol table is missing")
    result = {}
    for item in rel.iter_relocations():
        address = item["r_offset"]
        if address in result:
            raise RuntimeError("duplicate typed relocation address")
        result[address] = {"type": item["r_info_type"], "symbol": symbols.get_symbol(item["r_info_sym"]).name}
    return result


def _relative_data(address, target, relocations, elf, blob):
    item = relocations.get(address)
    if item != {"type": 23, "symbol": ""} or _word(elf, blob, address) != target:
        raise RuntimeError("R_ARM_RELATIVE typed record differs")
    return {"address": address, "section_name": ".rel.dyn", "relocation_type": "R_ARM_RELATIVE", "evidence_kind": "relocation", "target": target}


def _relative_code(address, thumb_target, relocations, elf, blob):
    item = relocations.get(address)
    if item != {"type": 23, "symbol": ""} or _word(elf, blob, address) != thumb_target:
        raise RuntimeError("R_ARM_RELATIVE code record differs")
    return {"address": address, "section_name": ".rel.dyn", "relocation_type": "R_ARM_RELATIVE", "evidence_kind": "relocation", "thumb_target": thumb_target}


def _absolute(address, symbol, relocations):
    if relocations.get(address) != {"type": 2, "symbol": symbol}:
        raise RuntimeError("R_ARM_ABS32 typed record differs")
    return {"address": address, "section_name": ".rel.dyn", "relocation_type": "R_ARM_ABS32", "symbol": symbol, "evidence_kind": "relocation"}


def _metadata_from_file(source_path):
    Cs, arch, thumb_mode, call_group, imm_type, ELFFile = _require_dependencies()
    path = Path(source_path)
    before = _sha256(path)
    if path.name != EXPECTED_PROGRAM or before != EXPECTED_SHA256 or path.stat().st_size != EXPECTED_IMAGE_SIZE:
        raise RuntimeError("UI layout vtable source identity is not pinned")
    blob = path.read_bytes()
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        relocations = _relocation_map(elf)
        text = elf.get_section_by_name(".text")
        exidx = elf.get_section_by_name(".ARM.exidx")
        if text is None or exidx is None:
            raise RuntimeError("owner function metadata sections are missing")
        exidx_starts = sorted({_prel31(int.from_bytes(blob[offset:offset + 4], "little"), exidx["sh_addr"] + index * 8) for index, offset in enumerate(range(exidx["sh_offset"], exidx["sh_offset"] + exidx["sh_size"], 8))})
        owner_start = EXPECTED_OWNER["range"]["start"]
        owner_end = EXPECTED_OWNER["range"]["end"]
        if owner_start not in exidx_starts or exidx_starts.index(owner_start) + 1 >= len(exidx_starts) or exidx_starts[exidx_starts.index(owner_start) + 1] != owner_end:
            raise RuntimeError("forwarding owner is not the exact ARM.exidx function range")
        if not text["sh_addr"] <= owner_start < owner_end <= text["sh_addr"] + text["sh_size"]:
            raise RuntimeError("forwarding owner is outside .text")
        thumb = Cs(arch, thumb_mode)
        thumb.detail = True
        calls = []
        code = text.data()[owner_start - text["sh_addr"]:owner_end - text["sh_addr"]]
        for instruction in thumb.disasm(code, owner_start):
            if instruction.id and instruction.group(call_group) and instruction.operands and instruction.operands[0].type == imm_type:
                calls.append({"caller": owner_start, "site": instruction.address, "target": instruction.operands[0].imm & ~1, "kind": "direct"})
        if EXPECTED_OWNER["forwarding_edge"] not in calls:
            raise RuntimeError("forwarding owner edge is not exact")
        tables = []
        headers = []
        for expected in EXPECTED_TABLES:
            name, rtti, vtable = expected["class_name"], expected["rtti"], expected["vtable"]
            header = vtable["header"]
            address_point = vtable["address_point"]
            if address_point != header + 8 or _word(elf, blob, header) != 0:
                raise RuntimeError("vtable header is not a typed Itanium address point")
            header_relocation = _relative_data(header + 4, rtti["address"], relocations, elf, blob)
            typeinfo = _absolute(rtti["address"], TYPEINFO_SYMBOL, relocations)
            name_relocation = _relative_data(rtti["address"] + 4, _word(elf, blob, rtti["address"] + 4), relocations, elf, blob)
            if _cstring(elf, blob, name_relocation["target"]) != name:
                raise RuntimeError("RTTI class name is not exact")
            slots = []
            for expected_slot in vtable["slots"]:
                address = expected_slot["address"]
                if address != address_point + expected_slot["index"] * 4:
                    raise RuntimeError("vtable slot is not address-point relative")
                expected_relocation = expected_slot["relocation"]
                if expected_relocation["relocation_type"] == "R_ARM_RELATIVE":
                    relocation = _relative_code(address, expected_relocation["thumb_target"], relocations, elf, blob)
                    slot = {"index": expected_slot["index"], "address": address, "relocation": relocation, "normalized_owner": expected_relocation["thumb_target"] & ~1}
                else:
                    relocation = _absolute(address, expected_relocation["symbol"], relocations)
                    slot = {"index": expected_slot["index"], "address": address, "relocation": relocation}
                slots.append(slot)
            tables.append({"class_name": name, "rtti": {"address": rtti["address"], "class_typeinfo_relocation": typeinfo, "name_relocation": name_relocation}, "vtable": {"header": header, "address_point": address_point, "end": vtable["end"], "rtti_relocation": header_relocation, "slots": slots}})
            headers.append(header)
        for index, table in enumerate(tables):
            candidates = [other["vtable"]["header"] for other in tables[index + 1:]] + [table["rtti"]["address"]]
            if table["vtable"]["end"] != min(item for item in candidates if item > table["vtable"]["header"]):
                raise RuntimeError("vtable end is not reconstructed from typed boundary evidence")
        if tuple(tables) != EXPECTED_TABLES:
            raise RuntimeError("UI layout vtable metadata differs from exact result")
    if _sha256(path) != before:
        raise RuntimeError("UI layout vtable source changed during read-only export")
    return {"owner": EXPECTED_OWNER, "tables": tuple(tables)}


def _prior_owner_registration_from_file(prior_path):
    path = Path(prior_path)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("prior owner-registration evidence must be a regular file")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError("prior owner-registration evidence is not valid JSON") from error
    normalize_ui_factory_owner_registration_export(document)
    digest = summarize_ui_factory_owner_registration_export(document)["canonical_export_sha256"]
    evidence = {"analysis_contract": "ui_factory_owner_registration", "canonical_export_sha256": digest}
    if evidence != EXPECTED_PRIOR_OWNER_REGISTRATION:
        raise RuntimeError("prior owner-registration evidence digest is not pinned")
    return evidence


def build_raw_export(adapter):
    if adapter.program_name() != EXPECTED_PROGRAM or adapter.program_sha256() != EXPECTED_SHA256 or adapter.program_size() != EXPECTED_IMAGE_SIZE:
        raise RuntimeError("UI layout vtable adapter source identity is invalid")
    if adapter.analysis_mode() != EXPECTED_ANALYSIS_MODE or adapter.owner_metadata() != EXPECTED_OWNER or adapter.prior_owner_registration() != EXPECTED_PRIOR_OWNER_REGISTRATION or adapter.table_metadata() != EXPECTED_TABLES:
        raise RuntimeError("UI layout vtable metadata differs from exact typed result")
    return {"schema_version": 1, "program": EXPECTED_PROGRAM, "sha256": EXPECTED_SHA256, "image_size": EXPECTED_IMAGE_SIZE, "analysis_mode": dict(EXPECTED_ANALYSIS_MODE), "prior_owner_registration": dict(EXPECTED_PRIOR_OWNER_REGISTRATION), "owner": json.loads(json.dumps(EXPECTED_OWNER)), "tables": [json.loads(json.dumps(item)) for item in EXPECTED_TABLES], "truncated": False}


class FileAdapter:
    def __init__(self, source_path, prior_path):
        self.source_path = Path(source_path)
        self.prior_path = Path(prior_path)
        self._metadata = None
        self._prior = None
    def program_name(self): return self.source_path.name
    def program_sha256(self): return _sha256(self.source_path)
    def program_size(self): return self.source_path.stat().st_size
    def analysis_mode(self): return dict(EXPECTED_ANALYSIS_MODE)
    def _read(self):
        if self._metadata is None: self._metadata = _metadata_from_file(self.source_path)
        return self._metadata
    def owner_metadata(self): return self._read()["owner"]
    def table_metadata(self): return self._read()["tables"]
    def prior_owner_registration(self):
        if self._prior is None: self._prior = _prior_owner_registration_from_file(self.prior_path)
        return self._prior


def write_json_atomic(output_path, document):
    output = Path(output_path)
    root_literal = Path(OUTPUT_ROOT).absolute()
    root = Path(OUTPUT_ROOT).resolve(strict=True)
    if root != root_literal or root.is_symlink():
        raise RuntimeError("UI layout vtable output root must not be a symlink")
    expected_output = root / "raw-ui-layout-vtable-interface.json"
    if Path(os.path.abspath(output)) != expected_output or output.parent.resolve(strict=True) != root or output.is_symlink() or (output.exists() and not output.is_file()):
        raise RuntimeError("UI layout vtable output is outside approved artifact root")
    handle, temporary = tempfile.mkstemp(dir=str(root), prefix=".ui-layout-vtable-", suffix=".tmp")
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
    if len(args) != 3: raise SystemExit("usage: <source.so> <prior-owner-registration.json> <output.json>")
    if Path(os.path.abspath(args[2])) != Path(os.path.abspath(OUTPUT_ROOT / "raw-ui-layout-vtable-interface.json")):
        raise RuntimeError("UI layout vtable main output is not the pinned artifact path")
    document = build_raw_export(FileAdapter(args[0], args[1]))
    write_json_atomic(args[2], document)
    print("UI_LAYOUT_VTABLE_INTERFACE_EXPORT|tables=5|slot_34_owner=5|selector=0|touch=0")


if __name__ == "__main__": main()
