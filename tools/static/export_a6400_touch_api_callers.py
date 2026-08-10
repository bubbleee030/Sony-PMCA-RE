"""Read-only α6400 inventory of bounded direct touch API callers."""
from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
from pmca.analysis.touch_api_callers import (
    ANALYSIS_LOAD_BIAS, API_BINDINGS, CALLERS, PRIOR_UI_GRAPH_SHA256, ROOTS,
    VIEW_UNIFIED2_SHA256, VIEW_UNIFIED2_SIZE, normalize_touch_api_callers_export,
)

SOURCE = ROOT / ".artifacts" / "decrypted" / "a6400-tw-v2.00" / "ma1co" / "firmware.tar_unpacked" / "0700_part_image" / "dev" / "nflasha15_unpacked" / "lib" / "viewUnified2.so"
PRIOR_REPORT = ROOT / "analysis" / "a6400-ui-dispatch-boundary.json"
PRIOR_RAW = ROOT / ".artifacts" / "ui-trace" / "a6400-v2.00" / "raw-ui-dispatch.json"
OUTPUT_ROOT = ROOT / ".artifacts" / "touch-api-caller-trace" / "a6400-v2.00"
OUTPUT_NAME = "raw-touch-api-callers.json"
ARTIFACT_BASE = ROOT / ".artifacts"
ROOT_ADDRESSES = [0x22355E, 0x1BB41C, 0x1BB2D2, 0x1C1E76]
SYMBOLS = {
    "force-release": "_ZN12InputService14forceReleaseTpEv",
    "enable-area": "_ZN12InputService15setTpEnableAreaEiiii",
    "focus-coordinate": "_ZN12CmnViewFocus40getNewCoordinatesForFocusPointOnTouchPadEiiiiRiS0_",
    "resource-settings": "_ZN12InputService21setResourceTpSettingsEiii",
    "disable-area": "_ZN23CmnViewTPAreaEnableUtil26setTouchPadEnableAreaToOffEv",
    "enable-evf-area": "_ZN23CmnViewTPAreaEnableUtil27setTouchPadEnabAreaForEvfOnEv",
}


def _deps():
    try:
        from capstone import CS_ARCH_ARM, CS_GRP_CALL, CS_GRP_JUMP, CS_MODE_ARM, CS_MODE_THUMB, CS_OP_IMM, Cs
        from elftools.elf.elffile import ELFFile
    except ImportError:
        for package_root in (ROOT / ".artifacts" / "python-packages", ROOT / ".artifacts" / "pydeps_vlf"):
            if package_root.is_dir(): sys.path.insert(0, str(package_root))
        try:
            from capstone import CS_ARCH_ARM, CS_GRP_CALL, CS_GRP_JUMP, CS_MODE_ARM, CS_MODE_THUMB, CS_OP_IMM, Cs
            from elftools.elf.elffile import ELFFile
        except ImportError as exc:
            raise RuntimeError("local Capstone and pyelftools are required") from exc
    return CS_ARCH_ARM, CS_GRP_CALL, CS_GRP_JUMP, CS_MODE_ARM, CS_MODE_THUMB, CS_OP_IMM, Cs, ELFFile


def capstone_available():
    try: _deps()
    except RuntimeError: return False
    return True


def _section(elf, name):
    section = elf.get_section_by_name(name)
    if section is None: raise RuntimeError("required ELF section is absent")
    return section


def _load_mappings(elf):
    return [(segment["p_vaddr"], segment["p_vaddr"] + segment["p_filesz"], segment["p_offset"]) for segment in elf.iter_segments() if segment["p_type"] == "PT_LOAD"]


def _bytes_at_va(binary, mappings, address, length):
    matches = [offset + address - start for start, end, offset in mappings if start <= address and address + length <= end]
    if len(matches) != 1: raise RuntimeError("requested virtual range does not map exactly once")
    return binary[matches[0]:matches[0] + length]


def _exidx_ranges(elf):
    section = _section(elf, ".ARM.exidx"); data = section.data(); entries = []
    for index in range(section["sh_size"] // 8):
        address = section["sh_addr"] + index * 8; value = int.from_bytes(data[index * 8:index * 8 + 4], "little")
        offset = value & 0x7fffffff
        if offset & 0x40000000: offset -= 0x80000000
        entries.append(address + offset)
    entries.sort()
    return [(start, entries[index + 1] if index + 1 < len(entries) else None) for index, start in enumerate(entries)]


def _direct_edges(binary, mappings, owner, end, decoder, call_group, jump_group, immediate):
    instructions = list(decoder.disasm(_bytes_at_va(binary, mappings, owner, end - owner), owner | 1))
    if sum(instruction.size for instruction in instructions) != end - owner: return None
    result = []
    for instruction in instructions:
        if instruction.group(call_group) or instruction.group(jump_group):
            for operand in instruction.operands:
                if operand.type == immediate: result.append((instruction.address & ~1, operand.imm & ~1))
    return result


def _plt_bindings(elf, binary, mappings):
    arch, _call, _jump, arm_mode, _thumb, _imm, Cs, _ELF = _deps()
    decoder = Cs(arch, arm_mode); decoder.detail = True; plt = _section(elf, ".plt")
    stubs = {}
    for address in range(plt["sh_addr"], plt["sh_addr"] + plt["sh_size"] - 11, 4):
        instructions = list(decoder.disasm(_bytes_at_va(binary, mappings, address, 12), address))
        if len(instructions) != 3 or [item.mnemonic for item in instructions] != ["add", "add", "ldr"]: continue
        try: got = address + 8 + instructions[0].operands[2].imm + instructions[1].operands[2].imm + instructions[2].operands[1].mem.disp
        except (AttributeError, IndexError): continue
        if got in stubs: raise RuntimeError("PLT GOT address has multiple stubs")
        stubs[got] = address
    dynsym, relplt = _section(elf, ".dynsym"), _section(elf, ".rel.plt")
    relocations = list(relplt.iter_relocations()); result = []
    for expected in API_BINDINGS:
        index = expected["relocation_index"]
        if index >= len(relocations): raise RuntimeError("required JUMP_SLOT index is absent")
        relocation = relocations[index]; candidate = dict(expected)
        if relocation.entry.r_offset != int(expected["got_address"], 16) or stubs.get(relocation.entry.r_offset) != int(expected["plt_address"], 16): raise RuntimeError("decoded PLT/GOT binding differs")
        if dynsym.get_symbol(relocation.entry.r_info_sym).name != SYMBOLS[expected["api"]]: raise RuntimeError("JUMP_SLOT symbol differs")
        result.append(candidate)
    if result != API_BINDINGS: raise RuntimeError("bounded PLT binding inventory differs")
    return result


def _prior_graph():
    report = json.loads(PRIOR_REPORT.read_text(encoding="utf-8"))
    if report.get("bounded_export_summary", {}).get("artifact_sha256") != PRIOR_UI_GRAPH_SHA256: raise RuntimeError("prior UI graph digest differs")
    document = json.loads(PRIOR_RAW.read_text(encoding="utf-8"))
    if document.get("program") != "viewUnified2.so" or document.get("sha256") != VIEW_UNIFIED2_SHA256 or document.get("image_size") != VIEW_UNIFIED2_SIZE or document.get("truncated") is not False: raise RuntimeError("prior raw UI traversal identity differs")
    edges = document.get("edges")
    if not isinstance(edges, list) or len(edges) != 2046: raise RuntimeError("prior UI traversal edge count differs")
    owners = {int(item["owner"], 16) for item in CALLERS}
    hits = sorted({edge.get("target") for edge in edges if edge.get("target") in owners})
    if hits: raise RuntimeError("prior UI traversal targets a known touch API caller")
    return {"edge_count": len(edges), "known_caller_owner_hits": []}


def _root_paths(direct, owners):
    starts = []
    for root in ROOT_ADDRESSES:
        address = root - ANALYSIS_LOAD_BIAS
        matches = [owner for owner, end in owners if end is not None and owner <= address < end]
        if len(matches) != 1: raise RuntimeError("root does not have one complete owner")
        starts.append(matches[0])
    owner_starts = {owner for owner, _end in owners}; targets = {int(item["owner"], 16) - ANALYSIS_LOAD_BIAS for item in CALLERS}
    results = []
    for name, start in zip(ROOTS, starts):
        seen = {start}; queue = [(start, 0)]; found = set()
        while queue:
            owner, depth = queue.pop(0)
            if depth == 32: continue
            for _site, target in direct.get(owner, []):
                if target not in owner_starts or target not in direct: continue
                if target in targets: found.add(target)
                if target not in seen: seen.add(target); queue.append((target, depth + 1))
        if found: raise RuntimeError("direct root traversal reaches a known touch API caller")
        results.append({"root": name, "depth_cap": 32, "known_caller_count": 23, "paths": []})
    return results


def build_raw_export(source=SOURCE):
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    if before != VIEW_UNIFIED2_SHA256 or source.stat().st_size != VIEW_UNIFIED2_SIZE: raise RuntimeError("pinned source identity differs")
    arch, call_group, jump_group, _arm, thumb, immediate, Cs, ELFFile = _deps()
    binary = source.read_bytes(); decoder = Cs(arch, thumb); decoder.detail = True
    with io.BytesIO(binary) as stream:
        elf = ELFFile(stream); mappings = _load_mappings(elf); owners = _exidx_ranges(elf); plt_bindings = _plt_bindings(elf, binary, mappings)
        direct = {}; incomplete = 0; terminal = 0
        for owner, end in owners:
            if end is None: terminal += 1; continue
            edges = _direct_edges(binary, mappings, owner, end, decoder, call_group, jump_group, immediate)
            if edges is None: incomplete += 1; continue
            direct[owner] = edges
        if (len(direct), incomplete, terminal) != (28869, 1593, 1): raise RuntimeError("complete owner accounting differs")
        target_to_api = {int(item["plt_address"], 16): item["api"] for item in plt_bindings}; classification = {item["api"]: item["classification"] for item in plt_bindings}
        callers = []
        for owner, edges in direct.items():
            end = next(item_end for item_owner, item_end in owners if item_owner == owner)
            for site, target in edges:
                if target in target_to_api:
                    api = target_to_api[target]
                    callers.append({"api": api, "classification": classification[api], "owner": hex(owner + ANALYSIS_LOAD_BIAS), "end": hex(end + ANALYSIS_LOAD_BIAS), "site": hex(site + ANALYSIS_LOAD_BIAS)})
        callers.sort(key=lambda item: (API_BINDINGS.index(next(binding for binding in API_BINDINGS if binding["api"] == item["api"])), int(item["site"], 16)))
        if callers != CALLERS: raise RuntimeError("complete-owner direct call sites differ")
        root_paths = _root_paths(direct, owners)
    document = {"program": "viewUnified2.so", "sha256": VIEW_UNIFIED2_SHA256, "file_size": VIEW_UNIFIED2_SIZE, "analysis_mode": {"read_only": True, "static_elf_metadata": True, "thumb_control_flow": True}, "program_changed": False, "prior_ui_graph_sha256": PRIOR_UI_GRAPH_SHA256, "api_bindings": plt_bindings, "callers": callers, "owner_accounting": {"complete_owner_count": len(direct), "incomplete_owner_count": incomplete, "terminal_unbounded_owner_count": terminal}, "root_paths": root_paths, "prior_traversal": _prior_graph(), "truncated": False}
    normalize_touch_api_callers_export(document)
    if hashlib.sha256(source.read_bytes()).hexdigest() != before: raise RuntimeError("source changed during read-only export")
    return document


def _literal_directory_under(root, artifact_base):
    base, root = Path(os.path.abspath(os.fspath(artifact_base))), Path(os.path.abspath(os.fspath(root)))
    if base.is_symlink() or not base.is_dir(): raise RuntimeError("artifact base is not a literal directory")
    try: resolved_base, resolved_root = base.resolve(strict=True), root.resolve(strict=True); root.relative_to(base)
    except (OSError, ValueError, RuntimeError) as exc: raise RuntimeError("approved output root is not contained") from exc
    if not root.is_dir() or root.is_symlink() or resolved_base != base or resolved_root != root: raise RuntimeError("approved output root escapes through a symlink")
    return root


def prepare_output_root(approved_root=OUTPUT_ROOT, artifact_base=ARTIFACT_BASE):
    base, root = Path(os.path.abspath(os.fspath(artifact_base))), Path(os.path.abspath(os.fspath(approved_root)))
    if base.is_symlink() or not base.is_dir() or base.resolve(strict=True) != base: raise RuntimeError("artifact base is not a literal directory")
    try: relative = root.relative_to(base)
    except ValueError as exc: raise RuntimeError("approved output root is not contained") from exc
    current = base
    for component in relative.parts:
        candidate = current / component
        if candidate.is_symlink() or (candidate.exists() and not candidate.is_dir()): raise RuntimeError("approved output root has a non-literal ancestor")
        if not candidate.exists(): candidate.mkdir()
        if candidate.is_symlink() or not candidate.is_dir() or candidate.resolve(strict=True) != candidate: raise RuntimeError("approved output root escapes through a symlink")
        current = candidate
    return _literal_directory_under(root, base)


def write_json_atomic(output, document, approved_root=OUTPUT_ROOT, artifact_base=ARTIFACT_BASE):
    output = Path(os.path.abspath(os.fspath(output))); root = _literal_directory_under(approved_root, artifact_base)
    if output.name != OUTPUT_NAME or output.parent != root or output.is_symlink() or (output.exists() and not output.is_file()): raise RuntimeError("output containment is invalid")
    descriptor, temporary = tempfile.mkstemp(dir=str(root), prefix=".touch-api-callers-", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(json.dumps(document, sort_keys=True, separators=(",", ":")).encode() + b"\n"); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, output)
    except BaseException:
        try: os.unlink(temporary)
        except FileNotFoundError: pass
        raise


if __name__ == "__main__":
    prepare_output_root(); write_json_atomic(OUTPUT_ROOT / OUTPUT_NAME, build_raw_export())
    print("TOUCH_API_CALLERS_EXPORT|apis=6|callers=23|direct_root_paths=0")
