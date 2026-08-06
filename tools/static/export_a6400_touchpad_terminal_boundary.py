"""Read-only, deterministic α6400 touchpad terminal-boundary exporter."""
from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from pmca.analysis.touchpad_terminal_boundary import (
    INTERNAL_EDGES, OWNERS, PLT_BINDINGS, PRIOR_UI_GRAPH_SHA256, VERIFIED_PATH_EDGES,
    VIEW_UNIFIED2_SHA256, VIEW_UNIFIED2_SIZE, normalize_touchpad_terminal_export,
)

SOURCE = ROOT / ".artifacts" / "decrypted" / "a6400-tw-v2.00" / "ma1co" / "firmware.tar_unpacked" / "0700_part_image" / "dev" / "nflasha15_unpacked" / "lib" / "viewUnified2.so"
PRIOR_GRAPH = ROOT / "analysis" / "a6400-ui-dispatch-boundary.json"
OUTPUT_ROOT = ROOT / ".artifacts" / "touchpad-terminal-boundary-trace" / "a6400-v2.00"
OUTPUT_NAME = "raw-touchpad-terminal-boundary.json"
ARTIFACT_BASE = ROOT / ".artifacts"
ANALYSIS_LOAD_BIAS = 0x10000


def _deps():
    try:
        from capstone import CS_ARCH_ARM, CS_GRP_CALL, CS_GRP_JUMP, CS_MODE_THUMB, CS_OP_IMM, CS_OP_MEM, Cs
        from capstone.arm import ARM_REG_PC
        from elftools.elf.elffile import ELFFile
    except ImportError:
        for package_root in (ROOT / ".artifacts" / "python-packages", ROOT / ".artifacts" / "pydeps_vlf"):
            if package_root.is_dir(): sys.path.insert(0, str(package_root))
        try:
            from capstone import CS_ARCH_ARM, CS_GRP_CALL, CS_GRP_JUMP, CS_MODE_THUMB, CS_OP_IMM, CS_OP_MEM, Cs
            from capstone.arm import ARM_REG_PC
            from elftools.elf.elffile import ELFFile
        except ImportError as exc:
            raise RuntimeError("local Capstone and pyelftools are required") from exc
    return CS_ARCH_ARM, CS_GRP_CALL, CS_GRP_JUMP, CS_MODE_THUMB, CS_OP_IMM, CS_OP_MEM, ARM_REG_PC, Cs, ELFFile


def capstone_available():
    try: _deps()
    except RuntimeError: return False
    return True


def _section(elf, name):
    result = elf.get_section_by_name(name)
    if result is None: raise RuntimeError("required ELF section is absent")
    return result


def _exidx_ranges(elf):
    section = _section(elf, ".ARM.exidx")
    data = section.data()
    entries = []
    for index in range(section["sh_size"] // 8):
        address = section["sh_addr"] + index * 8
        # pyelftools exposes raw entry values only inconsistently; read it directly.
        raw = data[index * 8:index * 8 + 4]
        value = int.from_bytes(raw, "little")
        offset = value & 0x7fffffff
        if offset & 0x40000000: offset -= 0x80000000
        entries.append((address + offset, address))
    entries.sort()
    return [(start, entries[pos + 1][0] if pos + 1 < len(entries) else None) for pos, (start, _address) in enumerate(entries)]


def _range_for(ranges, owner):
    matches = [end for start, end in ranges if start == owner]
    if len(matches) != 1 or matches[0] is None: raise RuntimeError("owner lacks an exact exidx range")
    return matches[0]


def _load_mappings(elf):
    return [(segment["p_vaddr"], segment["p_vaddr"] + segment["p_filesz"], segment["p_offset"]) for segment in elf.iter_segments() if segment["p_type"] == "PT_LOAD"]


def _u32_at_va(binary, mappings, address):
    """Read an addend through precomputed PT_LOAD mappings, not segment objects."""
    matches = [file_offset + address - start for start, end, file_offset in mappings if start <= address and address + 4 <= end]
    if len(matches) != 1: raise RuntimeError("relocation addend does not map to one file offset")
    return int.from_bytes(binary[matches[0]:matches[0] + 4], "little")


def _bytes_at_va(binary, mappings, address, length):
    matches = [file_offset + address - start for start, end, file_offset in mappings if start <= address and address + length <= end]
    if len(matches) != 1: raise RuntimeError("range does not map to one file offset")
    return binary[matches[0]:matches[0] + length]


def _direct_edges(binary, mappings, owner, end):
    CS_ARCH_ARM, CS_GRP_CALL, CS_GRP_JUMP, CS_MODE_THUMB, CS_OP_IMM, _CS_OP_MEM, _ARM_REG_PC, Cs, _ELFFile = _deps()
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB); decoder.detail = True
    instructions = list(decoder.disasm(_bytes_at_va(binary, mappings, owner, end-owner), owner | 1))
    if sum(item.size for item in instructions) != end-owner: raise RuntimeError("owner does not decode completely")
    edges = []
    for item in instructions:
        if item.group(CS_GRP_CALL) or item.group(CS_GRP_JUMP):
            for operand in item.operands:
                if operand.type == CS_OP_IMM: edges.append((item.address & ~1, operand.imm & ~1))
    return edges


def _prior_digest():
    document = json.loads(PRIOR_GRAPH.read_text(encoding="utf-8"))
    digest = document.get("bounded_export_summary", {}).get("artifact_sha256")
    if digest != PRIOR_UI_GRAPH_SHA256: raise RuntimeError("prior UI graph digest differs")
    return digest


def _plt_bindings(elf, binary, mappings):
    dynsym, relplt = _section(elf, ".dynsym"), _section(elf, ".rel.plt")
    expected_by_index = {item["relocation_index"]: item for item in PLT_BINDINGS}
    result = []
    CS_ARCH_ARM, _CS_GRP_CALL, _CS_GRP_JUMP, _CS_MODE_THUMB, _CS_OP_IMM, CS_OP_MEM, ARM_REG_PC, Cs, _ELFFile = _deps()
    from capstone import CS_MODE_ARM
    decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM); decoder.detail = True
    # ARM PLT stubs are decoded, rather than relying only on their layout.
    plt = _section(elf, ".plt")
    relocation_by_got = {relocation.entry.r_offset: (index, relocation) for index, relocation in enumerate(relplt.iter_relocations())}
    if len(relocation_by_got) != relplt.num_relocations(): raise RuntimeError("PLT GOT entries are duplicated")
    decoded = {}
    for plt_address in range(plt["sh_addr"], plt["sh_addr"] + plt["sh_size"] - 11, 4):
        instructions = list(decoder.disasm(_bytes_at_va(binary, mappings, plt_address, 12), plt_address))
        if len(instructions) != 3 or [item.mnemonic for item in instructions] != ["add", "add", "ldr"]:
            continue
        aliases = {
            "InputService::forceReleaseTp": "_ZN12InputService14forceReleaseTpEv",
            "InputService::setTpEnableArea": "_ZN12InputService15setTpEnableAreaEiiii",
            "CmnViewTPAreaEnableUtil::setTouchPadEnableAreaToOff": "_ZN23CmnViewTPAreaEnableUtil26setTouchPadEnableAreaToOffEv",
            "CmnViewTPAreaEnableUtil::setTouchPadEnabAreaForEvfOn": "_ZN23CmnViewTPAreaEnableUtil27setTouchPadEnabAreaForEvfOnEv",
        }
        try:
            got = plt_address + 8 + instructions[0].operands[2].imm + instructions[1].operands[2].imm
            if instructions[2].operands[1].type != CS_OP_MEM:
                continue
            got += instructions[2].operands[1].mem.disp
        except (AttributeError, IndexError) as exc:
            continue
        if got in decoded: raise RuntimeError("PLT GOT address has multiple decoded stubs")
        decoded[got] = plt_address
    for index, expected in expected_by_index.items():
        relocation_index, relocation = relocation_by_got.get(int(expected["got_address"], 16), (None, None))
        if relocation is None: raise RuntimeError("required PLT GOT entry is absent")
        plt_address = decoded.get(relocation.entry.r_offset)
        if plt_address is None: raise RuntimeError("required PLT stub was not decoded")
        symbol = dynsym.get_symbol(relocation.entry.r_info_sym).name
        aliases = {
            "InputService::forceReleaseTp": "_ZN12InputService14forceReleaseTpEv",
            "InputService::setTpEnableArea": "_ZN12InputService15setTpEnableAreaEiiii",
            "CmnViewTPAreaEnableUtil::setTouchPadEnableAreaToOff": "_ZN23CmnViewTPAreaEnableUtil26setTouchPadEnableAreaToOffEv",
            "CmnViewTPAreaEnableUtil::setTouchPadEnabAreaForEvfOn": "_ZN23CmnViewTPAreaEnableUtil27setTouchPadEnabAreaForEvfOnEv",
        }
        candidate = {"relocation_index": relocation_index, "got_address": hex(relocation.entry.r_offset), "plt_address": hex(plt_address), "symbol": expected["symbol"]}
        if symbol != aliases[expected["symbol"]] or candidate != expected: raise RuntimeError("PLT binding differs")
        result.append(candidate)
    if result != PLT_BINDINGS: raise RuntimeError("required PLT binding is absent")
    return result


def build_raw_export(source=SOURCE):
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    if before != VIEW_UNIFIED2_SHA256 or source.stat().st_size != VIEW_UNIFIED2_SIZE: raise RuntimeError("pinned source identity differs")
    _CS_ARCH_ARM, _CS_GRP_CALL, _CS_GRP_JUMP, _CS_MODE_THUMB, _CS_OP_IMM, _CS_OP_MEM, _ARM_REG_PC, _Cs, ELFFile = _deps()
    binary = source.read_bytes()
    with io.BytesIO(binary) as stream:
        elf = ELFFile(stream)
        mappings = _load_mappings(elf)
        ranges = _exidx_ranges(elf)
        observed_owners = [{"owner": hex(owner), "end": hex(_range_for(ranges, owner))} for owner in (0x162608, 0x41b244, 0x41add8, 0x2b3f7c)]
        if observed_owners != OWNERS: raise RuntimeError("exidx owner ranges differ")
        direct = {int(item["owner"], 16): _direct_edges(binary, mappings, int(item["owner"], 16), int(item["end"], 16)) for item in OWNERS}
        for edge in VERIFIED_PATH_EDGES:
            owner = int(edge["owner"], 16) - ANALYSIS_LOAD_BIAS
            end = _range_for(ranges, owner)
            observed = {(site + ANALYSIS_LOAD_BIAS, target + ANALYSIS_LOAD_BIAS) for site, target in _direct_edges(binary, mappings, owner, end)}
            if (int(edge["site"], 16), int(edge["target"], 16)) not in observed: raise RuntimeError("verified path edge is not direct")
        for edge in INTERNAL_EDGES:
            observed = set(direct[int(edge["owner"], 16)])
            if (int(edge["site"], 16), int(edge["target"], 16)) not in observed: raise RuntimeError("internal edge differs")
        callee_calls = len(direct[0x2b3f7c])
        rel_dyn = _section(elf, ".rel.dyn")
        dynamic_relocations = list(rel_dyn.iter_relocations())
        if len(dynamic_relocations) != 137966: raise RuntimeError("dynamic relocation count differs")
        reverse = []
        owner_values = {int(item["owner"], 16) for item in OWNERS}
        for relocation in dynamic_relocations:
            if relocation.entry.r_info_type == 23:
                addend = _u32_at_va(binary, mappings, relocation.entry.r_offset) & ~1
                if addend in owner_values: reverse.append(addend)
        if reverse: raise RuntimeError("reverse relocation scan differs")
        dynsym = _section(elf, ".dynsym")
        for owner in owner_values:
            end = _range_for(ranges, owner)
            if any(symbol["st_value"] & ~1 in range(owner, end) for symbol in dynsym.iter_symbols() if symbol.name): raise RuntimeError("owner has dynamic symbol identity")
            if any(owner <= relocation.entry.r_offset < end for relocation in dynamic_relocations): raise RuntimeError("owner has dynamic relocation")
        plt_bindings = _plt_bindings(elf, binary, mappings)
        targets = {int(item["plt_address"], 16) for item in plt_bindings}
        if any(target in targets for edges in direct.values() for _site, target in edges): raise RuntimeError("owner directly calls bounded touch API")
    document = {"program": "viewUnified2.so", "sha256": VIEW_UNIFIED2_SHA256, "file_size": VIEW_UNIFIED2_SIZE,
        "analysis_mode": {"read_only": True, "static_elf_metadata": True, "thumb_control_flow": True}, "program_changed": False,
        "prior_ui_graph_sha256": _prior_digest(), "verified_path_edges": VERIFIED_PATH_EDGES, "owners": observed_owners,
        "owner_dynamic_relocations": [], "owner_dynamic_symbols": [], "internal_edges": INTERNAL_EDGES,
        "callee_direct_call_count": callee_calls, "reverse_reference_scan": {"rel_dyn_count": rel_dyn.num_relocations(), "matching_relative_addends": []},
        "plt_bindings": plt_bindings, "owner_direct_plt_calls": [], "truncated": False}
    normalize_touchpad_terminal_export(document)
    if hashlib.sha256(source.read_bytes()).hexdigest() != before: raise RuntimeError("source changed during read-only export")
    return document


def _literal_directory_under(root, artifact_base):
    """Require a literal directory beneath a literal, fixed artifact base."""
    literal_base = Path(os.path.abspath(os.fspath(artifact_base)))
    literal_root = Path(os.path.abspath(os.fspath(root)))
    if literal_base.is_symlink() or not literal_base.is_dir():
        raise RuntimeError("artifact base is not a literal directory")
    try:
        literal_root.relative_to(literal_base)
        resolved_base = literal_base.resolve(strict=True)
        resolved_root = literal_root.resolve(strict=True)
    except (OSError, ValueError, RuntimeError) as exc:
        raise RuntimeError("approved output root is not contained") from exc
    if not literal_root.is_dir() or literal_root.is_symlink() or resolved_base != literal_base or resolved_root != literal_root:
        raise RuntimeError("approved output root escapes through a symlink")
    return literal_root


def prepare_output_root(approved_root=OUTPUT_ROOT, artifact_base=ARTIFACT_BASE):
    """Create only missing literal path components beneath the trusted artifact base."""
    literal_base = Path(os.path.abspath(os.fspath(artifact_base)))
    literal_root = Path(os.path.abspath(os.fspath(approved_root)))
    if literal_base.is_symlink() or not literal_base.is_dir() or literal_base.resolve(strict=True) != literal_base:
        raise RuntimeError("artifact base is not a literal directory")
    try:
        relative = literal_root.relative_to(literal_base)
    except ValueError as exc:
        raise RuntimeError("approved output root is not contained") from exc
    current = literal_base
    for component in relative.parts:
        candidate = current / component
        if candidate.is_symlink() or (candidate.exists() and not candidate.is_dir()):
            raise RuntimeError("approved output root has a non-literal ancestor")
        if not candidate.exists():
            candidate.mkdir()
        if candidate.is_symlink() or not candidate.is_dir() or candidate.resolve(strict=True) != candidate:
            raise RuntimeError("approved output root escapes through a symlink")
        current = candidate
    return _literal_directory_under(literal_root, literal_base)


def write_json_atomic(output, document, approved_root=OUTPUT_ROOT, artifact_base=ARTIFACT_BASE):
    output = Path(os.path.abspath(os.fspath(output)))
    root = _literal_directory_under(approved_root, artifact_base)
    if output.name != OUTPUT_NAME or output.parent != root or output.is_symlink() or (output.exists() and not output.is_file()):
        raise RuntimeError("output containment is invalid")
    descriptor, temporary = tempfile.mkstemp(dir=str(root), prefix=".touchpad-terminal-", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(json.dumps(document, sort_keys=True, separators=(",", ":")).encode() + b"\n"); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, output)
    except BaseException:
        try: os.unlink(temporary)
        except FileNotFoundError: pass
        raise


if __name__ == "__main__":
    prepare_output_root()
    write_json_atomic(OUTPUT_ROOT / OUTPUT_NAME, build_raw_export())
    print("TOUCHPAD_TERMINAL_BOUNDARY_EXPORT|owners=4|direct_touch_api_calls=0|reverse_refs=0")
