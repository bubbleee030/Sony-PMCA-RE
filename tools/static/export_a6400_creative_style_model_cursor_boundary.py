"""Read-only α6400 generic setting-node model/cursor boundary exporter."""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pmca.analysis.creative_style_model_cursor_boundary import (
    BELT_WIDGET_UPDATE,
    EXPECTED_EXPORT,
    FIELD_ACCESSES,
    LOCAL_TERMINAL_ROUTINES,
    METHODS,
    MODEL_CURSOR_BOUNDARY,
    SET_DISP_STATE_BINDING,
    VIEW_UNIFIED2_SHA256,
    VIEW_UNIFIED2_SIZE,
    VIRTUAL_CALLS,
    normalize_creative_style_model_cursor_boundary_export,
)
from tools.static.export_a6400_creative_style_definition_registration import (
    _load_mappings,
)


SOURCE = ROOT / ".artifacts" / "decrypted" / "a6400-tw-v2.00" / "ma1co" / "firmware.tar_unpacked" / "0700_part_image" / "dev" / "nflasha15_unpacked" / "lib" / "viewUnified2.so"
ARTIFACT_BASE = ROOT / ".artifacts"
OUTPUT_ROOT = ARTIFACT_BASE / "creative-style-model-cursor-boundary" / "a6400-v2.00"
OUTPUT_NAME = "model-cursor-boundary-export.json"


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _dependencies():
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_GRP_CALL, CS_GRP_JUMP, CS_MODE_THUMB
        from capstone.arm import (
            ARM_INS_LDR, ARM_INS_STR, ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG,
            ARM_REG_R0, ARM_REG_R1, ARM_REG_R2, ARM_REG_R3,
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


def _at(blob, mappings, address, length):
    offsets = [
        offset + address - start
        for start, end, offset in mappings
        if start <= address and address + length <= end
    ]
    if len(offsets) != 1:
        raise RuntimeError("virtual address does not map exactly once")
    return blob[offsets[0] : offsets[0] + length]


def _ror32(value, amount):
    amount &= 31
    return value if amount == 0 else ((value >> amount) | (value << (32 - amount))) & 0xFFFFFFFF


def _arm_immediate(word):
    return _ror32(word & 0xFF, ((word >> 8) & 0xF) * 2)


def _decoded_plt_addresses_exact(elf, blob, mappings):
    """Decode ARM add/add/ldr veneers, including rotated immediates."""
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
    from capstone.arm import (
        ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC, ARM_REG_R12,
    )

    plt = elf.get_section_by_name(".plt")
    if plt is None:
        raise RuntimeError("PLT section is unavailable")
    decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    decoder.detail = True
    decoded = {}
    for address in range(plt["sh_addr"], plt["sh_addr"] + plt["sh_size"] - 11, 4):
        chunk = _at(blob, mappings, address, 12)
        instructions = list(decoder.disasm(chunk, address))
        if len(instructions) != 3 or [item.mnemonic for item in instructions] != ["add", "add", "ldr"]:
            continue
        first_ops, second_ops, third_ops = [item.operands for item in instructions]
        if (
            len(first_ops) < 3
            or [operand.type for operand in first_ops[:3]] != [ARM_OP_REG, ARM_OP_REG, ARM_OP_IMM]
            or any(operand.type != ARM_OP_IMM for operand in first_ops[3:])
            or first_ops[0].reg != ARM_REG_R12
            or first_ops[1].reg != ARM_REG_PC
            or len(second_ops) < 3
            or [operand.type for operand in second_ops[:3]] != [ARM_OP_REG, ARM_OP_REG, ARM_OP_IMM]
            or any(operand.type != ARM_OP_IMM for operand in second_ops[3:])
            or second_ops[0].reg != ARM_REG_R12
            or second_ops[1].reg != ARM_REG_R12
            or len(third_ops) != 2
            or third_ops[0].type != ARM_OP_REG
            or third_ops[0].reg != ARM_REG_PC
            or third_ops[1].type != ARM_OP_MEM
            or third_ops[1].mem.base != ARM_REG_R12
            or third_ops[1].mem.index != 0
        ):
            continue
        first, second, third = struct.unpack("<III", chunk)
        load_offset = third & 0xFFF
        if not (third & (1 << 23)):
            load_offset = -load_offset
        got = (address + 8 + _arm_immediate(first) + _arm_immediate(second) + load_offset) & 0xFFFFFFFF
        if got in decoded:
            raise RuntimeError("multiple PLT veneers map to one GOT entry")
        decoded[got] = address
    return decoded


def _decode_methods(blob, mappings, dynsym, deps):
    decoder = deps["Cs"](deps["arch"], deps["mode"])
    decoder.detail = True
    symbols = list(dynsym.iter_symbols())
    records = []
    decoded = {}
    for expected in METHODS:
        symbol = symbols[expected["symbol_index"]]
        record = {
            "role": expected["role"],
            "symbol_index": expected["symbol_index"],
            "symbol": symbol.name,
            "owner": symbol["st_value"] & ~1,
            "size": symbol["st_size"],
        }
        if record != expected or symbol["st_shndx"] == "SHN_UNDEF" or symbol["st_info"]["type"] != "STT_FUNC":
            raise RuntimeError("setting-node utility method identity differs")
        items = list(decoder.disasm(_at(blob, mappings, record["owner"], record["size"]), record["owner"]))
        if not items or (items[0].address & ~1) != record["owner"] or items[-1].address + items[-1].size != record["owner"] + record["size"]:
            raise RuntimeError("setting-node utility method decode is incomplete")
        records.append(record)
        decoded[record["role"]] = items
    return records, decoded, symbols


def _instruction_maps(decoded):
    return {
        role: {item.address & ~1: item for item in items}
        for role, items in decoded.items()
    }


def _field_accesses(decoded, deps):
    by_role = _instruction_maps(decoded)
    result = []
    for expected in FIELD_ACCESSES:
        accesses = []
        instructions = by_role[expected["method_role"]]
        for item_expected in expected["accesses"]:
            item = instructions.get(item_expected["site"])
            if item is None or item.id not in (deps["ldr"], deps["str"]) or len(item.operands) < 2 or item.operands[1].type != deps["mem"]:
                raise RuntimeError("utility field access instruction differs")
            memory = item.operands[1].mem
            record = {
                "site": item.address & ~1,
                "offset": memory.disp,
                "width": 4,
                "access": "read" if item.id == deps["ldr"] else "write",
            }
            if record != item_expected:
                raise RuntimeError("utility field access differs")
            accesses.append(record)
        result.append({"method_role": expected["method_role"], "accesses": accesses})
    if result != FIELD_ACCESSES:
        raise RuntimeError("utility field-access surface differs")
    return result


def _calls(decoded, deps):
    result = {}
    for role, items in decoded.items():
        calls = []
        for index, item in enumerate(items):
            if not item.group(deps["call_group"]):
                continue
            immediate = [operand.imm & ~1 for operand in item.operands if operand.type == deps["imm"]]
            registers = [operand.reg for operand in item.operands if operand.type == deps["reg"]]
            calls.append({
                "site": item.address & ~1,
                "target": immediate[0] if len(immediate) == 1 else None,
                "target_register": registers[0] if not immediate and len(registers) == 1 else None,
                "instruction_index": index,
            })
        result[role] = calls
    return result


def _plt_by_symbol(elf, blob, mappings):
    rel_plt = elf.get_section_by_name(".rel.plt")
    if rel_plt is None:
        raise RuntimeError("PLT relocations are unavailable")
    got_to_plt = _decoded_plt_addresses_exact(elf, blob, mappings)
    result = {}
    for relocation in rel_plt.iter_relocations():
        plt = got_to_plt.get(relocation["r_offset"])
        if plt is not None:
            result.setdefault(relocation["r_info_sym"], []).append(plt & ~1)
    return result


def _validate_plt_binding(elf, blob, mappings, dynsym, expected, include_owner=False):
    rel_plt = list(elf.get_section_by_name(".rel.plt").iter_relocations())
    relocation = rel_plt[expected["relocation_index"]]
    symbol = dynsym.get_symbol(relocation["r_info_sym"])
    record = {
        "symbol": symbol.name,
        "symbol_index": relocation["r_info_sym"],
        "symbol_defined": symbol["st_shndx"] != "SHN_UNDEF",
        "relocation_index": expected["relocation_index"],
        "got": relocation["r_offset"],
        "plt": _decoded_plt_addresses_exact(elf, blob, mappings).get(relocation["r_offset"]),
    }
    if include_owner:
        record.update({"defined_owner": symbol["st_value"] & ~1, "defined_size": symbol["st_size"]})
    if record != {key: expected[key] for key in record}:
        raise RuntimeError("named PLT binding differs")
    return record


def _call_at(calls, role, site):
    matches = [item for item in calls[role] if item["site"] == site]
    if len(matches) != 1:
        raise RuntimeError("expected utility call site differs")
    return matches[0]


def _direct_boundaries(calls, plt_by_symbol):
    named = []
    for expected in MODEL_CURSOR_BOUNDARY["set_value_to_model"]["named_lookup_calls"]:
        call = _call_at(calls, "set-value-to-model", expected["site"])
        if call["target"] not in plt_by_symbol.get(expected["symbol_index"], []):
            raise RuntimeError("named model lookup PLT binding differs")
        named.append(copy.deepcopy(expected))
    local = []
    for expected in MODEL_CURSOR_BOUNDARY["set_value_to_model"]["local_terminal_calls"]:
        call = _call_at(calls, "set-value-to-model", expected["site"])
        record = {"site": call["site"], "target": call["target"], "name_resolved": False}
        if record != expected:
            raise RuntimeError("local model terminal differs")
        local.append(record)
    move_targets = [item["target"] for item in calls["move-cursor"] if item["target"] is not None]
    if move_targets != MODEL_CURSOR_BOUNDARY["move_cursor_local_targets"]:
        raise RuntimeError("move-cursor target surface differs")
    belt_call = _call_at(calls, "update-belt-widget", BELT_WIDGET_UPDATE["site"])
    if belt_call["target"] != BELT_WIDGET_UPDATE["plt"]:
        raise RuntimeError("belt-widget update call differs")
    return named, local, move_targets


def _decode_range(blob, mappings, deps, start, end):
    decoder = deps["Cs"](deps["arch"], deps["mode"])
    decoder.detail = True
    items = list(decoder.disasm(_at(blob, mappings, start, end - start), start))
    if not items or (items[0].address & ~1) != start or items[-1].address + items[-1].size != end:
        raise RuntimeError("bounded helper decode is incomplete")
    return items


def _direct_targets(items, deps):
    result = []
    for item in items:
        if not item.group(deps["call_group"]):
            continue
        targets = [operand.imm & ~1 for operand in item.operands if operand.type == deps["imm"]]
        if targets:
            result.append({"site": item.address & ~1, "target": targets[0]})
    return result


def _virtual_cells(items, deps):
    result = []
    for index, item in enumerate(items):
        if not item.group(deps["call_group"]):
            continue
        registers = [operand.reg for operand in item.operands if operand.type == deps["reg"]]
        immediates = [operand.imm for operand in item.operands if operand.type == deps["imm"]]
        if immediates or len(registers) != 1:
            continue
        writer = _previous_writer(items, index, registers[0])
        if writer is None or writer.id != deps["ldr"] or len(writer.operands) < 2 or writer.operands[1].type != deps["mem"]:
            raise RuntimeError("bounded helper virtual target differs")
        result.append(writer.operands[1].mem.disp // 4)
    return list(dict.fromkeys(result))


def _local_terminal_routines(blob, mappings, deps, set_disp_binding):
    result = []
    for expected in LOCAL_TERMINAL_ROUTINES:
        items = _decode_range(blob, mappings, deps, expected["start"], expected["end"])
        calls = _direct_targets(items, deps)
        matching_sites = [item["site"] for item in calls if item["target"] == set_disp_binding["plt"]]
        if matching_sites != expected["named_call_sites"] or any(item["target"] != set_disp_binding["plt"] for item in calls):
            raise RuntimeError("widget display-state call surface differs")
        if _virtual_cells(items, deps) != expected["virtual_cells"]:
            raise RuntimeError("widget display-state virtual surface differs")
        result.append(copy.deepcopy(expected))
    return result


def _belt_widget_update(blob, mappings, deps, elf, dynsym):
    binding = _validate_plt_binding(elf, blob, mappings, dynsym, BELT_WIDGET_UPDATE, include_owner=True)
    if binding["plt"] != BELT_WIDGET_UPDATE["plt"]:
        raise RuntimeError("belt update PLT differs")
    items = _decode_range(
        blob,
        mappings,
        deps,
        BELT_WIDGET_UPDATE["defined_owner"],
        BELT_WIDGET_UPDATE["defined_owner"] + BELT_WIDGET_UPDATE["defined_size"],
    )
    icon_expected = BELT_WIDGET_UPDATE["icon_content_setter"]
    icon_binding = _validate_plt_binding(elf, blob, mappings, dynsym, icon_expected)
    icon_calls = [item for item in _direct_targets(items, deps) if item["target"] == icon_binding["plt"]]
    if icon_calls != [{"site": icon_expected["site"], "target": icon_expected["plt"]}]:
        raise RuntimeError("belt icon-content setter differs")
    caller = _decode_range(blob, mappings, deps, 0x2FEEF8, 0x2FEF18)
    tail_targets = [
        operand.imm & ~1
        for item in caller
        if item.group(deps["jump_group"]) and not item.group(deps["call_group"])
        for operand in item.operands
        if operand.type == deps["imm"]
    ]
    if BELT_WIDGET_UPDATE["tail_target"] not in tail_targets:
        raise RuntimeError("belt update tail target differs")
    return copy.deepcopy(BELT_WIDGET_UPDATE)


def _previous_writer(items, before_index, register):
    for item in reversed(items[:before_index]):
        try:
            _reads, writes = item.regs_access()
        except Exception:
            writes = []
        if register in writes:
            return item
    return None


def _previous_writer_index(items, before_index, register):
    for index in range(before_index - 1, -1, -1):
        item = items[index]
        try:
            _reads, writes = item.regs_access()
        except Exception:
            writes = []
        if register in writes:
            return index
    return None


def _register_origin(items, before_index, register, deps, seen=None):
    seen = set() if seen is None else set(seen)
    key = (before_index, register)
    if key in seen:
        return "unknown"
    seen.add(key)
    for index in range(before_index - 1, -1, -1):
        item = items[index]
        if item.group(deps["call_group"]) and register in deps["caller_saved"]:
            return f"call-result:{item.address & ~1:#x}" if register == deps["r0"] else "unknown"
        try:
            _reads, writes = item.regs_access()
        except Exception:
            writes = []
        if register not in writes:
            continue
        operands = item.operands
        if item.mnemonic.startswith("mov") and len(operands) >= 2 and operands[1].type == deps["reg"]:
            return _register_origin(items, index, operands[1].reg, deps, seen)
        if item.id == deps["ldr"] and len(operands) >= 2 and operands[1].type == deps["mem"]:
            memory = operands[1].mem
            base = _register_origin(items, index, memory.base, deps, seen)
            if base == "this" and memory.index == 0:
                return f"this+0x{memory.disp:02x}"
            if base == "typed-argument-node" and memory.disp == 0 and memory.index == 0:
                return "typed-argument-node-deref"
            return f"intermediate-load:{item.address & ~1:#x}"
        return "unknown"
    if register == deps["r0"]:
        return "this"
    if register == deps["r1"]:
        return "typed-argument-node"
    return "unknown"


def _receiver_matches_object(items, call_index, target_writer_index, deps):
    writer = items[target_writer_index]
    vtable_register = writer.operands[1].mem.base
    vtable_writer_index = _previous_writer_index(items, target_writer_index, vtable_register)
    if vtable_writer_index is None:
        return False, "unknown"
    vtable_writer = items[vtable_writer_index]
    if vtable_writer.id != deps["ldr"] or len(vtable_writer.operands) < 2 or vtable_writer.operands[1].type != deps["mem"] or vtable_writer.operands[1].mem.disp != 0:
        return False, "unknown"
    object_register = vtable_writer.operands[1].mem.base
    if object_register != deps["r0"]:
        receiver_writer_index = _previous_writer_index(items, call_index, deps["r0"])
        if receiver_writer_index is None:
            return False, "unknown"
        receiver_writer = items[receiver_writer_index]
        if not receiver_writer.mnemonic.startswith("mov") or len(receiver_writer.operands) < 2 or receiver_writer.operands[1].type != deps["reg"] or receiver_writer.operands[1].reg != object_register:
            return False, "unknown"
        for item in items[receiver_writer_index + 1 : call_index]:
            try:
                _reads, writes = item.regs_access()
            except Exception:
                writes = []
            if object_register in writes:
                return False, "unknown"
    return True, _register_origin(items, vtable_writer_index, object_register, deps)


def _virtual_calls(decoded, calls, deps):
    result = []
    by_role = _instruction_maps(decoded)
    for expected in VIRTUAL_CALLS:
        call = _call_at(calls, expected["method_role"], expected["site"])
        if call["target"] is not None or call["target_register"] is None:
            raise RuntimeError("virtual call is not register-indirect")
        items = decoded[expected["method_role"]]
        writer = _previous_writer(items, call["instruction_index"], call["target_register"])
        if writer is None or writer.id != deps["ldr"] or len(writer.operands) < 2 or writer.operands[1].type != deps["mem"]:
            raise RuntimeError("virtual target load differs")
        if writer.operands[1].mem.disp != expected["interface_cell"] * 4:
            raise RuntimeError(
                f"virtual interface cell differs at {expected['site']:#x}: "
                f"expected {expected['interface_cell']}, observed {writer.operands[1].mem.disp // 4}"
            )
        writer_index = items.index(writer)
        receiver_matches, receiver_origin = _receiver_matches_object(
            items, call["instruction_index"], writer_index, deps
        )
        if not receiver_matches:
            raise RuntimeError(f"virtual receiver identity differs at {expected['site']:#x}")
        if expected["receiver"] != "intermediate-untyped" and receiver_origin != expected["receiver"]:
            raise RuntimeError(
                f"virtual receiver field differs at {expected['site']:#x}: "
                f"expected {expected['receiver']}, observed {receiver_origin}"
            )
        if expected["receiver"] == "intermediate-untyped" and receiver_origin.startswith("this+"):
            raise RuntimeError(f"intermediate receiver was promoted at {expected['site']:#x}")
        if expected["site"] not in by_role[expected["method_role"]]:
            raise RuntimeError("virtual call is outside its owner")
        result.append(copy.deepcopy(expected))
    if result != VIRTUAL_CALLS:
        raise RuntimeError("bounded virtual-call surface differs")
    return result


def _metadata_from_file(source=SOURCE):
    source = Path(source)
    if source.is_symlink() or not source.is_file():
        raise RuntimeError("source must be a literal regular file")
    before = _sha256(source)
    if source.name != "viewUnified2.so" or source.stat().st_size != VIEW_UNIFIED2_SIZE or before != VIEW_UNIFIED2_SHA256:
        raise RuntimeError("source identity differs")
    deps = _dependencies()
    blob = source.read_bytes()
    with io.BytesIO(blob) as stream:
        elf = deps["ELFFile"](stream)
        mappings = _load_mappings(elf)
        dynsym = elf.get_section_by_name(".dynsym")
        if dynsym is None:
            raise RuntimeError("dynamic symbols are unavailable")
        methods, decoded, _symbols = _decode_methods(blob, mappings, dynsym, deps)
        calls = _calls(decoded, deps)
        field_accesses = _field_accesses(decoded, deps)
        named, local, move_targets = _direct_boundaries(calls, _plt_by_symbol(elf, blob, mappings))
        virtual_calls = _virtual_calls(decoded, calls, deps)
        set_disp_binding = _validate_plt_binding(elf, blob, mappings, dynsym, SET_DISP_STATE_BINDING)
        local_routines = _local_terminal_routines(blob, mappings, deps, set_disp_binding)
        belt = _belt_widget_update(blob, mappings, deps, elf, dynsym)
    boundary = copy.deepcopy(MODEL_CURSOR_BOUNDARY)
    boundary.update({
        "field_accesses": field_accesses,
        "virtual_calls": virtual_calls,
        "move_cursor_local_targets": move_targets,
        "update_belt_widget_call": belt,
        "set_value_to_model": {
            "named_lookup_calls": named,
            "local_terminal_calls": local,
            "local_terminal_routines": local_routines,
            "local_terminal_semantics_resolved": False,
            "local_terminal_classification": "contains-widget-display-state-updates-with-unresolved-virtual-effects",
        },
    })
    document = copy.deepcopy(EXPECTED_EXPORT)
    document.update({"methods": methods, "model_cursor_boundary": boundary})
    normalize_creative_style_model_cursor_boundary_export(document)
    if _sha256(source) != before:
        raise RuntimeError("source changed during static export")
    return document


class FileAdapter:
    def __init__(self, source=SOURCE):
        self.source = source

    def metadata(self):
        return _metadata_from_file(self.source)


def build_raw_export(adapter=None):
    try:
        return normalize_creative_style_model_cursor_boundary_export((adapter or FileAdapter()).metadata())
    except Exception as exc:
        raise RuntimeError("Creative Style model/cursor metadata differs from the exact bounded static result") from exc


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
    handle, temporary = tempfile.mkstemp(dir=str(root), prefix=".model-cursor-", suffix=".tmp")
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
    print("CREATIVE_STYLE_MODEL_CURSOR_BOUNDARY_EXPORT|methods=7|virtual_calls=17|local_terminals=2|creative_binding=0|persistence=0")
