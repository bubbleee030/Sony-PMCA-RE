"""Read-only exporter for the α6400 Creative Style activation-caller boundary."""

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

from pmca.analysis.creative_style_activation_caller_boundary import (
    CLAIMS,
    DEPENDENCY,
    EXPECTED_EXPORT,
    FIRST_UNRESOLVED_BOUNDARY,
    MANAGER_IDENTITY,
    READINESS,
    SOURCE,
    TYPED_ACTIVATION_DEPENDENCY,
    build_creative_style_activation_caller_boundary_report,
    normalize_creative_style_activation_caller_boundary_export,
    validate_creative_style_activation_caller_boundary_report,
)
from pmca.analysis.creative_style_view_lifecycle_boundary import (
    validate_creative_style_view_lifecycle_boundary_report,
)
from tools.static.export_a6400_creative_style_view_lifecycle_boundary import (
    _dependencies,
)
from tools.static.export_a6400_creative_style_view_model_binding import (
    _at,
    _call_symbol,
    _decode,
    _direct_target,
    _instruction,
    _mappings,
    _owner,
    _plt_symbols,
    _relocations,
    _validate_relative,
    _word,
)
from tools.static.export_a6400_generic_model_owner_provenance import _exidx_ranges


SOURCE_PATH = (
    ROOT
    / ".artifacts"
    / "decrypted"
    / "a6400-tw-v2.00"
    / "ma1co"
    / "firmware.tar_unpacked"
    / "0700_part_image"
    / "dev"
    / "nflasha15_unpacked"
    / "lib"
    / "viewUnified2.so"
)
DEPENDENCY_PATH = ROOT / DEPENDENCY["report"]
RAW_OUTPUT_PATH = (
    ROOT
    / ".artifacts"
    / "creative-style-activation-caller-boundary"
    / "a6400-v2.00"
    / "creative-style-activation-caller-boundary-export.json"
)
REPORT_PATH = ROOT / "analysis" / "a6400-creative-style-activation-caller-boundary.json"


def dependencies_available():
    try:
        _dependencies()
    except RuntimeError:
        return False
    return True


def sources_available():
    return (
        SOURCE_PATH.is_file()
        and not SOURCE_PATH.is_symlink()
        and DEPENDENCY_PATH.is_file()
        and not DEPENDENCY_PATH.is_symlink()
    )


def _sha256_bytes(blob):
    return hashlib.sha256(blob).hexdigest()


def _context(blob, deps):
    stream = io.BytesIO(blob)
    elf = deps["ELFFile"](stream)
    mappings = _mappings(elf)
    rels, by_site = _relocations(elf)
    return {
        "stream": stream,
        "elf": elf,
        "blob": blob,
        "mappings": mappings,
        "rels": rels,
        "by_site": by_site,
        "exidx": _exidx_ranges(elf, blob),
        "plt_symbols": _plt_symbols(elf, blob, mappings),
    }


def _validate_dependency():
    import json

    report = validate_creative_style_view_lifecycle_boundary_report(
        json.loads(DEPENDENCY_PATH.read_text(encoding="utf-8"))
    )
    if (
        report["evidence_digest"] != DEPENDENCY["evidence_digest"]
        or report["evidence"]["typed_activation"][
            "typed_process_id_42_caller_proven"
        ]
        != DEPENDENCY["typed_process_id_42_caller_proven"]
        or report["claims"]["runtime_factory_invocation_proven"]
        != DEPENDENCY["runtime_factory_invocation_proven"]
    ):
        raise RuntimeError("view-lifecycle dependency differs")


def _require_relative(context, *, index, site, target, label):
    try:
        _validate_relative(
            context["rels"],
            context["by_site"],
            context["blob"],
            context["mappings"],
            index=index,
            site=site,
            target=target,
        )
    except (KeyError, RuntimeError, ValueError) as exc:
        raise RuntimeError(label + " relocation differs") from exc


def _validate_manager_identity(context, deps):
    blob = context["blob"]
    mappings = context["mappings"]
    exidx = context["exidx"]
    manager = MANAGER_IDENTITY
    accessor = manager["accessor"]
    constructor = manager["constructor"]

    if _owner(exidx, accessor["owner"]["start"]) != (
        accessor["owner"]["start"],
        accessor["owner"]["end"],
    ):
        raise RuntimeError("process manager accessor owner differs")
    accessor_pic_base = _word(blob, mappings, accessor["pic_literal_site"]) + 0x15835C
    if accessor_pic_base != accessor["pic_base"]:
        raise RuntimeError("process manager accessor PIC base differs")
    guard_cell = accessor_pic_base + _word(blob, mappings, 0x15839C)
    instance_cell = accessor_pic_base + _word(blob, mappings, 0x1583A0)
    if guard_cell != accessor["guard_got_cell"] or instance_cell != accessor["instance_got_cell"]:
        raise RuntimeError("process manager accessor GOT cells differ")
    _require_relative(
        context,
        index=accessor["guard_relocation_index"],
        site=guard_cell,
        target=accessor["guard_storage"],
        label="process manager guard",
    )
    _require_relative(
        context,
        index=accessor["instance_relocation_index"],
        site=instance_cell,
        target=manager["instance_object"],
        label="process manager instance",
    )
    receiver = _instruction(blob, mappings, deps, accessor["constructor_receiver_site"])
    returned = _instruction(blob, mappings, deps, accessor["return_site"])
    instance_offset_load = _instruction(blob, mappings, deps, 0x158362)
    instance_offset_literal = (
        ((instance_offset_load.address + 4) & ~3)
        + instance_offset_load.operands[1].mem.disp
        if (
            instance_offset_load.id == deps["ldr"]
            and len(instance_offset_load.operands) == 2
            and instance_offset_load.operands[0].reg == deps["r3"]
            and instance_offset_load.operands[1].type == deps["mem"]
            and instance_offset_load.operands[1].mem.base == deps["pc"]
            and instance_offset_load.operands[1].mem.index == 0
        )
        else None
    )
    if (
        instance_offset_literal != 0x1583A0
        or receiver.id != deps["mov"]
        or receiver.operands[0].reg != deps["r0"]
        or receiver.operands[1].reg != deps["r5"]
        or _call_symbol(
            blob,
            mappings,
            deps,
            context["plt_symbols"],
            accessor["constructor_call_site"],
        )
        != accessor["constructor_symbol"]
        or returned.id != deps["mov"]
        or returned.operands[0].reg != deps["r0"]
        or returned.operands[1].reg != deps["r5"]
    ):
        raise RuntimeError("process manager accessor receiver/return differs")
    instance_load = _instruction(blob, mappings, deps, 0x158364)
    if (
        instance_load.id != deps["ldr"]
        or instance_load.operands[0].reg != deps["r5"]
        or instance_load.operands[1].mem.base != deps["r4"]
        or instance_load.operands[1].mem.index != deps["r3"]
    ):
        raise RuntimeError("process manager instance load differs")

    if _owner(exidx, constructor["owner"]["start"]) != (
        constructor["owner"]["start"],
        constructor["owner"]["end"],
    ):
        raise RuntimeError("process manager constructor owner differs")
    constructor_pic_base = _word(blob, mappings, constructor["pic_literal_site"]) + 0x43906E
    if constructor_pic_base != constructor["pic_base"]:
        raise RuntimeError("process manager constructor PIC base differs")
    vtable_cell = constructor_pic_base + _word(
        blob, mappings, constructor["vtable_offset_literal_site"]
    )
    if vtable_cell != constructor["vtable_got_cell"]:
        raise RuntimeError("process manager vtable GOT cell differs")
    _require_relative(
        context,
        index=constructor["vtable_relocation_index"],
        site=vtable_cell,
        target=constructor["vtable_header_target"],
        label="process manager vtable header",
    )
    vtable_load = _instruction(blob, mappings, deps, constructor["vtable_load_site"])
    address_point = _instruction(blob, mappings, deps, constructor["address_point_add_site"])
    vptr_store = _instruction(blob, mappings, deps, constructor["vptr_store_site"])
    constructor_return = _instruction(blob, mappings, deps, constructor["return_site"])
    if (
        vtable_load.id != deps["ldr"]
        or vtable_load.operands[0].reg != deps["r3"]
        or vtable_load.operands[1].mem.base != deps["r4"]
        or address_point.id != deps["add"]
        or address_point.operands[0].reg != deps["r3"]
        or address_point.operands[-1].imm != 8
        or vptr_store.id != deps["str"]
        or vptr_store.operands[0].reg != deps["r3"]
        or vptr_store.operands[1].mem.base != deps["r0"]
        or vptr_store.operands[1].mem.disp != 0
        or constructor_return.id != deps["mov"]
        or constructor_return.operands[0].reg != deps["r0"]
        or constructor_return.operands[1].reg != deps["r5"]
    ):
        raise RuntimeError("process manager constructor vptr store differs")
    _require_relative(
        context,
        index=manager["bridge_relocation_index"],
        site=manager["bridge_cell"],
        target=manager["bridge_target"],
        label="process manager slot 20",
    )
    if _owner(exidx, manager["bridge_target"]) != (
        manager["bridge_owner"]["start"],
        manager["bridge_owner"]["end"],
    ):
        raise RuntimeError("process manager bridge owner differs")
    bridge = manager["bridge"]
    condition_capture = _instruction(
        blob, mappings, deps, bridge["condition_capture_site"]
    )
    condition_forward = _instruction(
        blob, mappings, deps, bridge["condition_forward_site"]
    )
    typed_slot_load = _instruction(
        blob, mappings, deps, bridge["typed_slot_load_site"]
    )
    typed_slot_call = _instruction(
        blob, mappings, deps, bridge["typed_slot_call_site"]
    )
    if (
        condition_capture.id != deps["mov"]
        or condition_capture.operands[0].reg != deps["r4"]
        or condition_capture.operands[1].reg != deps["r2"]
        or _direct_target(
            _instruction(blob, mappings, deps, bridge["lookup_call_site"]), deps
        )
        != bridge["lookup_target"]
        or condition_forward.id != deps["mov"]
        or condition_forward.operands[0].reg != deps["r1"]
        or condition_forward.operands[1].reg != deps["r4"]
        or typed_slot_load.id != deps["ldr"]
        or typed_slot_load.operands[0].reg != deps["r3"]
        or typed_slot_load.operands[1].mem.base != deps["r3"]
        or typed_slot_load.operands[1].mem.disp != bridge["typed_slot_offset"]
        or typed_slot_call.id != deps["blx"]
        or typed_slot_call.operands[0].reg != deps["r3"]
    ):
        raise RuntimeError("process manager bridge condition/typed-slot flow differs")
    return copy.deepcopy(manager)


def _validate_typed_dependency(context):
    typed = TYPED_ACTIVATION_DEPENDENCY
    _require_relative(
        context,
        index=typed["relocation_index"],
        site=typed["cell"],
        target=typed["wrapper_target"],
        label="Creative Style typed slot 25",
    )
    if _owner(context["exidx"], typed["wrapper_target"]) != (0x4891D4, 0x489238):
        raise RuntimeError("Creative Style typed activation wrapper owner differs")
    return copy.deepcopy(typed)


def _written_registers(instruction):
    try:
        return set(instruction.regs_access()[1])
    except (AttributeError, ValueError):
        return set()


def _canonical_calls(context, deps):
    blob = context["blob"]
    mappings = context["mappings"]
    decoder = deps["Cs"](deps["arch"], deps["mode"])
    decoder.detail = True
    result = []
    complete_count = 0
    incomplete_count = 0
    direct_inbound = {
        MANAGER_IDENTITY["bridge_target"]: [],
        TYPED_ACTIVATION_DEPENDENCY["wrapper_target"]: [],
    }
    for start, end in context["exidx"]:
        items = list(decoder.disasm(_at(blob, mappings, start, end - start), start))
        complete = bool(
            items
            and items[0].address == start
            and items[-1].address + items[-1].size == end
        )
        for item in items:
            if not (item.group(deps["call_group"]) or item.group(deps["jump_group"])):
                continue
            target = _direct_target(item, deps)
            if target in direct_inbound:
                direct_inbound[target].append(
                    (item.address & ~1, start, end, item.mnemonic)
                )
        if not complete:
            incomplete_count += 1
            continue
        complete_count += 1
        for call_index, call in enumerate(items):
            if (
                call.id != deps["blx"]
                or len(call.operands) != 1
                or call.operands[0].type != deps["reg"]
            ):
                continue
            call_register = call.operands[0].reg
            slot_index = call_index - 1
            if slot_index < 0:
                continue
            slot = items[slot_index]
            if (
                slot.id != deps["ldr"]
                or len(slot.operands) != 2
                or slot.operands[0].type != deps["reg"]
                or slot.operands[0].reg != call_register
                or slot.operands[1].type != deps["mem"]
                or slot.operands[1].mem.index != 0
                or slot.operands[1].mem.disp != 0x50
            ):
                continue
            vptr_register = slot.operands[1].mem.base
            vptr_index = None
            for candidate_index in range(max(0, slot_index - 3), slot_index):
                candidate = items[candidate_index]
                if (
                    candidate.id == deps["ldr"]
                    and len(candidate.operands) == 2
                    and candidate.operands[0].type == deps["reg"]
                    and candidate.operands[0].reg == vptr_register
                    and candidate.operands[1].type == deps["mem"]
                    and candidate.operands[1].mem.index == 0
                    and candidate.operands[1].mem.disp == 0
                ):
                    between = items[candidate_index + 1 : slot_index]
                    if not any(vptr_register in _written_registers(item) for item in between):
                        vptr_index = candidate_index
            if vptr_index is None:
                continue
            receiver_register = items[vptr_index].operands[1].mem.base
            result.append(
                {
                    "owner": {"start": start, "end": end, "complete": True},
                    "vptr_load_site": items[vptr_index].address,
                    "slot_load_site": slot.address,
                    "call_site": call.address,
                    "receiver_register": decoder.reg_name(receiver_register),
                    "manager_receiver_proven": False,
                    "manager_vptr_proven": False,
                    "process_id_42_proven": False,
                    "condition_r2_proven": False,
                    "accepted": False,
                }
            )
    return (
        result,
        complete_count,
        incomplete_count,
        {
            target: list(dict.fromkeys(matches))
            for target, matches in direct_inbound.items()
        },
    )


def _caller_scan(context, deps):
    calls, complete_count, incomplete_count, direct_inbound = _canonical_calls(
        context, deps
    )
    return {
        "exidx_owner_count": len(context["exidx"]),
        "fully_decoded_owner_count": complete_count,
        "incomplete_or_terminal_owner_count": incomplete_count,
        "canonical_slot_offset": 0x50,
        "canonical_slot_20_calls": calls,
        "accepted_candidates": [item for item in calls if item["accepted"]],
        "manager_bridge_direct_inbound": direct_inbound[
            MANAGER_IDENTITY["bridge_target"]
        ],
        "typed_wrapper_direct_inbound": direct_inbound[
            TYPED_ACTIVATION_DEPENDENCY["wrapper_target"]
        ],
        "direct_inbound_scan_complete": incomplete_count == 0,
        "whole_program_absence_proven": False,
        "unresolved_universes": [
            "decode-incomplete-or-terminal-exidx-owners",
            "noncanonical-virtual-dispatch",
            "indirect-callback-or-runtime-initialized-receiver",
            "cross-module-or-loader-mediated-delivery",
        ],
    }


def _validate_caller_scan(context, deps):
    scan = _caller_scan(context, deps)
    if scan != EXPECTED_EXPORT["caller_scan"]:
        raise RuntimeError("bounded Creative Style activation caller inventory differs")
    return scan


def _build_raw_export_from_blob(blob, deps):
    if len(blob) != SOURCE["size"] or _sha256_bytes(blob) != SOURCE["sha256"]:
        raise RuntimeError("viewUnified2 source identity differs")
    context = _context(blob, deps)
    document = {
        "schema_version": 1,
        "analysis_mode": "offline-static-creative-style-activation-caller-boundary",
        "source": copy.deepcopy(SOURCE),
        "dependency": copy.deepcopy(DEPENDENCY),
        "manager_identity": _validate_manager_identity(context, deps),
        "typed_activation_dependency": _validate_typed_dependency(context),
        "caller_scan": _validate_caller_scan(context, deps),
        "claims": copy.deepcopy(CLAIMS),
        "readiness": READINESS,
        "first_unresolved_boundary": FIRST_UNRESOLVED_BOUNDARY,
    }
    return normalize_creative_style_activation_caller_boundary_export(document)


def build_raw_export():
    _validate_dependency()
    return _build_raw_export_from_blob(SOURCE_PATH.read_bytes(), _dependencies())


def build_outputs():
    raw = normalize_creative_style_activation_caller_boundary_export(
        build_raw_export()
    )
    report = validate_creative_style_activation_caller_boundary_report(
        build_creative_style_activation_caller_boundary_report(raw)
    )
    return {RAW_OUTPUT_PATH: raw, REPORT_PATH: report}


def _encoded(document):
    return (
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def publish_outputs():
    outputs = build_outputs()
    temporary_paths = []
    try:
        for path, document in outputs.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temporary = tempfile.mkstemp(
                prefix=path.name + ".", suffix=".tmp", dir=path.parent
            )
            temporary_path = Path(temporary)
            temporary_paths.append(temporary_path)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(_encoded(document))
                stream.flush()
                os.fsync(stream.fileno())
        for temporary_path, path in zip(temporary_paths, outputs):
            os.replace(temporary_path, path)
        temporary_paths.clear()
    finally:
        for temporary_path in temporary_paths:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
    return outputs


def main():
    outputs = publish_outputs()
    print(
        "CREATIVE_STYLE_ACTIVATION_CALLER_BOUNDARY_EXPORT|"
        f"canonical_calls={len(outputs[RAW_OUTPUT_PATH]['caller_scan']['canonical_slot_20_calls'])}|"
        "accepted=0|runtime=0|installable=0|camera=0"
    )


if __name__ == "__main__":
    main()
