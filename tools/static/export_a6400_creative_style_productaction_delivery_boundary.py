"""Read-only exporter for the cross-ELF ProductAction delivery boundary."""
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

from pmca.analysis.creative_style_productaction_delivery_boundary import (
    CANONICAL_SLOT37_SCAN,
    DEPENDENCIES,
    DIRECT_SLOT64_SCAN,
    EXPECTED_RAW_EXPORT,
    FIRMWARE_INVENTORY,
    PRODUCTACTION_INTERFACE,
    PRODUCTACTION_SYMBOL_PUBLICATION,
    VU2_DIRECT_CALLER_CLASSIFICATION,
    build_creative_style_productaction_delivery_boundary_report,
    normalize_creative_style_productaction_delivery_boundary_export,
)
from pmca.analysis.creative_style_selected_node_identity_boundary import (
    validate_creative_style_selected_node_identity_boundary_report,
)
from pmca.analysis.orientation_object_table_boundary import (
    validate_orientation_object_table_boundary_report,
)
from tools.static.export_a6400_creative_style_registry_consumers import (
    FIRMWARE_ROOT,
    _inventory,
)
from tools.static.export_a6400_creative_style_selected_node_identity_boundary import (
    SOURCE_PATH,
    _defined_symbols_covering,
    _dependencies,
    _known_immediate_before,
    _relative_address_taken_records,
    _written_registers,
)
from tools.static.export_a6400_creative_style_view_model_binding import (
    _at,
    _direct_target,
    _instruction,
    _owner,
    _word,
)
from tools.static.export_a6400_generic_model_owner_provenance import (
    _exidx_ranges,
    _mappings,
)


SELECTED_NODE_REPORT_PATH = ROOT / DEPENDENCIES["selected_node_identity"]["report"]
ORIENTATION_REPORT_PATH = ROOT / DEPENDENCIES["orientation_object_table"]["report"]
REPORT_PATH = (
    ROOT / "analysis" / "a6400-creative-style-productaction-delivery-boundary.json"
)


def _digest(value):
    return hashlib.sha256(
        (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )
    ).hexdigest()


def sources_available():
    paths = (SOURCE_PATH, SELECTED_NODE_REPORT_PATH, ORIENTATION_REPORT_PATH)
    return FIRMWARE_ROOT.is_dir() and all(
        path.is_file() and not path.is_symlink() for path in paths
    )


def _validate_dependencies():
    selected = validate_creative_style_selected_node_identity_boundary_report(
        json.loads(SELECTED_NODE_REPORT_PATH.read_text(encoding="utf-8"))
    )
    selected_expected = DEPENDENCIES["selected_node_identity"]
    if (
        selected["schema_version"] != selected_expected["schema_version"]
        or selected["summary"]["canonical_export_sha256"]
        != selected_expected["canonical_export_sha256"]
        or selected["claims"]["viewsettingmenu_productaction_10_delivery_proven"]
        != selected_expected["viewsettingmenu_productaction_10_delivery_proven"]
    ):
        raise RuntimeError("selected-node dependency differs")

    orientation = validate_orientation_object_table_boundary_report(
        json.loads(ORIENTATION_REPORT_PATH.read_text(encoding="utf-8"))
    )
    orientation_expected = DEPENDENCIES["orientation_object_table"]
    derived = next(
        item for item in orientation["type_tables"] if item["role"] == "derived"
    )
    if (
        orientation["summary"]["canonical_export_sha256"]
        != orientation_expected["canonical_export_sha256"]
        or derived["address_point"] != orientation_expected["af_address_point"]
        or orientation["summary"]["widget_address_point_match_count"]
        != orientation_expected["widget_address_point_match_count"]
    ):
        raise RuntimeError("orientation dependency differs")


def _canonical_calls(blob, elf, deps, exidx):
    mappings = _mappings(elf)
    decoder = deps["Cs"](deps["arch"], deps["mode"])
    decoder.detail = True
    calls = {0x94: [], 0x100: []}
    complete_count = 0
    incomplete_count = 0
    direct_edges = {
        target: []
        for target in (
            0x310CD8,
            0x310E30,
            0x3110BC,
            0x3112DC,
            PRODUCTACTION_INTERFACE["productaction_entry"],
        )
    }
    for start, end in exidx:
        items = list(decoder.disasm(_at(blob, mappings, start, end - start), start))
        for item in items:
            target = _direct_target(item, deps)
            if target in direct_edges and (
                item.group(deps["call_group"]) or item.group(deps["jump_group"])
            ):
                direct_edges[target].append(
                    {
                        "site": item.address & ~1,
                        "owner_start": start,
                        "owner_end": end,
                    }
                )
        complete = bool(
            items
            and items[0].address == start
            and items[-1].address + items[-1].size == end
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
            slot_index = None
            slot_offset = None
            for candidate_index in range(
                call_index - 1, max(-1, call_index - 7), -1
            ):
                candidate = items[candidate_index]
                if call_register not in _written_registers(candidate):
                    continue
                if (
                    candidate.id == deps["ldr"]
                    and len(candidate.operands) == 2
                    and candidate.operands[0].type == deps["reg"]
                    and candidate.operands[0].reg == call_register
                    and candidate.operands[1].type == deps["mem"]
                    and candidate.operands[1].mem.index == 0
                    and candidate.operands[1].mem.disp in calls
                ):
                    slot_index = candidate_index
                    slot_offset = candidate.operands[1].mem.disp
                break
            if slot_index is None:
                continue
            vptr_register = items[slot_index].operands[1].mem.base
            vptr_index = None
            for candidate_index in range(
                slot_index - 1, max(-1, slot_index - 9), -1
            ):
                candidate = items[candidate_index]
                if vptr_register not in _written_registers(candidate):
                    continue
                if (
                    candidate.id == deps["ldr"]
                    and len(candidate.operands) == 2
                    and candidate.operands[0].type == deps["reg"]
                    and candidate.operands[0].reg == vptr_register
                    and candidate.operands[1].type == deps["mem"]
                    and candidate.operands[1].mem.index == 0
                    and candidate.operands[1].mem.disp == 0
                ):
                    vptr_index = candidate_index
                break
            if vptr_index is None:
                continue
            calls[slot_offset].append(
                {
                    "owner_start": start,
                    "owner_end": end,
                    "vptr_load_site": items[vptr_index].address,
                    "slot_load_site": items[slot_index].address,
                    "call_site": call.address,
                    "selector": _known_immediate_before(
                        items, call_index, deps["r1"], deps
                    ),
                }
            )
    return calls, complete_count, incomplete_count, direct_edges


def _productaction_publication(elf, relative):
    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym is None:
        return None
    matches = [
        (index, symbol)
        for index, symbol in enumerate(dynsym.iter_symbols())
        if symbol.name == PRODUCTACTION_SYMBOL_PUBLICATION["symbol"]
    ]
    if not matches:
        return None
    if len(matches) != 1:
        raise RuntimeError("ProductAction dynamic symbol inventory differs")
    symbol_index, symbol = matches[0]
    records = []
    for section_name in (".rel.dyn", ".rel.plt"):
        section = elf.get_section_by_name(section_name)
        if section is None:
            continue
        for relocation_index, relocation in enumerate(section.iter_relocations()):
            if relocation["r_info_sym"] != symbol_index:
                continue
            records.append(
                {
                    "module": relative,
                    "section": section_name,
                    "relocation_index": relocation_index,
                    "cell": relocation["r_offset"],
                    "relocation_type": relocation["r_info_type"],
                    "symbol_index": symbol_index,
                }
            )
    dynamic = elf.get_section_by_name(".dynamic")
    needed = [] if dynamic is None else [
        tag.needed
        for tag in dynamic.iter_tags()
        if tag.entry.d_tag == "DT_NEEDED"
    ]
    if not records:
        raise RuntimeError("ProductAction publication records are missing")
    return (
        {
            "module": relative,
            "symbol_index": symbol_index,
            "defined": symbol["st_shndx"] != "SHN_UNDEF",
            "symbol_value": symbol["st_value"],
            "symbol_size": symbol["st_size"],
            "abs32_cell_count": sum(
                item["relocation_type"] == 2 for item in records
            ),
            "first_relocation_index": records[0]["relocation_index"],
            "last_relocation_index": records[-1]["relocation_index"],
            "first_cell": records[0]["cell"],
            "last_cell": records[-1]["cell"],
            "needed_viewunified2": "viewUnified2.so" in needed,
        },
        records,
    )


def _scan_inventory(deps, elf_paths):
    call_modules = {0x94: [], 0x100: []}
    excluded = []
    known_selector_calls = {0x94: [], 0x100: []}
    complete_owner_count = 0
    incomplete_owner_count = 0
    canonical_call_count = {0x94: 0, 0x100: 0}
    vu2_direct_edges = None
    publication_modules = []
    publication_records = []
    for relative in elf_paths:
        path = FIRMWARE_ROOT / relative
        blob = path.read_bytes()
        elf = deps["ELFFile"](io.BytesIO(blob))
        publication = _productaction_publication(elf, relative)
        if publication is not None:
            module, records = publication
            publication_modules.append(module)
            publication_records.extend(records)
        if elf.get_section_by_name(".ARM.exidx") is None:
            excluded.append({"module": relative, "reason": "missing-arm-exidx"})
            continue
        exidx = _exidx_ranges(elf, blob)
        if not exidx:
            excluded.append({"module": relative, "reason": "missing-arm-exidx"})
            continue
        calls, complete, incomplete, direct_edges = _canonical_calls(
            blob, elf, deps, exidx
        )
        complete_owner_count += complete
        incomplete_owner_count += incomplete
        for offset in canonical_call_count:
            canonical_call_count[offset] += len(calls[offset])
        if relative == "lib/viewUnified2.so":
            vu2_direct_edges = direct_edges
        for offset in calls:
            if calls[offset]:
                call_modules[offset].append(
                    {
                        "module": relative,
                        "complete_owner_count": complete,
                        "incomplete_owner_count": incomplete,
                        "canonical_call_count": len(calls[offset]),
                    }
                )
            for call in calls[offset]:
                if call["selector"] is not None:
                    known_selector_calls[offset].append(
                        {"module": relative, **call}
                    )

    if vu2_direct_edges is None:
        raise RuntimeError("viewUnified2 direct-edge scan is missing")
    excluded_reason_counts = {
        "kernel-module-without-usable-arm-exidx": sum(
            item["module"].endswith(".ko") for item in excluded
        ),
        "shared-object-without-usable-arm-exidx": sum(
            not item["module"].endswith(".ko") for item in excluded
        ),
    }
    histogram = {0x94: {}, 0x100: {}}
    for call in known_selector_calls[0x94]:
        key = str(call["selector"])
        histogram[0x94][key] = histogram[0x94].get(key, 0) + 1
    scan = {
        "scope": CANONICAL_SLOT37_SCAN["scope"],
        "exidx_scanned_file_count": len(elf_paths) - len(excluded),
        "excluded_file_count": len(excluded),
        "excluded_reason_counts": excluded_reason_counts,
        "excluded_records_sha256": _digest(excluded),
        "complete_owner_count": complete_owner_count,
        "incomplete_owner_count": incomplete_owner_count,
        "call_modules": call_modules[0x94],
        "canonical_call_count": canonical_call_count[0x94],
        "known_selector_calls": known_selector_calls[0x94],
        "known_selector_calls_sha256": _digest(known_selector_calls[0x94]),
        "known_selector_histogram": histogram[0x94],
        "unknown_selector_count": canonical_call_count[0x94] - len(known_selector_calls[0x94]),
        "selector_10_call_count": sum(
            call["selector"] == 10 for call in known_selector_calls[0x94]
        ),
        "noncanonical_dispatch_scanned": False,
        "incomplete_owner_dispatch_scanned": False,
        "runtime_indirect_dispatch_scanned": False,
        "whole_elf_universe_absence_proven": False,
    }
    slot64_histogram = {}
    for call in known_selector_calls[0x100]:
        key = str(call["selector"])
        slot64_histogram[key] = slot64_histogram.get(key, 0) + 1
    slot64 = {
        "scope": DIRECT_SLOT64_SCAN["scope"],
        "slot": 64,
        "slot_offset": 0x100,
        "complete_owner_count": complete_owner_count,
        "incomplete_owner_count": incomplete_owner_count,
        "call_modules": call_modules[0x100],
        "canonical_call_count": canonical_call_count[0x100],
        "known_selector_calls": known_selector_calls[0x100],
        "known_selector_calls_sha256": _digest(known_selector_calls[0x100]),
        "known_selector_call_count": len(known_selector_calls[0x100]),
        "known_selector_histogram": slot64_histogram,
        "unknown_selector_count": canonical_call_count[0x100]
        - len(known_selector_calls[0x100]),
        "selector_10_call_count": sum(
            call["selector"] == 10 for call in known_selector_calls[0x100]
        ),
        "receiver_identity_analysis_performed": False,
        "whole_runtime_absence_proven": False,
    }
    publication_result = {
        "symbol": PRODUCTACTION_SYMBOL_PUBLICATION["symbol"],
        "module_count": len(publication_modules),
        "modules": publication_modules,
        "abs32_publication_cell_count": sum(
            item["relocation_type"] == 2 for item in publication_records
        ),
        "publication_records_sha256": _digest(publication_records),
        "glob_dat_cell_count": sum(
            item["relocation_type"] == 21 for item in publication_records
        ),
        "plt_relocation_count": sum(
            item["section"] == ".rel.plt" for item in publication_records
        ),
        "importer_needed_viewunified2_count": sum(
            item["needed_viewunified2"]
            for item in publication_modules
            if not item["defined"]
        ),
        "direct_call_count": len(
            vu2_direct_edges[PRODUCTACTION_INTERFACE["productaction_entry"]]
        ),
        "cross_module_provider_binding_proven": False,
        "publication_proves_invocation": False,
    }
    return scan, slot64, publication_result, vu2_direct_edges


def _require_direct(context, deps, site, target, label):
    item = _instruction(context["blob"], context["mappings"], deps, site)
    if _direct_target(item, deps) != target or not (
        item.group(deps["call_group"]) or item.group(deps["jump_group"])
    ):
        raise RuntimeError(label + " differs")


def _validate_vu2_structure(blob, deps, direct_edges):
    """Validate exact VU2 instructions/relocations after source identity checks."""

    blob = bytes(blob)
    stream = io.BytesIO(blob)
    elf = deps["ELFFile"](stream)
    context = {
        "stream": stream,
        "elf": elf,
        "blob": blob,
        "mappings": _mappings(elf),
        "rels": list(elf.get_section_by_name(".rel.dyn").iter_relocations()),
        "exidx": _exidx_ranges(elf, blob),
    }
    for start, end in (
        (0x310CD8, 0x310E30),
        (0x310E30, 0x3110BC),
        (0x3110BC, 0x3112DC),
        (0x3112DC, 0x311514),
        (0x31286C, 0x31297C),
    ):
        if _owner(context["exidx"], start) != (start, end):
            raise RuntimeError("ProductAction caller owner differs")

    for site, target in (
        (0x31107E, 0x310CD8),
        (0x3112A0, 0x310CD8),
        (0x3114C6, 0x310CD8),
        (0x3128CA, 0x3112DC),
        (0x31293A, 0x3110BC),
    ):
        _require_direct(context, deps, site, target, "ProductAction caller edge")

    for start in (0x310CD8, 0x310E30, 0x3110BC, 0x3112DC, 0x31286C):
        if _defined_symbols_covering(context, start):
            raise RuntimeError("ProductAction caller unexpectedly has a symbol")
    for start, end in (
        (0x310CD8, 0x310E30),
        (0x310E30, 0x3110BC),
        (0x3110BC, 0x3112DC),
        (0x3112DC, 0x311514),
    ):
        if _relative_address_taken_records(context, start, end):
            raise RuntimeError("ProductAction helper publication differs")

    expected_edges = {
        0x310CD8: [
            {"site": 0x31107E, "owner_start": 0x310E30, "owner_end": 0x3110BC},
            {"site": 0x3112A0, "owner_start": 0x3110BC, "owner_end": 0x3112DC},
            {"site": 0x3114C6, "owner_start": 0x3112DC, "owner_end": 0x311514},
        ],
        0x310E30: [],
        0x3110BC: [
            {"site": 0x31293A, "owner_start": 0x31286C, "owner_end": 0x31297C}
        ],
        0x3112DC: [
            {"site": 0x3128CA, "owner_start": 0x31286C, "owner_end": 0x31297C}
        ],
        PRODUCTACTION_INTERFACE["productaction_entry"]: [],
    }
    if direct_edges != expected_edges:
        raise RuntimeError("ProductAction direct inbound inventory differs")

    rel_index = VU2_DIRECT_CALLER_CLASSIFICATION["af_slot36_route"][
        "relocation_index"
    ]
    relocation = context["rels"][rel_index]
    cell = VU2_DIRECT_CALLER_CLASSIFICATION["af_slot36_route"]["cell"]
    if (
        relocation["r_offset"] != cell
        or relocation["r_info_type"] != 23
        or relocation["r_info_sym"] != 0
        or _word(context["blob"], context["mappings"], cell) != 0x31286D
    ):
        raise RuntimeError("AF slot-36 ProductAction route differs")
    return copy.deepcopy(VU2_DIRECT_CALLER_CLASSIFICATION)


def _validate_vu2_classification(deps, direct_edges):
    blob = SOURCE_PATH.read_bytes()
    if (
        len(blob) != PRODUCTACTION_INTERFACE["module_size"]
        or hashlib.sha256(blob).hexdigest()
        != PRODUCTACTION_INTERFACE["module_sha256"]
    ):
        raise RuntimeError("viewUnified2 source identity differs")
    return _validate_vu2_structure(blob, deps, direct_edges)


def build_raw_export():
    if not sources_available():
        raise RuntimeError("pinned ProductAction delivery sources are unavailable")
    deps = _dependencies()
    _validate_dependencies()
    inventory_before, elf_paths = _inventory()
    if inventory_before != FIRMWARE_INVENTORY:
        raise RuntimeError("firmware inventory differs")
    source_snapshot = {
        relative: (
            (FIRMWARE_ROOT / relative).stat().st_size,
            (FIRMWARE_ROOT / relative).stat().st_mtime_ns,
        )
        for relative in elf_paths
    }
    scan, slot64, publication, direct_edges = _scan_inventory(deps, elf_paths)
    classification = _validate_vu2_classification(deps, direct_edges)
    if source_snapshot != {
        relative: (
            (FIRMWARE_ROOT / relative).stat().st_size,
            (FIRMWARE_ROOT / relative).stat().st_mtime_ns,
        )
        for relative in elf_paths
    }:
        raise RuntimeError("firmware source changed during read-only analysis")
    document = copy.deepcopy(EXPECTED_RAW_EXPORT)
    document["firmware_inventory"] = inventory_before
    document["canonical_slot37_scan"] = scan
    document["direct_slot64_scan"] = slot64
    document["productaction_symbol_publication"] = publication
    document["vu2_direct_caller_classification"] = classification
    return normalize_creative_style_productaction_delivery_boundary_export(document)


def write_report_atomic(report, path=REPORT_PATH):
    target = Path(path)
    if target.parent.is_symlink() or not target.parent.is_dir():
        raise RuntimeError("report directory is not a literal directory")
    data = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    handle, temporary = tempfile.mkstemp(
        prefix=target.name + ".", suffix=".tmp", dir=target.parent
    )
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    raw = build_raw_export()
    report = build_creative_style_productaction_delivery_boundary_report(raw)
    write_report_atomic(report)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
