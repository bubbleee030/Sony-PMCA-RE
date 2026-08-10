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
    TYPED_PRODUCTACTION_PUBLICATIONS,
    VU2_DIRECT_CALLER_CLASSIFICATION,
    VIEWSETTINGMENU_FACTORY_AVAILABILITY,
    WIDENED_BASIC_BLOCK_SLOT37_SCAN,
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
from tools.static.export_a6400_creative_style_activation_caller_boundary import (
    _literal_address,
)
from tools.static.export_a6400_creative_style_view_model_binding import (
    _at,
    _call_symbol,
    _cstring,
    _direct_target,
    _instruction,
    _owner,
    _plt_symbols,
    _relocations,
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


def _require_text(item, mnemonic, operands, label):
    if item.mnemonic != mnemonic or item.op_str != operands:
        raise RuntimeError(label + " differs")


def _whole_basic_block_slot37(items, call_index, deps):
    call = items[call_index]
    call_register = call.operands[0].reg
    slot_index = None
    for candidate_index in range(call_index - 1, -1, -1):
        candidate = items[candidate_index]
        if (
            candidate.group(deps["call_group"])
            or candidate.group(deps["jump_group"])
            or candidate.group(deps["ret_group"])
        ):
            break
        if call_register not in _written_registers(candidate):
            continue
        if (
            candidate.id == deps["ldr"]
            and len(candidate.operands) == 2
            and candidate.operands[0].type == deps["reg"]
            and candidate.operands[0].reg == call_register
            and candidate.operands[1].type == deps["mem"]
            and candidate.operands[1].mem.index == 0
            and candidate.operands[1].mem.disp == 0x94
        ):
            slot_index = candidate_index
        break
    if slot_index is None:
        return None, None
    vptr_register = items[slot_index].operands[1].mem.base
    vptr_index = None
    for candidate_index in range(slot_index - 1, -1, -1):
        candidate = items[candidate_index]
        if (
            candidate.group(deps["call_group"])
            or candidate.group(deps["jump_group"])
            or candidate.group(deps["ret_group"])
        ):
            break
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
        return None, None
    record = {
        "owner_start": items[0].address,
        "owner_end": items[-1].address + items[-1].size,
        "vptr_load_site": items[vptr_index].address,
        "slot_load_site": items[slot_index].address,
        "call_site": call.address,
    }
    calls = []
    selector = None
    selector_source = None
    for candidate in reversed(items[:call_index]):
        if candidate.group(deps["call_group"]):
            calls.append(
                {"site": candidate.address, "target": _direct_target(candidate, deps)}
            )
        elif candidate.group(deps["jump_group"]) or candidate.group(
            deps["ret_group"]
        ):
            break
        if deps["r1"] not in _written_registers(candidate):
            continue
        if (
            candidate.id == deps["mov"]
            and len(candidate.operands) == 2
            and candidate.operands[0].type == deps["reg"]
            and candidate.operands[0].reg == deps["r1"]
            and candidate.operands[1].type == deps["imm"]
        ):
            selector = candidate.operands[1].imm & 0xFFFFFFFF
            selector_source = candidate.address
        break
    candidate = None
    if selector is not None:
        candidate = {
            **record,
            "selector": selector,
            "selector_source_site": selector_source,
            "intervening_calls": list(
                reversed([item for item in calls if item["site"] > selector_source])
            ),
        }
    return record, candidate


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
    basic_block_slot37_calls = []
    basic_block_selector_candidates = []
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
            VIEWSETTINGMENU_FACTORY_AVAILABILITY["factory_entry"],
            VIEWSETTINGMENU_FACTORY_AVAILABILITY["constructor_entry"],
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
            basic_block, selector_candidate = _whole_basic_block_slot37(
                items, call_index, deps
            )
            if basic_block is not None:
                basic_block_slot37_calls.append(basic_block)
            if selector_candidate is not None:
                basic_block_selector_candidates.append(selector_candidate)
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
    return (
        calls,
        basic_block_slot37_calls,
        basic_block_selector_candidates,
        complete_count,
        incomplete_count,
        direct_edges,
    )


def _productaction_publication(elf, relative, blob, mappings):
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
    all_relocations = {}
    for section_name in (".rel.dyn", ".rel.plt"):
        section = elf.get_section_by_name(section_name)
        if section is None:
            continue
        for relocation_index, relocation in enumerate(section.iter_relocations()):
            all_relocations[relocation["r_offset"]] = (
                section_name,
                relocation_index,
                relocation,
            )
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
    typed_records = []
    for record in records:
        cell = record["cell"]
        address_point = cell - 37 * 4
        header = address_point - 8
        try:
            _rtti_section, _rtti_index, rtti_relocation = all_relocations[
                header + 4
            ]
            _slot_section, _slot_index, slot_relocation = all_relocations[
                address_point + 64 * 4
            ]
        except KeyError as exc:
            raise RuntimeError("typed ProductAction table relation is missing") from exc
        rtti_raw = _word(blob, mappings, header + 4)
        rtti_symbol = None
        if (
            rtti_relocation["r_info_type"] == 23
            and rtti_relocation["r_info_sym"] == 0
        ):
            rtti = rtti_raw
        elif rtti_relocation["r_info_type"] == 2:
            rtti_symbol_record = dynsym.get_symbol(rtti_relocation["r_info_sym"])
            rtti_symbol = rtti_symbol_record.name
            rtti = (rtti_symbol_record["st_value"] + rtti_raw) & 0xFFFFFFFF
        else:
            raise RuntimeError("typed ProductAction RTTI header differs")
        try:
            _name_section, _name_index, name_relocation = all_relocations[rtti + 4]
        except KeyError as exc:
            raise RuntimeError("typed ProductAction RTTI name is missing") from exc
        if (
            name_relocation["r_info_type"] != 23
            or name_relocation["r_info_sym"] != 0
        ):
            raise RuntimeError("typed ProductAction RTTI name differs")
        slot_symbol = None
        if slot_relocation["r_info_sym"]:
            slot_symbol = dynsym.get_symbol(slot_relocation["r_info_sym"]).name
        typed_records.append(
            {
                "module": relative,
                "product_cell": cell,
                "address_point": address_point,
                "header": header,
                "offset_to_top": _word(blob, mappings, header),
                "rtti": rtti,
                "rtti_rel_type": rtti_relocation["r_info_type"],
                "rtti_symbol": rtti_symbol,
                "type_name": _cstring(
                    blob, mappings, _word(blob, mappings, rtti + 4)
                ),
                "slot64_cell": address_point + 64 * 4,
                "slot64_raw": _word(blob, mappings, address_point + 64 * 4),
                "slot64_rel_type": slot_relocation["r_info_type"],
                "slot64_symbol": slot_symbol,
            }
        )
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
        typed_records,
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
    typed_publication_records = []
    basic_block_calls = []
    basic_block_selector_candidates = []
    for relative in elf_paths:
        path = FIRMWARE_ROOT / relative
        blob = path.read_bytes()
        elf = deps["ELFFile"](io.BytesIO(blob))
        mappings = _mappings(elf)
        publication = _productaction_publication(elf, relative, blob, mappings)
        if publication is not None:
            module, records, typed_records = publication
            publication_modules.append(module)
            publication_records.extend(records)
            typed_publication_records.extend(typed_records)
        if elf.get_section_by_name(".ARM.exidx") is None:
            excluded.append({"module": relative, "reason": "missing-arm-exidx"})
            continue
        exidx = _exidx_ranges(elf, blob)
        if not exidx:
            excluded.append({"module": relative, "reason": "missing-arm-exidx"})
            continue
        (
            calls,
            module_basic_block_calls,
            module_selector_candidates,
            complete,
            incomplete,
            direct_edges,
        ) = _canonical_calls(blob, elf, deps, exidx)
        basic_block_calls.extend(
            {"module": relative, **item} for item in module_basic_block_calls
        )
        basic_block_selector_candidates.extend(
            {"module": relative, **item} for item in module_selector_candidates
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
    typed_result = {
        "scope": TYPED_PRODUCTACTION_PUBLICATIONS["scope"],
        "record_count": len(typed_publication_records),
        "records_sha256": _digest(typed_publication_records),
        "zero_offset_to_top_count": sum(
            item["offset_to_top"] == 0 for item in typed_publication_records
        ),
        "rtti_name_resolved_count": sum(
            bool(item["type_name"]) for item in typed_publication_records
        ),
        "rtti_header_relative_count": sum(
            item["rtti_rel_type"] == 23 for item in typed_publication_records
        ),
        "rtti_header_abs32_count": sum(
            item["rtti_rel_type"] == 2 for item in typed_publication_records
        ),
        "slot64_cell_count": len(typed_publication_records),
        "slot64_relative_count": sum(
            item["slot64_rel_type"] == 23 for item in typed_publication_records
        ),
        "slot64_abs32_count": sum(
            item["slot64_rel_type"] == 2 for item in typed_publication_records
        ),
        "viewsettingmenu": copy.deepcopy(
            next(
                item
                for item in typed_publication_records
                if item["module"] == "lib/viewUnified2.so"
                and item["type_name"] == "15ViewSettingMenu"
            )
        ),
        "viewcreativestyle": copy.deepcopy(
            next(
                item
                for item in typed_publication_records
                if item["module"] == "lib/viewUnified2.so"
                and item["type_name"] == "17ViewCreativeStyle"
            )
        ),
        "typed_publication_proves_invocation": False,
    }
    selector_histogram = {}
    for item in basic_block_selector_candidates:
        key = str(item["selector"])
        selector_histogram[key] = selector_histogram.get(key, 0) + 1
    additional = next(
        item
        for item in basic_block_calls
        if item["module"] == "lib/libObj.so" and item["call_site"] == 0x140664
    )
    additional_candidate = next(
        item
        for item in basic_block_selector_candidates
        if item["module"] == "lib/libObj.so" and item["call_site"] == 0x140664
    )
    widened_result = {
        "scope": WIDENED_BASIC_BLOCK_SLOT37_SCAN["scope"],
        "complete_owner_count": complete_owner_count,
        "incomplete_owner_count": incomplete_owner_count,
        "call_count": len(basic_block_calls),
        "call_records_sha256": _digest(basic_block_calls),
        "explicit_selector_candidate_count": len(basic_block_selector_candidates),
        "explicit_selector_candidates_sha256": _digest(
            basic_block_selector_candidates
        ),
        "explicit_selector_histogram": selector_histogram,
        "selector_10_candidate_count": sum(
            item["selector"] == 10 for item in basic_block_selector_candidates
        ),
        "intervening_call_candidate_count": sum(
            bool(item["intervening_calls"])
            for item in basic_block_selector_candidates
        ),
        "intervening_call_preservation_validated_count": 0,
        "additional_call": {
            **additional,
            "selector_candidate_source_site": additional_candidate[
                "selector_source_site"
            ],
            "selector_candidate": additional_candidate["selector"],
            "intervening_call_site": additional_candidate["intervening_calls"][
                0
            ]["site"],
            "intervening_call_target": additional_candidate[
                "intervening_calls"
            ][0]["target"],
            "receiver_type": "N9OBJEFFECT24SequenceDecodeBackgroundE",
            "receiver_address_point": 0x131F4D0,
            "viewsettingmenu_receiver": False,
            "accepted": False,
        },
        "non_basic_block_or_runtime_indirect_scanned": False,
        "whole_runtime_absence_proven": False,
    }
    return (
        scan,
        slot64,
        publication_result,
        typed_result,
        widened_result,
        vu2_direct_edges,
    )


def _require_direct(context, deps, site, target, label):
    item = _instruction(context["blob"], context["mappings"], deps, site)
    if _direct_target(item, deps) != target or not (
        item.group(deps["call_group"]) or item.group(deps["jump_group"])
    ):
        raise RuntimeError(label + " differs")


def _validate_sequence_false_lead(deps, blob=None):
    path = FIRMWARE_ROOT / "lib/libObj.so"
    blob = path.read_bytes() if blob is None else bytes(blob)
    stream = io.BytesIO(blob)
    elf = deps["ELFFile"](stream)
    mappings = _mappings(elf)
    exidx = _exidx_ranges(elf, blob)
    rels, by_site = _relocations(elf)
    context = {
        "blob": blob,
        "mappings": mappings,
        "exidx": exidx,
        "rels": rels,
        "by_site": by_site,
    }
    if (
        _owner(exidx, 0x1405E8) != (0x1405E8, 0x140824)
        or _owner(exidx, 0x140FC8) != (0x140FC8, 0x141160)
    ):
        raise RuntimeError("Sequence ProductAction owner differs")
    for site, mnemonic, operands in (
        (0x1405F0, "mov", "r4, r0"),
        (0x14062C, "movs", "r1, #0x10"),
        (0x140638, "ldr", "r3, [r4]"),
        (0x14065A, "ldr.w", "r3, [r3, #0x94]"),
        (0x140662, "mov", "r0, r4"),
        (0x140664, "blx", "r3"),
        (0x140FCE, "mov", "r4, r0"),
        (0x141042, "mov", "r0, r4"),
    ):
        _require_text(
            _instruction(blob, mappings, deps, site),
            mnemonic,
            operands,
            "Sequence ProductAction dataflow",
        )
    _require_direct(context, deps, 0x140634, 0x107AC8, "Sequence helper call")
    _require_direct(context, deps, 0x141046, 0x1405E8, "Sequence parent call")
    expected_relatives = (
        (23_358, 0x131F4C0, 0xE4E9E4),
        (23_359, 0x131F4C4, 0x13227D0),
        (23_360, 0x131F4CC, 0x131F4BC),
        (23_365, 0x131F4F0, 0x140FC8),
    )
    for index, site, target in expected_relatives:
        actual_index, relocation = by_site[site]
        if (
            actual_index != index
            or relocation["r_info_type"] != 23
            or relocation["r_info_sym"] != 0
            or (_word(blob, mappings, site) & ~1) != target
        ):
            raise RuntimeError("Sequence ProductAction relocation differs")
    dynsym = elf.get_section_by_name(".dynsym")
    abi = rels[76_748]
    if (
        abi["r_offset"] != 0x131F4BC
        or abi["r_info_type"] != 2
        or dynsym.get_symbol(abi["r_info_sym"]).name
        != "_ZTVN10__cxxabiv120__si_class_type_infoE"
        or _word(blob, mappings, 0x131F4C8) != 0
        or _cstring(blob, mappings, 0xE4E9E4)
        != "N9OBJEFFECT24SequenceDecodeBackgroundE"
    ):
        raise RuntimeError("Sequence ProductAction RTTI differs")
    return copy.deepcopy(WIDENED_BASIC_BLOCK_SLOT37_SCAN["additional_call"])


def _resolve_pic_string(context, deps, record, role):
    load_site = record[role + "_load_site"]
    add_site = record[role + "_add_site"]
    literal_cell = record[role + "_literal_cell"]
    literal_word = record[role + "_literal_word"]
    address = record[role + "_address"]
    load = _instruction(context["blob"], context["mappings"], deps, load_site)
    add = _instruction(context["blob"], context["mappings"], deps, add_site)
    if (
        _literal_address(load, deps) != literal_cell
        or _word(context["blob"], context["mappings"], literal_cell)
        != literal_word
        or len(load.operands) != 2
        or len(add.operands) < 2
        or load.operands[0].type != deps["reg"]
        or add.operands[0].type != deps["reg"]
        or load.operands[0].reg != add.operands[0].reg
        or not any(
            operand.type == deps["reg"] and operand.reg == deps["pc"]
            for operand in add.operands[1:]
        )
        or (literal_word + add_site + 4) & 0xFFFFFFFF != address
        or _cstring(context["blob"], context["mappings"], address)
        != record[role]
    ):
        raise RuntimeError("ViewSettingMenu registration " + role + " differs")


def _validate_viewsettingmenu_factory(blob, deps, direct_edges):
    stream = io.BytesIO(blob)
    elf = deps["ELFFile"](stream)
    mappings = _mappings(elf)
    rels, by_site = _relocations(elf)
    exidx = _exidx_ranges(elf, blob)
    dynsym = elf.get_section_by_name(".dynsym")
    context = {
        "blob": blob,
        "mappings": mappings,
        "rels": rels,
        "by_site": by_site,
        "exidx": exidx,
        "plt_symbols": _plt_symbols(elf, blob, mappings),
    }
    expected = VIEWSETTINGMENU_FACTORY_AVAILABILITY
    symbol = dynsym.get_symbol(expected["factory_symbol_index"])
    if (
        symbol.name != expected["factory_symbol"]
        or (symbol["st_value"] & ~1) != expected["factory_entry"]
        or symbol["st_size"] != expected["factory_end"] - expected["factory_entry"]
        or _owner(exidx, expected["factory_entry"])
        != (expected["factory_entry"], expected["factory_end"])
        or _owner(exidx, expected["constructor_entry"])
        != (expected["constructor_entry"], expected["constructor_end"])
    ):
        raise RuntimeError("ViewSettingMenu factory identity differs")
    allocation = _instruction(blob, mappings, deps, expected["allocation_size_site"])
    if (
        allocation.id != deps["mov"]
        or allocation.operands[0].reg != deps["r0"]
        or allocation.operands[1].type != deps["imm"]
        or allocation.operands[1].imm != expected["allocation_size"]
        or _call_symbol(
            blob,
            mappings,
            deps,
            context["plt_symbols"],
            expected["allocation_call_site"],
        )
        != expected["allocation_symbol"]
    ):
        raise RuntimeError("ViewSettingMenu factory allocation differs")
    _require_direct(
        context,
        deps,
        expected["constructor_call_site"],
        expected["constructor_entry"],
        "ViewSettingMenu constructor call",
    )
    if (
        direct_edges[expected["factory_entry"]]
        or direct_edges[expected["constructor_entry"]]
        != [
            {
                "site": expected["constructor_call_site"],
                "owner_start": expected["factory_entry"],
                "owner_end": expected["factory_end"],
            }
        ]
        or _relative_address_taken_records(
            {"elf": elf, "blob": blob, "mappings": mappings, "rels": rels},
            expected["factory_entry"],
            expected["factory_end"],
        )
    ):
        raise RuntimeError("ViewSettingMenu factory publication differs")
    vptr = expected["vptr_store"]
    if (
        _literal_address(
            _instruction(blob, mappings, deps, vptr["pic_base_load_site"]), deps
        )
        != vptr["pic_base_literal_cell"]
        or _word(blob, mappings, vptr["pic_base_literal_cell"])
        != vptr["pic_base_literal_word"]
        or vptr["pic_base_literal_word"] + vptr["pic_base_add_site"] + 4
        != vptr["pic_base"]
        or _literal_address(
            _instruction(blob, mappings, deps, vptr["got_offset_load_site"]),
            deps,
        )
        != vptr["got_offset_literal_cell"]
        or _word(blob, mappings, vptr["got_offset_literal_cell"])
        != vptr["got_offset"]
        or vptr["pic_base"] + vptr["got_offset"] != vptr["got_cell"]
    ):
        raise RuntimeError("ViewSettingMenu vptr PIC provenance differs")
    actual_index, relocation = by_site[vptr["got_cell"]]
    if (
        actual_index != vptr["got_relocation_index"]
        or relocation["r_info_type"] != 23
        or relocation["r_info_sym"] != 0
        or _word(blob, mappings, vptr["got_cell"]) != vptr["vtable_header"]
    ):
        raise RuntimeError("ViewSettingMenu vptr GOT differs")
    for site, mnemonic, operands in (
        (0x204CA8, "ldr", "r3, [r4, r3]"),
        (0x204CAA, "add.w", "r2, r3, #8"),
        (0x204CB2, "str", "r2, [r5]"),
    ):
        _require_text(
            _instruction(blob, mappings, deps, site),
            mnemonic,
            operands,
            "ViewSettingMenu vptr store",
        )
    row = expected["registration_row"]
    if _owner(exidx, row["owner"]["start"]) != (
        row["owner"]["start"],
        row["owner"]["end"],
    ):
        raise RuntimeError("ViewSettingMenu registration owner differs")
    for role in ("alias", "component", "factory"):
        _resolve_pic_string(context, deps, row, role)
    if (
        _call_symbol(
            blob, mappings, deps, context["plt_symbols"], row["get_call_site"]
        )
        != "_ZN11IdGenerator3GetEPKc"
        or _call_symbol(
            blob, mappings, deps, context["plt_symbols"], row["add_call_site"]
        )
        != "_ZN9IdSoTable3addEiPKcS1_"
    ):
        raise RuntimeError("ViewSettingMenu registration calls differ")
    for site, mnemonic, operands in (
        (row["id_to_key_site"], "mov", "r1, r0"),
        (row["receiver_site"], "mov", "r0, r4"),
    ):
        _require_text(
            _instruction(blob, mappings, deps, site),
            mnemonic,
            operands,
            "ViewSettingMenu registration ABI",
        )
    component_matches = sum(
        path.is_file() and not path.is_symlink() and path.name == row["component"]
        for path in FIRMWARE_ROOT.rglob(row["component"])
    )
    if component_matches != row["component_file_match_count"]:
        raise RuntimeError("ViewSettingMenu component inventory differs")
    return copy.deepcopy(expected)


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
        VIEWSETTINGMENU_FACTORY_AVAILABILITY["factory_entry"]: [],
        VIEWSETTINGMENU_FACTORY_AVAILABILITY["constructor_entry"]: [
            {
                "site": VIEWSETTINGMENU_FACTORY_AVAILABILITY[
                    "constructor_call_site"
                ],
                "owner_start": VIEWSETTINGMENU_FACTORY_AVAILABILITY[
                    "factory_entry"
                ],
                "owner_end": VIEWSETTINGMENU_FACTORY_AVAILABILITY["factory_end"],
            }
        ],
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
    (
        scan,
        slot64,
        publication,
        typed_publications,
        widened_scan,
        direct_edges,
    ) = _scan_inventory(deps, elf_paths)
    classification = _validate_vu2_classification(deps, direct_edges)
    view_blob = SOURCE_PATH.read_bytes()
    availability = _validate_viewsettingmenu_factory(view_blob, deps, direct_edges)
    if _validate_sequence_false_lead(deps) != widened_scan["additional_call"]:
        raise RuntimeError("Sequence ProductAction false lead differs")
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
    document["typed_productaction_publications"] = typed_publications
    document["widened_basic_block_slot37_scan"] = widened_scan
    document["viewsettingmenu_factory_availability"] = availability
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
