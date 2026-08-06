"""Fail-closed α6400 generic widget hit-test vtable evidence contract."""
from __future__ import annotations

import copy
import hashlib
import json
import re


VIEW_UNIFIED2_SHA256 = "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2"
VIEW_UNIFIED2_SIZE = 11_530_552
TOUCHPAD_TERMINAL_DIGEST = "d4b9a5520d65b5243db55f84651cc19dbeca92a351196de37532eea886ec1d78"
TOUCH_API_CALLERS_DIGEST = "51715c6db751360960ee27db372b8c58b5e2f12c3c9a8393795d0f578ebd9688"
SYS_IS_HIT_DYNSYM = 1086
IS_HIT_DYNSYM = 66
ON_DUMP_DYNSYM = 569
SET_HIT_MARGIN_DYNSYM = 860
RTTI_DYNSYM = 476
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FORBIDDEN = ("raw", "byte", "disassembly", "instruction", "key", "device", "usb", "write", "flash", "package", "payload")

# Exact ELF virtual-slot addresses, captured only from R_ARM_ABS32 relocations for
# dynsym 1086.  The exporter must derive this same complete sequence; it never
# discovers vtables through arbitrary pointer values.
_SYS_IS_HIT_ADDRESSES = tuple(int(value) for value in """9457844,9508364,9508820,9509260,9509724,9510164,9510628,9511084,9511540,9511996,9512452,9512892,9513356,9513812,9514268,9514708,9515164,9515628,9516068,9516532,9516988,9517444,9517900,9518356,9518812,9519268,9519708,9520164,9520628,9521084,9521524,9521980,9522444,9522900,9523356,9523796,9524260,9524700,9525156,9525612,9526076,9526516,9526972,9527436,9527892,9528348,9528788,9529252,9529692,9530156,9530596,9531060,9531500,9531964,9532404,9532868,9533324,9533780,9534236,9534676,9535132,9535596,9536052,9536492,9536956,9537412,9537852,9538308,9538772,9539228,9539668,9540132,9540572,9541036,9541492,9541932,9542396,9542852,9543292,9543748,9544204,9544660,9545124,9545580,9546036,9546476,9546932,9547388,9547844,9548308,9548748,9549212,9549668,9550124,9550564,9551028,9551484,9551924,9552380,9552836,9553300,9553740,9554196,9554660,9555100,9555564,9556004,9556460,9556924,9557364,9557820,9558284,9558724,9559188,9559644,9560084,9560540,9560996,9561452,9561916,9562356,9562820,9563260,9563724,9564164,9564620,9565076,9565540,9565980,9566444,9566884,9567340,9567796,9568252,9568716,9569172,9569628,9570084,9570540,9570996,9571452,9571908,9572348,9572812,9573268,9573708,9574172,9574628,9575084,9575524,9575980,9576444,9576900,9577356,9577796,9578260,9578700,9579164,9579604,9580068,9580524,9580964,9581420,9581884,9582340,9582796,9583236,9583692,9584156,9584596,9585060,9585516,9585956,9586412,9586868,9587324,9587788,9588228,9588692,9589132,9589596,9590052,9590492,9590948,9591404,9591868,9592324,9592764,9593228,9593668,9594124,9594580,9595044,9595500,9595956,9596396,9596860,9597300,9597764,9598220,9598660,9599116,9599572,9600036,9600492,9600948,9601388,9601844,9602308,9602764,9603204,9603660,9604124,9604580,9605020,9605484,9605924,9606380,9606844,9607284,9607748,9608204,9608660,9609116,9609556,9610020,9610460,9610924,9611380,9611820,9612276,9612740,9613196,9613636,9614100,9614540,9615004,9615444,9615908,9616364,9616820,9617284,9617724,9617940,9618380,9618836,9619292,9619748,9619940,9620404,9620860,9621316,9621780,9622236,9622716,9623172,9623652,9624124,9624580,9625052,9625492,9625948,9626436,9626916,9627372,9627844,9628308,9628764,9629220,9629748,9630204,9630652,9631124,9631596,9632060,9632516,9632972,9633436,9633876,9634332,9634788,9635260,9635756,9636212,9636692,9637148,9637588,9638076,9638532,9639012,9639476,9639932,9640428,9640868,9641356,9641812,9642268,9642724,9643212,9643772,9644220,9644796,9645276,9645756,9646212,9646676,9647140,9647596,9648052,9648508,9648948,9649436,9649924,9650412,9650916,9651372,9651820,9652292,9652748,9653228,9653668,9654132,9654596,9655068,9655524,9655996,9656436,9656900,9657404,9657924,9658380,9658820,9659284,9659764,9660244,9660700,9661196,9661676,9662140,9662668,9663148,9663604,9664076,9664532,9664980,9665476,9665972,9666436,9666892,9667340,9667804,9668244,9668708,9669172,9669644,9669860,9670348,9670804,9671260,9671724,9672188,9672716,9673172,9673636,9674092,9674548,9674988,9675484,9675956,9676396,9676852,9677316,9677772,9678236,9678692,9679156,9679612,9680076,9680540,9680996,9681452,9681908,9682372,9682812,9683348,9683804,9684268,9684732,9685180,9685636,9686100,9686540,9686988,9687468,9687924,9688388,9688860,9689316,9689756,9690228,9690724,9691180,9691652,9692116,9692572,9693036,9693492""".split(","))
_EXCEPTIONS = (0x92D114, 0x92EC5C, 0x9319EC, 0x9324CC, 0x9328BC, 0x9384DC, 0x93B134, 0x93B4CC, 0x93CA84, 0x93DE64)


class WidgetHitTestVtablesError(ValueError):
    """Raised when generic widget evidence is incomplete, unsafe, or promoted."""


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _forbid(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if any(token in str(key).casefold() for token in _FORBIDDEN):
                raise WidgetHitTestVtablesError("unsafe or reconstructive evidence field")
            _forbid(child)
    elif isinstance(value, list):
        for child in value:
            _forbid(child)


def _exact(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise WidgetHitTestVtablesError(label + " fields differ")
    return value


def _family(address, ordinal):
    return {
        "on_dump_address": address - 4,
        "on_dump_relocation_index": 101654 + ordinal,
        "sys_is_hit_address": address,
        "sys_is_hit_relocation_index": 102061 + ordinal,
        "is_hit_address": address + 4,
        "is_hit_relocation_index": 102468 + ordinal,
        "rtti_header_address": address - 0x98,
        "address_point": address - 0x90,
        "rtti_type": "LayoutableWidgetBase" if ordinal == 0 else None,
    }


_FAMILIES = [_family(address, ordinal) for ordinal, address in enumerate(_SYS_IS_HIT_ADDRESSES)]
FAMILY_DIGEST = "15deaac14585f3be0c81fc2c88ec86631e18a5d279110b8fe7bd56a9be79aed3"
CLAIMS = {
    "generic_widget_hit_test_infrastructure_found": True,
    "typed_layoutable_widget_base_boundary_found": True,
    "menu_touch_hit_test_found": False,
    "menu_touch_selection_found": False,
    "touch_coordinate_transform_found": False,
    "gesture_found": False,
    "local_widget_identity_found": False,
}
EXPECTED_RAW_EXPORT = {
    "schema_version": 1,
    "program": "viewUnified2.so",
    "sha256": VIEW_UNIFIED2_SHA256,
    "file_size": VIEW_UNIFIED2_SIZE,
    "analysis_mode": {"read_only": True, "static_elf_metadata": True, "source_unchanged": True},
    "program_changed": False,
    "dynamic_symbols": [
        {"name": "WidgetBase::sys_isHit", "dynsym_index": SYS_IS_HIT_DYNSYM},
        {"name": "Widget::isHit", "dynsym_index": IS_HIT_DYNSYM},
    ],
    "chain_symbols": {
        "on_dump": {"name": "Widget::onDump", "dynsym_index": ON_DUMP_DYNSYM},
        "sys_is_hit": {"name": "WidgetBase::sys_isHit", "dynsym_index": SYS_IS_HIT_DYNSYM},
        "is_hit": {"name": "Widget::isHit", "dynsym_index": IS_HIT_DYNSYM},
        "set_hit_margin": {"name": "Widget::setHitMargin", "dynsym_index": SET_HIT_MARGIN_DYNSYM},
    },
    "families": _FAMILIES,
    "typed_layoutable_widget_base": {
        "class_name": "LayoutableWidgetBase",
        "rtti_cell_elf": 0x90501C, "rtti_relocation_index": 89099,
        "address_point_elf": 0x905024, "address_point_analysis": 0x915024, "address_point_relocation_index": 36807,
        "sys_is_hit_slot": {"slot": 36, "elf_address": 0x9050B4, "analysis_address": 0x9150B4, "relocation_index": 102061},
        "is_hit_slot": {"slot": 37, "elf_address": 0x9050B8, "analysis_address": 0x9150B8, "relocation_index": 102468},
        "set_hit_margin_slot": {"slot": 38, "elf_address": 0x9050BC, "analysis_address": 0x9150BC, "relocation_index": 102875},
    },
    "set_hit_margin_summary": {"family_count": 397, "exception_sys_is_hit_addresses": list(_EXCEPTIONS), "dynsym_index": SET_HIT_MARGIN_DYNSYM},
    "untyped_header_summary": {"family_count": 406, "dynamically_named_rtti_table_count": 1, "class_or_object_identity_assigned": False},
    "prior_touchpad_terminal": {"analysis_contract": "touchpad_terminal_boundary", "artifact_sha256": TOUCHPAD_TERMINAL_DIGEST},
    "prior_touch_api_callers": {"analysis_contract": "touch_api_callers", "artifact_sha256": TOUCH_API_CALLERS_DIGEST},
    "ordered_root_paths": {"touchpad_terminal_paths": [], "touch_api_caller_paths": []},
    "claims": CLAIMS,
    "truncated": False,
}


def normalize_widget_hit_test_vtables_export(document):
    """Accept only this exact generic hit-test vtable inventory."""
    _forbid(document)
    fields = set(EXPECTED_RAW_EXPORT)
    candidate = _exact(document, fields, "widget hit-test export")
    for field in fields - {"families"}:
        if candidate[field] != EXPECTED_RAW_EXPORT[field]:
            raise WidgetHitTestVtablesError(field + " is not pinned")
    families = candidate["families"]
    if not isinstance(families, list) or len(families) != 407 or _digest(families) != FAMILY_DIGEST:
        raise WidgetHitTestVtablesError("complete adjacent family inventory differs")
    family_fields = set(_FAMILIES[0])
    for ordinal, item in enumerate(families):
        _exact(item, family_fields, "family")
        if item != _FAMILIES[ordinal]:
            raise WidgetHitTestVtablesError("family chain is not exactly adjacent")
    return {
        "artifact_sha256": _digest(candidate),
        "family_count": 407,
        "sys_is_hit_reference_count": 407,
        "is_hit_reference_count": 407,
        "named_set_hit_margin_count": 397,
        "typed_rtti_table_count": 1,
        "claims": copy.deepcopy(CLAIMS),
    }


def validate_widget_hit_test_vtables_report(document):
    _forbid(document)
    report = _exact(document, {"schema_version", "analysis_scope", "camera_policy", "camera_executed", "installable", "camera_test_eligible", "source", "export_summary", "typed_boundary", "set_hit_margin_summary", "ordered_root_paths", "claims", "readiness", "conclusion"}, "report")
    if report["schema_version"] != 1 or report["analysis_scope"] != "offline-static-widget-hit-test-vtables" or report["camera_policy"] != "physically-disconnected":
        raise WidgetHitTestVtablesError("report scope differs")
    if any(report[key] is not False for key in ("camera_executed", "installable", "camera_test_eligible")):
        raise WidgetHitTestVtablesError("report promotes camera activity")
    expected = normalize_widget_hit_test_vtables_export(copy.deepcopy(EXPECTED_RAW_EXPORT))
    if report["source"] != {"module": "lib/viewUnified2.so", "size": VIEW_UNIFIED2_SIZE, "sha256": VIEW_UNIFIED2_SHA256} or report["export_summary"] != {key: expected[key] for key in expected if key != "claims"}:
        raise WidgetHitTestVtablesError("report source or summary differs")
    if report["typed_boundary"] != EXPECTED_RAW_EXPORT["typed_layoutable_widget_base"] or report["set_hit_margin_summary"] != EXPECTED_RAW_EXPORT["set_hit_margin_summary"] or report["ordered_root_paths"] != EXPECTED_RAW_EXPORT["ordered_root_paths"] or report["claims"] != CLAIMS or report["readiness"] != "GENERIC_HIT_TEST_INFRASTRUCTURE_ONLY" or report["conclusion"] != "The target contains a generic widget hit-test vtable family and one RTTI-typed LayoutableWidgetBase boundary. Local widget identity, menu hit-test routing, coordinate transforms, gesture paths, and selection dispatch remain unresolved; the ordered prior touch roots remain empty.":
        raise WidgetHitTestVtablesError("report promotes unestablished behavior")
    return copy.deepcopy(report)
