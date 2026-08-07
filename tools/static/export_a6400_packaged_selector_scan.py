"""Validate the bounded packaged updater-selector false leads.

The exporter reads pinned α6400 files only.  It emits metadata, source
identities, and conservative joins; it never executes a Sony program or writes
to a camera/device.
"""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pmca.analysis.cxd90045_transition_report import PACKAGED_SELECTOR_EVIDENCE
from tools.static import export_a6400_creative_style_runtime_binding as _elf


SOURCE_BASE = (
    ROOT / ".artifacts" / "decrypted" / "a6400-tw-v2.00" / "ma1co"
    / "firmware.tar_unpacked" / "0700_part_image" / "dev"
    / "nflasha15_unpacked"
)


def sources_available() -> bool:
    return all(
        (SOURCE_BASE / record["path"]).is_file()
        and not (SOURCE_BASE / record["path"]).is_symlink()
        for record in PACKAGED_SELECTOR_EVIDENCE["sources"].values()
    )


def dependencies_available() -> bool:
    return _elf.dependencies_available()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _validate_sources() -> None:
    for label, record in PACKAGED_SELECTOR_EVIDENCE["sources"].items():
        path = SOURCE_BASE / record["path"]
        if (
            not path.is_file()
            or path.is_symlink()
            or path.stat().st_size != record["bytes"]
            or _sha256(path) != record["sha256"]
        ):
            raise RuntimeError(f"Packaged selector {label} source differs")


def _cstring(blob: bytes, mappings, address: int) -> str:
    data = bytearray()
    for offset in range(256):
        value = _elf._at(blob, mappings, address + offset, 1)[0]
        if value == 0:
            return data.decode("ascii")
        if value < 0x20 or value >= 0x7F:
            break
        data.append(value)
    raise RuntimeError("Packaged selector string differs")


def _context(source: str) -> dict:
    path = SOURCE_BASE / PACKAGED_SELECTOR_EVIDENCE["sources"][source]["path"]
    blob = path.read_bytes()
    deps = _elf._dependencies()
    stream = path.open("rb")
    try:
        elf = deps["ELFFile"](stream)
        mappings = _elf._mappings(elf)
        return {
            "blob": blob,
            "deps": deps,
            "stream": stream,
            "elf": elf,
            "mappings": mappings,
            "exidx": _elf._exidx_ranges(elf, blob),
            "plt": _elf._plt_symbols(elf, blob, mappings),
        }
    except BaseException:
        stream.close()
        raise


def _require_pc_literal_word(context: dict, site: int, register: int, value: int, label: str) -> None:
    item = _elf._transport._instruction(
        context["blob"], context["mappings"], context["deps"], site
    )
    deps = context["deps"]
    if (
        item.id != deps["ldr"]
        or len(item.operands) != 2
        or item.operands[0].type != deps["reg"]
        or item.operands[0].reg != register
        or item.operands[1].type != deps["mem"]
        or item.operands[1].mem.base != deps["pc"]
        or item.operands[1].mem.index != 0
        or item.writeback
    ):
        raise RuntimeError(label + " literal load differs")
    literal_site = ((site + 4) & ~3) + item.operands[1].mem.disp
    if _elf._word(context["blob"], context["mappings"], literal_site) != value:
        raise RuntimeError(label + " literal value differs")


def _require_pc_relative_address(
    context: dict,
    load_site: int,
    add_site: int,
    register: int,
    address: int,
    label: str,
) -> None:
    _require_pc_literal_word(context, load_site, register, _elf._word(
        context["blob"],
        context["mappings"],
        ((load_site + 4) & ~3)
        + _elf._transport._instruction(
            context["blob"], context["mappings"], context["deps"], load_site
        ).operands[1].mem.disp,
    ), label)
    add = _elf._transport._instruction(
        context["blob"], context["mappings"], context["deps"], add_site
    )
    deps = context["deps"]
    if (
        add.id != deps["add"]
        or len(add.operands) != 2
        or add.operands[0].type != deps["reg"]
        or add.operands[0].reg != register
        or add.operands[1].type != deps["reg"]
        or add.operands[1].reg != deps["pc"]
    ):
        raise RuntimeError(label + " PC-relative add differs")
    load = _elf._transport._instruction(
        context["blob"], context["mappings"], context["deps"], load_site
    )
    literal_site = ((load_site + 4) & ~3) + load.operands[1].mem.disp
    resolved = (_elf._word(context["blob"], context["mappings"], literal_site) + add_site + 4) & 0xFFFFFFFF
    if resolved != address:
        raise RuntimeError(label + " resolved address differs")


def _require_shift(context: dict, site: int, mnemonic: str, immediate: int, label: str) -> None:
    item = _elf._transport._instruction(
        context["blob"], context["mappings"], context["deps"], site
    )
    deps = context["deps"]
    if (
        not item.mnemonic.startswith(mnemonic)
        or len(item.operands) != 3
        or item.operands[0].type != deps["reg"]
        or item.operands[0].reg != deps["r0"]
        or item.operands[1].type != deps["reg"]
        or item.operands[1].reg != deps["r0"]
        or item.operands[2].type != deps["imm"]
        or item.operands[2].imm != immediate
    ):
        raise RuntimeError(label + " identifier mask differs")


def _require_indirect_call(context: dict, site: int, register: int, label: str) -> None:
    item = _elf._transport._instruction(
        context["blob"], context["mappings"], context["deps"], site
    )
    deps = context["deps"]
    if (
        not item.group(deps["call_group"])
        or _elf._direct_target(item, deps) is not None
        or len(item.operands) != 1
        or item.operands[0].type != deps["reg"]
        or item.operands[0].reg != register
    ):
        raise RuntimeError(label + " indirect dispatch differs")


def _require_compare(context: dict, site: int, register: int, value: int, label: str) -> None:
    item = _elf._transport._instruction(
        context["blob"], context["mappings"], context["deps"], site
    )
    deps = context["deps"]
    if (
        item.id != deps["cmp"]
        or len(item.operands) != 2
        or item.operands[0].type != deps["reg"]
        or item.operands[0].reg != register
        or item.operands[1].type != deps["imm"]
        or item.operands[1].imm != value
    ):
        raise RuntimeError(label + " comparison differs")


def _require_branch(
    context: dict,
    site: int,
    target: int,
    label: str,
    *,
    condition: int | None = None,
    instruction_id: int | None = None,
) -> None:
    item = _elf._transport._instruction(
        context["blob"], context["mappings"], context["deps"], site
    )
    deps = context["deps"]
    if (
        not item.group(deps["jump_group"])
        or _elf._direct_target(item, deps) != target
        or (condition is not None and item.cc != condition)
        or (instruction_id is not None and item.id != instruction_id)
    ):
        raise RuntimeError(label + " branch differs")


def _validate_libobj_consumers() -> None:
    path = SOURCE_BASE / PACKAGED_SELECTOR_EVIDENCE["sources"]["libobj"]["path"]
    blob = path.read_bytes()
    deps = _elf._dependencies()
    with path.open("rb") as stream:
        elf = deps["ELFFile"](stream)
        mappings = _elf._mappings(elf)
        owners = set(_elf._exidx_ranges(elf, blob))

    for record in PACKAGED_SELECTOR_EVIDENCE["libobj_literal_consumers"]:
        owner = record["owner"]
        if (owner["start"], owner["end"]) not in owners:
            raise RuntimeError("Packaged selector libObj owner differs")
        for xref in record["xrefs"]:
            load = _elf._transport._instruction(blob, mappings, deps, xref["load"])
            add = _elf._transport._instruction(blob, mappings, deps, xref["add"])
            if (
                load.id != deps["ldr"]
                or len(load.operands) != 2
                or load.operands[0].type != deps["reg"]
                or load.operands[1].type != deps["mem"]
                or load.operands[1].mem.base != deps["pc"]
                or add.id != deps["add"]
                or len(add.operands) < 2
                or add.operands[0].type != deps["reg"]
                or add.operands[0].reg != load.operands[0].reg
                or not any(
                    operand.type == deps["reg"] and operand.reg == deps["pc"]
                    for operand in add.operands[1:]
                )
            ):
                raise RuntimeError("Packaged selector libObj literal dataflow differs")
            literal_site = (
                ((load.address + 4) & ~3) + load.operands[1].mem.disp
            )
            string_address = (
                _elf._word(blob, mappings, literal_site) + add.address + 4
            ) & 0xFFFFFFFF
            if _cstring(blob, mappings, string_address) != xref["path"]:
                raise RuntimeError("Packaged selector libObj path differs")


def _validate_up_sh() -> None:
    record = PACKAGED_SELECTOR_EVIDENCE["up_sh"]
    path = SOURCE_BASE / PACKAGED_SELECTOR_EVIDENCE["sources"]["up_sh"]["path"]
    text = path.read_text(encoding="ascii")
    required = (
        "$UPDIR/mode1", "$UPDIR/mode3", "$UPDIR/mode6",
        "mode_num=2", "mode_num=3", "mode_num=4", "mode_num=6",
        "ud_send_lsi.elf $mode_num", "/dev/nflasha1",
        'func_com_mod_modreg "model" "dat2"',
        'func_com_mod_modreg "region" "dat3"',
        "/setting/updater/dat4",
    )
    if any(token not in text for token in required):
        raise RuntimeError("Packaged selector up.sh evidence differs")
    if (
        record["mode_flags"] != ["mode", "mode1", "mode3", "mode6"]
        or record["lsi_modes"] != [2, 3, 4, 6]
    ):
        raise RuntimeError("Packaged selector up.sh classification differs")


def _validate_nested_component() -> None:
    record = PACKAGED_SELECTOR_EVIDENCE["nested_updater_component"]
    path = SOURCE_BASE / PACKAGED_SELECTOR_EVIDENCE["sources"]["nested_script"]["path"]
    text = path.read_text(encoding="ascii")
    required = (
        "/dev/nflasha1", "cp /ramdsk/dat2", "cp /ramdsk/dat3",
        "cp /ramdsk/dat4 /setting/updater/", "touch /setting/updater/mode",
        "touch /setting/updater/mode6",
    )
    if any(token not in text for token in required):
        raise RuntimeError("Packaged selector nested component differs")


def _validate_crypter() -> None:
    record = PACKAGED_SELECTOR_EVIDENCE["crypter"]
    path = SOURCE_BASE / PACKAGED_SELECTOR_EVIDENCE["sources"]["crypter"]["path"]
    blob = path.read_bytes()
    deps = _elf._dependencies()
    with path.open("rb") as stream:
        elf = deps["ELFFile"](stream)
        dynsym = elf.get_section_by_name(".dynsym")
        names = {symbol.name for symbol in dynsym.iter_symbols()}
    for class_name in record["flag_classes"]:
        if not any(class_name in name for name in names):
            raise RuntimeError("Packaged selector crypter flag class differs")
    for value in (
        b"/tmp_updater/updater/bodyfs/bodylib/libupdaterbody.so",
        b"/tmp_updater/updater/bodyimg",
    ):
        if value not in blob:
            raise RuntimeError("Packaged selector crypter nested path differs")


def _printable_strings(blob: bytes) -> list[str]:
    values: list[str] = []
    current = bytearray()
    for value in blob:
        if 0x20 <= value < 0x7F:
            current.append(value)
        else:
            if len(current) >= 4:
                values.append(current.decode("ascii"))
            current.clear()
    if len(current) >= 4:
        values.append(current.decode("ascii"))
    return values


def _validate_bootin() -> None:
    record = PACKAGED_SELECTOR_EVIDENCE["bootin"]
    path = SOURCE_BASE / PACKAGED_SELECTOR_EVIDENCE["sources"]["bootin"]["path"]
    strings = _printable_strings(path.read_bytes())
    joined = "\n".join(strings)
    if any(mode not in joined for mode in record["documented_application_modes"]):
        raise RuntimeError("Packaged selector bootin mode documentation differs")
    lowered = joined.lower()
    search = record["named_reference_search"]
    hits = sum(lowered.count(needle) for needle in search["needles"])
    if search["scope"] != "printable-strings" or hits != search["hits"]:
        raise RuntimeError("Packaged selector bootin direct reference differs")


def _validate_lsi_delivery() -> None:
    expected = PACKAGED_SELECTOR_EVIDENCE["lsi_delivery"]
    sender = expected["sender"]
    sender_context = _context(sender["source"])
    try:
        deps = sender_context["deps"]
        _elf._require_owner(sender_context["exidx"], sender["owner"], "LSI sender")
        _elf._require_mov_immediate(
            sender_context["blob"], sender_context["mappings"], deps,
            0x8742, deps["r0"], sender["backup_read"]["record_id"],
            "LSI backup record",
        )
        _elf._require_add_immediate(
            sender_context["blob"], sender_context["mappings"], deps,
            0x8740, deps["r1"], deps["r7"], 7, "LSI backup byte buffer",
        )
        _elf._require_call_symbol(
            sender_context["blob"], sender_context["mappings"], deps,
            sender_context["plt"], sender["backup_read"]["site"],
            sender["backup_read"]["symbol"], "LSI backup read",
        )
        allocation = sender["message_allocation"]
        _require_pc_literal_word(
            sender_context, 0x8764, deps["r0"], allocation["destination"],
            "LSI destination",
        )
        _elf._require_move(
            sender_context["blob"], sender_context["mappings"], deps,
            0x8766, deps["r1"], deps["r7"], "LSI allocation output slot",
        )
        _elf._require_mov_immediate(
            sender_context["blob"], sender_context["mappings"], deps,
            0x8768, deps["r2"], allocation["size"], "LSI payload size",
        )
        _elf._require_call_symbol(
            sender_context["blob"], sender_context["mappings"], deps,
            sender_context["plt"], allocation["site"], allocation["symbol"],
            "LSI message allocation",
        )
        _require_pc_literal_word(
            sender_context, 0x8782, deps["r6"], sender["message_source_id"],
            "LSI source identifier",
        )
        _elf._require_memory(
            sender_context["blob"], sender_context["mappings"], deps,
            sender["source_id_store_site"], deps["str"], deps["r6"],
            deps["r5"], -4, "LSI source identifier store",
        )
        _elf._require_memory(
            sender_context["blob"], sender_context["mappings"], deps,
            0x8784, deps["ldr"], deps["r0"], deps["r4"], 4,
            "LSI mode argument",
        )
        _elf._require_call_symbol(
            sender_context["blob"], sender_context["mappings"], deps,
            sender_context["plt"], sender["mode_parse_site"], "atoi",
            "LSI numeric mode parse",
        )
        _elf._require_memory(
            sender_context["blob"], sender_context["mappings"], deps,
            sender["mode_store_site"], deps["str"], deps["r0"], deps["r5"],
            0, "LSI numeric mode store",
        )
        _require_pc_literal_word(
            sender_context, 0x8792, deps["r0"], allocation["destination"],
            "LSI send destination",
        )
        _elf._require_call_symbol(
            sender_context["blob"], sender_context["mappings"], deps,
            sender_context["plt"], sender["send_site"], "osal_snd_msg",
            "LSI send",
        )
        _elf._require_move(
            sender_context["blob"], sender_context["mappings"], deps,
            0x87A8, deps["r0"], deps["r6"], "LSI reply queue",
        )
        _elf._require_mov_immediate(
            sender_context["blob"], sender_context["mappings"], deps,
            0x87AC, deps["r2"], sender["receive_timeout_ms"],
            "LSI reply timeout",
        )
        _elf._require_call_symbol(
            sender_context["blob"], sender_context["mappings"], deps,
            sender_context["plt"], sender["receive_site"], "osal_rcv_msg_tmo",
            "LSI reply receive",
        )
    finally:
        sender_context["stream"].close()

    registration = expected["receiver_registration"]
    object_context = _context(registration["source"])
    try:
        deps = object_context["deps"]
        _elf._require_owner(
            object_context["exidx"], registration["owner"],
            "LSI receiver registration",
        )
        _require_pc_literal_word(
            object_context, registration["queue_id_load_site"], deps["r0"],
            registration["queue_id"], "LSI receiver queue",
        )
        _require_pc_relative_address(
            object_context, 0x83EC04, 0x83EC0A, deps["r1"],
            registration["context"], "LSI callback context",
        )
        _require_pc_relative_address(
            object_context, 0x83EC06, 0x83EC0C, deps["r2"],
            registration["callback"] | 1, "LSI callback",
        )
        _elf._require_call_symbol(
            object_context["blob"], object_context["mappings"], deps,
            object_context["plt"], registration["registration_site"],
            registration["symbol"], "LSI callback registration",
        )

        callback = expected["flag_callback"]
        _elf._require_owner(object_context["exidx"], callback["owner"], "LSI flag callback")
        clear = callback["clear_helper"]
        create = callback["create_helper"]
        _elf._require_owner(object_context["exidx"], clear["owner"], "LSI mode clear helper")
        _elf._require_owner(object_context["exidx"], create["owner"], "LSI mode create helper")
        _elf._require_direct_target(
            object_context["blob"], object_context["mappings"], deps,
            clear["call_site"], clear["owner"]["start"],
            "LSI mode clear", call=True,
        )
        _require_pc_relative_address(
            object_context, 0x83E54C, 0x83E550, deps["r0"],
            clear["command_address"], "LSI mode clear command",
        )
        if _cstring(
            object_context["blob"], object_context["mappings"],
            clear["command_address"],
        ) != clear["command"]:
            raise RuntimeError("LSI mode clear command differs")
        for site in (create["first_call_site"], create["second_call_site"]):
            _elf._require_direct_target(
                object_context["blob"], object_context["mappings"], deps,
                site, create["owner"]["start"], "LSI mode create", call=True,
            )
        for site, source, label in (
            (0x83E5E2, deps["r6"], "LSI base-mode create argument"),
            (0x83E61E, deps["r4"], "LSI extra-mode create argument"),
        ):
            _elf._transport._require_reg_to_reg(
                _elf._transport._instruction(
                    object_context["blob"], object_context["mappings"], deps, site
                ),
                deps,
                deps["mov"],
                deps["r0"],
                source,
                label,
            )
        if [record["path"] for record in callback["mode_path_sites"]] != callback["mode_paths"]:
            raise RuntimeError("LSI mode path inventory differs")
        for record in callback["mode_path_sites"]:
            _require_pc_relative_address(
                object_context, record["load_site"], record["add_site"],
                deps["r6"] if record["path"].endswith("/mode") else deps["r4"],
                record["address"],
                "LSI mode path",
            )
            if _cstring(
                object_context["blob"], object_context["mappings"], record["address"]
            ) != record["path"]:
                raise RuntimeError("LSI mode path differs")
        path_by_name = {record["path"]: record for record in callback["mode_path_sites"]}
        for route in callback["payload_routes"]:
            _require_compare(
                object_context, route["compare_site"], deps["r4"],
                route["mode"], "LSI mode value",
            )
            if route["mode"] == 3:
                _require_branch(
                    object_context, route["guard_branch_site"],
                    route["guard_mismatch_target"], "LSI mode-3 mismatch",
                    condition=deps["ne"],
                )
                _require_branch(
                    object_context, route["branch_site"], route["branch_target"],
                    "LSI mode-3 route", condition=deps["al"],
                )
            else:
                _require_branch(
                    object_context, route["branch_site"], route["branch_target"],
                    "LSI mode route", condition=deps["eq"],
                )
            if route["extra_mode_path"] is not None:
                path_record = path_by_name[route["extra_mode_path"]]
                if route["branch_target"] != path_record["load_site"]:
                    raise RuntimeError("LSI payload-to-path join differs")
        _require_branch(
            object_context, 0x83E608, 0x83E61E, "LSI mode-6 create join",
            condition=deps["al"],
        )
        _require_branch(
            object_context, 0x83E618, 0x83E61E, "LSI mode-1 create join",
            condition=deps["al"],
        )
        success = callback["success_acknowledgement_path"]
        _require_branch(
            object_context, success["flag_create_success_branch_site"],
            success["flag_create_success_target"], "LSI flag-create success",
            instruction_id=deps["cbz"],
        )
        _require_branch(
            object_context, 0x83E674, 0x83E63A,
            "LSI acknowledgement allocation failure", condition=deps["ne"],
        )
        _require_branch(
            object_context, success["allocation_success_branch_site"],
            success["allocation_success_target"], "LSI acknowledgement allocation success",
            condition=deps["al"],
        )
        acknowledgement = callback["acknowledgement"]
        for site, symbol, label in (
            (acknowledgement["allocation_site"], "osal_valloc_msg_wait", "LSI acknowledgement allocation"),
            (acknowledgement["send_site"], "osal_snd_msg", "LSI acknowledgement send"),
            (acknowledgement["free_site"], "osal_free_msg", "LSI input release"),
        ):
            _elf._require_call_symbol(
                object_context["blob"], object_context["mappings"], deps,
                object_context["plt"], site, symbol, label,
            )
    finally:
        object_context["stream"].close()

    osal = expected["osal_dispatch"]
    osal_context = _context(osal["source"])
    try:
        deps = osal_context["deps"]
        _elf._require_owner(osal_context["exidx"], osal["send"]["owner"], "OSAL sender")
        _elf._require_owner(
            osal_context["exidx"], osal["registration"]["owner"],
            "OSAL callback registration",
        )
        _elf._require_owner(osal_context["exidx"], osal["queue_lookup"], "OSAL queue lookup")
        _require_shift(osal_context, osal["send"]["mask_sites"][0], "lsl", 17, "OSAL send")
        _require_shift(osal_context, osal["send"]["mask_sites"][1], "lsr", 17, "OSAL send")
        _require_shift(
            osal_context, osal["registration"]["mask_sites"][0], "lsl", 17,
            "OSAL registration",
        )
        _require_shift(
            osal_context, osal["registration"]["mask_sites"][1], "lsr", 17,
            "OSAL registration",
        )
        normalized = osal["normalized_queue_id"]
        mask = osal["queue_id_mask"]
        if (
            mask != 0x7FFF
            or expected["sender"]["message_allocation"]["destination"] & mask
            != normalized
            or expected["receiver_registration"]["queue_id"] & mask
            != normalized
        ):
            raise RuntimeError("Packaged LSI queue identifier join differs")
        for record in (osal["send"], osal["registration"]):
            _elf._require_direct_target(
                osal_context["blob"], osal_context["mappings"], deps,
                record["lookup_call_site"], osal["queue_lookup"]["start"],
                "OSAL shared queue lookup", call=True,
            )

        callback_record = osal["callback_record"]
        _require_pc_relative_address(
            osal_context, 0x4350, 0x4358, deps["r2"],
            osal["wrapper"]["entry"] | 1, "OSAL callback wrapper",
        )
        for site, register, offset, label in (
            (callback_record["wrapper_store_site"], deps["r2"], callback_record["wrapper_offset"], "OSAL wrapper store"),
            (callback_record["handler_store_site"], deps["r5"], callback_record["handler_offset"], "OSAL handler store"),
            (callback_record["context_store_site"], deps["r6"], callback_record["context_offset"], "OSAL context store"),
        ):
            _elf._require_memory(
                osal_context["blob"], osal_context["mappings"], deps,
                site, deps["str"], register, deps["r9"], offset, label,
            )

        wrapper = osal["wrapper"]
        _elf._require_owner(osal_context["exidx"], wrapper["owner"], "OSAL callback wrapper")
        _elf._require_memory(
            osal_context["blob"], osal_context["mappings"], deps,
            wrapper["handler_load_site"], deps["ldr"], deps["r3"], deps["r5"],
            callback_record["handler_offset"], "OSAL handler load",
        )
        _elf._require_add_immediate(
            osal_context["blob"], osal_context["mappings"], deps,
            0x317A, deps["r0"], deps["r6"], wrapper["payload_offset"],
            "OSAL callback payload",
        )
        _elf._require_memory(
            osal_context["blob"], osal_context["mappings"], deps,
            wrapper["context_load_site"], deps["ldr"], deps["r1"], deps["r5"],
            callback_record["context_offset"], "OSAL callback context",
        )
        _require_indirect_call(
            osal_context, wrapper["handler_call_site"], deps["r3"],
            "OSAL registered handler",
        )

        _elf._require_owner(
            osal_context["exidx"], osal["dispatch_owner"], "OSAL queue dispatch"
        )
        for load_site, call_site, base in (
            (0x38A0, 0x38A2, deps["r4"]),
            (0x38F8, 0x38FA, deps["r4"]),
            (0x398A, 0x3992, deps["r5"]),
        ):
            _elf._require_memory(
                osal_context["blob"], osal_context["mappings"], deps,
                load_site, deps["ldr"], deps["r3"], base,
                callback_record["wrapper_offset"], "OSAL dispatch wrapper load",
            )
            _require_indirect_call(
                osal_context, call_site, deps["r3"], "OSAL dispatch wrapper"
            )
    finally:
        osal_context["stream"].close()

    if expected["claims"] != {
        "packaged_lsi_flag_delivery_path_proven": True,
        "local_flag_state_management_proven": True,
        "success_acknowledgement_path_proven": True,
        "all_payloads_acknowledged_proven": False,
        "pre_normal_partition_selector_join_proven": False,
        "external_or_opaque_selector_unresolved": True,
    }:
        raise RuntimeError("Packaged LSI delivery claims differ")


def _validate_selector_assessment() -> None:
    assessment = PACKAGED_SELECTOR_EVIDENCE["selector_assessment"]
    if assessment != {
        "nflasha1_selector_join_proven": False,
        "bounded_named_reference_search_only": True,
        "numeric_or_indirect_selector_analysis_complete": False,
        "external_or_opaque_selector_unresolved": True,
    }:
        raise RuntimeError("Packaged selector unresolved assessment differs")


def build_raw_export() -> dict:
    _validate_sources()
    _validate_libobj_consumers()
    _validate_up_sh()
    _validate_nested_component()
    _validate_crypter()
    _validate_bootin()
    _validate_lsi_delivery()
    _validate_selector_assessment()
    return copy.deepcopy(PACKAGED_SELECTOR_EVIDENCE)


def main() -> None:
    build_raw_export()
    print(
        "A6400_PACKAGED_SELECTOR_SCAN|libobj_owners=4|"
        "selector_join_proven=0|bootin_named_hits=0|"
        "numeric_selector_analysis_complete=0|installable=0"
    )


if __name__ == "__main__":
    main()
