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
