"""Read-only α6400 generic widget hit-test vtable exporter."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from pmca.analysis.touch_api_callers import normalize_touch_api_callers_export
from pmca.analysis.touchpad_terminal_boundary import normalize_touchpad_terminal_export
from pmca.analysis.widget_hit_test_vtables import (
    EXPECTED_RAW_EXPORT,
    IS_HIT_DYNSYM,
    ON_DUMP_DYNSYM,
    RTTI_DYNSYM,
    SET_HIT_MARGIN_DYNSYM,
    SYS_IS_HIT_DYNSYM,
    TOUCH_API_CALLERS_DIGEST,
    TOUCHPAD_TERMINAL_DIGEST,
    VIEW_UNIFIED2_SHA256,
    VIEW_UNIFIED2_SIZE,
    normalize_widget_hit_test_vtables_export,
)


SOURCE = ROOT / ".artifacts" / "decrypted" / "a6400-tw-v2.00" / "ma1co" / "firmware.tar_unpacked" / "0700_part_image" / "dev" / "nflasha15_unpacked" / "lib" / "viewUnified2.so"
TOUCHPAD_TERMINAL = ROOT / ".artifacts" / "touchpad-terminal-boundary-trace" / "a6400-v2.00" / "raw-touchpad-terminal-boundary.json"
TOUCH_API_CALLERS = ROOT / ".artifacts" / "touch-api-caller-trace" / "a6400-v2.00" / "raw-touch-api-callers.json"
ARTIFACT_BASE = ROOT / ".artifacts"
OUTPUT_ROOT = ARTIFACT_BASE / "widget-hit-test-vtable-trace" / "a6400-v2.00"
OUTPUT_NAME = "raw-widget-hit-test-vtables.json"


def _deps():
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        for location in (ROOT / ".artifacts" / "pydeps", ROOT / ".artifacts" / "pydeps_vlf", ROOT / ".artifacts" / "python-packages"):
            if location.is_dir():
                sys.path.insert(0, str(location))
        try:
            from elftools.elf.elffile import ELFFile
        except ImportError as error:
            raise RuntimeError("local pyelftools is required for static ELF metadata") from error
    return ELFFile


def pyelftools_available():
    try:
        _deps()
    except RuntimeError:
        return False
    return True


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _prior(path, normalizer, expected_digest, contract):
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file():
        raise RuntimeError("prior evidence must be a literal regular JSON file")
    try:
        summary = normalizer(json.loads(candidate.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise RuntimeError("prior evidence is not its pinned fail-closed export") from error
    if summary["artifact_sha256"] != expected_digest:
        raise RuntimeError("prior evidence digest differs")
    return {"analysis_contract": contract, "artifact_sha256": summary["artifact_sha256"]}


def _dynsym_exact(dynsym, index, expected):
    symbol = dynsym.get_symbol(index)
    if symbol.name != expected or symbol["st_shndx"] != "SHN_UNDEF":
        raise RuntimeError("required undefined dynamic symbol differs")


def _relocation_index_by_offset(relocations):
    mapping = {}
    for index, relocation in enumerate(relocations):
        offset = relocation["r_offset"]
        if offset in mapping:
            raise RuntimeError("dynamic relocation offsets are not unique")
        mapping[offset] = (index, relocation)
    return mapping


def _relocation(mapping, address, relocation_type, dynsym_index, label):
    pair = mapping.get(address)
    if pair is None:
        raise RuntimeError(label + " relocation is absent")
    index, relocation = pair
    if relocation["r_info_type"] != relocation_type or relocation["r_info_sym"] != dynsym_index:
        raise RuntimeError(label + " relocation differs")
    return index


def _families(relocations):
    by_offset = _relocation_index_by_offset(relocations)
    sys_records = [(index, relocation) for index, relocation in enumerate(relocations) if relocation["r_info_type"] == 2 and relocation["r_info_sym"] == SYS_IS_HIT_DYNSYM]
    hit_records = [(index, relocation) for index, relocation in enumerate(relocations) if relocation["r_info_type"] == 2 and relocation["r_info_sym"] == IS_HIT_DYNSYM]
    if len(sys_records) != 407 or len(hit_records) != 407:
        raise RuntimeError("generic hit-test relocation population differs")
    result, exceptions, named_margin_count, named_rtti_count = [], [], 0, 0
    for ordinal, (sys_index, sys_relocation) in enumerate(sys_records):
        address = sys_relocation["r_offset"]
        on_dump_index = _relocation(by_offset, address - 4, 2, ON_DUMP_DYNSYM, "onDump")
        is_hit_index = _relocation(by_offset, address + 4, 2, IS_HIT_DYNSYM, "isHit")
        if sys_index != 102061 + ordinal or on_dump_index != 101654 + ordinal or is_hit_index != 102468 + ordinal:
            raise RuntimeError("adjacent dynamic relocation order differs")
        header = address - 0x98
        header_pair = by_offset.get(header)
        rtti_type = None
        if header_pair is not None and header_pair[1]["r_info_sym"] != 0:
            if header_pair[1]["r_info_type"] != 2 or header_pair[1]["r_info_sym"] != RTTI_DYNSYM or header_pair[0] != 89099:
                raise RuntimeError("unexpected dynamically named vtable RTTI pointer")
            rtti_type = "LayoutableWidgetBase"
            named_rtti_count += 1
        margin_pair = by_offset.get(address + 8)
        if margin_pair is not None and margin_pair[1]["r_info_type"] == 2 and margin_pair[1]["r_info_sym"] == SET_HIT_MARGIN_DYNSYM:
            named_margin_count += 1
        else:
            exceptions.append(address)
        result.append({
            "on_dump_address": address - 4, "on_dump_relocation_index": on_dump_index,
            "sys_is_hit_address": address, "sys_is_hit_relocation_index": sys_index,
            "is_hit_address": address + 4, "is_hit_relocation_index": is_hit_index,
            "rtti_header_address": header, "address_point": address - 0x90,
            "rtti_type": rtti_type,
        })
    if named_rtti_count != 1 or named_margin_count != 397 or len(exceptions) != 10:
        raise RuntimeError("RTTI or setHitMargin aggregate differs")
    return result, exceptions


def _typed_boundary(relocations):
    by_offset = _relocation_index_by_offset(relocations)
    _relocation(by_offset, 0x90501C, 2, RTTI_DYNSYM, "LayoutableWidgetBase RTTI")
    _relocation(by_offset, 0x905024, 23, 0, "LayoutableWidgetBase address point")
    _relocation(by_offset, 0x9050B4, 2, SYS_IS_HIT_DYNSYM, "LayoutableWidgetBase sys_isHit")
    _relocation(by_offset, 0x9050B8, 2, IS_HIT_DYNSYM, "LayoutableWidgetBase isHit")
    _relocation(by_offset, 0x9050BC, 2, SET_HIT_MARGIN_DYNSYM, "LayoutableWidgetBase setHitMargin")
    return copy.deepcopy(EXPECTED_RAW_EXPORT["typed_layoutable_widget_base"])


def _metadata_from_file(source=SOURCE, touchpad_terminal=TOUCHPAD_TERMINAL, touch_api_callers=TOUCH_API_CALLERS):
    source = Path(source)
    before = _sha256(source)
    if source.name != "viewUnified2.so" or source.stat().st_size != VIEW_UNIFIED2_SIZE or before != VIEW_UNIFIED2_SHA256:
        raise RuntimeError("source identity is not pinned")
    prior_terminal = _prior(touchpad_terminal, normalize_touchpad_terminal_export, TOUCHPAD_TERMINAL_DIGEST, "touchpad_terminal_boundary")
    prior_api = _prior(touch_api_callers, normalize_touch_api_callers_export, TOUCH_API_CALLERS_DIGEST, "touch_api_callers")
    ELFFile = _deps()
    with source.open("rb") as stream:
        elf = ELFFile(stream)
        dynsym = elf.get_section_by_name(".dynsym")
        rel_dyn = elf.get_section_by_name(".rel.dyn")
        if dynsym is None or rel_dyn is None:
            raise RuntimeError("required ELF metadata sections are absent")
        _dynsym_exact(dynsym, SYS_IS_HIT_DYNSYM, "_ZN2ux6wgtsys10WidgetBase9sys_isHitERKNS_4core7Vector2E")
        _dynsym_exact(dynsym, IS_HIT_DYNSYM, "_ZN2ux6wgtsys6Widget5isHitERKNS_4core7Vector2E")
        _dynsym_exact(dynsym, ON_DUMP_DYNSYM, "_ZN2ux6wgtsys6Widget6onDumpERN5libra10DictionaryE")
        _dynsym_exact(dynsym, SET_HIT_MARGIN_DYNSYM, "_ZN2ux6wgtsys6Widget12setHitMarginEssss")
        _dynsym_exact(dynsym, RTTI_DYNSYM, "_ZTI20LayoutableWidgetBase")
        relocations = list(rel_dyn.iter_relocations())
        families, exceptions = _families(relocations)
        typed_boundary = _typed_boundary(relocations)
    document = copy.deepcopy(EXPECTED_RAW_EXPORT)
    document["families"] = families
    document["typed_layoutable_widget_base"] = typed_boundary
    document["set_hit_margin_summary"]["exception_sys_is_hit_addresses"] = exceptions
    document["prior_touchpad_terminal"] = prior_terminal
    document["prior_touch_api_callers"] = prior_api
    normalize_widget_hit_test_vtables_export(document)
    if _sha256(source) != before:
        raise RuntimeError("source changed during read-only static export")
    return document


class FileAdapter:
    def __init__(self, source=SOURCE, touchpad_terminal=TOUCHPAD_TERMINAL, touch_api_callers=TOUCH_API_CALLERS):
        self.source, self.touchpad_terminal, self.touch_api_callers = source, touchpad_terminal, touch_api_callers

    def metadata(self):
        return _metadata_from_file(self.source, self.touchpad_terminal, self.touch_api_callers)


def build_raw_export(adapter=None):
    candidate = (adapter or FileAdapter()).metadata()
    try:
        normalize_widget_hit_test_vtables_export(candidate)
    except Exception as error:
        raise RuntimeError("widget hit-test metadata differs from the exact bounded result") from error
    return candidate


def _literal_directory_under(root, artifact_base):
    literal_base = Path(os.path.abspath(os.fspath(artifact_base)))
    literal_root = Path(os.path.abspath(os.fspath(root)))
    if literal_base.is_symlink() or not literal_base.is_dir():
        raise RuntimeError("artifact base is not a literal directory")
    try:
        literal_root.relative_to(literal_base)
        resolved_base = literal_base.resolve(strict=True)
        resolved_root = literal_root.resolve(strict=True)
    except (OSError, ValueError, RuntimeError) as error:
        raise RuntimeError("approved output root is not contained") from error
    if not literal_root.is_dir() or literal_root.is_symlink() or resolved_base != literal_base or resolved_root != literal_root:
        raise RuntimeError("approved output root escapes through a symlink")
    return literal_root


def prepare_output_root(approved_root=OUTPUT_ROOT, artifact_base=ARTIFACT_BASE):
    literal_base = Path(os.path.abspath(os.fspath(artifact_base)))
    literal_root = Path(os.path.abspath(os.fspath(approved_root)))
    if literal_base.is_symlink() or not literal_base.is_dir() or literal_base.resolve(strict=True) != literal_base:
        raise RuntimeError("artifact base is not a literal directory")
    try:
        relative = literal_root.relative_to(literal_base)
    except ValueError as error:
        raise RuntimeError("approved output root is not contained") from error
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
    descriptor, temporary = tempfile.mkstemp(dir=str(root), prefix=".widget-hit-test-", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(json.dumps(document, sort_keys=True, separators=(",", ":")).encode() + b"\n")
            handle.flush(); os.fsync(handle.fileno())
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
    print("WIDGET_HIT_TEST_VTABLE_EXPORT|families=407|set_hit_margin=397|typed_rtti=1|menu_selection=0")
