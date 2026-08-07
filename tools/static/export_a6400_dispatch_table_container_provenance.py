"""Read-only exporter for typed α6400 generic-dispatch containers."""
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

from pmca.analysis.dispatch_table_container_provenance import (
    CLAIMS,
    CREATIVE_STYLE_BOUNDARY,
    DISPATCHER_OWNERS,
    EXPECTED_EXPORT,
    MODULES,
    PRIOR_OWNER_REPORT,
    normalize_dispatch_table_container_provenance_export,
)
from pmca.analysis.generic_model_owner_provenance import validate_generic_model_owner_provenance_report
from tools.static.export_a6400_generic_model_owner_provenance import _at, _mappings, _section_name


FIRMWARE_LIB = ROOT / ".artifacts" / "decrypted" / "a6400-tw-v2.00" / "ma1co" / "firmware.tar_unpacked" / "0700_part_image" / "dev" / "nflasha15_unpacked" / "lib"
SOURCES = {
    "lib/viewUnified4.so": FIRMWARE_LIB / "viewUnified4.so",
    "lib/viewUnified7.so": FIRMWARE_LIB / "viewUnified7.so",
}
PRIOR_REPORT = ROOT / PRIOR_OWNER_REPORT["path"]
ARTIFACT_BASE = ROOT / ".artifacts"
OUTPUT_ROOT = ARTIFACT_BASE / "dispatch-table-container-provenance" / "a6400-v2.00"
OUTPUT_NAME = "dispatch-table-container-provenance-export.json"

_ABI_SYMBOLS = {
    "__vmi_class_type_info": "_ZTVN10__cxxabiv121__vmi_class_type_infoE",
    "__si_class_type_info": "_ZTVN10__cxxabiv120__si_class_type_infoE",
}
_BASE_SYMBOLS = {
    "ViewBaseForMR": "_ZTI13ViewBaseForMR",
    "WrapperSettingUtil": "_ZTI18WrapperSettingUtil",
    "ViewBaseProduct": "_ZTI15ViewBaseProduct",
}


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _dependencies():
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError as exc:
        raise RuntimeError("local pyelftools is required") from exc
    return {"ELFFile": ELFFile}


def dependencies_available():
    try:
        _dependencies()
    except RuntimeError:
        return False
    return True


def sources_available():
    return all(path.is_file() and not path.is_symlink() for path in SOURCES.values()) and PRIOR_REPORT.is_file() and not PRIOR_REPORT.is_symlink()


def _word(blob, mappings, address, signed=False):
    return int.from_bytes(_at(blob, mappings, address, 4), "little", signed=signed)


def _cstring(blob, mappings, address, limit=128):
    pieces = bytearray()
    for offset in range(limit):
        value = _at(blob, mappings, address + offset, 1)[0]
        if value == 0:
            try:
                return pieces.decode("ascii")
            except UnicodeDecodeError as exc:
                raise RuntimeError("RTTI name is not ASCII") from exc
        pieces.append(value)
    raise RuntimeError("RTTI name is not bounded")


def _rel_record(relocations, mappings, blob, section_owner, index, site, relocation_type, target=None):
    relocation = relocations[index]
    record = {
        "index": index,
        "site": relocation["r_offset"],
        "type": relocation["r_info_type"],
        "symbol_index": relocation["r_info_sym"],
        "section": section_owner(relocation["r_offset"]),
    }
    if relocation_type == 23:
        record["target"] = _word(blob, mappings, relocation["r_offset"]) & ~1
    expected = {
        "index": index,
        "site": site,
        "type": relocation_type,
        "symbol_index": 0,
        "section": ".data.rel.ro",
    }
    if target is not None:
        expected["target"] = target
    if record != expected:
        raise RuntimeError("relative relocation record differs")
    return record


def _rtti_bases(expected, blob, mappings, relocation_by_site, dynsym):
    rtti = expected["rtti"]
    if expected["abi_type_info"] == "__vmi_class_type_info":
        if _word(blob, mappings, rtti + 12) != len(expected["bases"]):
            raise RuntimeError("VMI base count differs")
        rows = []
        for position, base_expected in enumerate(expected["bases"]):
            cell = rtti + 16 + position * 8
            _index, relocation = relocation_by_site[cell]
            symbol = dynsym.get_symbol(relocation["r_info_sym"])
            offset_flags = _word(blob, mappings, cell + 4, signed=True)
            row = {
                "type": base_expected["type"],
                "offset": offset_flags >> 8,
                "public": bool(offset_flags & 2),
                "virtual": bool(offset_flags & 1),
            }
            if relocation["r_info_type"] != 2 or symbol.name != _BASE_SYMBOLS[base_expected["type"]] or row != base_expected:
                raise RuntimeError("VMI base metadata differs")
            rows.append(row)
        return rows
    cell = rtti + 8
    _index, relocation = relocation_by_site[cell]
    base_expected = expected["bases"][0]
    if relocation["r_info_type"] != 2 or dynsym.get_symbol(relocation["r_info_sym"]).name != _BASE_SYMBOLS[base_expected["type"]]:
        raise RuntimeError("SI base metadata differs")
    return [copy.deepcopy(base_expected)]


def _typed_owner(expected, blob, elf):
    mappings = _mappings(elf)
    rel_dyn = list(elf.get_section_by_name(".rel.dyn").iter_relocations())
    relocation_by_site = {relocation["r_offset"]: (index, relocation) for index, relocation in enumerate(rel_dyn)}
    dynsym = elf.get_section_by_name(".dynsym")
    primary = expected["primary_vtable"]
    if _section_name(elf, primary["header"]) != ".data.rel.ro" or _word(blob, mappings, primary["header"], signed=True) != 0:
        raise RuntimeError("primary vtable header differs")
    typeinfo_cell = primary["header"] + 4
    typeinfo_index, typeinfo_relocation = relocation_by_site[typeinfo_cell]
    if (
        typeinfo_relocation["r_info_type"] != 23
        or typeinfo_relocation["r_info_sym"] != 0
        or (_word(blob, mappings, typeinfo_cell) & ~1) != expected["rtti"]
        or primary["address_point"] != typeinfo_cell + 4
        or primary["slot_count"] != (primary["end"] - primary["address_point"]) // 4
    ):
        raise RuntimeError("primary vtable RTTI header differs")

    abi_index, abi_relocation = relocation_by_site[expected["rtti"]]
    abi_symbol = dynsym.get_symbol(abi_relocation["r_info_sym"])
    name_index, name_relocation = relocation_by_site[expected["rtti"] + 4]
    if abi_relocation["r_info_type"] != 2 or abi_symbol.name != _ABI_SYMBOLS[expected["abi_type_info"]]:
        raise RuntimeError("RTTI ABI identity differs")
    if name_relocation["r_info_type"] != 23 or name_relocation["r_info_sym"] != 0:
        raise RuntimeError("RTTI name relocation differs")
    encoding = _cstring(blob, mappings, _word(blob, mappings, expected["rtti"] + 4))
    if encoding != expected["type_name_encoding"] or encoding[len(str(len(expected["type_name"]))):] != expected["type_name"]:
        raise RuntimeError("RTTI type name differs")
    bases = _rtti_bases(expected, blob, mappings, relocation_by_site, dynsym)

    shape = {"absolute": 0, "relative": 0, "unrelocated_zero": 0}
    creative_relocations = 0
    for cell in range(primary["address_point"], primary["end"], 4):
        pair = relocation_by_site.get(cell)
        if pair is None:
            if _word(blob, mappings, cell) != 0:
                raise RuntimeError("unrelocated primary slot is nonzero")
            shape["unrelocated_zero"] += 1
            continue
        _index, relocation = pair
        if relocation["r_info_type"] == 2:
            shape["absolute"] += 1
            name = dynsym.get_symbol(relocation["r_info_sym"]).name
            creative_relocations += "creative" in name.casefold()
        elif relocation["r_info_type"] == 23 and relocation["r_info_sym"] == 0:
            shape["relative"] += 1
        else:
            raise RuntimeError("primary slot relocation type differs")
    if shape != expected["slot_relocation_shape"] or creative_relocations != expected["creative_style_typed_relocation_count"]:
        raise RuntimeError("primary vtable relocation shape differs")
    secondary = expected["next_secondary_header"]
    if (
        secondary["offset_to_top_cell"] != primary["end"]
        or secondary["typeinfo_cell"] != primary["end"] + 4
        or _section_name(elf, secondary["offset_to_top_cell"]) != ".data.rel.ro"
        or _word(blob, mappings, secondary["offset_to_top_cell"], signed=True) != secondary["offset_to_top"]
    ):
        raise RuntimeError("immediate secondary vtable header differs")
    next_typeinfo_pair = relocation_by_site.get(secondary["typeinfo_cell"])
    if next_typeinfo_pair is None or next_typeinfo_pair[1]["r_info_type"] != 23 or (_word(blob, mappings, secondary["typeinfo_cell"]) & ~1) != expected["rtti"]:
        raise RuntimeError("primary vtable end is not followed by a same-RTTI secondary header")

    dispatcher = _rel_record(
        rel_dyn,
        mappings,
        blob,
        lambda address: _section_name(elf, address),
        expected["dispatcher_relocation"]["index"],
        expected["dispatcher_cell"],
        expected["dispatcher_relocation"]["type"],
        expected["dispatcher"],
    )
    if (expected["dispatcher_cell"] - primary["address_point"]) // 4 != expected["dispatcher_slot"]:
        raise RuntimeError("dispatcher slot differs")

    to_instance_expected = expected["to_instance_symbol"]
    to_instance = dynsym.get_symbol(to_instance_expected["symbol_index"])
    if (
        to_instance.name != to_instance_expected["symbol"]
        or to_instance["st_shndx"] == "SHN_UNDEF"
        or to_instance["st_info"]["type"] != "STT_FUNC"
        or (to_instance["st_value"] & ~1) != to_instance_expected["range"]["start"]
        or (to_instance["st_value"] & ~1) + to_instance["st_size"] != to_instance_expected["range"]["end"]
    ):
        raise RuntimeError("typed ToInstance symbol differs")

    result = copy.deepcopy(expected)
    result["bases"] = bases
    result["dispatcher_relocation"] = {"index": dispatcher["index"], "type": dispatcher["type"]}
    if "adjacent_split_entry" in expected:
        adjacent = expected["adjacent_split_entry"]
        pair = relocation_by_site[adjacent["cell"]]
        if pair[1]["r_info_type"] != 23 or pair[1]["r_info_sym"] != 0 or (_word(blob, mappings, adjacent["cell"]) & ~1) != adjacent["target"] or (adjacent["cell"] - primary["address_point"]) // 4 != adjacent["slot"]:
            raise RuntimeError("adjacent split vtable entry differs")
    if "initializer" in expected:
        pair = relocation_by_site[expected["initializer_cell"]]
        if pair[0] != expected["initializer_relocation"]["index"] or pair[1]["r_info_type"] != 23 or (_word(blob, mappings, expected["initializer_cell"]) & ~1) != expected["initializer"] or (expected["initializer_cell"] - primary["address_point"]) // 4 != expected["initializer_slot"]:
            raise RuntimeError("VU7 initializer vtable entry differs")
        window = expected["local_relative_window"]
        pairs = [relocation_by_site.get(cell) for cell in range(window["start"], window["end"], 4)]
        if len(pairs) != window["relocation_count"] or any(pair is None or pair[1]["r_info_type"] != 23 or pair[1]["r_info_sym"] != 0 for pair in pairs):
            raise RuntimeError("VU7 local relative window differs")
        if (window["start"] - primary["address_point"]) // 4 != window["first_slot"] or (window["end"] - primary["address_point"]) // 4 - 1 != window["last_slot"]:
            raise RuntimeError("VU7 local relative slot window differs")
        secondary = expected["wrapper_secondary_vtable"]
        if _word(blob, mappings, secondary["header"], signed=True) != secondary["offset_to_top"]:
            raise RuntimeError("WrapperSettingUtil secondary offset differs")
        secondary_pair = relocation_by_site[secondary["typeinfo_cell"]]
        if secondary_pair[1]["r_info_type"] != 23 or (_word(blob, mappings, secondary["typeinfo_cell"]) & ~1) != expected["rtti"] or secondary["address_point"] != secondary["typeinfo_cell"] + 4:
            raise RuntimeError("WrapperSettingUtil secondary RTTI differs")
    return result


def _prior_report():
    if PRIOR_REPORT.is_symlink() or not PRIOR_REPORT.is_file() or _sha256(PRIOR_REPORT) != PRIOR_OWNER_REPORT["sha256"]:
        raise RuntimeError("prior owner report identity differs")
    return validate_generic_model_owner_provenance_report(json.loads(PRIOR_REPORT.read_text(encoding="utf-8")))


def _metadata_from_files(sources=SOURCES):
    deps = _dependencies()
    _prior_report()
    identities = {item["module"]: item for item in MODULES}
    before = {}
    opened = {}
    for module, source in sources.items():
        if source.is_symlink() or not source.is_file():
            raise RuntimeError("source must be a literal regular file")
        before[module] = _sha256(source)
        identity = identities[module]
        if source.name != Path(module).name or source.stat().st_size != identity["size"] or before[module] != identity["sha256"]:
            raise RuntimeError("source identity differs")
        blob = source.read_bytes()
        opened[module] = (blob, deps["ELFFile"](io.BytesIO(blob)))
    owners = [_typed_owner(expected, *opened[expected["module"]]) for expected in DISPATCHER_OWNERS]
    document = copy.deepcopy(EXPECTED_EXPORT)
    document.update({
        "dispatcher_owners": owners,
        "creative_style_boundary": copy.deepcopy(CREATIVE_STYLE_BOUNDARY),
        "claims": copy.deepcopy(CLAIMS),
    })
    normalize_dispatch_table_container_provenance_export(document)
    if any(_sha256(sources[module]) != before[module] for module in before):
        raise RuntimeError("source changed during static export")
    return document


class FileAdapter:
    def __init__(self, sources=SOURCES):
        self.sources = sources

    def metadata(self):
        return _metadata_from_files(self.sources)


def build_raw_export(adapter=None):
    try:
        return normalize_dispatch_table_container_provenance_export((adapter or FileAdapter()).metadata())
    except Exception as exc:
        raise RuntimeError("dispatch-table container provenance differs from the exact bounded static result") from exc


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
    handle, temporary = tempfile.mkstemp(dir=str(root), prefix=".dispatch-container-", suffix=".tmp")
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
    print("DISPATCH_TABLE_CONTAINER_PROVENANCE_EXPORT|typed_owners=3|slot64=3|creative_owner=0|persistence=0")
