"""Read-only exporter for the α6400 Creative Style view-lifecycle boundary."""

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

from pmca.analysis.creative_style_view_lifecycle_boundary import (
    DEPENDENCIES,
    EXPECTED_EXPORT,
    SOURCES,
    build_creative_style_view_lifecycle_boundary_report,
    normalize_creative_style_view_lifecycle_boundary_export,
    validate_creative_style_view_lifecycle_boundary_report,
)
from tools.static.export_a6400_creative_style_view_model_binding import (
    _call_symbol,
    _cstring,
    _decode,
    _dependencies as _view_dependencies,
    _direct_target,
    _exidx_ranges,
    _instruction,
    _mappings,
    _owner,
    _plt_symbols,
    _relocations,
    _require_register_unchanged,
    _word,
)


SOURCE_ROOT = (
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
)
SOURCE_PATHS = {
    "view": SOURCE_ROOT / "viewUnified2.so",
    "object": SOURCE_ROOT / "libObj.so",
}
DEPENDENCY_PATHS = {
    role: ROOT / record["report"] for role, record in DEPENDENCIES.items()
}
ARTIFACT_ROOT = (
    ROOT
    / ".artifacts"
    / "creative-style-view-lifecycle-boundary"
    / "a6400-v2.00"
)
OUTPUT_NAME = "creative-style-view-lifecycle-boundary-export.json"
RAW_OUTPUT_ROOT = ARTIFACT_ROOT
RAW_OUTPUT_PATH = RAW_OUTPUT_ROOT / OUTPUT_NAME
REPORT_OUTPUT_ROOT = ROOT / "analysis"
REPORT_PATH = REPORT_OUTPUT_ROOT / "a6400-creative-style-view-lifecycle-boundary.json"


def _sha256_bytes(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def _sha256(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _dependencies():
    deps = _view_dependencies()
    try:
        from capstone.arm import ARM_REG_R6, ARM_REG_R8, ARM_REG_R10, ARM_REG_R9
    except (ImportError, AttributeError) as exc:
        raise RuntimeError("local Capstone and pyelftools are required") from exc
    deps.update({"r6": ARM_REG_R6, "r8": ARM_REG_R8, "sl": ARM_REG_R10, "sb": ARM_REG_R9})
    return deps


def dependencies_available() -> bool:
    try:
        _dependencies()
    except RuntimeError:
        return False
    return True


def sources_available() -> bool:
    return all(path.is_file() and not path.is_symlink() for path in SOURCE_PATHS.values())


def _context(blob: bytes, deps):
    elf = deps["ELFFile"](io.BytesIO(blob))
    mappings = _mappings(elf)
    rels, by_site = _relocations(elf)
    return {
        "elf": elf,
        "blob": blob,
        "mappings": mappings,
        "rels": rels,
        "by_site": by_site,
        "dynsym": elf.get_section_by_name(".dynsym"),
        "plt_symbols": _plt_symbols(elf, blob, mappings),
        "exidx": _exidx_ranges(elf, blob),
    }


def _require_text(item, mnemonic: str, op_str: str, label: str):
    if item.mnemonic != mnemonic or item.op_str != op_str:
        raise RuntimeError(label + " differs")


def _require_direct(ctx, deps, site: int, target: int, label: str):
    item = _instruction(ctx["blob"], ctx["mappings"], deps, site)
    if _direct_target(item, deps) != target:
        raise RuntimeError(label + " differs")


def _require_relative(ctx, *, index: int, site: int, target: int, label: str):
    actual_index, relocation = ctx["by_site"].get(site, (None, None))
    if (
        actual_index != index
        or relocation is None
        or relocation["r_info_type"] != 23
        or relocation["r_info_sym"] != 0
        or (_word(ctx["blob"], ctx["mappings"], site) & ~1) != target
    ):
        raise RuntimeError(label + " differs")


def _require_abs_symbol(ctx, *, index: int, site: int, symbol_index: int, symbol: str, label: str):
    actual_index, relocation = ctx["by_site"].get(site, (None, None))
    if (
        actual_index != index
        or relocation is None
        or relocation["r_info_type"] != 2
        or relocation["r_info_sym"] != symbol_index
        or ctx["dynsym"].get_symbol(symbol_index).name != symbol
    ):
        raise RuntimeError(label + " differs")


def _require_symbol(ctx, index: int, name: str, value: int, size: int, *, defined: bool, label: str):
    symbol = ctx["dynsym"].get_symbol(index)
    shndx = symbol["st_shndx"]
    is_defined = shndx != "SHN_UNDEF" and shndx != 0
    if (
        symbol.name != name
        or symbol["st_value"] != value
        or symbol["st_size"] != size
        or is_defined is not defined
    ):
        raise RuntimeError(label + " differs")


def _needed(elf) -> list[str]:
    dynamic = elf.get_section_by_name(".dynamic")
    return [tag.needed for tag in dynamic.iter_tags() if tag.entry.d_tag == "DT_NEEDED"]


def _require_pic_string(ctx, deps, *, load_site: int, add_site: int, literal_cell: int, address: int, value: str, label: str):
    load = _instruction(ctx["blob"], ctx["mappings"], deps, load_site)
    add = _instruction(ctx["blob"], ctx["mappings"], deps, add_site)
    if load.id != deps["ldr"] or add.id != deps["add"]:
        raise RuntimeError(label + " instruction class differs")
    computed = add_site + 4 + _word(ctx["blob"], ctx["mappings"], literal_cell)
    if computed != address or _cstring(ctx["blob"], ctx["mappings"], computed) != value:
        raise RuntimeError(label + " dataflow differs")


def _validate_dependencies():
    for role, expected in DEPENDENCIES.items():
        path = DEPENDENCY_PATHS[role]
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(f"{role} dependency report is unavailable")
        document = json.loads(path.read_text(encoding="utf-8"))
        summary = document.get("summary")
        if not isinstance(summary, dict) or summary.get("canonical_export_sha256") != expected["canonical_export_sha256"]:
            raise RuntimeError(f"{role} dependency digest differs")
    view = json.loads(DEPENDENCY_PATHS["view_model_binding"].read_text(encoding="utf-8"))
    runtime = json.loads(DEPENDENCY_PATHS["runtime_binding"].read_text(encoding="utf-8"))
    transport = json.loads(DEPENDENCY_PATHS["model_request_transport"].read_text(encoding="utf-8"))
    if (
        view.get("claims", {}).get("view_factory_function_found") is not True
        or view.get("camera_test_eligible") is not False
        or runtime.get("claims", {}).get("generic_dynamic_loader_chain_proven") is not True
        or runtime.get("camera_test_eligible") is not False
        or transport.get("claims", {}).get("operation_38_queue_to_consumer_identity_proven") is not False
        or transport.get("camera_test_eligible") is not False
    ):
        raise RuntimeError("lifecycle dependency claim boundary differs")


def _validate_provider_symbols(view, obj):
    records = EXPECTED_EXPORT["provider_binding"]["symbols"]
    for record in records:
        _require_symbol(
            view,
            record["view_dynsym_index"],
            record["symbol"],
            0,
            0,
            defined=False,
            label=record["role"] + " view import",
        )
        _require_symbol(
            obj,
            record["object_dynsym_index"],
            record["symbol"],
            record["object_entry"],
            record["object_size"],
            defined=True,
            label=record["role"] + " object candidate",
        )
    if _needed(view["elf"]) != EXPECTED_EXPORT["provider_binding"]["view_dt_needed"]:
        raise RuntimeError("view dynamic dependency list differs")


def _validate_typed_activation(view, deps):
    expected = EXPECTED_EXPORT["typed_activation"]
    element = expected["element"]
    _abi_index, abi_relocation = view["by_site"].get(element["rtti"], (None, None))
    _name_index, name_relocation = view["by_site"].get(element["rtti"] + 4, (None, None))
    if (
        abi_relocation is None
        or abi_relocation["r_info_type"] != 2
        or view["dynsym"].get_symbol(abi_relocation["r_info_sym"]).name
        != "_ZTVN10__cxxabiv120__si_class_type_infoE"
        or name_relocation is None
        or name_relocation["r_info_type"] != 23
        or name_relocation["r_info_sym"] != 0
        or _cstring(
            view["blob"],
            view["mappings"],
            _word(view["blob"], view["mappings"], element["rtti"] + 4),
        )
        != element["type_name_encoding"]
    ):
        raise RuntimeError("typed Creative Style element RTTI differs")
    if _owner(view["exidx"], expected["wrapper"]["entry"]) != (
        expected["wrapper"]["owner"]["start"], expected["wrapper"]["owner"]["end"]
    ):
        raise RuntimeError("typed openView wrapper owner differs")
    _require_relative(
        view,
        index=expected["relocation"]["index"],
        site=expected["cell"],
        target=expected["relocation"]["target"],
        label="typed openView slot relocation",
    )
    if _word(view["blob"], view["mappings"], expected["cell"]) != expected["relocation"]["thumb_value"]:
        raise RuntimeError("typed openView Thumb value differs")
    base = expected["base_abi"]
    _require_abs_symbol(
        view,
        index=base["relocation_index"],
        site=base["cell"],
        symbol_index=base["symbol_index"],
        symbol=base["symbol"],
        label="typed openView base ABI",
    )
    wrapper = expected["wrapper"]
    _require_text(_instruction(view["blob"], view["mappings"], deps, 0x489218), "ldr", "r0, [pc, #0xc]", "typed alias load")
    _require_text(_instruction(view["blob"], view["mappings"], deps, 0x48921C), "add", "r0, pc", "typed alias add")
    if _word(view["blob"], view["mappings"], wrapper["literal_cell"]) != wrapper["literal_word"]:
        raise RuntimeError("typed alias literal differs")
    alias = wrapper["alias_add_site"] + 4 + wrapper["literal_word"]
    if alias != wrapper["alias_address"] or _cstring(view["blob"], view["mappings"], alias) != wrapper["alias"]:
        raise RuntimeError("typed alias dataflow differs")
    if _call_symbol(view["blob"], view["mappings"], deps, view["plt_symbols"], wrapper["open_view_call"]["site"]) != wrapper["open_view_call"]["symbol"]:
        raise RuntimeError("typed openView call differs")
    _require_register_unchanged(
        _decode(view["blob"], view["mappings"], deps, wrapper["entry"], wrapper["open_view_call"]["site"], complete=False),
        deps["r1"],
        label="typed openView condition preservation",
    )
    _require_text(_instruction(view["blob"], view["mappings"], deps, 0x489224), "movs", "r0, #1", "typed openView success return")

    bridge = expected["manager_bridge"]
    if _owner(view["exidx"], bridge["owner"]["start"]) != (bridge["owner"]["start"], bridge["owner"]["end"]):
        raise RuntimeError("typed process manager bridge owner differs")
    _require_relative(
        view,
        index=bridge["manager_relocation_index"],
        site=bridge["manager_cell"],
        target=bridge["manager_target"],
        label="typed process manager bridge relocation",
    )
    checks = {
        0x4390C0: ("mov", "r4, r2"),
        0x4390CA: ("mov", "r1, r4"),
        0x4390CC: ("ldr", "r3, [r3, #0x64]"),
        0x4390CE: ("blx", "r3"),
    }
    for site, (mnemonic, op_str) in checks.items():
        _require_text(_instruction(view["blob"], view["mappings"], deps, site), mnemonic, op_str, "typed process manager bridge")
    _require_direct(view, deps, 0x4390C2, 0x439088, "typed process manager lookup call")


def _validate_registration(view, deps):
    expected = EXPECTED_EXPORT["registration"]
    caller = expected["caller"]
    if _owner(view["exidx"], caller["owner"]["start"]) != (caller["owner"]["start"], caller["owner"]["end"]):
        raise RuntimeError("registration caller owner differs")
    if _call_symbol(view["blob"], view["mappings"], deps, view["plt_symbols"], caller["get_instance_call"]["site"]) != caller["get_instance_call"]["symbol"]:
        raise RuntimeError("registration singleton call differs")
    if _call_symbol(view["blob"], view["mappings"], deps, view["plt_symbols"], expected["branch_source"]["backup_read_call_site"]) != expected["branch_source"]["backup_read_symbol"]:
        raise RuntimeError("registration branch source differs")
    if _word(view["blob"], view["mappings"], expected["branch_source"]["backup_id_literal_cell"]) != expected["branch_source"]["backup_id"]:
        raise RuntimeError("registration backup ID differs")
    for site, mnemonic, op_str in (
        (0x2DC1FA, "mov", "r4, r0"),
        (0x2DC204, "cmp", "r3, #1"),
        (0x2DC20C, "movs", "r2, #1"),
        (0x2DC214, "movs", "r2, #2"),
        (0x2DC21A, "mov", "r0, r4"),
        (0x40B9D4, "cmp", "r2, #1"),
        (0x40B9DC, "mov", "r4, r1"),
    ):
        _require_text(_instruction(view["blob"], view["mappings"], deps, site), mnemonic, op_str, "registration control/dataflow")
    _require_direct(view, deps, 0x2DC206, 0x2DC210, "registration backup branch")
    _require_direct(view, deps, caller["registration_call"]["site"], caller["registration_call"]["target"], "registration owner call")
    if _owner(view["exidx"], expected["owner"]["start"]) != (expected["owner"]["start"], expected["owner"]["end"]):
        raise RuntimeError("registration owner differs")
    _require_direct(view, deps, 0x40B9E0, 0x40D89C, "registration alternate branch")

    for row in expected["rows"]:
        _require_pic_string(
            view,
            deps,
            load_site=row["alias_load_site"],
            add_site=row["alias_add_site"],
            literal_cell=0x40C958 if row["branch_value"] == 1 else 0x40E690,
            address=row["alias_address"],
            value=row["alias"],
            label="registration alias",
        )
        if _call_symbol(view["blob"], view["mappings"], deps, view["plt_symbols"], row["get_call_site"]) != "_ZN11IdGenerator3GetEPKc":
            raise RuntimeError("registration IdGenerator call differs")
        if row["branch_value"] == 1:
            _require_pic_string(
                view, deps,
                load_site=row["component_load_site"], add_site=row["component_add_site"], literal_cell=0x40C95C,
                address=row["component_address"], value=row["component"], label="registration direct component",
            )
        else:
            _require_pic_string(
                view, deps,
                load_site=row["component_seed_load_site"], add_site=row["component_seed_add_site"], literal_cell=0x40E5A4,
                address=row["component_address"], value=row["component"], label="registration retained component",
            )
            _require_text(_instruction(view["blob"], view["mappings"], deps, row["component_forward_site"]), "mov", "r2, sl", "registration retained component forward")
        _require_pic_string(
            view,
            deps,
            load_site=row["factory_load_site"],
            add_site=row["factory_add_site"],
            literal_cell=0x40C960 if row["branch_value"] == 1 else 0x40E694,
            address=row["factory_address"],
            value=row["factory"],
            label="registration factory",
        )
        _require_text(_instruction(view["blob"], view["mappings"], deps, row["id_to_key_site"]), "mov", "r1, r0", "registration numeric key forward")
        _require_text(_instruction(view["blob"], view["mappings"], deps, row["receiver_site"]), "mov", "r0, r4", "registration receiver forward")
        if _call_symbol(view["blob"], view["mappings"], deps, view["plt_symbols"], row["add_call_site"]) != "_ZN9IdSoTable3addEiPKcS1_":
            raise RuntimeError("registration add call differs")


def _validate_view_config(view, deps):
    expected = EXPECTED_EXPORT["conditional_table_identity"]["view_config"]
    if _word(view["blob"], view["mappings"], expected["vtable_header"], signed=True) != 0:
        raise RuntimeError("ViewConfig vtable header differs")
    _require_relative(view, index=32516, site=expected["vtable_header"] + 4, target=expected["rtti"], label="ViewConfig RTTI header")
    name_address = _word(view["blob"], view["mappings"], expected["rtti"] + 4)
    if _cstring(view["blob"], view["mappings"], name_address) != "10ViewConfig":
        raise RuntimeError("ViewConfig RTTI name differs")
    _require_relative(view, index=32522, site=expected["forwarding_cell"], target=expected["forwarding_target"], label="ViewConfig table getter slot")
    if _word(view["blob"], view["mappings"], expected["forwarding_cell"]) != expected["forwarding_target"] + 1:
        raise RuntimeError("ViewConfig table getter Thumb value differs")
    if _owner(view["exidx"], expected["constructor"]["start"]) != (expected["constructor"]["start"], expected["constructor"]["end"]):
        raise RuntimeError("ViewConfig constructor owner differs")
    for site, mnemonic, op_str in (
        (0x3E9654, "ldr", "r3, [r4, r3]"),
        (0x3E965C, "adds", "r3, #8"),
        (0x3E965E, "str", "r3, [r5]"),
    ):
        _require_text(_instruction(view["blob"], view["mappings"], deps, site), mnemonic, op_str, "ViewConfig vptr dataflow")
    base = 0x3E9656 + _word(view["blob"], view["mappings"], 0x3E9698)
    got = base + _word(view["blob"], view["mappings"], 0x3E969C)
    _require_relative(view, index=60937, site=got, target=expected["vtable_header"], label="ViewConfig vtable GOT")


def _validate_conditional_identity(obj, deps):
    expected = EXPECTED_EXPORT["conditional_table_identity"]
    selector = expected["app_config_selector"]
    bss = obj["elf"].get_section_by_name(".bss")
    if not (bss["sh_addr"] <= selector["buffer_address"] < bss["sh_addr"] + bss["sh_size"]):
        raise RuntimeError("AppConfig runtime selector storage differs")
    if _cstring(obj["blob"], obj["mappings"], selector["literal_address"]) != selector["literal"]:
        raise RuntimeError("AppConfig selector literal differs")
    for site in selector["compare_call_sites"]:
        if _call_symbol(obj["blob"], obj["mappings"], deps, obj["plt_symbols"], site) != "strncmp":
            raise RuntimeError("AppConfig selector comparison differs")

    app = expected["app_config"]
    _require_relative(obj, index=37831, site=app["forwarding_cell"], target=app["forwarding_target"], label="AppConfig ViewConfig forwarding slot")
    for site, mnemonic, op_str in (
        (0x3FD7E8, "str", "r0, [r4, #4]"),
        (0x3FD43A, "ldr", "r0, [r0, #4]"),
        (0x3FD440, "ldr", "r3, [r0]"),
        (0x3FD442, "ldr", "r3, [r3, #0x14]"),
        (0x3FD444, "blx", "r3"),
    ):
        _require_text(_instruction(obj["blob"], obj["mappings"], deps, site), mnemonic, op_str, "AppConfig ViewConfig forwarding")

    candidate = expected["libobj_get_instance_candidate"]
    if _owner(obj["exidx"], candidate["owner"]["start"]) != (candidate["owner"]["start"], candidate["owner"]["end"]):
        raise RuntimeError("ViewIdSoTable singleton candidate owner differs")
    _require_text(_instruction(obj["blob"], obj["mappings"], deps, candidate["return_literal_site"]), "ldr", "r0, [pc, #0x18]", "ViewIdSoTable singleton return load")
    _require_text(_instruction(obj["blob"], obj["mappings"], deps, candidate["return_add_site"]), "add", "r0, pc", "ViewIdSoTable singleton return add")
    singleton = candidate["return_add_site"] + 4 + _word(obj["blob"], obj["mappings"], candidate["return_literal_cell"])
    if singleton != candidate["singleton_storage"] or singleton == 0x13A50D4:
        raise RuntimeError("ViewIdSoTable singleton storage differs")

    wrapper = expected["wrapper_table"]
    if _owner(obj["exidx"], wrapper["constructor"]["start"]) != (wrapper["constructor"]["start"], wrapper["constructor"]["end"]):
        raise RuntimeError("loader wrapper constructor owner differs")
    for site, mnemonic, op_str in (
        (0x845CAC, "ldr", "r4, [r7, #0x30]"),
        (0x845CEA, "ldr", "r3, [r3, #0x14]"),
        (0x845CEC, "blx", "r3"),
        (0x845CF0, "str", "r0, [r5, #8]"),
    ):
        _require_text(_instruction(obj["blob"], obj["mappings"], deps, site), mnemonic, op_str, "loader wrapper table dataflow")


def _validate_generic_loader(obj, deps):
    expected = EXPECTED_EXPORT["generic_loader"]
    open_view = expected["open_view_candidate"]
    if _owner(obj["exidx"], open_view["entry"]) != (open_view["owner"]["start"], open_view["owner"]["end"]):
        raise RuntimeError("openView candidate owner differs")
    _require_direct(obj, deps, open_view["helper_call"]["site"], open_view["helper_call"]["target"], "openView helper call")
    if _owner(obj["exidx"], open_view["helper_owner"]["start"]) != (open_view["helper_owner"]["start"], open_view["helper_owner"]["end"]):
        raise RuntimeError("openView helper owner differs")

    event = expected["event"]
    if _call_symbol(obj["blob"], obj["mappings"], deps, obj["plt_symbols"], event["id_generator_call_site"]) != "_ZN11IdGenerator3GetEPKc":
        raise RuntimeError("openView alias ID lookup differs")
    if _word(obj["blob"], obj["mappings"], event["event_id_literal_cell"]) != event["event_id"]:
        raise RuntimeError("openView Event ID differs")
    for site, mnemonic, op_str in (
        (0x3F2B7A, "movs", "r2, #4"),
        (0x3F2B7C, "movs", "r3, #0"),
        (0x3F2B94, "movs", "r1, #6"),
        (0x3F2BAC, "movs", "r1, #0x1a"),
    ):
        _require_text(_instruction(obj["blob"], obj["mappings"], deps, site), mnemonic, op_str, "openView event ABI")
    if _call_symbol(obj["blob"], obj["mappings"], deps, obj["plt_symbols"], event["constructor_call_site"]) != "_ZN5EventC1Emhh":
        raise RuntimeError("openView Event constructor differs")
    for site in (event["resolved_id_add_call_site"], event["condition_add_call_site"]):
        if _call_symbol(obj["blob"], obj["mappings"], deps, obj["plt_symbols"], site) != "_ZN5Event12addParameterEmP9ParamBase":
            raise RuntimeError("openView Event parameter add differs")
    _require_direct(obj, deps, event["push_call"]["site"], event["push_call"]["target"], "openView Event push")

    handler = expected["destination_4_handler"]
    if _owner(obj["exidx"], handler["owner"]["start"]) != (handler["owner"]["start"], handler["owner"]["end"]):
        raise RuntimeError("destination-4 handler owner differs")
    literal_address = (handler["literal_site"] + 4 & ~3) + 0x28C
    if _word(obj["blob"], obj["mappings"], literal_address) != event["event_id"]:
        raise RuntimeError("destination-4 Event ID literal differs")
    _require_text(_instruction(obj["blob"], obj["mappings"], deps, handler["compare_site"]), "cmp", "r0, r3", "destination-4 Event ID compare")
    _require_direct(obj, deps, handler["match_branch"]["site"], handler["match_branch"]["target"], "destination-4 Event match branch")
    _require_direct(obj, deps, handler["loader_call"]["site"], handler["loader_call"]["target"], "destination-4 loader call")

    loader = expected["record_loader"]
    if _owner(obj["exidx"], loader["owner"]["start"]) != (loader["owner"]["start"], loader["owner"]["end"]):
        raise RuntimeError("generic record loader owner differs")
    _require_direct(obj, deps, loader["component_lookup_call"]["site"], loader["component_lookup_call"]["target"], "generic component lookup")
    _require_text(_instruction(obj["blob"], obj["mappings"], deps, loader["dlopen_flags_site"]), "movw", "r1, #0x101", "generic dlopen flags")
    if _call_symbol(obj["blob"], obj["mappings"], deps, obj["plt_symbols"], loader["dlopen_call_site"]) != "dlopen":
        raise RuntimeError("generic dlopen call differs")
    _require_direct(obj, deps, loader["factory_lookup_call"]["site"], loader["factory_lookup_call"]["target"], "generic factory lookup")
    if _call_symbol(obj["blob"], obj["mappings"], deps, obj["plt_symbols"], loader["dlsym_call_site"]) != "dlsym":
        raise RuntimeError("generic dlsym call differs")
    _require_text(_instruction(obj["blob"], obj["mappings"], deps, loader["factory_call_site"]), "blx", "sb", "generic factory indirect call")
    _require_text(_instruction(obj["blob"], obj["mappings"], deps, loader["factory_result_store_site"]), "str", "r0, [r4, #4]", "generic factory result store")


def _validate_factory_dependency(view, deps):
    expected = EXPECTED_EXPORT["factory_dependency"]
    symbol = view["dynsym"].get_symbol(expected["symbol_index"])
    if (
        symbol.name != expected["symbol"]
        or symbol["st_value"] != expected["range"]["start"] + 1
        or symbol["st_size"] != expected["range"]["end"] - expected["range"]["start"]
    ):
        raise RuntimeError("Creative Style factory dependency differs")
    _require_text(
        _instruction(view["blob"], view["mappings"], deps, 0x5CD890),
        "mov.w",
        "r0, #0x194",
        "Creative Style factory allocation size",
    )
    _require_direct(view, deps, 0x5CD8A0, 0x5CD664, "Creative Style factory constructor call")


def _validate_view_source(ctx, deps):
    _validate_typed_activation(ctx, deps)
    _validate_registration(ctx, deps)
    _validate_view_config(ctx, deps)
    _validate_factory_dependency(ctx, deps)


def _validate_object_source(ctx, deps):
    _validate_conditional_identity(ctx, deps)
    _validate_generic_loader(ctx, deps)


def build_raw_export() -> dict:
    if not sources_available():
        raise RuntimeError("pinned lifecycle source is unavailable")
    deps = _dependencies()
    before = {}
    blobs = {}
    for role, path in SOURCE_PATHS.items():
        blob = path.read_bytes()
        expected = SOURCES[role]
        if len(blob) != expected["size"] or _sha256_bytes(blob) != expected["sha256"]:
            raise RuntimeError(f"pinned {role} lifecycle source identity differs")
        before[role] = expected["sha256"]
        blobs[role] = blob
    _validate_dependencies()
    view = _context(blobs["view"], deps)
    obj = _context(blobs["object"], deps)
    _validate_provider_symbols(view, obj)
    _validate_view_source(view, deps)
    _validate_object_source(obj, deps)
    for role, path in SOURCE_PATHS.items():
        if _sha256(path) != before[role]:
            raise RuntimeError(f"pinned {role} lifecycle source changed during export")
    return normalize_creative_style_view_lifecycle_boundary_export(
        copy.deepcopy(EXPECTED_EXPORT)
    )


def build_outputs() -> dict[Path, dict]:
    raw = build_raw_export()
    report = build_creative_style_view_lifecycle_boundary_report(raw)
    normalize_creative_style_view_lifecycle_boundary_export(raw)
    validate_creative_style_view_lifecycle_boundary_report(report)
    return {
        RAW_OUTPUT_PATH: raw,
        REPORT_PATH: report,
    }


def _encoded(document: dict) -> bytes:
    return (
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def _require_output_path(path: Path, root: Path, expected: Path) -> tuple[Path, Path]:
    path = Path(path).resolve(strict=False)
    root = Path(root).resolve(strict=False)
    expected = Path(expected).resolve(strict=False)
    if path != expected or path.parent != root:
        raise RuntimeError("lifecycle output path escapes its fixed root")
    if root.exists() and (root.is_symlink() or not root.is_dir()):
        raise RuntimeError("lifecycle output root is not a regular directory")
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise RuntimeError("lifecycle output is not a regular file")
    return path, root


def write_outputs_atomic(outputs: dict[Path, dict]) -> None:
    expected_paths = {Path(RAW_OUTPUT_PATH), Path(REPORT_PATH)}
    if set(map(Path, outputs)) != expected_paths:
        raise RuntimeError("lifecycle output transaction is incomplete")

    normalize_creative_style_view_lifecycle_boundary_export(outputs[RAW_OUTPUT_PATH])
    validate_creative_style_view_lifecycle_boundary_report(outputs[REPORT_PATH])

    checked = [
        _require_output_path(RAW_OUTPUT_PATH, RAW_OUTPUT_ROOT, RAW_OUTPUT_PATH),
        _require_output_path(REPORT_PATH, REPORT_OUTPUT_ROOT, REPORT_PATH),
    ]
    for _path, root in checked:
        root.mkdir(parents=True, exist_ok=True)
        if root.is_symlink() or not root.is_dir():
            raise RuntimeError("lifecycle output root changed during setup")

    staged: list[tuple[Path, Path]] = []
    try:
        documents = (outputs[RAW_OUTPUT_PATH], outputs[REPORT_PATH])
        for (path, root), document in zip(checked, documents):
            handle = tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=f".{path.name}.",
                suffix=".tmp",
                dir=root,
                delete=False,
            )
            temporary = Path(handle.name)
            try:
                handle.write(_encoded(document))
                handle.flush()
                os.fsync(handle.fileno())
            finally:
                handle.close()
            staged.append((temporary, path))
        for temporary, path in staged:
            os.replace(temporary, path)
    finally:
        for temporary, _path in staged:
            if temporary.exists():
                temporary.unlink()


def publish_outputs() -> dict[Path, dict]:
    outputs = build_outputs()
    write_outputs_atomic(outputs)
    return outputs


def main() -> int:
    outputs = publish_outputs()
    print(REPORT_PATH)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
