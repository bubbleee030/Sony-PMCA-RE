"""Read-only exporter for Creative Style model-request transport evidence."""
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

from pmca.analysis.creative_style_model_request_transport import (
    EXPECTED_EXPORT,
    SOURCES,
    normalize_creative_style_model_request_transport_export,
)
from tools.static.export_a6400_creative_style_selector_code import (
    _dependencies,
    _validate_request as _validate_selector_request,
)
from tools.static.export_a6400_creative_style_view_model_binding import (
    _call_symbol,
    _decode,
    _direct_target,
    _exidx_ranges,
    _instruction,
    _mappings,
    _owner,
    _plt_symbols,
)


SOURCE_ROOT = (
    ROOT / ".artifacts" / "decrypted" / "a6400-tw-v2.00" / "ma1co"
    / "firmware.tar_unpacked" / "0700_part_image" / "dev" / "nflasha15_unpacked"
    / "lib"
)
SOURCE_PATHS = {
    "view": SOURCE_ROOT / "viewUnified2.so",
    "object": SOURCE_ROOT / "libObj.so",
}
ARTIFACT_BASE = ROOT / ".artifacts"
OUTPUT_ROOT = ARTIFACT_BASE / "creative-style-model-request-transport" / "a6400-v2.00"
OUTPUT_NAME = "creative-style-model-request-transport-export.json"


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def dependencies_available():
    try:
        _dependencies()
    except RuntimeError:
        return False
    return True


def sources_available():
    return all(path.is_file() and not path.is_symlink() for path in SOURCE_PATHS.values())


def _require_source_identity(role, path):
    expected = SOURCES[role]
    digest = _sha256(path)
    if path.stat().st_size != expected["size"] or digest != expected["sha256"]:
        raise RuntimeError("pinned " + role + " source identity differs")
    return digest


def _require_owner(exidx, expected, label):
    actual = _owner(exidx, expected["start"])
    if actual != (expected["start"], expected["end"]):
        raise RuntimeError(label + " owner differs")


def _require_defined_symbol(dynsym, name, start, end, label):
    matches = [symbol for symbol in dynsym.iter_symbols() if symbol.name == name]
    if len(matches) != 1:
        raise RuntimeError(label + " symbol count differs")
    symbol = matches[0]
    value = symbol["st_value"] & ~1
    size = symbol["st_size"]
    if value != start or size != end - start or symbol["st_shndx"] == "SHN_UNDEF":
        raise RuntimeError(label + " symbol definition differs")


def _require_direct_edge(blob, mappings, deps, site, target, *, call, label):
    item = _instruction(blob, mappings, deps, site)
    group = deps["call_group"] if call else deps["jump_group"]
    if not item.group(group) or _direct_target(item, deps) != target:
        raise RuntimeError(label + " differs")


def _validate_typed_request(blob, mappings, deps, plt_symbols, exidx):
    expected = EXPECTED_EXPORT["typed_request"]
    _require_owner(exidx, expected["owner"], "typed Creative Style request")
    request = _validate_selector_request(blob, mappings, deps, plt_symbols)
    actual = {
        "owner": copy.deepcopy(expected["owner"]),
        "site": request["request_call_site"],
        "symbol": request["request_symbol"],
        "model": request["request_model"],
        "request_code": request["request_code"],
        "param_list_add_count": len(request["param_add_call_sites"]),
        "classification": expected["classification"],
    }
    if actual != expected:
        raise RuntimeError("typed Creative Style request contract differs")
    return actual


def _validate_view_transport(blob, mappings, deps, dynsym, plt_symbols, exidx):
    expected = EXPECTED_EXPORT["view_wrapper_transport"]
    _require_defined_symbol(
        dynsym,
        expected["wrapper_symbol"],
        expected["wrapper_owner"]["start"],
        expected["wrapper_owner"]["end"],
        "Creative Style request wrapper",
    )
    for key, label in (
        ("wrapper_owner", "Creative Style request wrapper"),
        ("helper_owner", "Creative Style request helper"),
        ("dispatcher_owner", "Creative Style request dispatcher"),
    ):
        _require_owner(exidx, expected[key], label)
    if _call_symbol(blob, mappings, deps, plt_symbols, expected["mr_util_call_site"]) != expected["mr_util_symbol"]:
        raise RuntimeError("Creative Style MR-util lookup differs")
    _require_direct_edge(
        blob, mappings, deps,
        expected["tail_branch"]["site"], expected["tail_branch"]["target"],
        call=False, label="Creative Style wrapper tail branch",
    )
    _require_direct_edge(
        blob, mappings, deps,
        expected["helper_call"]["site"], expected["helper_call"]["target"],
        call=True, label="Creative Style helper dispatcher call",
    )
    return copy.deepcopy(expected)


def _validate_candidate_boundary(blob, mappings, deps, plt_symbols):
    expected = EXPECTED_EXPORT["candidate_cross_module_boundary"]
    if _call_symbol(blob, mappings, deps, plt_symbols, expected["site"]) != expected["symbol"]:
        raise RuntimeError("candidate shared request edge differs")
    dispatcher = EXPECTED_EXPORT["view_wrapper_transport"]["dispatcher_owner"]
    if not dispatcher["start"] <= expected["site"] < dispatcher["end"]:
        raise RuntimeError("candidate shared request edge is outside dispatcher")
    named_edges = []
    for item in _decode(blob, mappings, deps, dispatcher["start"], dispatcher["end"]):
        if not item.group(deps["call_group"]):
            continue
        target = _direct_target(item, deps)
        if target in plt_symbols and plt_symbols[target] == expected["symbol"]:
            named_edges.append(item.address)
    if named_edges != [expected["site"]]:
        raise RuntimeError("named shared request edge inventory differs")
    return copy.deepcopy(expected)


def _validate_shared_transport(blob, mappings, deps, dynsym, plt_symbols, exidx):
    expected = EXPECTED_EXPORT["shared_libobj_transport"]
    _require_defined_symbol(
        dynsym,
        expected["request_symbol"],
        expected["request_owner"]["start"],
        expected["request_owner"]["end"],
        "shared request transport",
    )
    _require_owner(exidx, expected["request_owner"], "shared request transport")
    _require_owner(exidx, expected["event_builder_owner"], "request event builder")
    calls = (
        (expected["id_generator_call_site"], expected["id_generator_symbol"], "request ID generator"),
        (expected["event_builder_call_site"], expected["event_builder_symbol"], "request event builder"),
        (expected["event_constructor_call_site"], expected["event_constructor_symbol"], "Event constructor"),
        (expected["param_list_attach_call_site"], expected["param_list_attach_symbol"], "Event ParamList attach"),
    )
    for site, symbol, label in calls:
        if _call_symbol(blob, mappings, deps, plt_symbols, site) != symbol:
            raise RuntimeError(label + " differs")
    for site in expected["scalar_parameter_add_call_sites"]:
        if _call_symbol(blob, mappings, deps, plt_symbols, site) != expected["scalar_parameter_add_symbol"]:
            raise RuntimeError("Event scalar parameter add differs")
    _require_direct_edge(
        blob, mappings, deps,
        expected["event_continuation_branch_site"], expected["event_continuation"],
        call=False, label="shared request event continuation",
    )
    return copy.deepcopy(expected)


def _validate_event_queue(blob, mappings, deps, dynsym, exidx):
    expected = EXPECTED_EXPORT["event_queue_boundary"]
    _require_defined_symbol(
        dynsym,
        expected["push_symbol"],
        expected["push_owner"]["start"],
        expected["push_owner"]["end"],
        "EventManager queue boundary",
    )
    _require_owner(exidx, expected["push_owner"], "EventManager queue boundary")
    indirect = []
    for item in _decode(blob, mappings, deps, expected["push_owner"]["start"], expected["push_owner"]["end"]):
        if item.group(deps["call_group"]) and _direct_target(item, deps) is None:
            indirect.append(item)
    if [item.address for item in indirect] != expected["indirect_call_sites"]:
        raise RuntimeError("EventManager indirect call inventory differs")
    for item in indirect:
        if len(item.operands) != 1 or item.operands[0].type != deps["reg"]:
            raise RuntimeError("EventManager indirect call shape differs")
    if len(indirect) != expected["indirect_call_count"]:
        raise RuntimeError("EventManager indirect call count differs")
    return copy.deepcopy(expected)


class ElfAdapter:
    def metadata(self):
        if not sources_available():
            raise RuntimeError("pinned Creative Style request-transport sources are unavailable")
        before = {role: _require_source_identity(role, path) for role, path in SOURCE_PATHS.items()}
        deps = _dependencies()
        contexts = {}
        for role, path in SOURCE_PATHS.items():
            blob = path.read_bytes()
            handle = path.open("rb")
            try:
                elf = deps["ELFFile"](handle)
                contexts[role] = {
                    "handle": handle,
                    "blob": blob,
                    "elf": elf,
                    "mappings": _mappings(elf),
                    "dynsym": elf.get_section_by_name(".dynsym"),
                    "plt_symbols": _plt_symbols(elf, blob, _mappings(elf)),
                    "exidx": _exidx_ranges(elf, blob),
                }
            except Exception:
                handle.close()
                raise
        try:
            view = contexts["view"]
            obj = contexts["object"]
            typed_request = _validate_typed_request(
                view["blob"], view["mappings"], deps, view["plt_symbols"], view["exidx"]
            )
            view_transport = _validate_view_transport(
                view["blob"], view["mappings"], deps, view["dynsym"], view["plt_symbols"], view["exidx"]
            )
            candidate = _validate_candidate_boundary(
                view["blob"], view["mappings"], deps, view["plt_symbols"]
            )
            shared = _validate_shared_transport(
                obj["blob"], obj["mappings"], deps, obj["dynsym"], obj["plt_symbols"], obj["exidx"]
            )
            queue = _validate_event_queue(
                obj["blob"], obj["mappings"], deps, obj["dynsym"], obj["exidx"]
            )
        finally:
            for context in contexts.values():
                context["handle"].close()
        for role, path in SOURCE_PATHS.items():
            if _sha256(path) != before[role]:
                raise RuntimeError("pinned " + role + " source changed during export")
        document = copy.deepcopy(EXPECTED_EXPORT)
        document.update({
            "typed_request": typed_request,
            "view_wrapper_transport": view_transport,
            "candidate_cross_module_boundary": candidate,
            "shared_libobj_transport": shared,
            "event_queue_boundary": queue,
        })
        return document


def build_raw_export(adapter=None):
    document = (adapter or ElfAdapter()).metadata()
    return normalize_creative_style_model_request_transport_export(document)


def write_export(document, output_root=OUTPUT_ROOT):
    normalized = normalize_creative_style_model_request_transport_export(document)
    root = Path(output_root).resolve()
    approved = OUTPUT_ROOT.resolve()
    if root != approved or ARTIFACT_BASE.resolve() not in root.parents:
        raise RuntimeError("output root is outside the approved artifact path")
    root.mkdir(parents=True, exist_ok=True)
    target = root / OUTPUT_NAME
    if target.exists() and (target.is_symlink() or not target.is_file()):
        raise RuntimeError("output target is not a regular file")
    payload = json.dumps(normalized, indent=2, sort_keys=True) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=OUTPUT_NAME + ".", suffix=".tmp", dir=str(root))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return target


def main():
    output = write_export(build_raw_export())
    print("CREATIVE_STYLE_MODEL_REQUEST_TRANSPORT_EXPORT|typed=1|candidate=1|handler=0|sink=0|installable=0")
    print(output)


if __name__ == "__main__":
    main()
