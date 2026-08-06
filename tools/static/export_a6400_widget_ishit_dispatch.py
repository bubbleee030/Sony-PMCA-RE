"""Read-only bounded α6400 generic slot-37 dispatch exporter."""
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
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
from pmca.analysis.touch_api_callers import PRIOR_UI_GRAPH_SHA256, normalize_touch_api_callers_export
from pmca.analysis.widget_hit_test_vtables import normalize_widget_hit_test_vtables_export
from pmca.analysis.widget_ishit_dispatch import (
    ANALYSIS_LOAD_BIAS, DEFINED_PLT_BINDING, DISPATCHES, EXPECTED_RAW_EXPORT,
    PC_LITERAL_DIGEST, ROOT_PATHS, ROOT_RECORDS, SLOT_OFFSET, STACK_CANDIDATES,
    TOUCH_CALLERS_DIGEST, TOUCH_OWNER_RECORDS, TOUCH_REVERSE_PATHS,
    VIEW_UNIFIED2_SHA256, VIEW_UNIFIED2_SIZE,
    WIDGET_VTABLE_DIGEST, normalize_widget_ishit_dispatch_export,
)


SOURCE = ROOT / ".artifacts" / "decrypted" / "a6400-tw-v2.00" / "ma1co" / "firmware.tar_unpacked" / "0700_part_image" / "dev" / "nflasha15_unpacked" / "lib" / "viewUnified2.so"
WIDGET_VTABLES = ROOT / ".artifacts" / "widget-hit-test-vtable-trace" / "a6400-v2.00" / "raw-widget-hit-test-vtables.json"
TOUCH_CALLERS = ROOT / ".artifacts" / "touch-api-caller-trace" / "a6400-v2.00" / "raw-touch-api-callers.json"
UI_DISPATCH = ROOT / ".artifacts" / "ui-trace" / "a6400-v2.00" / "raw-ui-dispatch.json"
UI_DISPATCH_REPORT = ROOT / "analysis" / "a6400-ui-dispatch-boundary.json"
ARTIFACT_BASE = ROOT / ".artifacts"
OUTPUT_ROOT = ARTIFACT_BASE / "widget-ishit-dispatch-trace" / "a6400-v2.00"
OUTPUT_NAME = "raw-widget-ishit-dispatch.json"
DEFINED_SYMBOL = "_ZN27CmnWrpOrientationRegisterAF26getRecallRegisteredAfFrameEv"


def _deps():
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_GRP_CALL, CS_GRP_JUMP, CS_OP_IMM
        from capstone.arm import ARM_INS_ADD, ARM_INS_BLX, ARM_INS_LDR, ARM_INS_MOV, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC, ARM_REG_SP
        from elftools.elf.elffile import ELFFile
    except ImportError:
        for path in (ROOT / ".artifacts" / "pydeps_vlf", ROOT / ".artifacts" / "pydeps"):
            if path.is_dir(): sys.path.insert(0, str(path))
        try:
            from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_GRP_CALL, CS_GRP_JUMP, CS_OP_IMM
            from capstone.arm import ARM_INS_ADD, ARM_INS_BLX, ARM_INS_LDR, ARM_INS_MOV, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC, ARM_REG_SP
            from elftools.elf.elffile import ELFFile
        except ImportError as exc: raise RuntimeError("local Capstone and pyelftools are required") from exc
    return Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_GRP_CALL, CS_GRP_JUMP, CS_OP_IMM, ARM_INS_ADD, ARM_INS_BLX, ARM_INS_LDR, ARM_INS_MOV, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC, ARM_REG_SP, ELFFile


def _sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _prel31(value, address):
    value &= 0x7fffffff
    return address + (value - 0x80000000 if value & 0x40000000 else value)


def _mappings(elf):
    return [(segment["p_vaddr"], segment["p_vaddr"] + segment["p_filesz"], segment["p_offset"]) for segment in elf.iter_segments() if segment["p_type"] == "PT_LOAD"]


def _at(blob, mappings, address, length):
    offsets = [offset + address - start for start, end, offset in mappings if start <= address and address + length <= end]
    if len(offsets) != 1: raise RuntimeError("owner bytes do not map uniquely")
    return blob[offsets[0]:offsets[0] + length]


def _owners(elf):
    section = elf.get_section_by_name(".ARM.exidx")
    if section is None or section["sh_size"] % 8: raise RuntimeError("exception index is absent or malformed")
    values = sorted(_prel31(int.from_bytes(section.data()[offset:offset + 4], "little"), section["sh_addr"] + offset) for offset in range(0, section["sh_size"], 8))
    return [(value, values[index + 1] if index + 1 < len(values) else None) for index, value in enumerate(values)]


def _decode(owners, blob, mappings):
    Cs, arch, thumb, call, jump, immediate, add, blx, ldr, mov, mem, reg, pc, sp, _ = _deps()
    decoder = Cs(arch, thumb); decoder.detail = True
    complete, incomplete, terminal = [], [], 0
    for owner, end in owners:
        if end is None: terminal += 1; continue
        instructions = list(decoder.disasm(_at(blob, mappings, owner, end - owner), owner | 1))
        if sum(item.size for item in instructions) != end - owner: incomplete.append(owner)
        else: complete.append((owner, end, instructions))
    if (len(owners), len(complete), len(incomplete), terminal) != (30463, 28869, 1593, 1):
        raise RuntimeError("exception-index decode accounting differs")
    return complete


def _scan(complete):
    Cs, arch, thumb, call, jump, immediate, add, blx, ldr, mov, mem, reg, pc, sp, _ = _deps()
    dispatches, stacks, literals, edges = [], [], [], {}
    for owner, _end, instructions in complete:
        provenance, possible, direct = {}, [], []
        for item in instructions:
            address = item.address & ~1
            if item.group(call) or item.group(jump):
                for operand in item.operands:
                    if operand.type == immediate: direct.append((address, operand.imm & ~1))
            if item.id == ldr and len(item.operands) == 2 and item.operands[0].type == reg and item.operands[1].type == mem:
                destination, operand = item.operands[0].reg, item.operands[1].mem
                if operand.disp == SLOT_OFFSET and operand.base == pc:
                    literals.append((owner, address)); provenance.pop(destination, None)
                elif operand.disp == SLOT_OFFSET and (operand.base == sp or provenance.get(operand.base, (None,))[0] == "stack"):
                    stacks.append({"owner": owner, "site": address}); provenance.pop(destination, None)
                elif operand.base == pc: provenance[destination] = ("pc", address)
                elif operand.disp == 0 and operand.base != sp: provenance[destination] = ("vptr", address)
                elif operand.disp == SLOT_OFFSET:
                    prior = provenance.get(operand.base)
                    if prior and prior[0] == "vptr": possible.append((destination, address, prior[1]))
                    provenance.pop(destination, None)
                else: provenance.pop(destination, None)
            elif item.id in (add, mov) and len(item.operands) >= 2 and item.operands[0].type == reg and item.operands[1].type == reg and item.operands[1].reg == sp:
                provenance[item.operands[0].reg] = ("stack", address)
            elif item.id == blx and len(item.operands) == 1 and item.operands[0].type == reg:
                matched, possible = [record for record in possible if record[0] == item.operands[0].reg], [record for record in possible if record[0] != item.operands[0].reg]
                dispatches.extend({"owner": owner, "receiver_vptr_load": vptr, "slot_load": slot, "indirect_call": address} for _register, slot, vptr in matched)
        edges[owner] = direct
    dispatches.sort(key=lambda item: (item["owner"], item["slot_load"]))
    stacks.sort(key=lambda item: (item["owner"], item["site"])); literals.sort()
    if tuple(dispatches) != DISPATCHES or tuple(stacks) != STACK_CANDIDATES:
        raise RuntimeError("bounded structural candidates differ")
    digest = hashlib.sha256(json.dumps(literals, separators=(",", ":")).encode()).hexdigest()
    if len(literals) != 361 or digest != PC_LITERAL_DIGEST: raise RuntimeError("direct PC-relative rejection population differs")
    return dispatches, stacks, edges


def _defined_plt_binding(elf, blob, mappings, edges):
    """Resolve only the pinned locally defined orientation/AF method binding."""
    _deps()
    from capstone import CS_ARCH_ARM, CS_MODE_ARM, Cs

    dynsym = elf.get_section_by_name(".dynsym")
    relplt = elf.get_section_by_name(".rel.plt")
    plt = elf.get_section_by_name(".plt")
    if dynsym is None or relplt is None or plt is None:
        raise RuntimeError("required dynamic binding sections are absent")
    symbol_matches = [(index, symbol) for index, symbol in enumerate(dynsym.iter_symbols()) if symbol.name == DEFINED_SYMBOL]
    if len(symbol_matches) != 1:
        raise RuntimeError("defined orientation/AF symbol identity differs")
    symbol_index, symbol = symbol_matches[0]
    relocations = [(index, item) for index, item in enumerate(relplt.iter_relocations()) if item.entry.r_info_sym == symbol_index]
    if len(relocations) != 1:
        raise RuntimeError("defined orientation/AF JUMP_SLOT binding differs")
    relocation_index, relocation = relocations[0]
    got_address = relocation.entry.r_offset

    decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM); decoder.detail = True
    stubs = []
    for address in range(plt["sh_addr"], plt["sh_addr"] + plt["sh_size"] - 11, 4):
        instructions = list(decoder.disasm(_at(blob, mappings, address, 12), address))
        if len(instructions) != 3 or [item.mnemonic for item in instructions] != ["add", "add", "ldr"]:
            continue
        try:
            candidate_got = address + 8 + instructions[0].operands[2].imm + instructions[1].operands[2].imm + instructions[2].operands[1].mem.disp
        except (AttributeError, IndexError):
            continue
        if candidate_got == got_address:
            stubs.append(address)
    if len(stubs) != 1:
        raise RuntimeError("defined orientation/AF PLT stub differs")
    plt_address = stubs[0]
    callsites = sorted((owner, site) for owner, owner_edges in edges.items() for site, target in owner_edges if target == plt_address)
    callsite_digest = hashlib.sha256(json.dumps(callsites, separators=(",", ":")).encode()).hexdigest()
    defined_owner = symbol["st_value"] & ~1
    if edges.get(defined_owner) != [(0x35F670, 0x35F424)]:
        raise RuntimeError("defined orientation/AF receiver helper edge differs")
    binding = {
        "symbol": "CmnWrpOrientationRegisterAF::getRecallRegisteredAfFrame()",
        "symbol_index": symbol_index,
        "defined_owner": defined_owner,
        "defined_size": symbol["st_size"],
        "relocation_index": relocation_index,
        "got_address": got_address,
        "plt_address": plt_address,
        "direct_callsite_count": len(callsites),
        "direct_caller_owner_count": len({owner for owner, _site in callsites}),
        "direct_callsite_digest": callsite_digest,
        "receiver_provenance": "helper-return-r0",
        "receiver_helper_owner": edges[defined_owner][0][1],
        "receiver_helper_call": edges[defined_owner][0][0],
        "slot_load": 0x35F676,
        "indirect_call": 0x35F67A,
    }
    if binding != DEFINED_PLT_BINDING:
        raise RuntimeError("defined orientation/AF PLT evidence differs")
    return binding


def _find_path(edges, complete_owners, starts, goals, plt_resolutions):
    seen, queue = set(starts), [(item, []) for item in starts]
    while queue:
        current, path = queue.pop(0)
        if len(path) == 32:
            continue
        for site, direct_target in edges[current]:
            resolved_target = plt_resolutions.get(direct_target, direct_target)
            if resolved_target not in complete_owners or resolved_target in seen:
                continue
            edge = {"owner": current, "site": site, "direct_target": direct_target, "resolved_target": resolved_target}
            candidate = path + [edge]
            if resolved_target in goals:
                return candidate
            seen.add(resolved_target); queue.append((resolved_target, candidate))
    return []


def _prior(path, normalizer, digest, contract):
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file(): raise RuntimeError("prior evidence must be a literal regular file")
    try: summary = normalizer(json.loads(candidate.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc: raise RuntimeError("prior evidence is invalid") from exc
    if summary["artifact_sha256"] != digest: raise RuntimeError("prior evidence digest differs")
    return {"analysis_contract": contract, "artifact_sha256": digest}


def _json_literal_file(path, label):
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file(): raise RuntimeError(label + " must be a literal regular file")
    try: return json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc: raise RuntimeError(label + " is invalid") from exc


def path_records_from_prior(ui_document, touch_document):
    """Derive the only ELF-domain starts from prior analysis-domain evidence."""
    if not isinstance(ui_document, dict) or set(ui_document) != {"program", "sha256", "image_size", "roots", "edges", "truncated"}:
        raise RuntimeError("prior UI dispatch evidence fields differ")
    if (ui_document["program"], ui_document["sha256"], ui_document["image_size"], ui_document["truncated"]) != ("viewUnified2.so", VIEW_UNIFIED2_SHA256, VIEW_UNIFIED2_SIZE, False):
        raise RuntimeError("prior UI dispatch identity differs")
    if not isinstance(ui_document["edges"], list) or len(ui_document["edges"]) != 2046 or not isinstance(ui_document["roots"], list):
        raise RuntimeError("prior UI dispatch bounds differ")
    roots = []
    for item in ui_document["roots"]:
        if not isinstance(item, dict) or set(item) != {"name", "role", "source_kind", "source_offset", "analysis_address", "function_address"}:
            raise RuntimeError("prior UI root fields differ")
        analysis = item["analysis_address"]
        if not isinstance(analysis, int) or item["function_address"] != analysis:
            raise RuntimeError("prior UI root analysis address differs")
        elf = analysis - ANALYSIS_LOAD_BIAS
        if elf < 0 or item["source_kind"] not in {"analysis-address", "elf-file-offset"}:
            raise RuntimeError("prior UI root address domain differs")
        if ((item["source_kind"] == "analysis-address" and item["source_offset"] != analysis) or
                (item["source_kind"] == "elf-file-offset" and item["source_offset"] != elf)):
            raise RuntimeError("prior UI root provenance differs")
        roots.append({"name": item["name"], "role": item["role"], "source_kind": item["source_kind"], "source_offset": item["source_offset"], "analysis_address": analysis, "elf_address": elf})
    if tuple(roots) != ROOT_RECORDS: raise RuntimeError("prior UI root mapping differs")
    normalize_touch_api_callers_export(touch_document)
    owners = {}
    for caller in touch_document["callers"]:
        analysis = int(caller["owner"], 16)
        apis = owners.setdefault(analysis, [])
        if caller["api"] not in apis: apis.append(caller["api"])
    records = tuple({"apis": owners[address], "analysis_address": address, "elf_address": address - ANALYSIS_LOAD_BIAS} for address in sorted(owners))
    if tuple(records) != TOUCH_OWNER_RECORDS: raise RuntimeError("prior touch caller mapping differs")
    return tuple(roots), records


def _validate_prior_ui_report(ui_document, report_document):
    if not isinstance(report_document, dict): raise RuntimeError("prior UI dispatch report is invalid")
    summary = report_document.get("bounded_export_summary")
    if not isinstance(summary, dict) or summary.get("artifact_sha256") != PRIOR_UI_GRAPH_SHA256:
        raise RuntimeError("prior UI dispatch report digest differs")
    report_roots = report_document.get("roots")
    if not isinstance(report_roots, list): raise RuntimeError("prior UI dispatch report roots are invalid")
    normalized_roots = []
    for item in report_roots:
        if not isinstance(item, dict) or set(item) != {"name", "role", "module", "source_kind", "source_offset", "analysis_address", "function_address"} or item["module"] != "lib/viewUnified2.so":
            raise RuntimeError("prior UI dispatch report root fields differ")
        try:
            normalized_roots.append({key: int(item[key], 16) if key in {"source_offset", "analysis_address", "function_address"} else item[key] for key in ("name", "role", "source_kind", "source_offset", "analysis_address", "function_address")})
        except (TypeError, ValueError) as exc: raise RuntimeError("prior UI dispatch report root addresses differ") from exc
    if normalized_roots != ui_document["roots"]:
        raise RuntimeError("prior UI dispatch report roots differ")


def _metadata_from_file(source=SOURCE, widget_vtables=WIDGET_VTABLES, touch_callers=TOUCH_CALLERS, ui_dispatch=UI_DISPATCH, ui_dispatch_report=UI_DISPATCH_REPORT):
    source = Path(source); before = _sha(source)
    if source.name != "viewUnified2.so" or source.stat().st_size != VIEW_UNIFIED2_SIZE or before != VIEW_UNIFIED2_SHA256: raise RuntimeError("source identity is not pinned")
    prior_vtables = _prior(widget_vtables, normalize_widget_hit_test_vtables_export, WIDGET_VTABLE_DIGEST, "widget_hit_test_vtables")
    prior_touch = _prior(touch_callers, normalize_touch_api_callers_export, TOUCH_CALLERS_DIGEST, "touch_api_callers")
    ui_document = _json_literal_file(ui_dispatch, "prior UI dispatch evidence")
    touch_document = _json_literal_file(touch_callers, "prior touch caller evidence")
    _validate_prior_ui_report(ui_document, _json_literal_file(ui_dispatch_report, "prior UI dispatch report"))
    root_records, touch_records = path_records_from_prior(ui_document, touch_document)
    _, _, _, _, _, _, _, _, _, _, _, _, _, _, ELFFile = _deps()
    blob = source.read_bytes()
    with io.BytesIO(blob) as stream:
        elf = ELFFile(stream); mappings = _mappings(elf); complete = _decode(_owners(elf), blob, mappings); dispatches, stacks, edges = _scan(complete)
        binding = _defined_plt_binding(elf, blob, mappings, edges)
        ranges = {owner: end for owner, end, _instructions in complete}; direct_owners = set(ranges)
        root_starts = []
        for record in root_records:
            root = record["elf_address"]
            matches = [owner for owner, end in ranges.items() if owner <= root < end]
            if len(matches) != 1: raise RuntimeError("pinned root does not have one complete owner")
            root_starts.append((record, matches[0]))
        targets = {record["owner"] for record in dispatches}; touch = {record["elf_address"] for record in touch_records}
        plt_resolutions = {binding["plt_address"]: binding["defined_owner"]}
        named_dispatch = next(record for record in dispatches if record["owner"] == binding["defined_owner"])
        root_paths = []
        for root_record, start in root_starts:
            path = _find_path(edges, direct_owners, [start], targets, plt_resolutions)
            if path:
                if path[-1]["resolved_target"] != binding["defined_owner"]:
                    raise RuntimeError("unexpected accepted root dispatch owner")
                root_paths.append({"root": root_record["name"], "start_owner": start, "edges": path, "dispatch": named_dispatch})
        if tuple(root_paths) != ROOT_PATHS:
            raise RuntimeError("PLT-aware root path result differs")
        if any(_find_path(edges, direct_owners, [owner], touch, plt_resolutions) for owner in targets):
            raise RuntimeError("dispatch-to-touch path result differs")
        touch_reverse_paths = []
        for touch_record in touch_records:
            start = touch_record["elf_address"]
            path = _find_path(edges, direct_owners, [start], targets, plt_resolutions)
            if path:
                if path[-1]["resolved_target"] != binding["defined_owner"]:
                    raise RuntimeError("unexpected accepted touch dispatch owner")
                touch_reverse_paths.append({
                    "touch_api_caller_analysis_address": touch_record["analysis_address"],
                    "touch_api_caller_elf_owner": start,
                    "apis": touch_record["apis"],
                    "edges": path,
                    "dispatch": named_dispatch,
                })
        if tuple(touch_reverse_paths) != TOUCH_REVERSE_PATHS:
            raise RuntimeError("PLT-aware touch-to-dispatch path result differs")
    document = copy.deepcopy(EXPECTED_RAW_EXPORT); document["prior_widget_vtables"] = prior_vtables; document["prior_touch_api_callers"] = prior_touch; document["defined_plt_binding"] = binding
    normalize_widget_ishit_dispatch_export(document)
    if _sha(source) != before: raise RuntimeError("source changed during static export")
    return document


class FileAdapter:
    def __init__(self, source=SOURCE, widget_vtables=WIDGET_VTABLES, touch_callers=TOUCH_CALLERS, ui_dispatch=UI_DISPATCH, ui_dispatch_report=UI_DISPATCH_REPORT): self.source, self.widget_vtables, self.touch_callers, self.ui_dispatch, self.ui_dispatch_report = source, widget_vtables, touch_callers, ui_dispatch, ui_dispatch_report
    def metadata(self): return _metadata_from_file(self.source, self.widget_vtables, self.touch_callers, self.ui_dispatch, self.ui_dispatch_report)


def build_raw_export(adapter=None):
    try: return normalize_widget_ishit_dispatch_export((adapter or FileAdapter()).metadata())
    except Exception as exc: raise RuntimeError("slot-37 metadata differs from exact bounded static result") from exc


def _literal_directory_under(root, base):
    base, root = Path(os.path.abspath(os.fspath(base))), Path(os.path.abspath(os.fspath(root)))
    if base.is_symlink() or not base.is_dir() or base.resolve(strict=True) != base: raise RuntimeError("artifact base is not a literal directory")
    try: root.relative_to(base); resolved = root.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc: raise RuntimeError("approved output root is not contained") from exc
    if root.is_symlink() or not root.is_dir() or resolved != root: raise RuntimeError("approved output root escapes through a symlink")
    return root


def prepare_output_root(approved_root=OUTPUT_ROOT, artifact_base=ARTIFACT_BASE):
    base, root = Path(os.path.abspath(os.fspath(artifact_base))), Path(os.path.abspath(os.fspath(approved_root)))
    _literal_directory_under(base, base)
    try: relative = root.relative_to(base)
    except ValueError as exc: raise RuntimeError("approved output root is not contained") from exc
    current = base
    for part in relative.parts:
        candidate = current / part
        if candidate.is_symlink() or (candidate.exists() and not candidate.is_dir()): raise RuntimeError("approved output root has non-literal ancestor")
        if not candidate.exists(): candidate.mkdir()
        if candidate.is_symlink() or candidate.resolve(strict=True) != candidate: raise RuntimeError("approved output root escapes through a symlink")
        current = candidate
    return _literal_directory_under(root, base)


def write_json_atomic(output, document, approved_root=OUTPUT_ROOT, artifact_base=ARTIFACT_BASE):
    root = _literal_directory_under(approved_root, artifact_base); output = Path(os.path.abspath(os.fspath(output)))
    if output.name != OUTPUT_NAME or output.parent != root or output.is_symlink() or (output.exists() and not output.is_file()): raise RuntimeError("output containment is invalid")
    handle, temporary = tempfile.mkstemp(dir=str(root), prefix=".widget-ishit-", suffix=".tmp")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(json.dumps(document, sort_keys=True, separators=(",", ":")).encode() + b"\n"); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, output)
    except BaseException:
        try: os.unlink(temporary)
        except FileNotFoundError: pass
        raise


if __name__ == "__main__":
    prepare_output_root(); write_json_atomic(OUTPUT_ROOT / OUTPUT_NAME, build_raw_export())
    print("GENERIC_SLOT37_DISPATCH_EXPORT|accepted=10|pc_literals=361|menu_selection=0")
