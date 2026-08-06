# Export bounded α6400 Picture Profile metadata from the pinned target module.
# @category Sony.PictureProfile
# @runtime PyGhidra

"""Read-only Ghidra post-script for α6400 Picture Profile metadata."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from collections import deque

EXPECTED_PROGRAM = "CautionConfig.so"
CAUTION_CONFIG_SHA256 = (
    "bfd1bd7bad0ab3478b894da5dbb51c15464b1bedc4201240ccb61cd743150ef7"
)
CAUTION_CONFIG_SIZE = 12_070_800
DEPTH_CAP = 16


def _root(symbol, address):
    return {"analysis_address_int": address, "symbol": symbol}


PICTURE_PROFILE_ROOTS = (
    _root("CmnViewSettingNodePictureProfile::_getSubNode()", 0x7EBC04),
    _root("CmnViewSettingNodePictureProfile::clone()", 0x7EBBE0),
    _root("CmnViewSettingNodePictureProfileCopyPage1::_getSubNode()", 0x7EB824),
    _root("CmnViewSettingNodePictureProfileGamma::_getSubNode()", 0x7EB6BC),
    _root("CmnViewSettingNodePictureProfileColorMode::_getSubNode()", 0x7EDF5C),
)
PICTURE_PROFILE_SLOT_NODES = tuple(
    _root(symbol, address)
    for symbol, address in (
        ("cmnViewSettingNodePictureProfilePP1", 0xBAC208),
        ("cmnViewSettingNodePictureProfilePP2", 0xC5EE70),
        ("cmnViewSettingNodePictureProfilePP3", 0xC5EE98),
        ("cmnViewSettingNodePictureProfilePP4", 0xC5EEC0),
        ("cmnViewSettingNodePictureProfilePP5", 0xC5EEE8),
        ("cmnViewSettingNodePictureProfilePP6", 0xBAC240),
        ("cmnViewSettingNodePictureProfilePP7", 0xC5EF38),
        ("cmnViewSettingNodePictureProfilePP8", 0xC5EF60),
        ("cmnViewSettingNodePictureProfilePP9", 0xC5EF88),
    )
)
MAX_DIRECT_CALLS = 512
MAX_DATA_REFERENCES = 512
MAX_UNRESOLVED_INDIRECT_EDGES = 128
MAX_FUNCTIONS = 2048
MAX_TOTAL_INSTRUCTIONS = 150_000


def reference_is_data(reference):
    """Accept only Ghidra references explicitly classified as data."""

    reference_type = reference.getReferenceType()
    predicate = getattr(reference_type, "isData", None)
    return predicate is not None and bool(predicate())


def _validate_items(items, expected, label):
    if not isinstance(items, list):
        raise RuntimeError(f"{label} are invalid")
    expected_items = [
        {"address": item["analysis_address_int"], "symbol": item["symbol"]}
        for item in expected
    ]
    if items != expected_items:
        raise RuntimeError(f"{label} are not pinned")
    return items


def _validate_edges(items, fields, label, limit):
    if not isinstance(items, list) or len(items) > limit:
        raise RuntimeError(f"{label} exceed bounds")
    sites = set()
    for item in items:
        if not isinstance(item, dict) or set(item) != fields:
            raise RuntimeError(f"{label} metadata is invalid")
        site = item["site"]
        if not isinstance(site, str) or not site.startswith("0x") or site in sites:
            raise RuntimeError(f"{label} sites are invalid")
        sites.add(site)
    return items


def build_raw_export(adapter, expected_program, expected_sha256):
    """Build a metadata-only export using a read-only Ghidra adapter."""

    if expected_program != EXPECTED_PROGRAM or expected_sha256 != CAUTION_CONFIG_SHA256:
        raise RuntimeError("expected Picture Profile program identity is invalid")
    if adapter.program_name() != EXPECTED_PROGRAM:
        raise RuntimeError("open Ghidra program is not CautionConfig.so")
    if adapter.program_sha256().lower() != CAUTION_CONFIG_SHA256:
        raise RuntimeError("open Ghidra program digest is not pinned")
    if (
        adapter.program_headless_read_only() is not True
        or adapter.program_noanalysis() is not True
        or adapter.program_is_changed() is not False
    ):
        raise RuntimeError("Picture Profile export requires unchanged read-only mode")

    roots = _validate_items(adapter.roots(), PICTURE_PROFILE_ROOTS, "roots")
    slots = _validate_items(adapter.slot_nodes(), PICTURE_PROFILE_SLOT_NODES, "slot nodes")
    direct_calls, data_references, unresolved_indirect_edges = adapter.iter_edges(
        [item["address"] for item in roots], DEPTH_CAP
    )
    _validate_edges(direct_calls, {"caller", "site", "target", "owner"}, "direct calls", MAX_DIRECT_CALLS)
    _validate_edges(data_references, {"owner", "site", "target", "symbol"}, "data references", MAX_DATA_REFERENCES)
    _validate_edges(unresolved_indirect_edges, {"caller", "site", "owner"}, "unresolved indirect edges", MAX_UNRESOLVED_INDIRECT_EDGES)
    return {
        "program": EXPECTED_PROGRAM,
        "sha256": CAUTION_CONFIG_SHA256,
        "file_size": CAUTION_CONFIG_SIZE,
        "analysis_mode": {"read_only": True, "noanalysis": True},
        "roots": roots,
        "slot_nodes": slots,
        "direct_calls": direct_calls,
        "data_references": data_references,
        "unresolved_indirect_edges": unresolved_indirect_edges,
        "truncated": False,
        "depth_cap": DEPTH_CAP,
    }


def write_json_atomic(output_path, document, approved_root):
    output = Path(output_path)
    root = Path(approved_root).resolve(strict=True)
    if output.name != "raw-picture-profile.json" or not root.is_dir():
        raise RuntimeError("Picture Profile output target is invalid")
    if output.parent.resolve(strict=True) != root:
        raise RuntimeError("Picture Profile output is outside its approved root")
    if output.exists() and (output.is_symlink() or not output.is_file()):
        raise RuntimeError("Picture Profile output is not a regular file")
    handle, temporary_name = tempfile.mkstemp(dir=str(root), prefix=".picture-profile-", suffix=".tmp")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, output)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


class GhidraProgramAdapter:
    """Narrow Ghidra adapter that exports only bounded control-flow metadata."""

    def __init__(self, program, task_monitor):
        self._program = program
        self._monitor = task_monitor
        self._manager = program.getFunctionManager()
        self._listing = program.getListing()
        self._references = program.getReferenceManager()
        self._memory = program.getMemory()
        self._address_space = program.getAddressFactory().getDefaultAddressSpace()
        self._instruction_count = 0

    def program_name(self):
        return str(self._program.getName())

    def program_sha256(self):
        return str(self._program.getExecutableSHA256())

    def program_headless_read_only(self):
        from ghidra.app.util.headless import HeadlessAnalyzer

        options = HeadlessAnalyzer.getInstance().getOptions()
        field = options.getClass().getDeclaredField("readOnly")
        field.setAccessible(True)
        return bool(field.getBoolean(options))

    def program_is_changed(self):
        return bool(self._program.isChanged())

    def program_noanalysis(self):
        from ghidra.app.util.headless import HeadlessAnalyzer

        options = HeadlessAnalyzer.getInstance().getOptions()
        field = options.getClass().getDeclaredField("analyze")
        field.setAccessible(True)
        return not bool(field.getBoolean(options))

    def _address(self, value):
        return self._address_space.getAddress(hex(value)[2:])

    def _offset(self, address):
        return int(address.getOffset())

    def _function(self, address):
        function = self._manager.getFunctionAt(address)
        if function is None:
            function = self._manager.getFunctionContaining(address)
        if function is None or function.isExternal():
            return None
        return function

    def _pinned_functions(self):
        result = []
        for item in PICTURE_PROFILE_ROOTS:
            function = self._function(self._address(item["analysis_address_int"]))
            if function is None or self._offset(function.getEntryPoint()) != item["analysis_address_int"]:
                raise RuntimeError("Picture Profile root function did not resolve")
            result.append({"address": item["analysis_address_int"], "symbol": item["symbol"]})
        return result

    def roots(self):
        return self._pinned_functions()

    def slot_nodes(self):
        return [
            {"address": item["analysis_address_int"], "symbol": item["symbol"]}
            for item in PICTURE_PROFILE_SLOT_NODES
        ]

    def iter_edges(self, roots, depth_cap):
        from ghidra.program.model.pcode import PcodeOp

        if depth_cap != DEPTH_CAP:
            raise RuntimeError("Picture Profile traversal depth is invalid")
        direct_calls = []
        unresolved = []
        queued = set(roots)
        visited = set()
        queue = deque((address, 0) for address in roots)
        while queue:
            address, depth = queue.popleft()
            if address in visited:
                continue
            if depth > depth_cap or len(visited) >= MAX_FUNCTIONS:
                raise RuntimeError("Picture Profile call traversal exceeded bounds")
            function = self._function(self._address(address))
            if function is None or self._offset(function.getEntryPoint()) != address:
                continue
            visited.add(address)
            caller = hex(address)
            owner = str(function.getName(True))[:256]
            for instruction in self._listing.getInstructions(function.getBody(), True):
                self._monitor.checkCanceled()
                self._instruction_count += 1
                if self._instruction_count > MAX_TOTAL_INSTRUCTIONS:
                    raise RuntimeError("Picture Profile instruction bound exceeded")
                for operation in instruction.getPcode():
                    opcode = operation.getOpcode()
                    if opcode not in (PcodeOp.CALL, PcodeOp.CALLIND):
                        continue
                    site = hex(self._offset(instruction.getAddress()))
                    target = self._literal_target(operation) if opcode == PcodeOp.CALL else None
                    if opcode == PcodeOp.CALLIND:
                        unresolved.append({"caller": caller, "site": site, "owner": owner})
                    elif target is not None:
                        direct_calls.append(
                            {"caller": caller, "site": site, "target": hex(target), "owner": owner}
                        )
                        if target not in queued and target not in visited:
                            queue.append((target, depth + 1))
                            queued.add(target)
                    if len(direct_calls) > MAX_DIRECT_CALLS or len(unresolved) > MAX_UNRESOLVED_INDIRECT_EDGES:
                        raise RuntimeError("Picture Profile edge bound exceeded")

        references = []
        for node in self.slot_nodes():
            for reference in self._references.getReferencesTo(self._address(node["address"])):
                self._monitor.checkCanceled()
                if not reference_is_data(reference):
                    continue
                function = self._function(reference.getFromAddress())
                if function is None:
                    continue
                owner = self._offset(function.getEntryPoint())
                references.append(
                    {
                        "owner": hex(owner),
                        "site": hex(self._offset(reference.getFromAddress())),
                        "target": hex(node["address"]),
                        "symbol": node["symbol"],
                    }
                )
                if len(references) > MAX_DATA_REFERENCES:
                    raise RuntimeError("Picture Profile data-reference bound exceeded")
        return direct_calls, references, unresolved

    def _literal_target(self, operation):
        varnode = operation.getInput(0)
        if varnode is None:
            return None
        if varnode.isAddress():
            address = varnode.getAddress()
        elif varnode.isConstant():
            value = int(varnode.getOffset()) & ~1
            try:
                address = self._address(value)
            except BaseException:
                return None
        else:
            return None
        if not self._memory.contains(address):
            return None
        function = self._function(address)
        return None if function is None else self._offset(function.getEntryPoint())


def _run_ghidra_script():
    arguments = list(getScriptArgs())
    if len(arguments) != 3:
        raise RuntimeError("usage: <output.json> <expected-program> <expected-sha256>")
    output_path, expected_program, expected_sha256 = arguments
    document = build_raw_export(
        GhidraProgramAdapter(currentProgram, monitor), expected_program, expected_sha256
    )
    approved_root = Path(__file__).resolve().parents[2] / ".artifacts" / "picture-profile-trace" / "a6400-v2.00"
    write_json_atomic(output_path, document, approved_root)
    print(
        "PICTURE_PROFILE_EXPORT|direct=%d|references=%d|indirect=%d|truncated=false"
        % (
            len(document["direct_calls"]),
            len(document["data_references"]),
            len(document["unresolved_indirect_edges"]),
        )
    )


try:
    currentProgram
    getScriptArgs
except NameError:
    pass
else:
    _run_ghidra_script()
