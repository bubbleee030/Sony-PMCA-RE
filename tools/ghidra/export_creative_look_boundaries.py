# Export bounded Creative Look metadata from the pinned ILCE-6400 module.
# @category Sony.CreativeLook
# @runtime PyGhidra

"""Read-only Ghidra post-script for bounded Creative Look boundary metadata."""

from __future__ import annotations

from collections import deque
import json
import os
from pathlib import Path
import tempfile
import unicodedata


EXPECTED_PROGRAM = "CautionConfig.so"
EXPECTED_SHA256 = (
    "bfd1bd7bad0ab3478b894da5dbb51c15464b1bedc4201240ccb61cd743150ef7"
)
EXPECTED_FILE_SIZE = 12_070_800
ELF_LOAD_BIAS = 0x10000
A6400_CAUTION_CONFIG_MAX_SOURCE_ADDRESS = 0xC5B720
MAX_ANALYSIS_ADDRESS = A6400_CAUTION_CONFIG_MAX_SOURCE_ADDRESS + ELF_LOAD_BIAS
SELECTOR_SOURCE_OFFSET = 0x7DB958
SELECTOR_ANALYSIS_ADDRESS = SELECTOR_SOURCE_OFFSET + ELF_LOAD_BIAS
COMPILED_GRAPH_SOURCE_OFFSET = 0xB836CC
COMPILED_GRAPH_ANALYSIS_ADDRESS = COMPILED_GRAPH_SOURCE_OFFSET + ELF_LOAD_BIAS
DEPTH_CAP = 16
MAX_FUNCTION_ROOTS = 256
MAX_FUNCTIONS = 4096
MAX_CALLS = 10_000
MAX_REFERENCES = 2_048
MAX_TOTAL_INSTRUCTIONS = 250_000


def _optional_adapter_check(adapter, method_name, default):
    method = getattr(adapter, method_name, None)
    return default if method is None else method()


def _bounded_address(value):
    return type(value) is int and 0 <= value < 0x100000000 and value % 2 == 0


def _bounded_program_address(value):
    return _bounded_address(value) and ELF_LOAD_BIAS <= value < MAX_ANALYSIS_ADDRESS


def _sanitize_symbol(value, address):
    symbol = str(value)[:256]
    if not symbol or any(
        unicodedata.category(character).startswith("C") for character in symbol
    ):
        return "function@0x%x" % address
    return symbol


def _validate_named_function(item):
    if not isinstance(item, dict) or set(item) != {"address", "symbol"}:
        raise RuntimeError("Ghidra adapter returned an invalid named function")
    if not _bounded_program_address(item["address"]):
        raise RuntimeError("Ghidra adapter returned an invalid function address")
    symbol = _sanitize_symbol(item["symbol"], item["address"])
    return {"address": item["address"], "symbol": symbol}


def _validate_reference(item):
    fields = {"owner", "site", "target", "kind", "symbol"}
    if not isinstance(item, dict) or set(item) != fields:
        raise RuntimeError("Ghidra adapter returned an invalid graph reference")
    if any(
        not _bounded_program_address(item[field])
        for field in ("owner", "site", "target")
    ):
        raise RuntimeError("Ghidra adapter returned an invalid reference address")
    if (
        item["target"] != COMPILED_GRAPH_ANALYSIS_ADDRESS
        or item["kind"] != "data-reference"
    ):
        raise RuntimeError("Ghidra adapter returned an invalid graph reference target")
    return {
        **item,
        "symbol": _sanitize_symbol(item["symbol"], item["owner"]),
    }


def _validate_call(item):
    fields = {"caller", "site", "target", "kind", "owner"}
    if not isinstance(item, dict) or set(item) != fields:
        raise RuntimeError("Ghidra adapter returned an invalid call")
    if not _bounded_program_address(item["caller"]) or not _bounded_program_address(
        item["site"]
    ):
        raise RuntimeError("Ghidra adapter returned an invalid call address")
    if item["kind"] == "direct":
        if not _bounded_program_address(item["target"]):
            raise RuntimeError("Ghidra adapter returned an invalid direct target")
    elif item["kind"] in {"unresolved-direct", "unresolved-indirect"}:
        if item["target"] is not None:
            raise RuntimeError("Unresolved Ghidra call has a target")
    else:
        raise RuntimeError("Ghidra adapter returned an invalid call kind")
    return {**item, "owner": _sanitize_symbol(item["owner"], item["caller"])}


def build_raw_export(adapter, expected_program, expected_sha256):
    """Build exact bounded metadata from a read-only Ghidra program adapter."""

    if expected_program != EXPECTED_PROGRAM or expected_sha256.lower() != EXPECTED_SHA256:
        raise RuntimeError("Expected Creative Look program identity is invalid")
    if adapter.program_name() != EXPECTED_PROGRAM:
        raise RuntimeError("Open Ghidra program is not the pinned module")
    if adapter.program_sha256().lower() != EXPECTED_SHA256:
        raise RuntimeError("Open Ghidra program digest is not pinned")
    if _optional_adapter_check(adapter, "program_headless_read_only", False) is not True:
        raise RuntimeError("Creative Look export requires headless read-only mode")
    if _optional_adapter_check(adapter, "program_is_changed", False) is not False:
        raise RuntimeError("Open Ghidra program contains changes")

    selector = adapter.discover_function(SELECTOR_ANALYSIS_ADDRESS)
    if selector != SELECTOR_ANALYSIS_ADDRESS:
        raise RuntimeError("Pinned Creative Look selector function did not resolve")
    named_functions = [
        _validate_named_function(item) for item in adapter.creative_style_functions()
    ]
    if len(named_functions) > MAX_FUNCTION_ROOTS:
        raise RuntimeError("Creative Style named-function cap exceeded")
    named_functions.sort(key=lambda item: (item["address"], item["symbol"]))
    if len({item["address"] for item in named_functions}) != len(named_functions):
        raise RuntimeError("Creative Style named functions contain duplicate addresses")

    references = [
        _validate_reference(item)
        for item in adapter.graph_references(COMPILED_GRAPH_ANALYSIS_ADDRESS)
    ]
    if len(references) > MAX_REFERENCES:
        raise RuntimeError("Compiled graph reference cap exceeded")
    references.sort(key=lambda item: (item["site"], item["owner"]))
    if len({item["site"] for item in references}) != len(references):
        raise RuntimeError("Compiled graph references contain duplicate sites")

    function_addresses = {selector}
    function_addresses.update(item["address"] for item in named_functions)
    function_addresses.update(item["owner"] for item in references)
    calls = [
        _validate_call(item)
        for item in adapter.iter_calls(sorted(function_addresses), DEPTH_CAP)
    ]
    if len(calls) > MAX_CALLS:
        raise RuntimeError("Creative Look call cap exceeded")
    calls.sort(key=lambda item: (item["site"], item["caller"]))
    if len({item["site"] for item in calls}) != len(calls):
        raise RuntimeError("Creative Look calls contain duplicate sites")

    return {
        "program": EXPECTED_PROGRAM,
        "sha256": EXPECTED_SHA256,
        "file_size": EXPECTED_FILE_SIZE,
        "selector_source_offset": SELECTOR_SOURCE_OFFSET,
        "selector_analysis_address": SELECTOR_ANALYSIS_ADDRESS,
        "selector_function": selector,
        "compiled_graph_source_offset": COMPILED_GRAPH_SOURCE_OFFSET,
        "compiled_graph_analysis_address": COMPILED_GRAPH_ANALYSIS_ADDRESS,
        "named_functions": named_functions,
        "references": references,
        "calls": calls,
        "truncated": False,
        "depth_cap": DEPTH_CAP,
    }


def write_json_atomic(output_path, document, approved_root):
    output = Path(output_path)
    root = Path(approved_root).resolve(strict=True)
    if not root.is_dir() or output.name != "raw-boundaries.json":
        raise RuntimeError("Creative Look output root or filename is invalid")
    try:
        parent = output.parent.resolve(strict=True)
    except FileNotFoundError as error:
        raise RuntimeError("Creative Look output directory does not exist") from error
    if parent != root:
        raise RuntimeError("Creative Look output is outside the approved root")
    output = parent / output.name
    if output.exists() and (output.is_symlink() or not output.is_file()):
        raise RuntimeError("Creative Look output target is not a regular file")

    handle, temporary_name = tempfile.mkstemp(
        dir=str(parent), prefix=".creative-look-", suffix=".tmp"
    )
    try:
        encoded = (
            json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        with os.fdopen(handle, "wb") as stream:
            stream.write(encoded)
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
    """Small Ghidra API boundary for bounded read-only metadata extraction."""

    def __init__(self, program, task_monitor):
        self._program = program
        self._monitor = task_monitor
        self._manager = program.getFunctionManager()
        self._listing = program.getListing()
        self._memory = program.getMemory()
        self._references = program.getReferenceManager()
        self._address_space = program.getAddressFactory().getDefaultAddressSpace()
        self._instruction_count = 0

    def program_name(self):
        return str(self._program.getName())

    def program_sha256(self):
        getter = getattr(self._program, "getExecutableSHA256", None)
        if getter is None:
            raise RuntimeError("Ghidra program has no executable digest")
        return str(getter())

    def program_headless_read_only(self):
        from ghidra.app.util.headless import HeadlessAnalyzer

        options = HeadlessAnalyzer.getInstance().getOptions()
        field = options.getClass().getDeclaredField("readOnly")
        field.setAccessible(True)
        return bool(field.getBoolean(options))

    def program_is_changed(self):
        return bool(self._program.isChanged())

    def _address(self, value):
        return self._address_space.getAddress(hex(value)[2:])

    def _offset(self, address):
        value = int(address.getOffset())
        if not _bounded_address(value):
            raise RuntimeError("Ghidra address is outside the bounded address space")
        return value

    def _function(self, address):
        function = self._manager.getFunctionAt(address)
        if function is None:
            function = self._manager.getFunctionContaining(address)
        if function is None or function.isExternal():
            return None
        return function

    def discover_function(self, address):
        function = self._function(self._address(address))
        return None if function is None else self._offset(function.getEntryPoint())

    def creative_style_functions(self):
        found = []
        for function in self._manager.getFunctions(True):
            self._monitor.checkCanceled()
            name = str(function.getName(True))
            if "CreativeStyle" not in name:
                continue
            address = self._offset(function.getEntryPoint())
            found.append({"address": address, "symbol": _sanitize_symbol(name, address)})
            if len(found) > MAX_FUNCTION_ROOTS:
                raise RuntimeError("Creative Style function scan exceeded its cap")
        return found

    def graph_references(self, address):
        found = []
        for reference in self._references.getReferencesTo(self._address(address)):
            self._monitor.checkCanceled()
            site_address = reference.getFromAddress()
            function = self._function(site_address)
            if function is None:
                continue
            owner = self._offset(function.getEntryPoint())
            found.append(
                {
                    "owner": owner,
                    "site": self._offset(site_address),
                    "target": address,
                    "kind": "data-reference",
                    "symbol": _sanitize_symbol(function.getName(True), owner),
                }
            )
            if len(found) > MAX_REFERENCES:
                raise RuntimeError("Compiled graph reference scan exceeded its cap")
        return found

    def _literal_target(self, operation):
        varnode = operation.getInput(0)
        if varnode is None:
            return None
        if varnode.isAddress():
            address = varnode.getAddress()
        elif varnode.isConstant():
            value = int(varnode.getOffset())
            if value & 1:
                value -= 1
            try:
                address = self._address(value)
            except BaseException:
                return None
        else:
            return None
        function = self._function(address) if self._memory.contains(address) else None
        return None if function is None else self._offset(function.getEntryPoint())

    def _function_calls(self, function):
        from ghidra.program.model.pcode import PcodeOp

        caller = self._offset(function.getEntryPoint())
        owner = _sanitize_symbol(function.getName(True), caller)
        for instruction in self._listing.getInstructions(function.getBody(), True):
            self._monitor.checkCanceled()
            self._instruction_count += 1
            if self._instruction_count > MAX_TOTAL_INSTRUCTIONS:
                raise RuntimeError("Creative Look traversal exceeded instruction cap")
            for operation in instruction.getPcode():
                opcode = operation.getOpcode()
                if opcode not in (PcodeOp.CALL, PcodeOp.CALLIND):
                    continue
                target = self._literal_target(operation)
                if target is None:
                    kind = (
                        "unresolved-direct"
                        if opcode == PcodeOp.CALL
                        else "unresolved-indirect"
                    )
                else:
                    kind = "direct"
                yield {
                    "caller": caller,
                    "site": self._offset(instruction.getAddress()),
                    "target": target,
                    "kind": kind,
                    "owner": owner,
                }

    def iter_calls(self, function_addresses, depth_cap):
        queue = deque((address, 0) for address in function_addresses)
        queued = set(function_addresses)
        visited = set()
        calls = []
        while queue:
            address, depth = queue.popleft()
            if address in visited:
                continue
            if depth > depth_cap or len(visited) >= MAX_FUNCTIONS:
                raise RuntimeError("Creative Look traversal exceeded function bounds")
            function = self._function(self._address(address))
            if function is None or self._offset(function.getEntryPoint()) != address:
                continue
            visited.add(address)
            for call in self._function_calls(function):
                calls.append(call)
                if len(calls) > MAX_CALLS:
                    raise RuntimeError("Creative Look traversal exceeded call cap")
                target = call["target"]
                if target is not None and target not in visited and target not in queued:
                    queue.append((target, depth + 1))
                    queued.add(target)
        return calls


def _run_ghidra_script():
    arguments = list(getScriptArgs())
    if len(arguments) != 3:
        raise RuntimeError("usage: <output.json> <expected-program> <expected-sha256>")
    output_path, expected_program, expected_sha256 = arguments
    adapter = GhidraProgramAdapter(currentProgram, monitor)
    document = build_raw_export(adapter, expected_program, expected_sha256)
    approved_root = (
        Path(__file__).resolve().parents[2]
        / ".artifacts"
        / "creative-look-trace"
        / "a6400-v2.00"
    )
    write_json_atomic(output_path, document, approved_root)
    print(
        "CREATIVE_LOOK_EXPORT|functions=%d|references=%d|calls=%d|truncated=false"
        % (
            len(document["named_functions"]),
            len(document["references"]),
            len(document["calls"]),
        )
    )


def ghidra_runtime_available():
    try:
        currentProgram
        getScriptArgs
    except NameError:
        return False
    return True


if ghidra_runtime_available():
    _run_ghidra_script()
