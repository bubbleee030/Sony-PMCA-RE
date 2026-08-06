# Export bounded control-flow metadata from the pinned ILCE-6400A sauu binary.
# @category Sony.Recovery
# @runtime PyGhidra

"""Read-only Ghidra post-script for a non-transferable updater control sample."""

from __future__ import annotations

from collections import deque
import json
import os
from pathlib import Path
import tempfile


EXPECTED_PROGRAM = "sauu"
EXPECTED_SHA256 = "d79af0e6958e47c9b50622b1bedb4afe86b7384e3513ffd62ce09f9e2c18a322"
EXPECTED_FILE_SIZE = 84428
ADDRESS_MIN = 0x8000
ADDRESS_MAX = 0x1BEA4
ROOTS = (
    ("guard-dispatch", 0xDF5C),
    ("model-compare", 0xDEA2),
    ("region-compare", 0xDE84),
    ("version-compare", 0xDEC0),
    ("verification-key-hash", 0x10368),
    ("signature-verifier", 0x104E0),
    ("signature-workflow-caller", 0x10A88),
)
MAX_FUNCTIONS = 1024
MAX_CALLS = 4096
MAX_DEPTH = 8
MAX_TOTAL_INSTRUCTIONS = 100_000
ALLOWED_KINDS = {"direct", "unresolved-direct", "unresolved-indirect"}
_CALL_FIELDS = {"caller", "site", "target", "kind"}


def _optional_adapter_check(adapter, method_name, default):
    method = getattr(adapter, method_name, None)
    return default if method is None else method()


def _is_code_address(value):
    return type(value) is int and ADDRESS_MIN <= value < ADDRESS_MAX and value % 2 == 0


def _validate_call(item):
    if not isinstance(item, dict) or set(item) != _CALL_FIELDS:
        raise RuntimeError("Ghidra adapter returned an invalid sauu call")
    if not _is_code_address(item["caller"]) or not _is_code_address(item["site"]):
        raise RuntimeError("Ghidra adapter returned an out-of-range sauu call")
    if item["kind"] not in ALLOWED_KINDS:
        raise RuntimeError("Ghidra adapter returned an invalid sauu call kind")
    if item["kind"] == "direct":
        if not _is_code_address(item["target"]):
            raise RuntimeError("Resolved sauu call lacks a bounded target")
    elif item["target"] is not None:
        raise RuntimeError("Unresolved sauu call contains a target")
    return item


def build_raw_export(adapter, expected_program, expected_sha256):
    """Traverse a capped call graph from exact roots in a read-only program."""

    if expected_program != EXPECTED_PROGRAM:
        raise RuntimeError("Expected sauu program argument is invalid")
    if not isinstance(expected_sha256, str) or expected_sha256.lower() != EXPECTED_SHA256:
        raise RuntimeError("Expected sauu digest argument is invalid")
    if adapter.program_name() != EXPECTED_PROGRAM:
        raise RuntimeError("Open Ghidra program is not the pinned sauu binary")
    actual_sha256 = adapter.program_sha256()
    if not isinstance(actual_sha256, str) or actual_sha256.lower() != EXPECTED_SHA256:
        raise RuntimeError("Open Ghidra program digest is not pinned")
    if _optional_adapter_check(adapter, "program_headless_read_only", False) is not True:
        raise RuntimeError("sauu export requires headless read-only mode")
    if _optional_adapter_check(adapter, "program_noanalysis", False) is not True:
        raise RuntimeError("sauu export requires headless no-analysis mode")
    if _optional_adapter_check(adapter, "program_is_changed", False) is not False:
        raise RuntimeError("Open Ghidra program contains changes")

    roots = []
    queue = deque()
    queued = set()
    for root_id, source_address in ROOTS:
        function_address = adapter.discover_function(source_address)
        if not _is_code_address(function_address):
            probe_method = getattr(adapter, "probe_address", None)
            probe = None if probe_method is None else probe_method(source_address)
            expected_instruction_only = (
                root_id == "signature-workflow-caller"
                and isinstance(probe, dict)
                and set(probe)
                == {"instruction_address", "function_before", "function_after"}
                and probe["instruction_address"] == source_address
                and _is_code_address(probe["function_before"])
                and _is_code_address(probe["function_after"])
                and probe["function_before"]
                < source_address
                < probe["function_after"]
            )
            if not expected_instruction_only:
                raise RuntimeError(
                    "Pinned sauu root %s at 0x%x did not resolve to code; probe=%r"
                    % (root_id, source_address, probe)
                )
            roots.append(
                {
                    "id": root_id,
                    "source_address": source_address,
                    "resolution": "instruction-only",
                    "function_address": None,
                }
            )
            continue
        roots.append(
            {
                "id": root_id,
                "source_address": source_address,
                "resolution": "function",
                "function_address": function_address,
            }
        )
        if function_address not in queued:
            queue.append((function_address, 0))
            queued.add(function_address)

    visited = set()
    functions = []
    calls = []
    occupied_sites = set()
    while queue:
        function_address, depth = queue.popleft()
        if function_address in visited:
            continue
        if depth > MAX_DEPTH or len(visited) >= MAX_FUNCTIONS:
            raise RuntimeError("sauu traversal exceeded a hard graph cap")
        visited.add(function_address)
        functions.append({"address": function_address, "depth": depth})
        for raw_call in adapter.iter_calls(function_address):
            if len(calls) >= MAX_CALLS:
                raise RuntimeError("sauu traversal exceeded its call cap")
            call = dict(_validate_call(raw_call))
            if call["caller"] != function_address or call["site"] in occupied_sites:
                raise RuntimeError("sauu call is disconnected or duplicated")
            occupied_sites.add(call["site"])
            calls.append(call)
            target = call["target"]
            if target is not None and target not in visited and target not in queued:
                if depth >= MAX_DEPTH:
                    raise RuntimeError("sauu traversal exceeded its depth cap")
                queue.append((target, depth + 1))
                queued.add(target)

    functions.sort(key=lambda item: item["address"])
    calls.sort(
        key=lambda item: (
            item["caller"],
            item["site"],
            item["kind"],
            -1 if item["target"] is None else item["target"],
        )
    )
    return {
        "schema_version": 1,
        "program": EXPECTED_PROGRAM,
        "sha256": EXPECTED_SHA256,
        "file_size": EXPECTED_FILE_SIZE,
        "analysis_mode": {"read_only": True, "noanalysis": True},
        "roots": roots,
        "functions": functions,
        "calls": calls,
        "unresolved_direct_calls": sum(
            item["kind"] == "unresolved-direct" for item in calls
        ),
        "unresolved_indirect_calls": sum(
            item["kind"] == "unresolved-indirect" for item in calls
        ),
        "max_depth": max(item["depth"] for item in functions),
        "truncated": False,
    }


def write_json_atomic(output_path, document, approved_root):
    """Write only the fixed metadata filename under the ignored artifact root."""

    output = Path(output_path)
    root = Path(approved_root).resolve(strict=True)
    if not root.is_dir() or output.name != "raw-sauu-control.json":
        raise RuntimeError("sauu output root or filename is invalid")
    try:
        parent = output.parent.resolve(strict=True)
    except FileNotFoundError as error:
        raise RuntimeError("sauu output directory does not exist") from error
    if parent != root:
        raise RuntimeError("sauu output is outside the approved artifact root")
    output = parent / output.name
    if output.exists() and (output.is_symlink() or not output.is_file()):
        raise RuntimeError("sauu output target is not a regular file")

    descriptor, temporary_name = tempfile.mkstemp(
        dir=str(parent), prefix=".sauu-control-", suffix=".tmp"
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
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
    """Narrow Ghidra API boundary for metadata-only control-flow extraction."""

    def __init__(self, program, task_monitor):
        self._program = program
        self._monitor = task_monitor
        self._manager = program.getFunctionManager()
        self._listing = program.getListing()
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

    def program_noanalysis(self):
        from ghidra.app.util.headless import HeadlessAnalyzer

        options = HeadlessAnalyzer.getInstance().getOptions()
        field = options.getClass().getDeclaredField("analyze")
        field.setAccessible(True)
        return not bool(field.getBoolean(options))

    def program_is_changed(self):
        return bool(self._program.isChanged())

    def _address(self, value):
        return self._address_space.getAddress(hex(value)[2:])

    def _offset(self, address):
        value = int(address.getOffset())
        if not _is_code_address(value):
            raise RuntimeError("Ghidra address is outside pinned sauu code")
        return value

    def _function(self, address):
        function = self._manager.getFunctionAt(address)
        if function is None:
            function = self._manager.getFunctionContaining(address)
        return function

    def discover_function(self, source_address):
        function = self._function(self._address(source_address))
        if function is None or function.isExternal():
            return None
        return self._offset(function.getEntryPoint())

    def probe_address(self, source_address):
        address = self._address(source_address)
        instruction = self._listing.getInstructionContaining(address)
        before_iterator = self._manager.getFunctions(address, False)
        after_iterator = self._manager.getFunctions(address, True)
        before = before_iterator.next() if before_iterator.hasNext() else None
        after = after_iterator.next() if after_iterator.hasNext() else None

        def safe_entry(function):
            if function is None or function.isExternal():
                return None
            value = int(function.getEntryPoint().getOffset())
            return value if _is_code_address(value) else None

        return {
            "instruction_address": (
                None if instruction is None else int(instruction.getAddress().getOffset())
            ),
            "function_before": safe_entry(before),
            "function_after": safe_entry(after),
        }

    def iter_calls(self, function_address):
        function = self._function(self._address(function_address))
        if function is None or function.isExternal():
            return []
        found = []
        for instruction in self._listing.getInstructions(function.getBody(), True):
            self._monitor.checkCanceled()
            self._instruction_count += 1
            if self._instruction_count > MAX_TOTAL_INSTRUCTIONS:
                raise RuntimeError("sauu traversal exceeded its instruction cap")
            flow_type = instruction.getFlowType()
            if not flow_type.isCall():
                continue
            site = self._offset(instruction.getAddress())
            flows = list(instruction.getFlows())
            if flow_type.isComputed() or not flows:
                found.append(
                    {
                        "caller": function_address,
                        "site": site,
                        "target": None,
                        "kind": (
                            "unresolved-indirect"
                            if flow_type.isComputed()
                            else "unresolved-direct"
                        ),
                    }
                )
                continue
            if len(flows) != 1:
                raise RuntimeError(
                    "Non-computed sauu call has ambiguous flow destinations"
                )
            target_function = self._manager.getFunctionAt(flows[0])
            if target_function is None or target_function.isExternal():
                found.append(
                    {
                        "caller": function_address,
                        "site": site,
                        "target": None,
                        "kind": "unresolved-direct",
                    }
                )
                continue
            try:
                target = self._offset(target_function.getEntryPoint())
            except RuntimeError:
                target = None
            found.append(
                {
                    "caller": function_address,
                    "site": site,
                    "target": target,
                    "kind": "direct" if target is not None else "unresolved-direct",
                }
            )
        return found


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
        / "recovery-control"
        / "a6400a-v1.01"
    )
    write_json_atomic(output_path, document, approved_root)
    print(
        "SAUU_CONTROL_EXPORT|functions=%d|calls=%d|unresolved_direct=%d|"
        "unresolved_indirect=%d|truncated=false"
        % (
            len(document["functions"]),
            len(document["calls"]),
            document["unresolved_direct_calls"],
            document["unresolved_indirect_calls"],
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
