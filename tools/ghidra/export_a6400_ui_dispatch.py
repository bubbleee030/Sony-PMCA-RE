# Export bounded UI call metadata from the pinned ILCE-6400 view module.
# @category Sony.UI
# @runtime PyGhidra

"""Read-only Ghidra post-script for bounded α6400 UI dispatch metadata."""

from __future__ import annotations

from collections import deque
import json
import os
from pathlib import Path
import tempfile
import unicodedata


EXPECTED_PROGRAM = "viewUnified2.so"
EXPECTED_SHA256 = (
    "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2"
)
EXPECTED_IMAGE_SIZE = 11_530_552
ROOTS = (
    (
        "ViewSettingMenuEventSwitch",
        "setting-menu-event-switch",
        "analysis-address",
        0x22355E,
        0x22355E,
    ),
    (
        "ViewStlrecOrientationRegistration",
        "orientation-registration",
        "elf-file-offset",
        0x1AB41C,
        0x1BB41C,
    ),
    (
        "ViewStlrecLayoutModeAttach",
        "layout-mode-attach",
        "elf-file-offset",
        0x1AB2D2,
        0x1BB2D2,
    ),
    (
        "ViewStlrecAfOrientationDispatch",
        "af-orientation-dispatch",
        "elf-file-offset",
        0x1B1E76,
        0x1C1E76,
    ),
)
MAX_FUNCTIONS = 4096
MAX_EDGES = 10_000
MAX_DEPTH = 32
MAX_TOTAL_INSTRUCTIONS = 250_000
ALLOWED_KINDS = {
    "direct",
    "vtable-slot",
    "function-pointer-table",
    "unresolved-indirect",
}
_EDGE_FIELDS = {"caller", "site", "target", "kind", "slot", "table", "owner"}


def _optional_adapter_check(adapter, method_name, default):
    method = getattr(adapter, method_name, None)
    return default if method is None else method()


def _is_bounded_code_offset(value):
    return (
        type(value) is int
        and 0 <= value < EXPECTED_IMAGE_SIZE
        and value % 2 == 0
    )


def sanitize_owner(value, caller):
    owner = str(value)[:256]
    if not owner or any(
        unicodedata.category(character).startswith("C") for character in owner
    ):
        return "function@0x%x" % caller
    return owner


def _validate_raw_edge(edge):
    if not isinstance(edge, dict) or set(edge) != _EDGE_FIELDS:
        raise RuntimeError("Ghidra adapter returned an invalid edge shape")
    for field in ("caller", "site"):
        if not _is_bounded_code_offset(edge[field]):
            raise RuntimeError("Ghidra adapter returned an invalid code offset")
    if edge["target"] is not None and not _is_bounded_code_offset(edge["target"]):
        raise RuntimeError("Ghidra adapter returned an invalid target offset")
    if edge["kind"] not in ALLOWED_KINDS:
        raise RuntimeError("Ghidra adapter returned an invalid edge kind")
    if (
        not isinstance(edge["owner"], str)
        or not edge["owner"]
        or len(edge["owner"]) > 256
        or any(
            unicodedata.category(character).startswith("C")
            for character in edge["owner"]
        )
    ):
        raise RuntimeError("Ghidra adapter returned an invalid edge owner")
    if edge["kind"] in {"direct", "vtable-slot", "function-pointer-table"}:
        if edge["target"] is None:
            raise RuntimeError("Resolved Ghidra edge has no target")
    elif edge["target"] is not None:
        raise RuntimeError("Unresolved Ghidra edge has a target")
    if edge["kind"] in {"vtable-slot", "function-pointer-table"}:
        if type(edge["slot"]) is not int or not 0 <= edge["slot"] <= 1023:
            raise RuntimeError("Table edge has no bounded slot")
        if not _is_bounded_code_offset(edge["table"]):
            raise RuntimeError("Table edge has no table offset")
    elif edge["slot"] is not None or edge["table"] is not None:
        raise RuntimeError("Non-table edge contains table metadata")
    return edge


def classify_call(opcode_name, resolved_target):
    """Classify one p-code call without mislabeling external direct calls."""

    if opcode_name not in {"CALL", "CALLIND"}:
        raise RuntimeError("Unsupported p-code call operation")
    if resolved_target is not None:
        return "direct", resolved_target
    if opcode_name == "CALLIND":
        return "unresolved-indirect", None
    return None


def build_raw_export(adapter, expected_program, expected_sha256):
    """Build the exact raw metadata document from a read-only program adapter."""

    if expected_program != EXPECTED_PROGRAM:
        raise RuntimeError("Expected program argument is not the pinned module")
    if not isinstance(expected_sha256, str) or expected_sha256.lower() != EXPECTED_SHA256:
        raise RuntimeError("Expected digest argument is not the pinned module digest")
    if adapter.program_name() != EXPECTED_PROGRAM:
        raise RuntimeError("Open Ghidra program name does not match the pinned module")
    actual_sha256 = adapter.program_sha256()
    if not isinstance(actual_sha256, str) or actual_sha256.lower() != EXPECTED_SHA256:
        raise RuntimeError("Open Ghidra program digest does not match the pinned module")
    # AnalyzeHeadless -readOnly is authoritative. In Ghidra 12.1.2 canSave()
    # remains true and the script framework owns an active transaction even in
    # this mode; neither state grants this post-script persistence authority.
    if _optional_adapter_check(adapter, "program_headless_read_only", False) is not True:
        raise RuntimeError("Ghidra headless processing is not read-only")
    if _optional_adapter_check(adapter, "program_is_changed", False) is not False:
        raise RuntimeError("Ghidra program contains uncommitted changes")

    roots = []
    queue = deque()
    queued = set()
    for name, role, source_kind, source_offset, analysis_address in ROOTS:
        function_address = adapter.discover_function(analysis_address)
        if not _is_bounded_code_offset(function_address):
            raise RuntimeError("A required UI traversal root did not resolve")
        roots.append(
            {
                "name": name,
                "role": role,
                "source_kind": source_kind,
                "source_offset": source_offset,
                "analysis_address": analysis_address,
                "function_address": function_address,
            }
        )
        if function_address not in queued:
            queue.append((function_address, 0))
            queued.add(function_address)

    visited = set()
    edges = []
    while queue:
        function_offset, depth = queue.popleft()
        if function_offset in visited:
            continue
        if depth > MAX_DEPTH:
            raise RuntimeError("UI traversal exceeded its depth cap")
        if len(visited) >= MAX_FUNCTIONS:
            raise RuntimeError("UI traversal exceeded its function cap")
        visited.add(function_offset)

        for raw_edge in adapter.iter_edges(function_offset):
            if len(edges) >= MAX_EDGES:
                raise RuntimeError("UI traversal exceeded its edge cap")
            edge = dict(_validate_raw_edge(raw_edge))
            if edge["caller"] != function_offset:
                raise RuntimeError("Ghidra edge caller is disconnected from traversal")
            edges.append(edge)
            target = edge["target"]
            if target is not None and target not in visited and target not in queued:
                queue.append((target, depth + 1))
                queued.add(target)

    edges.sort(
        key=lambda item: (
            item["caller"],
            item["site"],
            item["kind"],
            -1 if item["target"] is None else item["target"],
        )
    )
    sites = [item["site"] for item in edges]
    if len(set(sites)) != len(sites):
        raise RuntimeError("UI traversal produced duplicate call sites")

    return {
        "program": EXPECTED_PROGRAM,
        "sha256": EXPECTED_SHA256,
        "image_size": EXPECTED_IMAGE_SIZE,
        "roots": roots,
        "edges": edges,
        "truncated": False,
    }


def write_json_atomic(output_path, document, approved_root):
    """Replace an existing or new JSON artifact only after a complete write."""

    output = Path(output_path)
    root = Path(approved_root).resolve(strict=True)
    if not root.is_dir():
        raise RuntimeError("Approved UI dispatch output root is not a directory")
    if output.name != "raw-ui-dispatch.json":
        raise RuntimeError("UI dispatch output filename is invalid")
    try:
        parent = output.parent.resolve(strict=True)
    except FileNotFoundError as error:
        raise RuntimeError("UI dispatch output directory does not exist") from error
    if parent != root:
        raise RuntimeError("UI dispatch output is outside the approved artifact root")
    output = parent / output.name
    if output.exists() and (output.is_symlink() or not output.is_file()):
        raise RuntimeError("UI dispatch output target is not a regular file")

    handle, temporary_name = tempfile.mkstemp(
        dir=str(output.parent), prefix=".ui-dispatch-", suffix=".tmp"
    )
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
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
    """Small Ghidra API boundary kept separate from testable traversal policy."""

    def __init__(self, program, task_monitor):
        self._program = program
        self._monitor = task_monitor
        self._manager = program.getFunctionManager()
        self._listing = program.getListing()
        self._memory = program.getMemory()
        self._address_space = program.getAddressFactory().getDefaultAddressSpace()
        self._instruction_count = 0

    def program_name(self):
        return str(self._program.getName())

    def program_sha256(self):
        getter = getattr(self._program, "getExecutableSHA256", None)
        if getter is None:
            raise RuntimeError("Ghidra program does not expose its executable digest")
        return str(getter())

    def program_headless_read_only(self):
        from ghidra.app.util.headless import HeadlessAnalyzer

        options = HeadlessAnalyzer.getInstance().getOptions()
        field = options.getClass().getDeclaredField("readOnly")
        field.setAccessible(True)
        return bool(field.getBoolean(options))

    def program_is_changed(self):
        return bool(self._program.isChanged())

    def _address(self, analysis_address):
        return self._address_space.getAddress(hex(analysis_address)[2:])

    def _analysis_address(self, address):
        offset = int(address.getOffset())
        if offset < 0 or offset >= EXPECTED_IMAGE_SIZE or offset % 2:
            raise RuntimeError("Ghidra address is outside the pinned module")
        return offset

    def _function(self, address):
        function = self._manager.getFunctionAt(address)
        if function is None:
            function = self._manager.getFunctionContaining(address)
        if function is None or function.isExternal():
            return None
        return function

    def discover_function(self, requested_address):
        function = self._function(self._address(requested_address))
        return None if function is None else self._analysis_address(function.getEntryPoint())

    def _literal_address(self, varnode):
        if varnode is None:
            return None
        if varnode.isAddress():
            address = varnode.getAddress()
        elif varnode.isConstant():
            value = int(varnode.getOffset())
            if value & 1:
                value -= 1
            try:
                address = self._address_space.getAddress(hex(value)[2:])
            except BaseException:
                return None
        else:
            return None
        return address if self._memory.contains(address) else None

    def _classify_instruction(self, function, instruction):
        from ghidra.program.model.pcode import PcodeOp

        calls = [
            operation
            for operation in instruction.getPcode()
            if operation.getOpcode() in (PcodeOp.CALL, PcodeOp.CALLIND)
        ]
        if not calls:
            return None

        caller = self._analysis_address(function.getEntryPoint())
        site = self._analysis_address(instruction.getAddress())
        owner = sanitize_owner(function.getName(), caller)

        classification = None
        if len(calls) == 1:
            operation = calls[0]
            literal = self._literal_address(operation.getInput(0))
            callee = None if literal is None else self._function(literal)
            resolved_target = (
                None
                if callee is None
                else self._analysis_address(callee.getEntryPoint())
            )
            opcode_name = (
                "CALLIND" if operation.getOpcode() == PcodeOp.CALLIND else "CALL"
            )
            classification = classify_call(opcode_name, resolved_target)
        elif any(operation.getOpcode() == PcodeOp.CALLIND for operation in calls):
            classification = ("unresolved-indirect", None)
        if classification is None:
            return None
        kind, target = classification

        return {
            "caller": caller,
            "site": site,
            "target": target,
            "kind": kind,
            "slot": None,
            "table": None,
            "owner": owner,
        }

    def iter_edges(self, function_offset):
        function = self._function(self._address(function_offset))
        if (
            function is None
            or self._analysis_address(function.getEntryPoint()) != function_offset
        ):
            raise RuntimeError("Queued UI traversal function is unavailable")
        for instruction in self._listing.getInstructions(function.getBody(), True):
            self._monitor.checkCanceled()
            self._instruction_count += 1
            if self._instruction_count > MAX_TOTAL_INSTRUCTIONS:
                raise RuntimeError("UI traversal exceeded its instruction cap")
            edge = self._classify_instruction(function, instruction)
            if edge is not None:
                yield edge


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
        / "ui-trace"
        / "a6400-v2.00"
    )
    write_json_atomic(output_path, document, approved_root)
    print(
        "UI_DISPATCH_EXPORT|roots=%d|edges=%d|truncated=false"
        % (len(document["roots"]), len(document["edges"]))
    )


def ghidra_runtime_available():
    """Detect bindings injected by PyGhidra without relying on globals()."""

    try:
        currentProgram
        getScriptArgs
    except NameError:
        return False
    return True


if ghidra_runtime_available():
    _run_ghidra_script()
