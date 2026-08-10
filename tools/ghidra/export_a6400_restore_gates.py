# Export bounded restore-gate metadata from the pinned α6400 host updater engine.
# @category Sony.Recovery
# @runtime PyGhidra

"""Read-only Ghidra post-script for metadata-only stock restore gate tracing."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile


EXPECTED_PROGRAM = "signed-updater-engine-8f2e8b22.exe"
EXPECTED_SHA256 = "8f2e8b229ef9e49a874cbf920301aba078727cebc490c891a992de60ff8a3528"
EXPECTED_FILE_SIZE = 122864
ADDRESS_MIN = 0x400000
ADDRESS_MAX = 0x420000
MAX_SCALARS = 512
MAX_CALLS = 512
MAX_INSTRUCTIONS = 100000
ROOTS = (
    ("dat-parser", 0x4012D0, "FUN_004012d0"),
    ("response-validator", 0x405A50, "FUN_00405a50"),
    ("request-builder", 0x4061C0, "FUN_004061c0"),
    ("raw-fdat-transfer", 0x406900, "FUN_00406900"),
    ("state-machine", 0x406A70, "FUN_00406a70"),
    ("request-dispatch", 0x4071B0, "FUN_004071b0"),
    ("volume-open", 0x4073B0, "FUN_004073b0"),
    ("volume-io", 0x407500, "FUN_00407500"),
    ("storage-probe", 0x407770, "FUN_00407770"),
    ("pass-through-submit", 0x407A50, "FUN_00407a50"),
    ("status-decoder", 0x408B30, "FUN_00408b30"),
)
ROOT_MAP = {address: (root_id, symbol) for root_id, address, symbol in ROOTS}
ALLOWED_IMPORTS = {"CreateFileW", "DeviceIoControl"}
ROOT_VALUE_ALLOWLIST = {
    "request-builder": {0x20, 0x40, 0x100},
    "raw-fdat-transfer": {0x40, 0x100},
    "state-machine": {0x01, 0x10, 0x20, 0x30, 0x40, 0x100, 0x200},
    "request-dispatch": {0x01, 0x10, 0x20, 0x30, 0x40, 0x100, 0x200},
    "pass-through-submit": {0x4D014},
    "status-decoder": {0x140, 0x141, 0x142},
}
ROOT_VALUE_SEMANTICS = {
    ("request-builder", 0x20): "request-header-size",
    ("request-builder", 0x40): "firmware-write-command",
    ("request-builder", 0x100): "completion-command",
    ("raw-fdat-transfer", 0x40): "firmware-write-command",
    ("raw-fdat-transfer", 0x100): "completion-command",
    ("state-machine", 0x01): "initialization-command",
    ("state-machine", 0x10): "guard-command",
    ("state-machine", 0x20): "version-command",
    ("state-machine", 0x30): "mode-switch-command",
    ("state-machine", 0x40): "firmware-write-command",
    ("state-machine", 0x100): "completion-command",
    ("state-machine", 0x200): "state-command",
    ("request-dispatch", 0x01): "initialization-command",
    ("request-dispatch", 0x10): "guard-command",
    ("request-dispatch", 0x20): "version-command",
    ("request-dispatch", 0x30): "mode-switch-command",
    ("request-dispatch", 0x40): "firmware-write-command",
    ("request-dispatch", 0x100): "completion-command",
    ("request-dispatch", 0x200): "state-command",
    ("pass-through-submit", 0x4D014): "pass-through-control-code",
    ("status-decoder", 0x140): "invalid-model-status",
    ("status-decoder", 0x141): "invalid-model-status",
    ("status-decoder", 0x142): "invalid-version-status",
}


def _optional_adapter_check(adapter, name, default):
    method = getattr(adapter, name, None)
    return default if method is None else method()


def _bounded_address(value):
    return type(value) is int and ADDRESS_MIN <= value < ADDRESS_MAX


def build_raw_export(adapter, expected_program, expected_sha256):
    """Build bounded metadata from a read-only Ghidra program adapter."""

    if expected_program != EXPECTED_PROGRAM or expected_sha256.lower() != EXPECTED_SHA256:
        raise RuntimeError("Expected restore-gate program identity is invalid")
    if adapter.program_name() != EXPECTED_PROGRAM:
        raise RuntimeError("Open Ghidra program is not the pinned updater engine")
    if adapter.program_sha256().lower() != EXPECTED_SHA256:
        raise RuntimeError("Open Ghidra program digest is not pinned")
    if _optional_adapter_check(adapter, "program_headless_read_only", False) is not True:
        raise RuntimeError("Restore-gate export requires headless read-only mode")
    if _optional_adapter_check(adapter, "program_noanalysis", False) is not True:
        raise RuntimeError("Restore-gate export requires headless no-analysis mode")
    if _optional_adapter_check(adapter, "program_is_changed", False) is not False:
        raise RuntimeError("Open Ghidra program contains changes")

    roots = []
    for root_id, address, symbol in ROOTS:
        discovered = adapter.discover_root(address)
        if discovered != {"address": address, "symbol": symbol}:
            raise RuntimeError("A pinned restore-gate root did not resolve exactly")
        roots.append({"id": root_id, **discovered})

    scalars = []
    occupied_sites = set()
    for root_id, address, _ in ROOTS:
        allowed_values = ROOT_VALUE_ALLOWLIST.get(root_id, set())
        for item in adapter.scalar_sites(address, allowed_values):
            if not isinstance(item, dict) or set(item) != {"site", "value"}:
                raise RuntimeError("Ghidra adapter returned an invalid scalar site")
            if not _bounded_address(item["site"]) or item["value"] not in allowed_values:
                raise RuntimeError("Ghidra adapter returned an unbounded scalar site")
            if item["site"] in occupied_sites:
                raise RuntimeError("Restore-gate export contains a duplicate site")
            occupied_sites.add(item["site"])
            scalars.append(
                {
                    "root_id": root_id,
                    "site": item["site"],
                    "value": item["value"],
                    "semantic": ROOT_VALUE_SEMANTICS[(root_id, item["value"])],
                }
            )
            if len(scalars) > MAX_SCALARS:
                raise RuntimeError("Restore-gate scalar cap exceeded")

    imports = sorted(adapter.import_names(ALLOWED_IMPORTS))
    if set(imports) != ALLOWED_IMPORTS or len(imports) != len(set(imports)):
        raise RuntimeError("Pinned restore-gate imports did not resolve")

    calls = []
    unresolved_direct = 0
    unresolved_indirect = 0
    for root_id, address, _ in ROOTS:
        for item in adapter.call_relationships(address, ROOT_MAP, ALLOWED_IMPORTS):
            fields = {
                "site",
                "target",
                "target_root",
                "target_symbol",
                "kind",
            }
            if not isinstance(item, dict) or set(item) != fields:
                raise RuntimeError("Ghidra adapter returned an invalid call relationship")
            if not _bounded_address(item["site"]) or item["site"] in occupied_sites:
                raise RuntimeError("Restore-gate call site is invalid or duplicated")
            occupied_sites.add(item["site"])
            calls.append({"caller_root": root_id, **item})
            if item["kind"] == "unresolved-direct":
                unresolved_direct += 1
            elif item["kind"] == "unresolved-indirect":
                unresolved_indirect += 1
            if len(calls) > MAX_CALLS:
                raise RuntimeError("Restore-gate call cap exceeded")

    scalars.sort(key=lambda item: (item["site"], item["root_id"], item["value"]))
    calls.sort(key=lambda item: (item["site"], item["caller_root"]))
    return {
        "schema_version": 1,
        "program": EXPECTED_PROGRAM,
        "sha256": EXPECTED_SHA256,
        "file_size": EXPECTED_FILE_SIZE,
        "analysis_mode": {"read_only": True, "noanalysis": True},
        "roots": roots,
        "scalar_comparisons": scalars,
        "imports": imports,
        "calls": calls,
        "unresolved_direct_calls": unresolved_direct,
        "unresolved_indirect_calls": unresolved_indirect,
        "truncated": False,
    }


def write_json_atomic(output_path, document, approved_root):
    output = Path(output_path)
    root = Path(approved_root).resolve(strict=True)
    if not root.is_dir() or output.name != "raw-restore-gates.json":
        raise RuntimeError("Restore-gate output root or filename is invalid")
    try:
        parent = output.parent.resolve(strict=True)
    except FileNotFoundError as error:
        raise RuntimeError("Restore-gate output directory does not exist") from error
    if parent != root:
        raise RuntimeError("Restore-gate output is outside the approved root")
    output = parent / output.name
    if output.exists() and (output.is_symlink() or not output.is_file()):
        raise RuntimeError("Restore-gate output target is not a regular file")

    descriptor, temporary_name = tempfile.mkstemp(
        dir=str(parent), prefix=".restore-gates-", suffix=".tmp"
    )
    try:
        encoded = (
            json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        with os.fdopen(descriptor, "wb") as stream:
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
    """Small Ghidra API boundary for bounded metadata extraction."""

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
        if not _bounded_address(value):
            raise RuntimeError("Ghidra address is outside the pinned updater image")
        return value

    def _function(self, address):
        function = self._manager.getFunctionAt(address)
        if function is None:
            function = self._manager.getFunctionContaining(address)
        return function

    def discover_root(self, address):
        function = self._function(self._address(address))
        if function is None or function.isExternal():
            return None
        return {
            "address": self._offset(function.getEntryPoint()),
            "symbol": str(function.getName()),
        }

    def scalar_sites(self, address, allowed_values):
        function = self._function(self._address(address))
        if function is None:
            return []
        found = []
        seen = set()
        for instruction in self._listing.getInstructions(function.getBody(), True):
            self._monitor.checkCanceled()
            self._instruction_count += 1
            if self._instruction_count > MAX_INSTRUCTIONS:
                raise RuntimeError("Restore-gate instruction cap exceeded")
            site = self._offset(instruction.getAddress())
            for index in range(instruction.getNumOperands()):
                scalar = instruction.getScalar(index)
                if scalar is None:
                    continue
                value = int(scalar.getUnsignedValue())
                if value in allowed_values and (site, value) not in seen:
                    seen.add((site, value))
                    found.append({"site": site, "value": value})
        return found

    def import_names(self, allowed_names):
        found = set()
        for function in self._manager.getExternalFunctions():
            self._monitor.checkCanceled()
            name = str(function.getName())
            if name in allowed_names:
                found.add(name)
        return found

    def call_relationships(self, address, root_map, allowed_imports):
        function = self._function(self._address(address))
        if function is None:
            return []
        found = []
        for instruction in self._listing.getInstructions(function.getBody(), True):
            self._monitor.checkCanceled()
            flow_type = instruction.getFlowType()
            if not flow_type.isCall():
                continue
            site = self._offset(instruction.getAddress())
            flows = list(instruction.getFlows())
            if not flows:
                kind = (
                    "unresolved-indirect"
                    if flow_type.isComputed()
                    else "unresolved-direct"
                )
                found.append(
                    {
                        "site": site,
                        "target": None,
                        "target_root": None,
                        "target_symbol": None,
                        "kind": kind,
                    }
                )
                continue
            target_address = flows[0]
            target_offset = int(target_address.getOffset())
            if target_offset in root_map:
                target_root, target_symbol = root_map[target_offset]
                found.append(
                    {
                        "site": site,
                        "target": target_offset,
                        "target_root": target_root,
                        "target_symbol": target_symbol,
                        "kind": "direct",
                    }
                )
                continue
            target_function = self._manager.getFunctionAt(target_address)
            if target_function is not None:
                target_symbol = str(target_function.getName())
                if target_symbol in allowed_imports:
                    found.append(
                        {
                            "site": site,
                            "target": None,
                            "target_root": None,
                            "target_symbol": target_symbol,
                            "kind": "external-direct",
                        }
                    )
                    continue
            found.append(
                {
                    "site": site,
                    "target": None,
                    "target_root": None,
                    "target_symbol": None,
                    "kind": "unresolved-direct",
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
        / "recovery-trace"
        / "a6400-v2.00"
    )
    write_json_atomic(output_path, document, approved_root)
    print(
        "RESTORE_GATE_EXPORT|roots=%d|scalars=%d|calls=%d|truncated=false"
        % (
            len(document["roots"]),
            len(document["scalar_comparisons"]),
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
