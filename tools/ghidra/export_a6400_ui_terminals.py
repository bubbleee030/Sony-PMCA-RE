# Export metadata for exactly two pinned ILCE-6400 UI indirect terminals.
# @category Sony.UI
# @runtime PyGhidra

"""Read-only Ghidra post-script for the bounded UI terminal trace."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile


EXPECTED_PROGRAM = "viewUnified2.so"
EXPECTED_SHA256 = (
    "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2"
)
EXPECTED_IMAGE_SIZE = 11_530_552
SOURCE_GRAPH_SHA256 = (
    "d19fc94fd52583f3d321535fd8b6a01aa03f4efc0c4dadde52adce3a9d246f22"
)
RESOLUTION_METHODS = (
    "instruction-flow",
    "pcode-literal",
    "reference-target",
)
TRACKS = (
    {
        "id": "orientation-handler-terminal",
        "root": 0x1BB41C,
        "predecessor_edges": (
            {
                "caller": 0x1BB41C,
                "site": 0x1BB74C,
                "target": 0x1B9B44,
                "kind": "direct",
            },
        ),
        "terminal": {
            "caller": 0x1B9B44,
            "site": 0x1B9B6A,
            "kind": "unresolved-indirect",
        },
    },
    {
        "id": "layout-attach-terminal",
        "root": 0x1BB2D2,
        "predecessor_edges": (),
        "terminal": {
            "caller": 0x1BB2D2,
            "site": 0x1BB30E,
            "kind": "unresolved-indirect",
        },
    },
)
_CANDIDATE_FIELDS = {"kind", "target", "table", "slot", "provenance"}
_CANDIDATE_KINDS = {"vtable-slot", "function-pointer-table"}


def _optional_adapter_check(adapter, method_name, default):
    method = getattr(adapter, method_name, None)
    return default if method is None else method()


def _is_bounded_even_offset(value):
    return type(value) is int and 0 <= value < EXPECTED_IMAGE_SIZE and value % 2 == 0


def _validate_candidate(value):
    if not isinstance(value, dict) or set(value) != _CANDIDATE_FIELDS:
        raise RuntimeError("Ghidra adapter returned an invalid terminal candidate")
    if value["kind"] not in _CANDIDATE_KINDS:
        raise RuntimeError("Ghidra adapter returned an invalid candidate kind")
    if not _is_bounded_even_offset(value["target"]):
        raise RuntimeError("Ghidra adapter returned an invalid candidate target")
    if not _is_bounded_even_offset(value["table"]):
        raise RuntimeError("Ghidra adapter returned an invalid candidate table")
    if type(value["slot"]) is not int or not 0 <= value["slot"] <= 1023:
        raise RuntimeError("Ghidra adapter returned an invalid candidate slot")
    if value["provenance"] not in RESOLUTION_METHODS:
        raise RuntimeError("Ghidra adapter returned invalid candidate provenance")
    return dict(value)


def build_raw_export(adapter):
    """Inspect only the exact terminal sites in a pinned read-only project."""

    if adapter.program_name() != EXPECTED_PROGRAM:
        raise RuntimeError("Open Ghidra program is not the pinned UI module")
    digest = adapter.program_sha256()
    if not isinstance(digest, str) or digest.lower() != EXPECTED_SHA256:
        raise RuntimeError("Open Ghidra program digest is not pinned")
    if _optional_adapter_check(adapter, "program_headless_read_only", False) is not True:
        raise RuntimeError("UI terminal export requires headless read-only mode")
    if _optional_adapter_check(adapter, "program_noanalysis", False) is not True:
        raise RuntimeError("UI terminal export requires headless no-analysis mode")
    if _optional_adapter_check(adapter, "program_is_changed", False) is not False:
        raise RuntimeError("Open Ghidra program contains changes")

    tracks = []
    for spec in TRACKS:
        terminal = spec["terminal"]
        candidates = [
            _validate_candidate(item)
            for item in adapter.candidate_targets(
                terminal["caller"], terminal["site"]
            )
        ]
        if len(candidates) > 32:
            raise RuntimeError("UI terminal candidate cap exceeded")
        candidates.sort(
            key=lambda item: (
                item["kind"],
                item["target"],
                item["table"],
                item["slot"],
                item["provenance"],
            )
        )
        identities = [tuple(item[field] for field in sorted(_CANDIDATE_FIELDS)) for item in candidates]
        if len(identities) != len(set(identities)):
            raise RuntimeError("UI terminal candidates are duplicated")
        tracks.append(
            {
                "id": spec["id"],
                "root": spec["root"],
                "predecessor_edges": [dict(item) for item in spec["predecessor_edges"]],
                "terminal": dict(terminal),
                "candidates": candidates,
            }
        )

    return {
        "schema_version": 1,
        "program": EXPECTED_PROGRAM,
        "sha256": EXPECTED_SHA256,
        "image_size": EXPECTED_IMAGE_SIZE,
        "analysis_mode": {"read_only": True, "noanalysis": True},
        "source_graph_sha256": SOURCE_GRAPH_SHA256,
        "resolution_methods": list(RESOLUTION_METHODS),
        "tracks": tracks,
        "truncated": False,
    }


def write_json_atomic(output_path, document, approved_root):
    """Write only the fixed metadata filename under the ignored artifact root."""

    output = Path(output_path)
    root = Path(approved_root).resolve(strict=True)
    if not root.is_dir() or output.name != "raw-ui-terminals.json":
        raise RuntimeError("UI terminal output root or filename is invalid")
    try:
        parent = output.parent.resolve(strict=True)
    except FileNotFoundError as error:
        raise RuntimeError("UI terminal output directory does not exist") from error
    if parent != root:
        raise RuntimeError("UI terminal output is outside the approved artifact root")
    output = parent / output.name
    if output.exists() and (output.is_symlink() or not output.is_file()):
        raise RuntimeError("UI terminal output target is not a regular file")

    descriptor, temporary_name = tempfile.mkstemp(
        dir=str(parent), prefix=".ui-terminals-", suffix=".tmp"
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
    """Narrow Ghidra boundary that emits only proven table-backed targets."""

    def __init__(self, program, task_monitor):
        self._program = program
        self._monitor = task_monitor
        self._listing = program.getListing()
        self._manager = program.getFunctionManager()
        self._references = program.getReferenceManager()
        self._address_space = program.getAddressFactory().getDefaultAddressSpace()

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

    @staticmethod
    def _even(value):
        return value - 1 if value & 1 else value

    def candidate_targets(self, caller, site):
        self._monitor.checkCanceled()
        address = self._address(site)
        instruction = self._listing.getInstructionAt(address)
        function = self._manager.getFunctionContaining(address)
        if instruction is None or function is None or function.isExternal():
            raise RuntimeError("Pinned UI terminal is not an instruction in a function")
        if self._even(int(function.getEntryPoint().getOffset())) != caller:
            raise RuntimeError("Pinned UI terminal caller does not match Ghidra")
        if not instruction.getFlowType().isComputed():
            raise RuntimeError("Pinned UI terminal is no longer an indirect flow")

        # Instruction flows, p-code inputs, and outgoing references were checked
        # during the bounded trace, but none proves a table base and slot.  Do not
        # relabel arbitrary referenced memory as a function-pointer table.  A
        # future exporter may emit candidates only after both table and slot have
        # independent static provenance.
        tuple(instruction.getFlows())
        tuple(instruction.getPcode())
        tuple(self._references.getReferencesFrom(address))
        return []


def _run_ghidra_script():
    arguments = list(getScriptArgs())
    if len(arguments) != 3:
        raise RuntimeError("usage: <output.json> <expected-program> <expected-sha256>")
    output_path, expected_program, expected_sha256 = arguments
    if expected_program != EXPECTED_PROGRAM:
        raise RuntimeError("Expected UI program argument is invalid")
    if not isinstance(expected_sha256, str) or expected_sha256.lower() != EXPECTED_SHA256:
        raise RuntimeError("Expected UI digest argument is invalid")
    adapter = GhidraProgramAdapter(currentProgram, monitor)
    document = build_raw_export(adapter)
    approved_root = (
        Path(__file__).resolve().parents[2]
        / ".artifacts"
        / "ui-trace"
        / "a6400-v2.00"
    )
    write_json_atomic(output_path, document, approved_root)
    print(
        "UI_TERMINAL_EXPORT|tracks=%d|candidates=%d|truncated=false"
        % (
            len(document["tracks"]),
            sum(len(item["candidates"]) for item in document["tracks"]),
        )
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
