# Export metadata for exactly two corrected ILCE-6400 UI sites.
# @category Sony.UI
# @runtime PyGhidra

"""Read-only Ghidra post-script for bounded, non-handoff UI sites."""

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
CLASSIFICATION_METHODS = (
    "instruction-flow",
    "reference-target",
    "symbol-identity",
)
EXPOSURE_GETTER_SYMBOL = (
    "_ZN33CmnViewModelWrpCameraExposureMode21getExposureModeActValEv"
)
TRACKS = (
    {
        "id": "orientation-handler-local-branch-landing",
        "traversal_entry": 0x1BB41C,
        "predecessor_edges": (
            {
                "caller": 0x1BB41C,
                "site": 0x1BB74C,
                "target": 0x1B9B44,
                "kind": "direct",
            },
        ),
        "site": {
            "owner": {"start": 0x1B97E4, "end": 0x1B9C1C},
            "offset": 0x1B9B6A,
            "classification": "local-branch-landing",
            "flow_target": None,
            "symbol": None,
        },
    },
    {
        "id": "layout-attach-exposure-mode-getter",
        "traversal_entry": 0x1BB2D2,
        "predecessor_edges": (),
        "site": {
            "owner": {"start": 0x1BB2C6, "end": 0x1BB3F8},
            "offset": 0x1BB30E,
            "classification": "exposure-mode-getter-plt-call",
            "flow_target": 0x14E688,
            "symbol": EXPOSURE_GETTER_SYMBOL,
        },
    },
)
def _optional_adapter_check(adapter, method_name, default):
    method = getattr(adapter, method_name, None)
    return default if method is None else method()


def _is_bounded_even_offset(value):
    return type(value) is int and 0 <= value < EXPECTED_IMAGE_SIZE and value % 2 == 0


def build_raw_export(adapter):
    """Inspect only the exact non-handoff sites in a pinned read-only project."""

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
        site = spec["site"]
        if not adapter.verify_owner_range(
            site["owner"]["start"], site["owner"]["end"]
        ):
            raise RuntimeError("Pinned UI site owner range is not exact")
        if not adapter.verify_traversal_entry(spec["traversal_entry"]):
            raise RuntimeError("Pinned UI traversal entry is not exact")
        for edge in spec["predecessor_edges"]:
            if not adapter.verify_predecessor_edge(
                edge["caller"], edge["site"], edge["target"], edge["kind"]
            ):
                raise RuntimeError("Pinned UI predecessor edge is not exact")
        if adapter.verify_site(
            site["owner"]["start"],
            site["owner"]["end"],
            site["offset"],
            site["classification"],
            site["flow_target"],
            site["symbol"],
        ) is not True:
            raise RuntimeError("Pinned UI site classification could not be verified")
        tracks.append(
            {
                "id": spec["id"],
                "traversal_entry": spec["traversal_entry"],
                "predecessor_edges": [dict(item) for item in spec["predecessor_edges"]],
                "site": {
                    **site,
                    "owner": dict(site["owner"]),
                },
            }
        )

    return {
        "schema_version": 1,
        "program": EXPECTED_PROGRAM,
        "sha256": EXPECTED_SHA256,
        "image_size": EXPECTED_IMAGE_SIZE,
        "analysis_mode": {"read_only": True, "noanalysis": True},
        "source_graph_sha256": SOURCE_GRAPH_SHA256,
        "classification_methods": list(CLASSIFICATION_METHODS),
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
    """Narrow Ghidra boundary that verifies only pinned UI-site classifications."""

    def __init__(self, program, task_monitor):
        self._program = program
        self._monitor = task_monitor
        self._listing = program.getListing()
        self._manager = program.getFunctionManager()
        self._references = program.getReferenceManager()
        self._symbols = program.getSymbolTable()
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

    @staticmethod
    def _prel31(value, place):
        value &= 0x7FFFFFFF
        if value & 0x40000000:
            value -= 0x80000000
        return place + value

    def _exidx_ranges(self):
        memory = self._program.getMemory()
        block = memory.getBlock(".ARM.exidx")
        if block is None:
            raise RuntimeError("Pinned UI exception index is missing")
        start = self._even(int(block.getStart().getOffset()))
        size = int(block.getSize())
        if size <= 0 or size % 8:
            raise RuntimeError("Pinned UI exception index size is invalid")
        starts = []
        for relative in range(0, size, 8):
            place = start + relative
            word = int(memory.getInt(self._address(place))) & 0xFFFFFFFF
            starts.append(self._prel31(word, place) & ~1)
        if starts != sorted(starts) or len(starts) != len(set(starts)):
            raise RuntimeError("Pinned UI exception-index owners are invalid")
        return set(zip(starts, starts[1:]))

    def verify_owner_range(self, start, end):
        self._monitor.checkCanceled()
        return (start, end) in self._exidx_ranges()

    def verify_traversal_entry(self, entry):
        self._monitor.checkCanceled()
        function = self._manager.getFunctionContaining(self._address(entry))
        return (
            function is not None
            and not function.isExternal()
            and self._even(int(function.getEntryPoint().getOffset())) == entry
        )

    def verify_predecessor_edge(self, caller, site, target, kind):
        self._monitor.checkCanceled()
        if kind != "direct":
            return False
        instruction = self._listing.getInstructionAt(self._address(site))
        function = self._manager.getFunctionContaining(self._address(site))
        if instruction is None or function is None or function.isExternal():
            return False
        if self._even(int(function.getEntryPoint().getOffset())) != caller:
            return False
        flow_type = instruction.getFlowType()
        if not (flow_type.isCall() or flow_type.isJump()):
            return False
        flows = tuple(
            self._even(int(address.getOffset())) for address in instruction.getFlows()
        )
        return flows == (target,)

    def verify_site(
        self, owner_start, owner_end, offset, classification, flow_target, symbol
    ):
        self._monitor.checkCanceled()
        if classification not in {
            "local-branch-landing",
            "exposure-mode-getter-plt-call",
        }:
            raise RuntimeError("Pinned UI site classification is unsupported")
        address = self._address(offset)
        instruction = self._listing.getInstructionAt(address)
        function = self._manager.getFunctionContaining(address)
        if instruction is None or function is None or function.isExternal():
            raise RuntimeError("Pinned UI site is not an instruction in a function")
        function_entry = self._even(int(function.getEntryPoint().getOffset()))
        if not owner_start <= offset < owner_end or not owner_start <= function_entry < owner_end:
            raise RuntimeError("Pinned UI site is outside its owner range")
        if classification == "local-branch-landing":
            if flow_target is not None or symbol is not None:
                return False
            for reference in self._references.getReferencesTo(address):
                source = self._listing.getInstructionAt(reference.getFromAddress())
                source_function = self._manager.getFunctionContaining(
                    reference.getFromAddress()
                )
                if (
                    source is not None
                    and source_function is not None
                    and owner_start
                    <= self._even(int(source_function.getEntryPoint().getOffset()))
                    < owner_end
                    and source.getFlowType().isJump()
                ):
                    return True
            return False
        if flow_target != 0x14E688 or symbol != EXPOSURE_GETTER_SYMBOL:
            return False
        if not instruction.getFlowType().isCall():
            return False
        flows = tuple(
            self._even(int(target.getOffset())) for target in instruction.getFlows()
        )
        if flows != (flow_target,):
            return False
        resolved = self._symbols.getPrimarySymbol(self._address(flow_target))
        return resolved is not None and str(resolved.getName()) == symbol


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
        "UI_SITE_EXPORT|tracks=%d|classifications=%d|truncated=false"
        % (len(document["tracks"]), len(document["tracks"]))
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
