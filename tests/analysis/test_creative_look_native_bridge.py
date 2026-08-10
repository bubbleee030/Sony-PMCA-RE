import ctypes
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.analysis.creative_look_native_abi import (
    CORE_SOURCE,
    VIEW_SOURCE,
    NativeFrame,
    NativeState,
    PresentCallback,
    StorageAdapter,
    StorageLoadCallback,
    StorageSaveCallback,
    ViewAdapter,
    assert_no_undefined_symbols,
    compile_freestanding_objects,
    compile_shared_library,
    compiler_linker,
    configure_core_exports,
    link_relocatable,
    retain_callback,
    unload_library,
)


NATIVE = CORE_SOURCE.parent
BRIDGE_H = NATIVE / "creative_look_bridge.h"
BRIDGE_C = NATIVE / "creative_look_bridge.c"

CL_OK = 0
CL_ERR_ARGUMENT = -1
CL_ERR_STATE = -2
CL_ERR_MODE_UNAVAILABLE = -3
CL_ERR_BLOB = -8
CL_ERR_NO_HIT = -9
CL_ERR_ADAPTER = -10
CL_ERR_MANIFEST = -11
CL_ERR_BINDING = -12
CL_ERR_LIFECYCLE = -13
CL_ERR_NOT_OPEN = -14
CL_ERR_ALREADY_OPEN = -15
CL_ERR_REVISION = -16
CL_ERR_INPUT_ATTACHMENT = -17
CL_ERR_REINIT_REQUIRED = -18
CL_ERR_BUSY = -19
CL_BRIDGE_ABI_VERSION = 1
CL_BRIDGE_BINDING_COUNT = 6
CL_BRIDGE_OUTPUT_MASK = 7
CL_BRIDGE_INITIALIZATION_MARKER = 0x434C4231
CL_STORAGE_MISSING = 1
CL_CALLBACK_NOT_ATTEMPTED = -(1 << 31)
CL_EXECUTION_PROFILE_OFFLINE_HOST = 0
CL_BINDING_EVIDENCE_UNBOUND = 0
CL_BINDING_EVIDENCE_STATIC_CANDIDATE = 1
CL_BINDING_EVIDENCE_STATIC_PROVEN = 2
CL_BINDING_RUNTIME_DISABLED = 0
CL_BINDING_RUNTIME_HOST_SIMULATED = 1
CL_INPUT_TOUCH = 0
CL_INPUT_ORIENTATION = 1
CL_UI_KIND_LOOK = 0
CL_UI_KIND_CUSTOM_BASE = 1
CL_UI_KIND_AXIS = 2
CL_UI_KIND_AXIS_VALUE = 3
CL_UI_KIND_ACTION = 4
CL_UI_ACTION_RESET = 5
CL_UI_ACTION_CATALOG = 6
CL_LOOK_VV = 3
CL_LOOK_CUSTOM1 = 12
CL_MODE_INTELLIGENT_AUTO = 0
CL_MODE_MOVIE = 3


class BindingRecord(ctypes.Structure):
    _fields_ = [
        ("kind", ctypes.c_uint8),
        ("evidence", ctypes.c_uint8),
        ("runtime", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8),
        ("evidence_sha256", ctypes.c_uint8 * 32),
    ]


class IntegrationManifest(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint16),
        ("execution_profile", ctypes.c_uint8),
        ("binding_count", ctypes.c_uint8),
        ("bindings", BindingRecord * CL_BRIDGE_BINDING_COUNT),
        ("processing_binding_proven", ctypes.c_uint8),
        ("recovery_validated", ctypes.c_uint8),
        ("camera_test_eligible", ctypes.c_uint8),
        ("installable", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 4),
    ]


class InputEvent(ctypes.Structure):
    _fields_ = [
        ("x", ctypes.c_int32),
        ("y", ctypes.c_int32),
        ("kind", ctypes.c_uint8),
        ("value", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 2),
    ]


class ProcessingSnapshot(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint16),
        ("effective_base", ctypes.c_uint8),
        ("output_mask", ctypes.c_uint8),
        ("processing_revision", ctypes.c_uint32),
        ("state", NativeState),
        ("reserved", ctypes.c_uint8 * 1),
    ]


class BridgeReport(ctypes.Structure):
    _fields_ = [
        ("transition_result", ctypes.c_int32),
        ("lifecycle_open_result", ctypes.c_int32),
        ("lifecycle_close_result", ctypes.c_int32),
        ("input_attach_result", ctypes.c_int32),
        ("input_detach_result", ctypes.c_int32),
        ("persistence_load_result", ctypes.c_int32),
        ("sync_results", ctypes.c_int32 * CL_BRIDGE_BINDING_COUNT),
        ("state_revision", ctypes.c_uint32),
        ("processing_revision", ctypes.c_uint32),
        ("attempted", ctypes.c_uint8),
        ("succeeded", ctypes.c_uint8),
        ("failed", ctypes.c_uint8),
        ("dirty", ctypes.c_uint8),
        ("state_committed", ctypes.c_uint8),
        ("opened", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 2),
    ]


LifecycleOpenCallback = ctypes.CFUNCTYPE(
    ctypes.c_int32, ctypes.c_void_p, ctypes.POINTER(NativeState)
)
LifecycleCloseCallback = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_void_p)
InputSinkCallback = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.POINTER(InputEvent),
    ctypes.POINTER(BridgeReport),
)
InputAttachCallback = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    InputSinkCallback,
    ctypes.c_void_p,
)
InputDetachCallback = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_void_p)
ModelSubmitCallback = ctypes.CFUNCTYPE(
    ctypes.c_int32, ctypes.c_void_p, ctypes.POINTER(ProcessingSnapshot)
)
OutputApplyCallback = ctypes.CFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.c_uint8,
    ctypes.POINTER(ProcessingSnapshot),
)


class LifecycleAdapter(ctypes.Structure):
    _fields_ = [
        ("context", ctypes.c_void_p),
        ("open", LifecycleOpenCallback),
        ("close", LifecycleCloseCallback),
    ]


class InputAdapter(ctypes.Structure):
    _fields_ = [
        ("context", ctypes.c_void_p),
        ("attach", InputAttachCallback),
        ("detach", InputDetachCallback),
    ]


class ModelAdapter(ctypes.Structure):
    _fields_ = [
        ("context", ctypes.c_void_p),
        ("submit", ModelSubmitCallback),
    ]


class OutputAdapter(ctypes.Structure):
    _fields_ = [
        ("context", ctypes.c_void_p),
        ("apply", OutputApplyCallback),
    ]


class BridgeAdapters(ctypes.Structure):
    _fields_ = [
        ("lifecycle", LifecycleAdapter),
        ("presentation", ViewAdapter),
        ("input", InputAdapter),
        ("persistence", StorageAdapter),
        ("model", ModelAdapter),
        ("output", OutputAdapter),
    ]


class Bridge(ctypes.Structure):
    _fields_ = [
        ("manifest", IntegrationManifest),
        ("last_report", BridgeReport),
        ("state_revision", ctypes.c_uint32),
        ("processing_revision", ctypes.c_uint32),
        ("retained_processing_snapshot", ProcessingSnapshot),
        ("initialization_marker", ctypes.c_uint32),
        ("state", NativeState),
        ("dirty_mask", ctypes.c_uint8),
        ("opened", ctypes.c_uint8),
        ("input_attached", ctypes.c_uint8),
        ("busy", ctypes.c_uint8),
        ("opened_once", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 4),
        ("adapters", BridgeAdapters),
    ]


class LifecycleFixture:
    def __init__(
        self,
        library,
        manifest,
        load_result=CL_STORAGE_MISSING,
        load_blob=None,
        callback_results=None,
        reenter_on=None,
        reinit_on=None,
        deliver_on=None,
        direct_event_on=None,
        raise_on=None,
    ):
        self.library = library
        self.manifest = manifest
        self.load_result = load_result
        self.load_blob = load_blob
        self.callback_results = {
            "open": 0,
            "close": 0,
            "present": 0,
            "attach": 0,
            "detach": 0,
            "save": 0,
            "model": 0,
            "output": 0,
            **(callback_results or {}),
        }
        self.reenter_on = set(reenter_on or ())
        self.reinit_on = set(reinit_on or ())
        self.deliver_on = set(deliver_on or ())
        self.direct_event_on = set(direct_event_on or ())
        self.raise_on = set(raise_on or ())
        self.calls = []
        self.presented_frames = []
        self.opened_states = []
        self.model_snapshots = []
        self.output_snapshots = []
        self.saved_blobs = []
        self.sink = None
        self.sink_context = None
        self.resource_open = False
        self.reentry_observations = []
        self.reinit_observations = []
        self.delivery_observations = []
        self.direct_event_observations = []
        self.bridge = Bridge()

        def load(_context, data, size):
            self.calls.append("load")
            self._maybe_handle_event("load")
            self._maybe_reenter("load")
            self._maybe_reinitialize("load")
            if "load" in self.raise_on:
                raise RuntimeError("load callback failure")
            if self.load_result == 0:
                if (
                    size != 164
                    or self.load_blob is None
                    or len(self.load_blob) != 164
                ):
                    return 73
                ctypes.memmove(data, self.load_blob, size)
            return self.load_result

        def save(_context, data, size):
            self.calls.append("save")
            self.saved_blobs.append(ctypes.string_at(data, size))
            self._maybe_reenter("save")
            self._maybe_reinitialize("save")
            return self.callback_results["save"]

        def lifecycle_open(_context, state_pointer):
            self.calls.append("open")
            self.opened_states.append(
                NativeState.from_buffer_copy(state_pointer.contents)
            )
            self.resource_open = self.callback_results["open"] == 0
            self._maybe_handle_event("open")
            self._maybe_reenter("open")
            self._maybe_reinitialize("open")
            return self.callback_results["open"]

        def lifecycle_close(_context):
            self.calls.append("close")
            self.resource_open = False
            self._maybe_reenter("close")
            self._maybe_reinitialize("close")
            return self.callback_results["close"]

        def present(_context, frame_pointer):
            self.calls.append("present")
            self.presented_frames.append(
                NativeFrame.from_buffer_copy(frame_pointer.contents)
            )
            self._maybe_handle_event("present")
            self._maybe_reenter("present")
            self._maybe_reinitialize("present")
            return self.callback_results["present"]

        def attach(_context, sink, sink_context):
            self.calls.append("attach")
            self.sink = sink
            self.sink_context = sink_context
            succeeded = False
            try:
                self._maybe_deliver("attach")
                self._maybe_handle_event("attach")
                self._maybe_reenter("attach")
                self._maybe_reinitialize("attach")
                if "attach" in self.raise_on:
                    raise RuntimeError("attach callback failure")
                result = self.callback_results["attach"]
                succeeded = result == 0
                return result
            finally:
                if not succeeded:
                    self.sink = None
                    self.sink_context = None

        def detach(_context):
            self.calls.append("detach")
            try:
                self._maybe_deliver("detach")
                self._maybe_handle_event("detach")
                self._maybe_reenter("detach")
                self._maybe_reinitialize("detach")
                if "detach" in self.raise_on:
                    raise RuntimeError("detach callback failure")
                return self.callback_results["detach"]
            finally:
                self.sink = None
                self.sink_context = None

        def submit(_context, snapshot_pointer):
            self.calls.append("model")
            self.model_snapshots.append(
                ProcessingSnapshot.from_buffer_copy(snapshot_pointer.contents)
            )
            self._maybe_reenter("model")
            self._maybe_reinitialize("model")
            return self.callback_results["model"]

        def apply(_context, kind, snapshot_pointer):
            output_names = ("live_view", "still_jpeg", "movie")
            self.calls.append(output_names[kind])
            self.output_snapshots.append(
                (
                    kind,
                    ProcessingSnapshot.from_buffer_copy(
                        snapshot_pointer.contents
                    ),
                )
            )
            self._maybe_reenter("output")
            self._maybe_reinitialize("output")
            return self.callback_results.get(output_names[kind], self.callback_results["output"])

        self.load_callback = retain_callback(
            self,
            StorageLoadCallback,
            load,
            exception_result=CL_ERR_ADAPTER,
        )
        self.save_callback = retain_callback(
            self, StorageSaveCallback, save
        )
        self.open_callback = retain_callback(
            self, LifecycleOpenCallback, lifecycle_open
        )
        self.close_callback = retain_callback(
            self, LifecycleCloseCallback, lifecycle_close
        )
        self.present_callback = retain_callback(
            self, PresentCallback, present
        )
        self.attach_callback = retain_callback(
            self, InputAttachCallback, attach
        )
        self.detach_callback = retain_callback(
            self, InputDetachCallback, detach
        )
        self.submit_callback = retain_callback(
            self, ModelSubmitCallback, submit
        )
        self.apply_callback = retain_callback(
            self, OutputApplyCallback, apply
        )
        self.adapters = BridgeAdapters(
            LifecycleAdapter(
                None, self.open_callback, self.close_callback
            ),
            ViewAdapter(None, self.present_callback),
            InputAdapter(
                None, self.attach_callback, self.detach_callback
            ),
            StorageAdapter(
                None, self.load_callback, self.save_callback
            ),
            ModelAdapter(None, self.submit_callback),
            OutputAdapter(None, self.apply_callback),
        )

    def initialize(self):
        return self.library.cl_bridge_init(
            ctypes.byref(self.bridge),
            ctypes.byref(self.manifest),
            ctypes.byref(self.adapters),
        )

    def _maybe_reenter(self, callback_name):
        if callback_name not in self.reenter_on:
            return
        nested_report = BridgeReport()
        ctypes.memset(
            ctypes.byref(nested_report), 0x5A, ctypes.sizeof(nested_report)
        )
        before = (
            bytes(self.bridge.state),
            self.bridge.state_revision,
            self.bridge.processing_revision,
            self.bridge.dirty_mask,
            self.bridge.opened,
            self.bridge.input_attached,
            self.bridge.opened_once,
            bytes(self.bridge.last_report),
            tuple(self.calls),
        )
        result = self.library.cl_bridge_close(
            ctypes.byref(self.bridge), ctypes.byref(nested_report)
        )
        after = (
            bytes(self.bridge.state),
            self.bridge.state_revision,
            self.bridge.processing_revision,
            self.bridge.dirty_mask,
            self.bridge.opened,
            self.bridge.input_attached,
            self.bridge.opened_once,
            bytes(self.bridge.last_report),
            tuple(self.calls),
        )
        self.reentry_observations.append(
            (callback_name, result, before == after, bytes(nested_report))
        )

    def _maybe_reinitialize(self, callback_name):
        if callback_name not in self.reinit_on:
            return
        before = (bytes(self.bridge), tuple(self.calls))
        result = self.library.cl_bridge_init(
            ctypes.byref(self.bridge),
            ctypes.byref(self.bridge.manifest),
            ctypes.byref(self.bridge.adapters),
        )
        after = (bytes(self.bridge), tuple(self.calls))
        self.reinit_observations.append(
            (callback_name, result, before == after)
        )

    def _maybe_deliver(self, callback_name):
        if callback_name not in self.deliver_on or self.sink is None:
            return
        event = InputEvent(120, 240, 0, 0, (ctypes.c_uint8 * 2)(0, 0))
        report = BridgeReport()
        ctypes.memset(ctypes.byref(report), 0x6B, ctypes.sizeof(report))
        before = bytes(report)
        result = self.sink(
            self.sink_context, ctypes.byref(event), ctypes.byref(report)
        )
        self.delivery_observations.append(
            (callback_name, result, before == bytes(report))
        )

    def _maybe_handle_event(self, callback_name):
        if callback_name not in self.direct_event_on:
            return
        report = BridgeReport()
        ctypes.memset(ctypes.byref(report), 0x59, ctypes.sizeof(report))
        before = bytes(report)
        result = self.library.cl_bridge_handle_event(
            ctypes.byref(self.bridge),
            ctypes.byref(InputEvent(
                0, 0, CL_INPUT_ORIENTATION, 1,
                (ctypes.c_uint8 * 2)(0, 0),
            )),
            ctypes.byref(report),
        )
        self.direct_event_observations.append(
            (callback_name, result, before == bytes(report))
        )

    def deliver(self, event, report=None):
        if report is None:
            report = BridgeReport()
        self.assert_sink_attached()
        result = self.sink(
            self.sink_context, ctypes.byref(event), ctypes.byref(report)
        )
        return result, report

    def assert_sink_attached(self):
        if self.sink is None:
            raise AssertionError("input sink is not attached")


class CreativeLookNativeBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._temporary = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        sources = [CORE_SOURCE, VIEW_SOURCE, BRIDGE_C]
        cls.library_path = compile_shared_library(
            cls._temporary.name, "creative_look_bridge", sources
        )
        objects = compile_freestanding_objects(cls._temporary.name, sources)
        cls.combined_object = link_relocatable(
            cls._temporary.name, "creative_look_bridge", objects
        )
        assert_no_undefined_symbols(
            cls.combined_object, "native core/view/bridge"
        )

        cls.library = ctypes.CDLL(str(cls.library_path))
        cls.size_exports = (
            "cl_binding_record_size",
            "cl_integration_manifest_size",
            "cl_input_event_size",
            "cl_processing_snapshot_size",
            "cl_bridge_report_size",
            "cl_bridge_size",
            "cl_bridge_adapters_offset",
            "cl_bridge_alignment",
        )
        cls.bridge_exports = (
            *cls.size_exports,
            "cl_bridge_manifest_host",
            "cl_bridge_validate_manifest",
            "cl_bridge_init",
            "cl_bridge_open",
            "cl_bridge_close",
            "cl_bridge_sync",
            "cl_bridge_retry",
            "cl_bridge_handle_event",
            "cl_bridge_set_mode",
            "cl_bridge_state",
            "cl_bridge_last_report",
            "cl_bridge_state_revision",
            "cl_bridge_processing_revision",
            "cl_bridge_dirty_mask",
        )
        cls.missing_exports = [
            name for name in cls.bridge_exports if not hasattr(cls.library, name)
        ]
        if cls.missing_exports:
            return
        for name in cls.size_exports:
            function = getattr(cls.library, name)
            function.argtypes = []
            function.restype = ctypes.c_size_t
        configure_core_exports(cls.library)
        cls.library.cl_bridge_manifest_host.argtypes = [
            ctypes.POINTER(IntegrationManifest)
        ]
        cls.library.cl_bridge_manifest_host.restype = ctypes.c_int
        cls.library.cl_bridge_validate_manifest.argtypes = [
            ctypes.POINTER(IntegrationManifest)
        ]
        cls.library.cl_bridge_validate_manifest.restype = ctypes.c_int
        cls.library.cl_bridge_init.argtypes = [
            ctypes.POINTER(Bridge),
            ctypes.POINTER(IntegrationManifest),
            ctypes.POINTER(BridgeAdapters),
        ]
        cls.library.cl_bridge_init.restype = ctypes.c_int
        cls.library.cl_bridge_open.argtypes = [
            ctypes.POINTER(Bridge),
            ctypes.POINTER(BridgeReport),
        ]
        cls.library.cl_bridge_open.restype = ctypes.c_int
        cls.library.cl_bridge_close.argtypes = [
            ctypes.POINTER(Bridge),
            ctypes.POINTER(BridgeReport),
        ]
        cls.library.cl_bridge_close.restype = ctypes.c_int
        cls.library.cl_bridge_sync.argtypes = [
            ctypes.POINTER(Bridge), ctypes.POINTER(BridgeReport)
        ]
        cls.library.cl_bridge_sync.restype = ctypes.c_int
        cls.library.cl_bridge_retry.argtypes = [
            ctypes.POINTER(Bridge), ctypes.POINTER(BridgeReport)
        ]
        cls.library.cl_bridge_retry.restype = ctypes.c_int
        cls.library.cl_bridge_handle_event.argtypes = [
            ctypes.POINTER(Bridge),
            ctypes.POINTER(InputEvent),
            ctypes.POINTER(BridgeReport),
        ]
        cls.library.cl_bridge_handle_event.restype = ctypes.c_int
        cls.library.cl_bridge_set_mode.argtypes = [
            ctypes.POINTER(Bridge),
            ctypes.c_uint8,
            ctypes.c_int,
            ctypes.POINTER(BridgeReport),
        ]
        cls.library.cl_bridge_set_mode.restype = ctypes.c_int
        cls.library.cl_view_build.argtypes = [
            ctypes.POINTER(NativeState), ctypes.POINTER(NativeFrame)
        ]
        cls.library.cl_view_build.restype = ctypes.c_int
        cls.library.cl_view_touch.argtypes = [
            ctypes.POINTER(NativeState), ctypes.c_int32, ctypes.c_int32
        ]
        cls.library.cl_view_touch.restype = ctypes.c_int
        cls.library.cl_bridge_state.argtypes = [ctypes.POINTER(Bridge)]
        cls.library.cl_bridge_state.restype = ctypes.POINTER(NativeState)
        cls.library.cl_bridge_last_report.argtypes = [ctypes.POINTER(Bridge)]
        cls.library.cl_bridge_last_report.restype = ctypes.POINTER(BridgeReport)
        cls.library.cl_bridge_state_revision.argtypes = [
            ctypes.POINTER(Bridge)
        ]
        cls.library.cl_bridge_state_revision.restype = ctypes.c_uint32
        cls.library.cl_bridge_processing_revision.argtypes = [
            ctypes.POINTER(Bridge)
        ]
        cls.library.cl_bridge_processing_revision.restype = ctypes.c_uint32
        cls.library.cl_bridge_dirty_mask.argtypes = [ctypes.POINTER(Bridge)]
        cls.library.cl_bridge_dirty_mask.restype = ctypes.c_uint8

    @classmethod
    def tearDownClass(cls):
        unload_library(cls, "library")
        cls._temporary.cleanup()

    def _host_manifest(self):
        manifest = IntegrationManifest()
        ctypes.memset(ctypes.byref(manifest), 0xA5, ctypes.sizeof(manifest))
        self.assertEqual(
            self.library.cl_bridge_manifest_host(ctypes.byref(manifest)),
            CL_OK,
        )
        return manifest

    def _encoded_blob(self, selected_look=3):
        state = NativeState()
        self.assertEqual(self.library.cl_init(ctypes.byref(state)), CL_OK)
        self.assertEqual(
            self.library.cl_select_look(
                ctypes.byref(state), selected_look
            ),
            CL_OK,
        )
        blob = (ctypes.c_uint8 * 164)()
        self.assertEqual(
            self.library.cl_encode(ctypes.byref(state), blob, 164), CL_OK
        )
        return bytes(blob), state

    def _fixture(self, **arguments):
        fixture = LifecycleFixture(
            self.library, self._host_manifest(), **arguments
        )
        self.assertEqual(fixture.initialize(), CL_OK)
        self.assertEqual(fixture.calls, [])
        self.assertEqual(fixture._native_callback_errors, [])
        return fixture

    def _assert_report(
        self,
        report,
        *,
        transition=CL_OK,
        lifecycle_open=CL_CALLBACK_NOT_ATTEMPTED,
        lifecycle_close=CL_CALLBACK_NOT_ATTEMPTED,
        input_attach=CL_CALLBACK_NOT_ATTEMPTED,
        input_detach=CL_CALLBACK_NOT_ATTEMPTED,
        persistence_load=CL_CALLBACK_NOT_ATTEMPTED,
        sync_results=None,
        state_revision=0,
        processing_revision=0,
        attempted=0,
        succeeded=0,
        failed=0,
        dirty=0,
        state_committed=0,
        opened=0,
    ):
        if sync_results is None:
            sync_results = [CL_CALLBACK_NOT_ATTEMPTED] * 6
        self.assertEqual(
            (
                report.transition_result,
                report.lifecycle_open_result,
                report.lifecycle_close_result,
                report.input_attach_result,
                report.input_detach_result,
                report.persistence_load_result,
            ),
            (
                transition,
                lifecycle_open,
                lifecycle_close,
                input_attach,
                input_detach,
                persistence_load,
            ),
        )
        self.assertEqual(list(report.sync_results), sync_results)
        self.assertEqual(
            (
                report.state_revision,
                report.processing_revision,
                report.attempted,
                report.succeeded,
                report.failed,
                report.dirty,
                report.state_committed,
                report.opened,
            ),
            (
                state_revision,
                processing_revision,
                attempted,
                succeeded,
                failed,
                dirty,
                state_committed,
                opened,
            ),
        )
        self.assertEqual(bytes(report.reserved), bytes(2))

    def _assert_default_state(self, state):
        self.assertEqual(
            (
                state.selected_look,
                state.screen,
                state.orientation,
                state.editing_axis,
                bytes(state.custom_bases),
                state.modes,
            ),
            (0, 0, 0, 255, bytes([255] * 6), 0),
        )
        self.assertEqual(
            bytes(state.adjustments), bytes([128] * (18 * 8))
        )

    def _event_for_element(
        self, fixture, kind, primary=None, action=None, value=None, state=None
    ):
        frame = NativeFrame()
        if state is None:
            state = fixture.bridge.state
        self.assertEqual(
            self.library.cl_view_build(
                ctypes.byref(state), ctypes.byref(frame)
            ),
            CL_OK,
        )
        element = next(
            element
            for element in frame.elements[:frame.count]
            if element.kind == kind
            and (primary is None or element.primary == primary)
            and (action is None or element.action == action)
            and (value is None or element.value == value)
        )
        return InputEvent(
            element.x + 1,
            element.y + 1,
            CL_INPUT_TOUCH,
            0,
            (ctypes.c_uint8 * 2)(0, 0),
        )

    def _open_fixture(self, **arguments):
        fixture = self._fixture(**arguments)
        self.assertEqual(
            self.library.cl_bridge_open(
                ctypes.byref(fixture.bridge), ctypes.byref(BridgeReport())
            ),
            CL_OK,
        )
        return fixture

    def test_canonical_sink_touch_commits_selected_look_and_processing(self):
        self._require_exports()
        fixture = self._open_fixture()
        frame = fixture.presented_frames[-1]
        vv = next(
            element
            for element in frame.elements[:frame.count]
            if element.kind == CL_UI_KIND_LOOK and element.primary == CL_LOOK_VV
        )
        event = InputEvent(
            vv.x + 1, vv.y + 1, CL_INPUT_TOUCH, 0,
            (ctypes.c_uint8 * 2)(0, 0),
        )

        report = BridgeReport()
        ctypes.memset(ctypes.byref(report), 0x5A, ctypes.sizeof(report))
        result, report = fixture.deliver(event, report)

        self.assertEqual(result, CL_OK)
        self.assertEqual(fixture.bridge.state.selected_look, CL_LOOK_VV)
        self._assert_report(
            report,
            state_revision=2,
            processing_revision=2,
            sync_results=[0] * 6,
            attempted=0x3F,
            succeeded=0x3F,
            dirty=0,
            state_committed=1,
            opened=1,
        )

    def test_processing_touch_synchronizes_full_snapshot_in_exact_order(self):
        """Fails if any six-domain callback is skipped, reordered, or copied incompletely."""
        self._require_exports()
        fixture = self._open_fixture()
        report = BridgeReport()

        self.assertEqual(
            fixture.deliver(
                self._event_for_element(fixture, CL_UI_KIND_LOOK, CL_LOOK_VV),
                report,
            )[0],
            CL_OK,
        )
        self.assertEqual(
            fixture.calls[-6:],
            ["present", "save", "model", "live_view", "still_jpeg", "movie"],
        )
        self.assertEqual((report.attempted, report.succeeded, report.failed, report.dirty), (0x3F, 0x3F, 0, 0))
        snapshots = [fixture.model_snapshots[-1]] + [snapshot for _, snapshot in fixture.output_snapshots[-3:]]
        for snapshot in snapshots:
            self.assertEqual((snapshot.abi_version, snapshot.output_mask, snapshot.processing_revision), (1, 7, report.processing_revision))
            self.assertEqual(snapshot.state.selected_look, fixture.bridge.state.selected_look)
            self.assertEqual(bytes(snapshot.state.custom_bases), bytes(fixture.bridge.state.custom_bases))
            self.assertEqual(bytes(snapshot.state.adjustments), bytes(fixture.bridge.state.adjustments))
            self.assertEqual(snapshot.effective_base, CL_LOOK_VV)
        self.assertEqual([kind for kind, _ in fixture.output_snapshots[-3:]], [0, 1, 2])
        self.assertEqual(
            len({bytes(snapshot) for snapshot in snapshots}),
            1,
        )

    def test_partial_failures_remain_dirty_and_retry_only_failed_domains(self):
        """Fails if a failed domain is cleared or retry rebuilds a broader call set."""
        self._require_exports()
        fixture = self._open_fixture()
        fixture.callback_results.update({"save": 41, "still_jpeg": 42})
        report = BridgeReport()
        self.assertEqual(
            fixture.deliver(
                self._event_for_element(fixture, CL_UI_KIND_LOOK, CL_LOOK_VV),
                report,
            )[0],
            CL_ERR_ADAPTER,
        )
        self.assertEqual(
            fixture.calls[-6:],
            ["present", "save", "model", "live_view", "still_jpeg", "movie"],
        )
        self.assertEqual((report.attempted, report.succeeded, report.failed, report.dirty), (0x3F, 0x2D, 0x12, 0x12))
        failed_revision = report.processing_revision
        failed_state = bytes(fixture.model_snapshots[-1])
        fixture.callback_results.update({"save": 0, "still_jpeg": 0})
        retry = BridgeReport()
        self.assertEqual(
            self.library.cl_bridge_retry(
                ctypes.byref(fixture.bridge), ctypes.byref(retry)
            ),
            CL_OK,
        )
        self.assertEqual(fixture.calls[-2:], ["save", "still_jpeg"])
        self.assertEqual((retry.attempted, retry.succeeded, retry.failed, retry.dirty), (0x12, 0x12, 0, 0))
        self.assertEqual(retry.processing_revision, failed_revision)
        self.assertEqual(bytes(fixture.output_snapshots[-1][1]), failed_state)

    def test_screen_and_orientation_changes_sync_only_presentation_and_persistence(self):
        """Fails if UI-only changes rebuild or apply processing output."""
        self._require_exports()
        fixture = self._open_fixture()
        self.assertEqual(
            fixture.deliver(
                self._event_for_element(fixture, CL_UI_KIND_LOOK, CL_LOOK_VV)
            )[0],
            CL_OK,
        )
        for event in (
            self._event_for_element(
                fixture, CL_UI_KIND_ACTION, action=CL_UI_ACTION_CATALOG
            ),
            InputEvent(
                0, 0, CL_INPUT_ORIENTATION, 1,
                (ctypes.c_uint8 * 2)(0, 0),
            ),
        ):
            with self.subTest(kind=event.kind):
                report = BridgeReport()
                self.assertEqual(fixture.deliver(event, report)[0], CL_OK)
                self.assertEqual(fixture.calls[-2:], ["present", "save"])
                self.assertEqual((report.attempted, report.succeeded, report.failed, report.dirty), (0x03, 0x03, 0, 0))

    def test_retry_reuses_immutable_snapshot_and_new_processing_coalesces(self):
        """Fails if retries rebuild from UI state or replay a stale processing revision."""
        self._require_exports()
        fixture = self._open_fixture()
        fixture.callback_results["model"] = 51
        first = BridgeReport()
        self.assertEqual(
            fixture.deliver(
                self._event_for_element(fixture, CL_UI_KIND_LOOK, CL_LOOK_VV), first
            )[0],
            CL_ERR_ADAPTER,
        )
        snapshot_n = bytes(fixture.model_snapshots[-1])
        revision_n = first.processing_revision
        for event in (
            self._event_for_element(
                fixture, CL_UI_KIND_ACTION, action=CL_UI_ACTION_CATALOG
            ),
            InputEvent(0, 0, CL_INPUT_ORIENTATION, 1, (ctypes.c_uint8 * 2)(0, 0)),
        ):
            self.assertEqual(fixture.deliver(event)[0], CL_ERR_ADAPTER)
            self.assertEqual(bytes(fixture.model_snapshots[-1]), snapshot_n)
            self.assertEqual(fixture.model_snapshots[-1].processing_revision, revision_n)
        fixture.callback_results["model"] = 0
        self.assertEqual(
            self.library.cl_bridge_retry(
                ctypes.byref(fixture.bridge), ctypes.byref(BridgeReport())
            ),
            CL_OK,
        )
        self.assertEqual(bytes(fixture.model_snapshots[-1]), snapshot_n)

        coalesced = self._open_fixture()
        coalesced.callback_results["model"] = 52
        baseline = len(coalesced.model_snapshots)
        self.assertEqual(
            coalesced.deliver(
                self._event_for_element(coalesced, CL_UI_KIND_LOOK, CL_LOOK_VV)
            )[0],
            CL_ERR_ADAPTER,
        )
        revision_n = coalesced.bridge.processing_revision
        self.assertEqual(
            self.library.cl_bridge_set_mode(
                ctypes.byref(coalesced.bridge), CL_MODE_MOVIE, 1,
                ctypes.byref(BridgeReport()),
            ),
            CL_ERR_ADAPTER,
        )
        self.assertEqual(len(coalesced.model_snapshots), baseline + 2)
        self.assertEqual(
            coalesced.model_snapshots[-1].processing_revision, revision_n + 1
        )
        self.assertNotEqual(
            bytes(coalesced.model_snapshots[-2]),
            bytes(coalesced.model_snapshots[-1]),
        )

    def test_initial_post_attach_sync_failure_keeps_only_failed_domain_dirty(self):
        """Fails if post-attach failures close the bridge or lose their retry bit."""
        self._require_exports()
        fixture = self._fixture(callback_results={"still_jpeg": 61})
        report = BridgeReport()
        self.assertEqual(
            self.library.cl_bridge_open(
                ctypes.byref(fixture.bridge), ctypes.byref(report)
            ),
            CL_ERR_ADAPTER,
        )
        self.assertEqual(
            fixture.calls,
            ["load", "open", "present", "attach", "save", "model", "live_view", "still_jpeg", "movie"],
        )
        self.assertEqual((report.attempted, report.succeeded, report.failed, report.dirty), (0x3F, 0x2F, 0x10, 0x10))
        self.assertEqual((fixture.bridge.opened, fixture.bridge.input_attached), (1, 1))

    def test_each_failed_sync_domain_retains_only_its_dirty_bit(self):
        """Fails if a domain failure clears itself or dirties a successful peer."""
        self._require_exports()
        cases = (
            ("present", 0x01, "present", "ui", -2),
            ("save", 0x02, "save", "ui", -1),
            ("model", 0x04, "model", "processing", -4),
            ("live_view", 0x08, "live_view", "processing", -3),
            ("still_jpeg", 0x10, "still_jpeg", "processing", -2),
            ("movie", 0x20, "movie", "processing", -1),
        )
        for callback_name, bit, result_name, event_kind, call_index in cases:
            fixture = self._open_fixture()
            fixture.callback_results[callback_name] = 71
            event = (
                InputEvent(0, 0, CL_INPUT_ORIENTATION, 1, (ctypes.c_uint8 * 2)(0, 0))
                if event_kind == "ui"
                else self._event_for_element(fixture, CL_UI_KIND_LOOK, CL_LOOK_VV)
            )
            with self.subTest(domain=callback_name):
                report = BridgeReport()
                self.assertEqual(fixture.deliver(event, report)[0], CL_ERR_ADAPTER)
                self.assertEqual((report.failed, report.dirty), (bit, bit))
                self.assertEqual(report.sync_results[(bit.bit_length() - 1)], 71)
                self.assertEqual(fixture.calls[call_index], result_name)

    def test_custom_selected_snapshot_uses_its_configured_effective_base(self):
        """Fails if Custom Look output uses the Custom slot rather than its base Look."""
        self._require_exports()
        fixture = self._open_fixture()
        self.assertEqual(
            fixture.deliver(
                self._event_for_element(fixture, CL_UI_KIND_LOOK, CL_LOOK_CUSTOM1)
            )[0],
            CL_OK,
        )
        self.assertEqual(
            fixture.deliver(
                self._event_for_element(fixture, CL_UI_KIND_CUSTOM_BASE, CL_LOOK_VV)
            )[0],
            CL_OK,
        )
        snapshot = fixture.model_snapshots[-1]
        self.assertEqual(
            (snapshot.state.selected_look, snapshot.effective_base),
            (CL_LOOK_CUSTOM1, CL_LOOK_VV),
        )

    def test_sink_flow_matches_direct_view_touch_for_editor_paths(self):
        self._require_exports()
        fixture = self._open_fixture()
        direct_state = NativeState()
        self.assertEqual(self.library.cl_init(ctypes.byref(direct_state)), CL_OK)
        steps = (
            (CL_UI_KIND_LOOK, CL_LOOK_VV, None, None),
            (CL_UI_KIND_ACTION, None, CL_UI_ACTION_CATALOG, None),
            (CL_UI_KIND_LOOK, CL_LOOK_CUSTOM1, None, None),
            (CL_UI_KIND_CUSTOM_BASE, CL_LOOK_VV, None, None),
            (CL_UI_KIND_AXIS, 0, None, None),
            (CL_UI_KIND_AXIS_VALUE, 0, None, 0),
            (CL_UI_KIND_ACTION, None, CL_UI_ACTION_RESET, None),
            (CL_UI_KIND_ACTION, None, CL_UI_ACTION_CATALOG, None),
        )

        for kind, primary, action, value in steps:
            with self.subTest(kind=kind, primary=primary, action=action):
                event = self._event_for_element(
                    fixture, kind, primary, action, value, direct_state
                )
                self.assertEqual(
                    self.library.cl_view_touch(
                        ctypes.byref(direct_state), event.x, event.y
                    ),
                    CL_OK,
                )
                self.assertEqual(fixture.deliver(event)[0], CL_OK)
                self.assertEqual(
                    bytes(fixture.bridge.state), bytes(direct_state)
                )
        self.assertEqual(fixture.calls[:9], [
            "load", "open", "present", "attach", "save", "model",
            "live_view", "still_jpeg", "movie",
        ])

    def test_event_rejects_an_invalid_successful_transition_atomically(self):
        self._require_exports()
        mutated_view = Path(self._temporary.name) / "invalid-view-touch.c"
        source = VIEW_SOURCE.read_text(encoding="utf-8")
        original = """            case CL_UI_ACTION_SELECT_LOOK:
                return cl_select_look(state, element->primary);
"""
        replacement = """            case CL_UI_ACTION_SELECT_LOOK:
                result = cl_select_look(state, element->primary);
                if (result == CL_OK) {
                    state->selected_look = CL_LOOK_COUNT;
                }
                return result;
"""
        self.assertIn(original, source)
        mutated_view.write_text(
            source.replace(original, replacement), encoding="utf-8"
        )
        library_path = compile_shared_library(
            self._temporary.name,
            "creative_look_bridge_invalid_candidate",
            [CORE_SOURCE, mutated_view, BRIDGE_C],
        )
        mutated_library = ctypes.CDLL(str(library_path))
        manifest = IntegrationManifest()
        self.assertEqual(
            mutated_library.cl_bridge_manifest_host(ctypes.byref(manifest)),
            CL_OK,
        )
        fixture = LifecycleFixture(mutated_library, manifest)
        self.assertEqual(fixture.initialize(), CL_OK)
        self.assertEqual(
            mutated_library.cl_bridge_open(
                ctypes.byref(fixture.bridge), ctypes.byref(BridgeReport())
            ),
            CL_OK,
        )
        event = self._event_for_element(fixture, CL_UI_KIND_LOOK, CL_LOOK_VV)
        before = (
            bytes(fixture.bridge.state), fixture.bridge.state_revision,
            fixture.bridge.processing_revision, fixture.bridge.dirty_mask,
        )

        result, report = fixture.deliver(event)

        self.assertEqual(result, CL_ERR_STATE)
        self._assert_report(
            report, transition=CL_ERR_STATE, state_revision=1,
            processing_revision=1, dirty=0, opened=1,
        )
        self.assertEqual(
            (
                bytes(fixture.bridge.state), fixture.bridge.state_revision,
                fixture.bridge.processing_revision, fixture.bridge.dirty_mask,
            ),
            before,
        )

    def test_processing_revision_tracks_look_base_axis_and_mode_only(self):
        self._require_exports()
        fixture = self._open_fixture()

        self.assertEqual(
            fixture.deliver(
                self._event_for_element(fixture, CL_UI_KIND_LOOK, CL_LOOK_CUSTOM1)
            )[0],
            CL_OK,
        )
        self.assertEqual(
            fixture.deliver(
                self._event_for_element(fixture, CL_UI_KIND_CUSTOM_BASE, CL_LOOK_VV)
            )[0],
            CL_OK,
        )
        self.assertEqual(
            fixture.deliver(self._event_for_element(fixture, CL_UI_KIND_AXIS, 0))[0],
            CL_OK,
        )
        self.assertEqual(
            fixture.deliver(
                self._event_for_element(fixture, CL_UI_KIND_AXIS_VALUE, 0, value=0)
            )[0],
            CL_OK,
        )
        self.assertEqual(
            (fixture.bridge.state_revision, fixture.bridge.processing_revision),
            (5, 4),
        )

        navigation = self._event_for_element(
            fixture, CL_UI_KIND_ACTION, action=CL_UI_ACTION_CATALOG
        )
        self.assertEqual(fixture.deliver(navigation)[0], CL_OK)
        orientation = InputEvent(
            0, 0, CL_INPUT_ORIENTATION, 1, (ctypes.c_uint8 * 2)(0, 0)
        )
        self.assertEqual(fixture.deliver(orientation)[0], CL_OK)
        self.assertEqual(
            (fixture.bridge.state_revision, fixture.bridge.processing_revision),
            (7, 4),
        )

        report = BridgeReport()
        self.assertEqual(
            self.library.cl_bridge_set_mode(
                ctypes.byref(fixture.bridge), CL_MODE_MOVIE, 1,
                ctypes.byref(report),
            ),
            CL_OK,
        )
        self._assert_report(
            report,
            state_revision=8,
            processing_revision=5,
            sync_results=[0] * 6,
            attempted=0x3F,
            succeeded=0x3F,
            dirty=0,
            state_committed=1,
            opened=1,
        )

    def test_invalid_restricted_and_no_hit_events_do_not_commit(self):
        self._require_exports()
        fixture = self._open_fixture()
        before = (
            bytes(fixture.bridge.state), fixture.bridge.state_revision,
            fixture.bridge.processing_revision, fixture.bridge.dirty_mask,
        )
        cases = (
            (InputEvent(0, 0, 99, 0, (ctypes.c_uint8 * 2)(0, 0)), CL_ERR_ARGUMENT),
            (InputEvent(0, 0, CL_INPUT_TOUCH, 1, (ctypes.c_uint8 * 2)(0, 0)), CL_ERR_ARGUMENT),
            (InputEvent(0, 0, CL_INPUT_TOUCH, 0, (ctypes.c_uint8 * 2)(1, 0)), CL_ERR_ARGUMENT),
            (InputEvent(0, 0, CL_INPUT_ORIENTATION, 3, (ctypes.c_uint8 * 2)(0, 0)), CL_ERR_ARGUMENT),
            (InputEvent(1, 0, CL_INPUT_ORIENTATION, 1, (ctypes.c_uint8 * 2)(0, 0)), CL_ERR_ARGUMENT),
            (InputEvent(-1, -1, CL_INPUT_TOUCH, 0, (ctypes.c_uint8 * 2)(0, 0)), CL_ERR_NO_HIT),
        )
        for event, expected in cases:
            with self.subTest(event=(event.kind, event.value, event.x, event.y)):
                self.assertEqual(fixture.deliver(event)[0], expected)
                self.assertEqual(
                    (
                        bytes(fixture.bridge.state), fixture.bridge.state_revision,
                        fixture.bridge.processing_revision, fixture.bridge.dirty_mask,
                    ),
                    before,
                )

        self.assertEqual(
            self.library.cl_bridge_set_mode(
                ctypes.byref(fixture.bridge), CL_MODE_INTELLIGENT_AUTO, 1,
                ctypes.byref(BridgeReport()),
            ),
            CL_OK,
        )
        before = (
            bytes(fixture.bridge.state), fixture.bridge.state_revision,
            fixture.bridge.processing_revision, fixture.bridge.dirty_mask,
        )
        restricted = self._event_for_element(fixture, CL_UI_KIND_LOOK, CL_LOOK_VV)
        self.assertEqual(fixture.deliver(restricted)[0], CL_ERR_MODE_UNAVAILABLE)
        self.assertEqual(
            (
                bytes(fixture.bridge.state), fixture.bridge.state_revision,
                fixture.bridge.processing_revision, fixture.bridge.dirty_mask,
            ),
            before,
        )

    def test_captured_sink_rejects_after_close_and_callback_delivery_is_busy(self):
        self._require_exports()
        fixture = self._open_fixture()
        retained_sink = fixture.sink
        retained_context = fixture.sink_context
        self.assertEqual(
            self.library.cl_bridge_close(
                ctypes.byref(fixture.bridge), ctypes.byref(BridgeReport())
            ),
            CL_OK,
        )
        report = BridgeReport()
        self.assertEqual(
            retained_sink(
                retained_context,
                ctypes.byref(InputEvent(0, 0, CL_INPUT_ORIENTATION, 1, (ctypes.c_uint8 * 2)(0, 0))),
                ctypes.byref(report),
            ),
            CL_ERR_NOT_OPEN,
        )

        busy_fixture = self._fixture(deliver_on={"attach", "detach"})
        self.assertEqual(
            self.library.cl_bridge_open(
                ctypes.byref(busy_fixture.bridge), ctypes.byref(BridgeReport())
            ),
            CL_OK,
        )
        self.assertEqual(
            self.library.cl_bridge_close(
                ctypes.byref(busy_fixture.bridge), ctypes.byref(BridgeReport())
            ),
            CL_OK,
        )
        self.assertEqual(
            busy_fixture.delivery_observations,
            [("attach", CL_ERR_BUSY, True), ("detach", CL_ERR_BUSY, True)],
        )

        callback_fixture = self._fixture(direct_event_on={"present"})
        self.assertEqual(
            self.library.cl_bridge_open(
                ctypes.byref(callback_fixture.bridge),
                ctypes.byref(BridgeReport()),
            ),
            CL_OK,
        )
        self.assertEqual(
            callback_fixture.direct_event_observations,
            [("present", CL_ERR_BUSY, True)],
        )

    def test_revision_overflow_rejects_only_the_changes_it_cannot_record(self):
        self._require_exports()
        fixture = self._open_fixture()
        fixture.bridge.state_revision = 0xFFFFFFFF
        fixture.bridge.processing_revision = 7
        before = (
            bytes(fixture.bridge.state), fixture.bridge.state_revision,
            fixture.bridge.processing_revision, fixture.bridge.dirty_mask,
        )
        self.assertEqual(
            fixture.deliver(self._event_for_element(fixture, CL_UI_KIND_LOOK, CL_LOOK_VV))[0],
            CL_ERR_REVISION,
        )
        self.assertEqual(
            (
                bytes(fixture.bridge.state), fixture.bridge.state_revision,
                fixture.bridge.processing_revision, fixture.bridge.dirty_mask,
            ),
            before,
        )
        self.assertEqual(
            fixture.deliver(
                InputEvent(
                    0, 0, CL_INPUT_ORIENTATION, 1,
                    (ctypes.c_uint8 * 2)(0, 0),
                )
            )[0],
            CL_ERR_REVISION,
        )
        self.assertEqual(
            (
                bytes(fixture.bridge.state), fixture.bridge.state_revision,
                fixture.bridge.processing_revision, fixture.bridge.dirty_mask,
            ),
            before,
        )

        fixture = self._open_fixture()
        fixture.bridge.processing_revision = 0xFFFFFFFF
        before = (
            bytes(fixture.bridge.state), fixture.bridge.state_revision,
            fixture.bridge.processing_revision, fixture.bridge.dirty_mask,
        )
        self.assertEqual(
            fixture.deliver(self._event_for_element(fixture, CL_UI_KIND_LOOK, CL_LOOK_VV))[0],
            CL_ERR_REVISION,
        )
        self.assertEqual(
            (
                bytes(fixture.bridge.state), fixture.bridge.state_revision,
                fixture.bridge.processing_revision, fixture.bridge.dirty_mask,
            ),
            before,
        )
        self.assertEqual(
            fixture.deliver(InputEvent(0, 0, CL_INPUT_ORIENTATION, 1, (ctypes.c_uint8 * 2)(0, 0)))[0],
            CL_OK,
        )
        self.assertEqual(
            (fixture.bridge.state_revision, fixture.bridge.processing_revision),
            (2, 0xFFFFFFFF),
        )

    def test_mode_noop_leaves_revisions_and_callbacks_untouched(self):
        self._require_exports()
        fixture = self._open_fixture()
        before = (
            bytes(fixture.bridge.state), fixture.bridge.state_revision,
            fixture.bridge.processing_revision, fixture.bridge.dirty_mask,
            list(fixture.calls),
        )
        report = BridgeReport()
        ctypes.memset(ctypes.byref(report), 0x5A, ctypes.sizeof(report))
        self.assertEqual(
            self.library.cl_bridge_set_mode(
                ctypes.byref(fixture.bridge), CL_MODE_MOVIE, 0,
                ctypes.byref(report),
            ),
            CL_OK,
        )
        self._assert_report(
            report, state_revision=1, processing_revision=1, dirty=0,
            opened=1,
        )
        self.assertEqual(
            (
                bytes(fixture.bridge.state), fixture.bridge.state_revision,
                fixture.bridge.processing_revision, fixture.bridge.dirty_mask,
                list(fixture.calls),
            ),
            before,
        )

    def _require_exports(self):
        if self.missing_exports:
            self.skipTest("bridge contract exports are not implemented")

    def _assert_manifest_rejected(self, manifest, label):
        with self.subTest(label=label):
            self.assertEqual(
                self.library.cl_bridge_validate_manifest(
                    ctypes.byref(manifest)
                ),
                CL_ERR_MANIFEST,
            )

    def test_wire_records_have_literal_sizes(self):
        self._require_exports()
        expected = (
            (NativeState, self.library.cl_state_size, 155),
            (BindingRecord, self.library.cl_binding_record_size, 36),
            (
                IntegrationManifest,
                self.library.cl_integration_manifest_size,
                228,
            ),
            (InputEvent, self.library.cl_input_event_size, 12),
            (
                ProcessingSnapshot,
                self.library.cl_processing_snapshot_size,
                164,
            ),
            (BridgeReport, self.library.cl_bridge_report_size, 64),
        )
        self.library.cl_state_size.argtypes = []
        self.library.cl_state_size.restype = ctypes.c_size_t
        for structure, size_query, literal_size in expected:
            with self.subTest(structure=structure.__name__):
                self.assertEqual(ctypes.sizeof(structure), literal_size)
                self.assertEqual(size_query(), literal_size)

    def test_host_manifest_is_ordered_simulated_and_safety_zero(self):
        self._require_exports()
        manifest = self._host_manifest()
        expected_bytes = bytearray(228)
        expected_bytes[0:2] = CL_BRIDGE_ABI_VERSION.to_bytes(
            2, byteorder="little"
        )
        expected_bytes[3] = CL_BRIDGE_BINDING_COUNT
        for index in range(CL_BRIDGE_BINDING_COUNT):
            binding_offset = 4 + index * 36
            expected_bytes[binding_offset] = index
            expected_bytes[binding_offset + 2] = (
                CL_BINDING_RUNTIME_HOST_SIMULATED
            )
        self.assertEqual(bytes(manifest), bytes(expected_bytes))
        self.assertEqual(manifest.abi_version, CL_BRIDGE_ABI_VERSION)
        self.assertEqual(
            manifest.execution_profile, CL_EXECUTION_PROFILE_OFFLINE_HOST
        )
        self.assertEqual(manifest.binding_count, CL_BRIDGE_BINDING_COUNT)
        self.assertEqual(
            [binding.kind for binding in manifest.bindings],
            [0, 1, 2, 3, 4, 5],
        )
        self.assertEqual(
            [binding.evidence for binding in manifest.bindings],
            [CL_BINDING_EVIDENCE_UNBOUND] * CL_BRIDGE_BINDING_COUNT,
        )
        self.assertEqual(
            [binding.runtime for binding in manifest.bindings],
            [CL_BINDING_RUNTIME_HOST_SIMULATED] * CL_BRIDGE_BINDING_COUNT,
        )
        for binding in manifest.bindings:
            self.assertEqual(binding.reserved, 0)
            self.assertEqual(bytes(binding.evidence_sha256), bytes(32))
        self.assertEqual(
            (
                manifest.processing_binding_proven,
                manifest.recovery_validated,
                manifest.camera_test_eligible,
                manifest.installable,
            ),
            (0, 0, 0, 0),
        )
        self.assertEqual(bytes(manifest.reserved), bytes(4))
        self.assertEqual(
            self.library.cl_bridge_validate_manifest(ctypes.byref(manifest)),
            CL_OK,
        )

    def test_manifest_validation_is_fail_closed(self):
        self._require_exports()
        self.assertEqual(
            self.library.cl_bridge_validate_manifest(None), CL_ERR_MANIFEST
        )

        scalar_mutations = (
            ("abi version", "abi_version", 2),
            ("execution profile", "execution_profile", 1),
            ("binding count", "binding_count", 5),
            (
                "processing binding safety",
                "processing_binding_proven",
                1,
            ),
            ("recovery safety", "recovery_validated", 1),
            ("camera safety", "camera_test_eligible", 1),
            ("installability safety", "installable", 1),
        )
        for label, field, value in scalar_mutations:
            manifest = self._host_manifest()
            setattr(manifest, field, value)
            self._assert_manifest_rejected(manifest, label)

        for index in range(CL_BRIDGE_BINDING_COUNT):
            manifest = self._host_manifest()
            manifest.bindings[index].kind = (index + 1) % CL_BRIDGE_BINDING_COUNT
            self._assert_manifest_rejected(manifest, f"binding {index} order")

            manifest = self._host_manifest()
            manifest.bindings[index].evidence = 3
            self._assert_manifest_rejected(
                manifest, f"binding {index} unknown evidence"
            )

            manifest = self._host_manifest()
            manifest.bindings[index].runtime = 2
            self._assert_manifest_rejected(
                manifest, f"binding {index} unknown runtime"
            )

            manifest = self._host_manifest()
            manifest.bindings[index].reserved = 1
            self._assert_manifest_rejected(
                manifest, f"binding {index} reserved"
            )

            manifest = self._host_manifest()
            manifest.bindings[index].evidence_sha256[31] = 1
            self._assert_manifest_rejected(
                manifest, f"binding {index} unbound digest"
            )

            for evidence, label in (
                (CL_BINDING_EVIDENCE_STATIC_CANDIDATE, "candidate"),
                (CL_BINDING_EVIDENCE_STATIC_PROVEN, "proven"),
            ):
                manifest = self._host_manifest()
                manifest.bindings[index].evidence = evidence
                self._assert_manifest_rejected(
                    manifest, f"binding {index} {label} empty digest"
                )

        for index in range(4):
            manifest = self._host_manifest()
            manifest.reserved[index] = 1
            self._assert_manifest_rejected(
                manifest, f"manifest reserved {index}"
            )

    def test_manifest_accepts_each_documented_evidence_and_runtime_value(self):
        self._require_exports()
        for index in range(CL_BRIDGE_BINDING_COUNT):
            for evidence in (
                CL_BINDING_EVIDENCE_STATIC_CANDIDATE,
                CL_BINDING_EVIDENCE_STATIC_PROVEN,
            ):
                manifest = self._host_manifest()
                manifest.bindings[index].evidence = evidence
                manifest.bindings[index].runtime = CL_BINDING_RUNTIME_DISABLED
                manifest.bindings[index].evidence_sha256[0] = index + 1
                with self.subTest(index=index, evidence=evidence):
                    self.assertEqual(
                        self.library.cl_bridge_validate_manifest(
                            ctypes.byref(manifest)
                        ),
                        CL_OK,
                    )

    def test_bridge_layout_and_init_are_exact_and_callback_free(self):
        self._require_exports()
        self.assertEqual(Bridge.adapters.offset, 632)
        self.assertEqual(self.library.cl_bridge_adapters_offset(), 632)
        self.assertEqual(self.library.cl_bridge_size(), ctypes.sizeof(Bridge))
        self.assertEqual(
            self.library.cl_bridge_alignment(), ctypes.alignment(Bridge)
        )
        fixture = self._fixture()
        self.assertEqual(bytes(fixture.bridge.manifest), bytes(fixture.manifest))
        retained_manifest = bytes(fixture.bridge.manifest)
        retained_adapters = bytes(fixture.bridge.adapters)
        fixture.manifest.binding_count = 0
        fixture.adapters = BridgeAdapters()
        self.assertEqual(bytes(fixture.bridge.manifest), retained_manifest)
        self.assertEqual(bytes(fixture.bridge.adapters), retained_adapters)
        self._assert_default_state(fixture.bridge.state)
        self.assertEqual(
            (
                fixture.bridge.state_revision,
                fixture.bridge.processing_revision,
                fixture.bridge.dirty_mask,
                fixture.bridge.opened,
                fixture.bridge.input_attached,
                fixture.bridge.busy,
                fixture.bridge.opened_once,
                fixture.bridge.initialization_marker,
                bytes(fixture.bridge.reserved),
            ),
            (
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                CL_BRIDGE_INITIALIZATION_MARKER,
                bytes(4),
            ),
        )
        self.assertEqual(
            bytes(fixture.bridge.retained_processing_snapshot), bytes(164)
        )
        self._assert_report(fixture.bridge.last_report)
        self.assertEqual(
            bytes(self.library.cl_bridge_state(ctypes.byref(fixture.bridge)).contents),
            bytes(fixture.bridge.state),
        )
        self.assertEqual(
            bytes(
                self.library.cl_bridge_last_report(
                    ctypes.byref(fixture.bridge)
                ).contents
            ),
            bytes(fixture.bridge.last_report),
        )
        self.assertEqual(
            self.library.cl_bridge_state_revision(
                ctypes.byref(fixture.bridge)
            ),
            0,
        )
        self.assertEqual(
            self.library.cl_bridge_processing_revision(
                ctypes.byref(fixture.bridge)
            ),
            0,
        )
        self.assertEqual(
            self.library.cl_bridge_dirty_mask(ctypes.byref(fixture.bridge)),
            0,
        )
        self.assertEqual(fixture.calls, [])

    def test_retain_callback_uses_callback_specific_exception_result(self):
        class Owner:
            pass

        owner = Owner()

        def raises(_context):
            raise RuntimeError("callback failure")

        try:
            callback = retain_callback(
                owner,
                LifecycleCloseCallback,
                raises,
                exception_result=73,
            )
        except TypeError as error:
            self.fail(f"callback-specific exception result unsupported: {error}")
        self.assertEqual(callback(None), 73)
        self.assertEqual(len(owner._native_callback_errors), 1)

    def test_first_init_requires_all_zero_storage_and_known_marker(self):
        self._require_exports()
        fixture = LifecycleFixture(self.library, self._host_manifest())

        nonzero_storage = Bridge()
        storage_bytes = (ctypes.c_uint8 * ctypes.sizeof(Bridge)).from_buffer(
            nonzero_storage
        )
        storage_bytes[17] = 1
        before = bytes(nonzero_storage)
        self.assertEqual(
            self.library.cl_bridge_init(
                ctypes.byref(nonzero_storage),
                ctypes.byref(fixture.manifest),
                ctypes.byref(fixture.adapters),
            ),
            CL_ERR_STATE,
        )
        self.assertEqual(bytes(nonzero_storage), before)

        unknown_marker = Bridge()
        unknown_marker.initialization_marker = 0xDEADBEEF
        before = bytes(unknown_marker)
        self.assertEqual(
            self.library.cl_bridge_init(
                ctypes.byref(unknown_marker),
                ctypes.byref(fixture.manifest),
                ctypes.byref(fixture.adapters),
            ),
            CL_ERR_STATE,
        )
        self.assertEqual(bytes(unknown_marker), before)
        self.assertEqual(fixture.calls, [])

    def test_reinit_requires_a_prior_open_attempt(self):
        self._require_exports()
        fixture = self._fixture()
        before = bytes(fixture.bridge)

        self.assertEqual(
            self.library.cl_bridge_init(
                ctypes.byref(fixture.bridge),
                ctypes.byref(fixture.bridge.manifest),
                ctypes.byref(fixture.bridge.adapters),
            ),
            CL_ERR_STATE,
        )
        self.assertEqual(bytes(fixture.bridge), before)
        self.assertEqual(fixture.calls, [])

    def test_open_requires_the_exact_initialization_marker(self):
        self._require_exports()
        child_script = f"""
import ctypes

library = ctypes.CDLL({str(self.library_path)!r})
library.cl_bridge_size.restype = ctypes.c_size_t
library.cl_bridge_open.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
library.cl_bridge_open.restype = ctypes.c_int32
bridge = ctypes.create_string_buffer(library.cl_bridge_size())
report = ctypes.create_string_buffer(64)
ctypes.memset(report, 0x6B, 64)
before_bridge = bytes(bridge)
before_report = bytes(report)
result = library.cl_bridge_open(ctypes.byref(bridge), ctypes.byref(report))
if result != {CL_ERR_STATE}:
    raise SystemExit(f"unexpected result: {{result}}")
if bytes(bridge) != before_bridge or bytes(report) != before_report:
    raise SystemExit("uninitialized open mutated storage")
"""
        completed = subprocess.run(
            [sys.executable, "-c", child_script],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            completed.stderr or completed.stdout or "child process crashed",
        )

        fixture = self._fixture()
        fixture.bridge.initialization_marker = 0xDEADBEEF
        report = BridgeReport()
        ctypes.memset(ctypes.byref(report), 0x6B, ctypes.sizeof(report))
        before_bridge = bytes(fixture.bridge)
        before_report = bytes(report)
        self.assertEqual(
            self.library.cl_bridge_open(
                ctypes.byref(fixture.bridge), ctypes.byref(report)
            ),
            CL_ERR_STATE,
        )
        self.assertEqual(bytes(fixture.bridge), before_bridge)
        self.assertEqual(bytes(report), before_report)
        self.assertEqual(fixture.calls, [])

    def test_close_requires_the_exact_initialization_marker(self):
        self._require_exports()
        uninitialized = Bridge()
        report = BridgeReport()
        ctypes.memset(ctypes.byref(report), 0x6B, ctypes.sizeof(report))
        before_bridge = bytes(uninitialized)
        before_report = bytes(report)
        self.assertEqual(
            self.library.cl_bridge_close(
                ctypes.byref(uninitialized), ctypes.byref(report)
            ),
            CL_ERR_STATE,
        )
        self.assertEqual(bytes(uninitialized), before_bridge)
        self.assertEqual(bytes(report), before_report)

        fixture = self._fixture()
        self.assertEqual(
            self.library.cl_bridge_open(
                ctypes.byref(fixture.bridge), ctypes.byref(BridgeReport())
            ),
            CL_OK,
        )
        retained_sink = fixture.sink
        fixture.bridge.initialization_marker = 0xDEADBEEF
        report = BridgeReport()
        ctypes.memset(ctypes.byref(report), 0x6B, ctypes.sizeof(report))
        before_bridge = bytes(fixture.bridge)
        before_report = bytes(report)
        before_calls = list(fixture.calls)
        self.assertEqual(
            self.library.cl_bridge_close(
                ctypes.byref(fixture.bridge), ctypes.byref(report)
            ),
            CL_ERR_STATE,
        )
        self.assertEqual(bytes(fixture.bridge), before_bridge)
        self.assertEqual(bytes(report), before_report)
        self.assertEqual(fixture.calls, before_calls)
        self.assertIs(fixture.sink, retained_sink)
        self.assertTrue(fixture.resource_open)

        fixture.bridge.initialization_marker = CL_BRIDGE_INITIALIZATION_MARKER
        self.assertEqual(
            self.library.cl_bridge_close(
                ctypes.byref(fixture.bridge), ctypes.byref(BridgeReport())
            ),
            CL_OK,
        )

    def test_init_busy_and_live_guards_are_mutation_free(self):
        self._require_exports()
        busy_fixture = self._fixture()
        busy_fixture.bridge.busy = 1
        before = bytes(busy_fixture.bridge)
        self.assertEqual(
            self.library.cl_bridge_init(
                ctypes.byref(busy_fixture.bridge),
                ctypes.byref(busy_fixture.bridge.manifest),
                ctypes.byref(busy_fixture.bridge.adapters),
            ),
            CL_ERR_BUSY,
        )
        self.assertEqual(bytes(busy_fixture.bridge), before)
        self.assertEqual(busy_fixture.calls, [])

        live_fixture = self._fixture()
        self.assertEqual(
            self.library.cl_bridge_open(
                ctypes.byref(live_fixture.bridge),
                ctypes.byref(BridgeReport()),
            ),
            CL_OK,
        )
        retained_sink = live_fixture.sink
        before = bytes(live_fixture.bridge)
        before_calls = list(live_fixture.calls)
        self.assertEqual(
            self.library.cl_bridge_init(
                ctypes.byref(live_fixture.bridge),
                ctypes.byref(live_fixture.bridge.manifest),
                ctypes.byref(live_fixture.bridge.adapters),
            ),
            CL_ERR_ALREADY_OPEN,
        )
        self.assertEqual(bytes(live_fixture.bridge), before)
        self.assertEqual(live_fixture.calls, before_calls)
        self.assertIs(live_fixture.sink, retained_sink)
        self.assertTrue(live_fixture.resource_open)
        self.assertEqual(
            self.library.cl_bridge_close(
                ctypes.byref(live_fixture.bridge),
                ctypes.byref(BridgeReport()),
            ),
            CL_OK,
        )

    def test_closed_and_failed_admission_allow_alias_safe_reinit(self):
        self._require_exports()
        closed_fixture = self._fixture()
        self.assertEqual(
            self.library.cl_bridge_open(
                ctypes.byref(closed_fixture.bridge),
                ctypes.byref(BridgeReport()),
            ),
            CL_OK,
        )
        self.assertEqual(
            self.library.cl_bridge_close(
                ctypes.byref(closed_fixture.bridge),
                ctypes.byref(BridgeReport()),
            ),
            CL_OK,
        )
        calls_before_reinit = list(closed_fixture.calls)
        self.assertEqual(
            self.library.cl_bridge_init(
                ctypes.byref(closed_fixture.bridge),
                ctypes.byref(closed_fixture.bridge.manifest),
                ctypes.byref(closed_fixture.bridge.adapters),
            ),
            CL_OK,
        )
        self.assertEqual(closed_fixture.calls, calls_before_reinit)
        self.assertEqual(
            (
                closed_fixture.bridge.initialization_marker,
                closed_fixture.bridge.state_revision,
                closed_fixture.bridge.processing_revision,
                closed_fixture.bridge.dirty_mask,
                closed_fixture.bridge.opened,
                closed_fixture.bridge.input_attached,
                closed_fixture.bridge.opened_once,
                bytes(closed_fixture.bridge.reserved),
            ),
            (
                CL_BRIDGE_INITIALIZATION_MARKER,
                0,
                0,
                0,
                0,
                0,
                0,
                bytes(4),
            ),
        )
        self.assertEqual(
            self.library.cl_bridge_open(
                ctypes.byref(closed_fixture.bridge),
                ctypes.byref(BridgeReport()),
            ),
            CL_OK,
        )
        self.assertEqual(
            self.library.cl_bridge_close(
                ctypes.byref(closed_fixture.bridge),
                ctypes.byref(BridgeReport()),
            ),
            CL_OK,
        )

        failed_fixture = self._fixture(
            callback_results={"present": 101}
        )
        self.assertEqual(
            self.library.cl_bridge_open(
                ctypes.byref(failed_fixture.bridge),
                ctypes.byref(BridgeReport()),
            ),
            CL_ERR_ADAPTER,
        )
        self.assertFalse(failed_fixture.resource_open)
        failed_fixture.callback_results["present"] = 0
        calls_before_reinit = list(failed_fixture.calls)
        self.assertEqual(
            self.library.cl_bridge_init(
                ctypes.byref(failed_fixture.bridge),
                ctypes.byref(failed_fixture.bridge.manifest),
                ctypes.byref(failed_fixture.bridge.adapters),
            ),
            CL_OK,
        )
        self.assertEqual(failed_fixture.calls, calls_before_reinit)
        self.assertEqual(
            self.library.cl_bridge_open(
                ctypes.byref(failed_fixture.bridge),
                ctypes.byref(BridgeReport()),
            ),
            CL_OK,
        )
        self.assertEqual(
            self.library.cl_bridge_close(
                ctypes.byref(failed_fixture.bridge),
                ctypes.byref(BridgeReport()),
            ),
            CL_OK,
        )

    def test_reentrant_init_from_each_lifecycle_callback_is_busy(self):
        self._require_exports()
        for callback_name in ("load", "open", "present", "attach"):
            fixture = self._fixture(reinit_on={callback_name})
            with self.subTest(callback=callback_name):
                self.assertEqual(
                    self.library.cl_bridge_open(
                        ctypes.byref(fixture.bridge),
                        ctypes.byref(BridgeReport()),
                    ),
                    CL_OK,
                )
                self.assertEqual(
                    fixture.reinit_observations,
                    [(callback_name, CL_ERR_BUSY, True)],
                )
                self.assertEqual(
                    self.library.cl_bridge_close(
                        ctypes.byref(fixture.bridge),
                        ctypes.byref(BridgeReport()),
                    ),
                    CL_OK,
                )

        for callback_name in ("detach", "close"):
            fixture = self._fixture(reinit_on={callback_name})
            self.assertEqual(
                self.library.cl_bridge_open(
                    ctypes.byref(fixture.bridge),
                    ctypes.byref(BridgeReport()),
                ),
                CL_OK,
            )
            with self.subTest(callback=callback_name):
                self.assertEqual(
                    self.library.cl_bridge_close(
                        ctypes.byref(fixture.bridge),
                        ctypes.byref(BridgeReport()),
                    ),
                    CL_OK,
                )
                self.assertEqual(
                    fixture.reinit_observations,
                    [(callback_name, CL_ERR_BUSY, True)],
                )
                self.assertEqual(fixture._native_callback_errors, [])

    def test_callback_exceptions_keep_load_and_sink_ownership_fail_closed(self):
        self._require_exports()
        load_fixture = self._fixture(raise_on={"load"})
        load_report = BridgeReport()
        self.assertEqual(
            self.library.cl_bridge_open(
                ctypes.byref(load_fixture.bridge), ctypes.byref(load_report)
            ),
            CL_ERR_ADAPTER,
        )
        self.assertEqual(load_fixture.calls, ["load"])
        self.assertEqual(
            load_report.persistence_load_result, CL_ERR_ADAPTER
        )
        self.assertEqual(len(load_fixture._native_callback_errors), 1)
        self.assertIsNone(load_fixture.sink)
        self.assertFalse(load_fixture.resource_open)

        attach_fixture = self._fixture(raise_on={"attach"})
        attach_report = BridgeReport()
        self.assertEqual(
            self.library.cl_bridge_open(
                ctypes.byref(attach_fixture.bridge),
                ctypes.byref(attach_report),
            ),
            CL_ERR_INPUT_ATTACHMENT,
        )
        self.assertEqual(
            attach_fixture.calls,
            ["load", "open", "present", "attach", "close"],
        )
        self.assertEqual(attach_report.input_attach_result, 1)
        self.assertEqual(len(attach_fixture._native_callback_errors), 1)
        self.assertIsNone(attach_fixture.sink)
        self.assertFalse(attach_fixture.resource_open)

        detach_fixture = self._fixture(raise_on={"detach"})
        self.assertEqual(
            self.library.cl_bridge_open(
                ctypes.byref(detach_fixture.bridge),
                ctypes.byref(BridgeReport()),
            ),
            CL_OK,
        )
        detach_report = BridgeReport()
        self.assertEqual(
            self.library.cl_bridge_close(
                ctypes.byref(detach_fixture.bridge),
                ctypes.byref(detach_report),
            ),
            CL_ERR_ADAPTER,
        )
        self.assertEqual(detach_fixture.calls[-2:], ["detach", "close"])
        self.assertEqual(detach_report.input_detach_result, 1)
        self.assertEqual(len(detach_fixture._native_callback_errors), 1)
        self.assertIsNone(detach_fixture.sink)
        self.assertFalse(detach_fixture.resource_open)

    def test_init_rejects_manifest_runtime_and_each_missing_callback(self):
        self._require_exports()
        invalid_manifest = self._host_manifest()
        invalid_manifest.recovery_validated = 1
        self.assertEqual(
            self.library.cl_bridge_init(
                ctypes.byref(Bridge()),
                ctypes.byref(invalid_manifest),
                ctypes.byref(BridgeAdapters()),
            ),
            CL_ERR_MANIFEST,
        )

        for index in range(CL_BRIDGE_BINDING_COUNT):
            disabled_manifest = self._host_manifest()
            disabled_manifest.bindings[index].runtime = (
                CL_BINDING_RUNTIME_DISABLED
            )
            fixture = LifecycleFixture(self.library, disabled_manifest)
            with self.subTest(disabled_runtime=index):
                self.assertEqual(fixture.initialize(), CL_ERR_BINDING)
                self.assertEqual(fixture.calls, [])

        valid_manifest = self._host_manifest()
        self.assertEqual(
            self.library.cl_bridge_init(
                ctypes.byref(Bridge()), ctypes.byref(valid_manifest), None
            ),
            CL_ERR_BINDING,
        )

        fixture = LifecycleFixture(self.library, valid_manifest)
        null_callbacks = (
            (
                "lifecycle open",
                lambda adapters: setattr(
                    adapters.lifecycle, "open", LifecycleOpenCallback()
                ),
            ),
            (
                "lifecycle close",
                lambda adapters: setattr(
                    adapters.lifecycle, "close", LifecycleCloseCallback()
                ),
            ),
            (
                "presentation",
                lambda adapters: setattr(
                    adapters.presentation, "present", PresentCallback()
                ),
            ),
            (
                "input attach",
                lambda adapters: setattr(
                    adapters.input, "attach", InputAttachCallback()
                ),
            ),
            (
                "input detach",
                lambda adapters: setattr(
                    adapters.input, "detach", InputDetachCallback()
                ),
            ),
            (
                "persistence load",
                lambda adapters: setattr(
                    adapters.persistence, "load", StorageLoadCallback()
                ),
            ),
            (
                "persistence save",
                lambda adapters: setattr(
                    adapters.persistence, "save", StorageSaveCallback()
                ),
            ),
            (
                "model submit",
                lambda adapters: setattr(
                    adapters.model, "submit", ModelSubmitCallback()
                ),
            ),
            (
                "output apply",
                lambda adapters: setattr(
                    adapters.output, "apply", OutputApplyCallback()
                ),
            ),
        )
        for label, clear_callback in null_callbacks:
            adapters = BridgeAdapters.from_buffer_copy(fixture.adapters)
            clear_callback(adapters)
            bridge = Bridge()
            with self.subTest(callback=label):
                self.assertEqual(
                    self.library.cl_bridge_init(
                        ctypes.byref(bridge),
                        ctypes.byref(valid_manifest),
                        ctypes.byref(adapters),
                    ),
                    CL_ERR_BINDING,
                )
                self.assertEqual(fixture.calls, [])

    def test_open_and_close_have_exact_missing_and_restored_prefixes(self):
        self._require_exports()
        restored_blob, restored_state = self._encoded_blob(selected_look=3)
        cases = (
            (
                "missing", CL_STORAGE_MISSING, None,
                ["load", "open", "present", "attach", "save", "model", "live_view", "still_jpeg", "movie"],
                [0] * 6, 0x3F, None,
            ),
            (
                "restored", 0, restored_blob,
                ["load", "open", "present", "attach", "model", "live_view", "still_jpeg", "movie"],
                [0, CL_CALLBACK_NOT_ATTEMPTED, 0, 0, 0, 0], 0x3D,
                restored_state,
            ),
        )
        for label, load_result, blob, calls, expected_sync, attempted, expected_state in cases:
            fixture = self._fixture(
                load_result=load_result, load_blob=blob
            )
            report = BridgeReport()
            with self.subTest(case=label):
                self.assertEqual(
                    self.library.cl_bridge_open(
                        ctypes.byref(fixture.bridge), ctypes.byref(report)
                    ),
                    CL_OK,
                )
                self.assertEqual(
                    fixture.calls, calls
                )
                self._assert_report(
                    report,
                    lifecycle_open=0,
                    input_attach=0,
                    persistence_load=load_result,
                    sync_results=expected_sync,
                    state_revision=1,
                    processing_revision=1,
                    attempted=attempted,
                    succeeded=attempted,
                    dirty=0,
                    state_committed=1,
                    opened=1,
                )
                self.assertEqual(bytes(report), bytes(fixture.bridge.last_report))
                self.assertEqual(
                    (
                        fixture.bridge.opened,
                        fixture.bridge.input_attached,
                        fixture.bridge.opened_once,
                        fixture.bridge.busy,
                    ),
                    (1, 1, 1, 0),
                )
                self.assertEqual(
                    self.library.cl_bridge_dirty_mask(
                        ctypes.byref(fixture.bridge)
                    ),
                    0,
                )
                if expected_state is None:
                    self._assert_default_state(fixture.bridge.state)
                else:
                    self.assertEqual(
                        bytes(fixture.bridge.state), bytes(expected_state)
                    )
                snapshot = fixture.bridge.retained_processing_snapshot
                self.assertEqual(
                    (
                        snapshot.abi_version,
                        snapshot.effective_base,
                        snapshot.output_mask,
                        snapshot.processing_revision,
                        bytes(snapshot.state),
                        bytes(snapshot.reserved),
                    ),
                    (
                        1,
                        fixture.bridge.state.selected_look,
                        CL_BRIDGE_OUTPUT_MASK,
                        1,
                        bytes(fixture.bridge.state),
                        bytes(1),
                    ),
                )
                self.assertIsNotNone(fixture.sink)
                self.assertTrue(fixture.resource_open)
                self.assertEqual(
                    (len(fixture.saved_blobs), len(fixture.model_snapshots), len(fixture.output_snapshots)),
                    (1 if label == "missing" else 0, 1, 3),
                )

                close_report = BridgeReport()
                self.assertEqual(
                    self.library.cl_bridge_close(
                        ctypes.byref(fixture.bridge),
                        ctypes.byref(close_report),
                    ),
                    CL_OK,
                )
                self.assertEqual(fixture.calls[-2:], ["detach", "close"])
                self._assert_report(
                    close_report,
                    lifecycle_close=0,
                    input_detach=0,
                    state_revision=1,
                    processing_revision=1,
                    dirty=0,
                )
                self.assertEqual(
                    (fixture.bridge.opened, fixture.bridge.input_attached),
                    (0, 0),
                )
                self.assertIsNone(fixture.sink)
                self.assertFalse(fixture.resource_open)
                self.assertEqual(fixture._native_callback_errors, [])

    def test_open_failures_pin_load_decode_and_lifecycle_results(self):
        self._require_exports()
        cases = (
            (
                "load",
                {"load_result": 71},
                CL_ERR_ADAPTER,
                ["load"],
                {"persistence_load": 71},
            ),
            (
                "decode",
                {"load_result": 0, "load_blob": bytes(164)},
                CL_ERR_BLOB,
                ["load"],
                {"transition": CL_ERR_BLOB, "persistence_load": 0},
            ),
            (
                "lifecycle",
                {"callback_results": {"open": 72}},
                CL_ERR_LIFECYCLE,
                ["load", "open"],
                {"lifecycle_open": 72, "persistence_load": 1},
            ),
        )
        for label, arguments, expected_result, calls, report_fields in cases:
            fixture = self._fixture(**arguments)
            report = BridgeReport()
            with self.subTest(case=label):
                self.assertEqual(
                    self.library.cl_bridge_open(
                        ctypes.byref(fixture.bridge), ctypes.byref(report)
                    ),
                    expected_result,
                )
                self.assertEqual(fixture.calls, calls)
                self._assert_report(report, **report_fields)
                self.assertEqual(
                    (
                        fixture.bridge.state_revision,
                        fixture.bridge.processing_revision,
                        fixture.bridge.dirty_mask,
                        fixture.bridge.opened,
                        fixture.bridge.input_attached,
                        fixture.bridge.opened_once,
                    ),
                    (0, 0, 0, 0, 0, 1),
                )
                self.assertFalse(fixture.resource_open)
                before_report = bytes(report)
                before_calls = list(fixture.calls)
                self.assertEqual(
                    self.library.cl_bridge_open(
                        ctypes.byref(fixture.bridge), ctypes.byref(report)
                    ),
                    CL_ERR_REINIT_REQUIRED,
                )
                self.assertEqual(bytes(report), before_report)
                self.assertEqual(fixture.calls, before_calls)

    def test_admission_cleanup_order_and_error_precedence_are_exact(self):
        self._require_exports()
        cases = (
            (
                "present",
                {"present": 81},
                CL_ERR_ADAPTER,
                ["load", "open", "present", "close"],
                {"presentation": 81, "attach": CL_CALLBACK_NOT_ATTEMPTED},
            ),
            (
                "present cleanup",
                {"present": 82, "close": 83},
                CL_ERR_LIFECYCLE,
                ["load", "open", "present", "close"],
                {"presentation": 82, "attach": CL_CALLBACK_NOT_ATTEMPTED},
            ),
            (
                "attach",
                {"attach": 84},
                CL_ERR_INPUT_ATTACHMENT,
                ["load", "open", "present", "attach", "close"],
                {"presentation": 0, "attach": 84},
            ),
            (
                "attach cleanup",
                {"attach": 85, "close": 86},
                CL_ERR_LIFECYCLE,
                ["load", "open", "present", "attach", "close"],
                {"presentation": 0, "attach": 85},
            ),
        )
        for label, callback_results, expected_result, calls, raw in cases:
            fixture = self._fixture(callback_results=callback_results)
            report = BridgeReport()
            with self.subTest(case=label):
                self.assertEqual(
                    self.library.cl_bridge_open(
                        ctypes.byref(fixture.bridge), ctypes.byref(report)
                    ),
                    expected_result,
                )
                self.assertEqual(fixture.calls, calls)
                expected_sync = [raw["presentation"]] + [
                    CL_CALLBACK_NOT_ATTEMPTED
                ] * 5
                self._assert_report(
                    report,
                    lifecycle_open=0,
                    lifecycle_close=callback_results.get("close", 0),
                    input_attach=raw["attach"],
                    persistence_load=1,
                    sync_results=expected_sync,
                    state_revision=1,
                    processing_revision=1,
                    attempted=1,
                    succeeded=1 if raw["presentation"] == 0 else 0,
                    failed=0 if raw["presentation"] == 0 else 1,
                    state_committed=1,
                )
                self.assertEqual(
                    (
                        fixture.bridge.dirty_mask,
                        fixture.bridge.opened,
                        fixture.bridge.input_attached,
                        fixture.bridge.opened_once,
                    ),
                    (0, 0, 0, 1),
                )
                self.assertNotIn("detach", fixture.calls)
                self.assertIsNone(fixture.sink)
                self.assertFalse(fixture.resource_open)

    def test_close_attempts_both_callbacks_and_pins_error_precedence(self):
        self._require_exports()
        cases = (
            ("detach", {"detach": 91}, CL_ERR_ADAPTER),
            ("close", {"close": 92}, CL_ERR_LIFECYCLE),
            (
                "both",
                {"detach": 93, "close": 94},
                CL_ERR_LIFECYCLE,
            ),
        )
        for label, callback_results, expected_result in cases:
            fixture = self._fixture(callback_results=callback_results)
            open_report = BridgeReport()
            self.assertEqual(
                self.library.cl_bridge_open(
                    ctypes.byref(fixture.bridge), ctypes.byref(open_report)
                ),
                CL_OK,
            )
            close_report = BridgeReport()
            with self.subTest(case=label):
                self.assertEqual(
                    self.library.cl_bridge_close(
                        ctypes.byref(fixture.bridge),
                        ctypes.byref(close_report),
                    ),
                    expected_result,
                )
                self.assertEqual(fixture.calls[-2:], ["detach", "close"])
                self._assert_report(
                    close_report,
                    lifecycle_close=callback_results.get("close", 0),
                    input_detach=callback_results.get("detach", 0),
                    state_revision=1,
                    processing_revision=1,
                    dirty=0,
                )
                self.assertEqual(
                    (
                        fixture.bridge.opened,
                        fixture.bridge.input_attached,
                        fixture.bridge.dirty_mask,
                    ),
                    (0, 0, 0),
                )
                self.assertIsNone(fixture.sink)
                self.assertFalse(fixture.resource_open)

    def test_lifecycle_misuse_does_not_mutate_reports_or_call_adapters(self):
        self._require_exports()
        fixture = self._fixture()
        report = BridgeReport()
        ctypes.memset(ctypes.byref(report), 0x4C, ctypes.sizeof(report))
        sentinel = bytes(report)
        initial_last_report = bytes(fixture.bridge.last_report)

        self.assertEqual(
            self.library.cl_bridge_close(
                ctypes.byref(fixture.bridge), ctypes.byref(report)
            ),
            CL_ERR_NOT_OPEN,
        )
        self.assertEqual(bytes(report), sentinel)
        self.assertEqual(bytes(fixture.bridge.last_report), initial_last_report)
        self.assertEqual(fixture.calls, [])

        open_report = BridgeReport()
        self.assertEqual(
            self.library.cl_bridge_open(
                ctypes.byref(fixture.bridge), ctypes.byref(open_report)
            ),
            CL_OK,
        )
        calls_after_open = list(fixture.calls)
        self.assertEqual(
            self.library.cl_bridge_open(
                ctypes.byref(fixture.bridge), ctypes.byref(report)
            ),
            CL_ERR_ALREADY_OPEN,
        )
        self.assertEqual(bytes(report), sentinel)
        self.assertEqual(fixture.calls, calls_after_open)

        close_report = BridgeReport()
        self.assertEqual(
            self.library.cl_bridge_close(
                ctypes.byref(fixture.bridge), ctypes.byref(close_report)
            ),
            CL_OK,
        )
        calls_after_close = list(fixture.calls)
        last_after_close = bytes(fixture.bridge.last_report)
        self.assertEqual(
            self.library.cl_bridge_open(
                ctypes.byref(fixture.bridge), ctypes.byref(report)
            ),
            CL_ERR_REINIT_REQUIRED,
        )
        self.assertEqual(bytes(report), sentinel)
        self.assertEqual(bytes(fixture.bridge.last_report), last_after_close)
        self.assertEqual(fixture.calls, calls_after_close)

    def test_callback_reentry_is_busy_and_mutation_free(self):
        self._require_exports()
        for callback_name in ("load", "open", "present", "attach"):
            fixture = self._fixture(reenter_on={callback_name})
            report = BridgeReport()
            with self.subTest(callback=callback_name):
                self.assertEqual(
                    self.library.cl_bridge_open(
                        ctypes.byref(fixture.bridge), ctypes.byref(report)
                    ),
                    CL_OK,
                )
                self.assertEqual(len(fixture.reentry_observations), 1)
                name, result, unchanged, nested_report = (
                    fixture.reentry_observations[0]
                )
                self.assertEqual((name, result, unchanged), (callback_name, CL_ERR_BUSY, True))
                self.assertEqual(nested_report, bytes([0x5A] * 64))
                self.assertEqual(
                    fixture.calls,
                    ["load", "open", "present", "attach", "save", "model", "live_view", "still_jpeg", "movie"],
                )

        for callback_name in ("detach", "close"):
            fixture = self._fixture(reenter_on={callback_name})
            self.assertEqual(
                self.library.cl_bridge_open(
                    ctypes.byref(fixture.bridge), ctypes.byref(BridgeReport())
                ),
                CL_OK,
            )
            with self.subTest(callback=callback_name):
                self.assertEqual(
                    self.library.cl_bridge_close(
                        ctypes.byref(fixture.bridge),
                        ctypes.byref(BridgeReport()),
                    ),
                    CL_OK,
                )
                self.assertEqual(len(fixture.reentry_observations), 1)
                name, result, unchanged, nested_report = (
                    fixture.reentry_observations[0]
                )
                self.assertEqual((name, result, unchanged), (callback_name, CL_ERR_BUSY, True))
                self.assertEqual(nested_report, bytes([0x5A] * 64))
                self.assertEqual(fixture.calls[-2:], ["detach", "close"])
                self.assertEqual(fixture._native_callback_errors, [])

    def test_input_delivery_during_attach_and_detach_is_busy(self):
        self._require_exports()
        fixture = self._fixture(deliver_on={"attach", "detach"})
        self.assertEqual(
            self.library.cl_bridge_open(
                ctypes.byref(fixture.bridge), ctypes.byref(BridgeReport())
            ),
            CL_OK,
        )
        self.assertIsNotNone(fixture.sink)
        self.assertEqual(fixture.delivery_observations, [("attach", CL_ERR_BUSY, True)])
        self.assertEqual(
            self.library.cl_bridge_close(
                ctypes.byref(fixture.bridge), ctypes.byref(BridgeReport())
            ),
            CL_OK,
        )
        self.assertEqual(
            fixture.delivery_observations,
            [
                ("attach", CL_ERR_BUSY, True),
                ("detach", CL_ERR_BUSY, True),
            ],
        )
        self.assertIsNone(fixture.sink)
        self.assertEqual(fixture._native_callback_errors, [])

    def test_bridge_contract_exports_are_present(self):
        self.assertEqual(self.missing_exports, [])

    def test_undefined_symbol_gate_catches_real_unresolved_symbols(self):
        directory = Path(self._temporary.name)
        for index, symbol in enumerate(
            ("_pei386_runtime_relocator", "cl_deliberately_unresolved")
        ):
            source = directory / f"unresolved-{index}.c"
            source.write_text(
                f"extern void {symbol}(void);\n"
                f"void cl_call_unresolved_{index}(void) {{ {symbol}(); }}\n",
                encoding="utf-8",
            )
            object_path = compile_freestanding_objects(directory, [source])[0]
            combined = link_relocatable(
                directory, f"unresolved-{index}", [object_path]
            )
            with self.subTest(symbol=symbol):
                with self.assertRaisesRegex(
                    AssertionError, "has undefined symbols"
                ) as caught:
                    assert_no_undefined_symbols(combined, "mutation object")
                self.assertIn(symbol, str(caught.exception))

    def test_undefined_symbol_gate_fails_when_nm_is_unavailable(self):
        with mock.patch(
            "tests.analysis.creative_look_native_abi.shutil.which",
            return_value=None,
        ):
            with self.assertRaisesRegex(
                AssertionError, "nm is required"
            ):
                assert_no_undefined_symbols(
                    self.combined_object, "native core/view/bridge"
                )

    def test_compiler_linker_rejects_bare_relative_and_missing_paths(self):
        reported_paths = (
            "ld\n",
            "toolchain/ld.exe\n",
            f"{Path(self._temporary.name) / 'missing-ld.exe'}\n",
        )
        for reported_path in reported_paths:
            completed = mock.Mock(stdout=reported_path)
            with self.subTest(reported_path=reported_path.strip()):
                with mock.patch(
                    "tests.analysis.creative_look_native_abi._run_checked",
                    return_value=completed,
                ):
                    with self.assertRaisesRegex(
                        AssertionError,
                        "absolute existing executable",
                    ):
                        compiler_linker()

    def test_compiler_linker_is_an_absolute_existing_file(self):
        linker = Path(compiler_linker())
        self.assertTrue(linker.is_absolute())
        self.assertTrue(linker.is_file())

    def test_bridge_source_is_offline_and_has_one_direct_dependency(self):
        source = BRIDGE_C.read_text(encoding="utf-8")
        self.assertEqual(
            [line for line in source.splitlines() if line.startswith("#include")],
            ['#include "creative_look_bridge.h"'],
        )
        for forbidden in (
            "malloc(",
            "calloc(",
            "realloc(",
            "free(",
            "fopen(",
            "socket(",
            "dlopen(",
            "LoadLibrary",
            "CreateFile",
            "CreateThread",
            "_beginthread",
            "pthread_",
            "libusb",
            "updater",
            "firmware_package",
            "partition_write",
            "Backup_",
            "ILCE-",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
