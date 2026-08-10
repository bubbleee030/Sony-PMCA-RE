import ctypes
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
CL_ERR_BLOB = -8
CL_ERR_ADAPTER = -10
CL_ERR_MANIFEST = -11
CL_ERR_BINDING = -12
CL_ERR_LIFECYCLE = -13
CL_ERR_NOT_OPEN = -14
CL_ERR_ALREADY_OPEN = -15
CL_ERR_INPUT_ATTACHMENT = -17
CL_ERR_REINIT_REQUIRED = -18
CL_ERR_BUSY = -19
CL_BRIDGE_ABI_VERSION = 1
CL_BRIDGE_BINDING_COUNT = 6
CL_BRIDGE_OUTPUT_MASK = 7
CL_STORAGE_MISSING = 1
CL_CALLBACK_NOT_ATTEMPTED = -(1 << 31)
CL_EXECUTION_PROFILE_OFFLINE_HOST = 0
CL_BINDING_EVIDENCE_UNBOUND = 0
CL_BINDING_EVIDENCE_STATIC_CANDIDATE = 1
CL_BINDING_EVIDENCE_STATIC_PROVEN = 2
CL_BINDING_RUNTIME_DISABLED = 0
CL_BINDING_RUNTIME_HOST_SIMULATED = 1


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
        ("state", NativeState),
        ("dirty_mask", ctypes.c_uint8),
        ("opened", ctypes.c_uint8),
        ("input_attached", ctypes.c_uint8),
        ("busy", ctypes.c_uint8),
        ("opened_once", ctypes.c_uint8),
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
        deliver_on=None,
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
        self.deliver_on = set(deliver_on or ())
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
        self.delivery_observations = []
        self.bridge = Bridge()

        def load(_context, data, size):
            self.calls.append("load")
            self._maybe_reenter("load")
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
            return self.callback_results["save"]

        def lifecycle_open(_context, state_pointer):
            self.calls.append("open")
            self.opened_states.append(
                NativeState.from_buffer_copy(state_pointer.contents)
            )
            self.resource_open = self.callback_results["open"] == 0
            self._maybe_reenter("open")
            return self.callback_results["open"]

        def lifecycle_close(_context):
            self.calls.append("close")
            self.resource_open = False
            self._maybe_reenter("close")
            return self.callback_results["close"]

        def present(_context, frame_pointer):
            self.calls.append("present")
            self.presented_frames.append(
                NativeFrame.from_buffer_copy(frame_pointer.contents)
            )
            self._maybe_reenter("present")
            return self.callback_results["present"]

        def attach(_context, sink, sink_context):
            self.calls.append("attach")
            self.sink = sink
            self.sink_context = sink_context
            self._maybe_deliver("attach")
            self._maybe_reenter("attach")
            result = self.callback_results["attach"]
            if result != 0:
                self.sink = None
                self.sink_context = None
            return result

        def detach(_context):
            self.calls.append("detach")
            self._maybe_deliver("detach")
            self._maybe_reenter("detach")
            self.sink = None
            self.sink_context = None
            return self.callback_results["detach"]

        def submit(_context, snapshot_pointer):
            self.calls.append("model")
            self.model_snapshots.append(
                ProcessingSnapshot.from_buffer_copy(snapshot_pointer.contents)
            )
            self._maybe_reenter("model")
            return self.callback_results["model"]

        def apply(_context, kind, snapshot_pointer):
            self.calls.append("output")
            self.output_snapshots.append(
                (
                    kind,
                    ProcessingSnapshot.from_buffer_copy(
                        snapshot_pointer.contents
                    ),
                )
            )
            self._maybe_reenter("output")
            return self.callback_results["output"]

        self.load_callback = retain_callback(
            self, StorageLoadCallback, load
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
        fixture = self._fixture()

        self.assertEqual(Bridge.adapters.offset, 624)
        self.assertEqual(self.library.cl_bridge_adapters_offset(), 624)
        self.assertEqual(self.library.cl_bridge_size(), ctypes.sizeof(Bridge))
        self.assertEqual(
            self.library.cl_bridge_alignment(), ctypes.alignment(Bridge)
        )
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
            ),
            (0, 0, 0, 0, 0, 0, 0),
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
            ("missing", CL_STORAGE_MISSING, None, 0x3E, None),
            ("restored", 0, restored_blob, 0x3C, restored_state),
        )
        for label, load_result, blob, dirty, expected_state in cases:
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
                    fixture.calls, ["load", "open", "present", "attach"]
                )
                expected_sync = [0] + [CL_CALLBACK_NOT_ATTEMPTED] * 5
                self._assert_report(
                    report,
                    lifecycle_open=0,
                    input_attach=0,
                    persistence_load=load_result,
                    sync_results=expected_sync,
                    state_revision=1,
                    processing_revision=1,
                    attempted=1,
                    succeeded=1,
                    dirty=dirty,
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
                    dirty,
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
                    (fixture.saved_blobs, fixture.model_snapshots, fixture.output_snapshots),
                    ([], [], []),
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
                    dirty=dirty,
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
                    dirty=0x3E,
                )
                self.assertEqual(
                    (
                        fixture.bridge.opened,
                        fixture.bridge.input_attached,
                        fixture.bridge.dirty_mask,
                    ),
                    (0, 0, 0x3E),
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
                    fixture.calls, ["load", "open", "present", "attach"]
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
