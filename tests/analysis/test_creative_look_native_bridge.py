import ctypes
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.analysis.creative_look_native_abi import (
    CORE_SOURCE,
    VIEW_SOURCE,
    NativeState,
    assert_no_undefined_symbols,
    compile_freestanding_objects,
    compile_shared_library,
    compiler_linker,
    link_relocatable,
    unload_library,
)


NATIVE = CORE_SOURCE.parent
BRIDGE_H = NATIVE / "creative_look_bridge.h"
BRIDGE_C = NATIVE / "creative_look_bridge.c"

CL_OK = 0
CL_ERR_MANIFEST = -11
CL_BRIDGE_ABI_VERSION = 1
CL_BRIDGE_BINDING_COUNT = 6
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
        cls.bridge_exports = (
            "cl_binding_record_size",
            "cl_integration_manifest_size",
            "cl_input_event_size",
            "cl_processing_snapshot_size",
            "cl_bridge_report_size",
            "cl_bridge_manifest_host",
            "cl_bridge_validate_manifest",
        )
        cls.missing_exports = [
            name for name in cls.bridge_exports if not hasattr(cls.library, name)
        ]
        if cls.missing_exports:
            return
        for name in cls.bridge_exports[:5]:
            function = getattr(cls.library, name)
            function.argtypes = []
            function.restype = ctypes.c_size_t
        cls.library.cl_bridge_manifest_host.argtypes = [
            ctypes.POINTER(IntegrationManifest)
        ]
        cls.library.cl_bridge_manifest_host.restype = ctypes.c_int
        cls.library.cl_bridge_validate_manifest.argtypes = [
            ctypes.POINTER(IntegrationManifest)
        ]
        cls.library.cl_bridge_validate_manifest.restype = ctypes.c_int

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
            "libusb",
            "firmware_package",
            "partition_write",
            "Backup_",
            "ILCE-",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
