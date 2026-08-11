"""Fail-closed tests for the Creative Look ARM target/toolchain profile."""
from __future__ import annotations

import copy
import ctypes
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest import mock

from tests.analysis import creative_look_native_abi as native_abi
from tests.analysis import test_creative_look_native_bridge as bridge_abi


ROOT = Path(__file__).resolve().parents[2]
PROFILE_PATH = ROOT / "analysis" / "a6400-creative-look-arm-target-profile.json"
MODULE_PATH = ROOT / "pmca" / "analysis" / "creative_look_arm_target_profile.py"
EXPORTER_PATH = ROOT / "tools" / "static" / "export_a6400_creative_look_arm_target.py"
TOOLCHAIN_ROOT = ROOT / ".artifacts" / "toolchains" / "15.2.rel1-extracted"
NATIVE_ROOT = ROOT / "native" / "a6400_creative_look"
TARGET_HEADER = NATIVE_ROOT / "creative_look_target.h"
TARGET_SOURCE = NATIVE_ROOT / "creative_look_target.c"

PRODUCTION_SOURCES = tuple(
    NATIVE_ROOT / name
    for name in (
        "creative_look_core.c",
        "creative_look_view.c",
        "creative_look_bridge.c",
    )
)
PUBLIC_HEADERS = tuple(
    NATIVE_ROOT / name
    for name in (
        "creative_look_core.h",
        "creative_look_view.h",
        "creative_look_bridge.h",
    )
)
ABI_LAYOUTS = {
    "cl_state": {"size": 155, "alignment": 1},
    "cl_binding_record": {"size": 36, "alignment": 1},
    "cl_integration_manifest": {"size": 228, "alignment": 2},
    "cl_processing_snapshot": {"size": 164, "alignment": 4},
    "cl_bridge_report": {"size": 64, "alignment": 4},
    "cl_bridge_adapters": {"size": 60, "alignment": 4},
    "cl_bridge": {"size": 692, "alignment": 4},
    "cl_bridge.adapters": {"offset": 632},
}

TARGET_SHA256 = "1e2867b6bff2d4fd4d3b93bacf8c7da0b9a86f266b4ba1763230e33badb6e7f2"
ARCHIVE_SHA256 = "7936cac895611023ffb22a64b8e426098c7104cb689778c1894572ca840b9ece"
ARCHIVE_BASENAME = (
    "arm-gnu-toolchain-15.2.rel1-mingw-w64-x86_64-arm-none-eabi.zip"
)
ARCHIVE_URL = (
    "https://gitlab.arm.com/api/v4/projects/tooling%2Fgnu-toolchains-for-arm/"
    "packages/generic/gnu-toolchain/15.2.rel1/" + ARCHIVE_BASENAME
)
CHECKSUM_URL = ARCHIVE_URL + ".sha256asc"
RELEASE_URL = (
    "https://gitlab.arm.com/tooling/gnu-toolchains-for-arm/-/blob/"
    "releases/15.2.rel1/README.md"
)
COMPILE_FLAGS = [
    "-std=c99",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-pedantic",
    "-ffreestanding",
    "-fno-builtin",
    "-fPIC",
    "-O2",
    "-finline-stringops=memcpy",
    "-march=armv7-a",
    "-mthumb",
    "-mfpu=vfpv3-d16",
    "-mfloat-abi=softfp",
    "-mabi=aapcs-linux",
    "-fno-unwind-tables",
    "-fno-asynchronous-unwind-tables",
]
TARGET_ATTRIBUTES = [
    {"tag": 6, "name": "Tag_CPU_arch", "value": "v7"},
    {"tag": 7, "name": "Tag_CPU_arch_profile", "value": "Application"},
    {"tag": 8, "name": "Tag_ARM_ISA_use", "value": "Yes"},
    {"tag": 9, "name": "Tag_THUMB_ISA_use", "value": "Thumb-2"},
    {"tag": 10, "name": "Tag_FP_arch", "value": "VFPv3-D16"},
    {"tag": 18, "name": "Tag_ABI_PCS_wchar_t", "value": 4},
    {"tag": 24, "name": "Tag_ABI_align_needed", "value": 8},
    {"tag": 26, "name": "Tag_ABI_enum_size", "value": 4},
]
PROHIBITED_ATTRIBUTES = [
    {"tag": 28, "name": "Tag_ABI_VFP_args", "presence": "forbidden"}
]
SAFETY_FIELDS = (
    "processing_binding_proven",
    "recovery_validated",
    "camera_test_eligible",
    "installable",
)

TARGET_SHELL_INITIALIZATION_MARKER = 0x434C5431
TARGET_PUBLICATION_PROPOSED_UNPUBLISHED = 0
TARGET_SHELL_ARM_LAYOUT = {
    "size": 1200,
    "alignment": 4,
    "bridge_offset": 0,
    "copied_frame_offset": 692,
    "retained_sink_offset": 1184,
    "retained_sink_context_offset": 1188,
    "initialization_marker_offset": 1192,
    "frame_valid_offset": 1196,
    "delivering_offset": 1197,
}
TARGET_IDENTITY_ARM_LAYOUT = {
    "size": 16,
    "alignment": 4,
    "publication_status_offset": 12,
}


class TargetIdentity(ctypes.Structure):
    _fields_ = [
        ("logical_alias", ctypes.c_char_p),
        ("component_label", ctypes.c_char_p),
        ("proposed_factory_label", ctypes.c_char_p),
        ("publication_status", ctypes.c_uint32),
    ]


class TargetShell(ctypes.Structure):
    _fields_ = [
        ("bridge", bridge_abi.Bridge),
        ("copied_frame", native_abi.NativeFrame),
        ("retained_sink", bridge_abi.InputSinkCallback),
        ("retained_sink_context", ctypes.c_void_p),
        ("initialization_marker", ctypes.c_uint32),
        ("frame_valid", ctypes.c_uint8),
        ("delivering", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 2),
    ]


def configure_target_exports(library):
    shell_pointer = ctypes.POINTER(TargetShell)
    manifest_pointer = ctypes.POINTER(bridge_abi.IntegrationManifest)
    adapters_pointer = ctypes.POINTER(bridge_abi.BridgeAdapters)
    report_pointer = ctypes.POINTER(bridge_abi.BridgeReport)
    event_pointer = ctypes.POINTER(bridge_abi.InputEvent)

    library.cl_bridge_manifest_host.argtypes = [manifest_pointer]
    library.cl_bridge_manifest_host.restype = ctypes.c_int
    library.cl_target_shell_size.argtypes = []
    library.cl_target_shell_size.restype = ctypes.c_size_t
    library.cl_target_shell_alignment.argtypes = []
    library.cl_target_shell_alignment.restype = ctypes.c_size_t
    library.cl_target_shell_init.argtypes = [
        shell_pointer,
        manifest_pointer,
        adapters_pointer,
    ]
    library.cl_target_shell_init.restype = ctypes.c_int
    library.cl_target_shell_open.argtypes = [shell_pointer, report_pointer]
    library.cl_target_shell_open.restype = ctypes.c_int
    library.cl_target_shell_close.argtypes = [shell_pointer, report_pointer]
    library.cl_target_shell_close.restype = ctypes.c_int
    library.cl_target_shell_deliver.argtypes = [
        shell_pointer,
        event_pointer,
        report_pointer,
    ]
    library.cl_target_shell_deliver.restype = ctypes.c_int
    library.cl_target_shell_copied_frame.argtypes = [shell_pointer]
    library.cl_target_shell_copied_frame.restype = ctypes.POINTER(
        native_abi.NativeFrame
    )
    library.cl_target_shell_bridge_state.argtypes = [shell_pointer]
    library.cl_target_shell_bridge_state.restype = ctypes.POINTER(
        native_abi.NativeState
    )
    library.cl_target_shell_last_report.argtypes = [shell_pointer]
    library.cl_target_shell_last_report.restype = ctypes.POINTER(
        bridge_abi.BridgeReport
    )
    library.cl_target_shell_identity.argtypes = []
    library.cl_target_shell_identity.restype = ctypes.POINTER(TargetIdentity)


class TargetShellFixture:
    """Caller-owned persistence/model/output adapters around the real shell."""

    def __init__(
        self,
        library,
        *,
        load_result=bridge_abi.CL_STORAGE_MISSING,
        callback_results=None,
        reenter_deliver_on=(),
        reenter_close_on=(),
    ):
        self.library = library
        self.shell = TargetShell()
        self.manifest = bridge_abi.IntegrationManifest()
        result = library.cl_bridge_manifest_host(ctypes.byref(self.manifest))
        if result != bridge_abi.CL_OK:
            raise AssertionError(f"host manifest failed: {result}")
        self.load_result = load_result
        self.callback_results = {
            "save": 0,
            "model": 0,
            "live_view": 0,
            "still_jpeg": 0,
            "movie": 0,
            **(callback_results or {}),
        }
        self.reenter_deliver_on = set(reenter_deliver_on)
        self.reenter_close_on = set(reenter_close_on)
        self.calls = []
        self.saved_blobs = []
        self.model_snapshots = []
        self.output_snapshots = []
        self.reentry = []
        self.contexts = {
            "persistence": 0x11112222,
            "model": 0x33334444,
            "output": 0x55556666,
        }

        def maybe_reenter(callback_name):
            if callback_name in self.reenter_deliver_on:
                frame_pointer = library.cl_target_shell_copied_frame(
                    ctypes.byref(self.shell)
                )
                if frame_pointer:
                    element = frame_pointer.contents.elements[0]
                    event = bridge_abi.InputEvent(
                        element.x + 1,
                        element.y + 1,
                        bridge_abi.CL_INPUT_TOUCH,
                        0,
                        (ctypes.c_uint8 * 2)(0, 0),
                    )
                else:
                    event = bridge_abi.InputEvent(
                        0,
                        0,
                        bridge_abi.CL_INPUT_ORIENTATION,
                        0,
                        (ctypes.c_uint8 * 2)(0, 0),
                    )
                report = bridge_abi.BridgeReport()
                ctypes.memset(ctypes.byref(report), 0x6D, ctypes.sizeof(report))
                before = (bytes(self.shell), bytes(report))
                nested = library.cl_target_shell_deliver(
                    ctypes.byref(self.shell), ctypes.byref(event), ctypes.byref(report)
                )
                self.reentry.append(
                    (callback_name, "deliver", nested, before == (bytes(self.shell), bytes(report)))
                )
            if callback_name in self.reenter_close_on:
                report = bridge_abi.BridgeReport()
                ctypes.memset(ctypes.byref(report), 0x5C, ctypes.sizeof(report))
                before = (bytes(self.shell), bytes(report))
                nested = library.cl_target_shell_close(
                    ctypes.byref(self.shell), ctypes.byref(report)
                )
                self.reentry.append(
                    (callback_name, "close", nested, before == (bytes(self.shell), bytes(report)))
                )

        def load(context, _data, _size):
            self.calls.append("load")
            if context != self.contexts["persistence"]:
                return 91
            maybe_reenter("load")
            return self.load_result

        def save(context, data, size):
            self.calls.append("save")
            if context != self.contexts["persistence"]:
                return 92
            self.saved_blobs.append(ctypes.string_at(data, size))
            maybe_reenter("save")
            return self.callback_results["save"]

        def model(context, snapshot_pointer):
            self.calls.append("model")
            if context != self.contexts["model"]:
                return 93
            self.model_snapshots.append(
                bridge_abi.ProcessingSnapshot.from_buffer_copy(
                    snapshot_pointer.contents
                )
            )
            maybe_reenter("model")
            return self.callback_results["model"]

        def output(context, kind, snapshot_pointer):
            names = ("live_view", "still_jpeg", "movie")
            name = names[kind]
            self.calls.append(name)
            if context != self.contexts["output"]:
                return 94
            self.output_snapshots.append(
                (
                    kind,
                    bridge_abi.ProcessingSnapshot.from_buffer_copy(
                        snapshot_pointer.contents
                    ),
                )
            )
            maybe_reenter(name)
            return self.callback_results[name]

        self.load_callback = native_abi.retain_callback(
            self,
            native_abi.StorageLoadCallback,
            load,
            exception_result=bridge_abi.CL_ERR_ADAPTER,
        )
        self.save_callback = native_abi.retain_callback(
            self,
            native_abi.StorageSaveCallback,
            save,
            exception_result=bridge_abi.CL_ERR_ADAPTER,
        )
        self.model_callback = native_abi.retain_callback(
            self,
            bridge_abi.ModelSubmitCallback,
            model,
            exception_result=bridge_abi.CL_ERR_ADAPTER,
        )
        self.output_callback = native_abi.retain_callback(
            self,
            bridge_abi.OutputApplyCallback,
            output,
            exception_result=bridge_abi.CL_ERR_ADAPTER,
        )
        self.adapters = bridge_abi.BridgeAdapters()
        self.adapters.persistence.context = self.contexts["persistence"]
        self.adapters.persistence.load = self.load_callback
        self.adapters.persistence.save = self.save_callback
        self.adapters.model.context = self.contexts["model"]
        self.adapters.model.submit = self.model_callback
        self.adapters.output.context = self.contexts["output"]
        self.adapters.output.apply = self.output_callback

    def initialize(self, manifest=None, adapters=None):
        return self.library.cl_target_shell_init(
            ctypes.byref(self.shell),
            ctypes.byref(self.manifest) if manifest is None else manifest,
            ctypes.byref(self.adapters) if adapters is None else adapters,
        )

    def open(self):
        report = bridge_abi.BridgeReport()
        result = self.library.cl_target_shell_open(
            ctypes.byref(self.shell), ctypes.byref(report)
        )
        return result, report

    def close(self):
        report = bridge_abi.BridgeReport()
        result = self.library.cl_target_shell_close(
            ctypes.byref(self.shell), ctypes.byref(report)
        )
        return result, report

    def deliver(self, event, report=None):
        if report is None:
            report = bridge_abi.BridgeReport()
        result = self.library.cl_target_shell_deliver(
            ctypes.byref(self.shell), ctypes.byref(event), ctypes.byref(report)
        )
        return result, report


class CreativeLookArmTargetProfileTests(unittest.TestCase):
    def _module(self):
        spec = importlib.util.spec_from_file_location(
            "creative_look_arm_target_profile", MODULE_PATH
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def _document(self):
        return json.loads(PROFILE_PATH.read_text(encoding="utf-8"))

    def _assert_rejected(self, mutate):
        module = self._module()
        candidate = copy.deepcopy(self._document())
        mutate(candidate)
        contract = copy.deepcopy(candidate)
        contract.pop("contract_sha256", None)
        candidate["contract_sha256"] = hashlib.sha256(
            (json.dumps(contract, sort_keys=True, separators=(",", ":")) + "\n").encode(
                "utf-8"
            )
        ).hexdigest()
        with self.assertRaises(module.CreativeLookArmTargetProfileError):
            module.validate_creative_look_arm_target_profile(candidate)

    def _assert_rejected_without_digest_refresh(self, mutate):
        module = self._module()
        candidate = copy.deepcopy(self._document())
        mutate(candidate)
        with self.assertRaises(module.CreativeLookArmTargetProfileError):
            module.validate_creative_look_arm_target_profile(candidate)

    def test_profile_files_exist_and_real_validator_accepts_exact_contract(self):
        """Break caught: the pinned profile or its real validator is absent/drifts."""
        self.assertTrue(PROFILE_PATH.is_file(), str(PROFILE_PATH))
        self.assertTrue(MODULE_PATH.is_file(), str(MODULE_PATH))
        self.assertTrue(Path(__file__).is_file(), str(Path(__file__)))

        module = self._module()
        document = self._document()
        validated = module.validate_creative_look_arm_target_profile(document)
        self.assertEqual(validated, document)
        self.assertEqual(
            module.load_creative_look_arm_target_profile(PROFILE_PATH), document
        )

        target = validated["target"]
        self.assertEqual(
            (target["module"], target["sha256"]),
            ("lib/viewUnified2.so", TARGET_SHA256),
        )
        self.assertEqual(
            target["elf"],
            {
                "class": "ELF32",
                "data": "little-endian",
                "machine": "ARM",
                "eabi_version": 5,
            },
        )
        self.assertIn("attribute_policy", target)
        self.assertEqual(
            target["attribute_policy"],
            {
                "mandatory": TARGET_ATTRIBUTES,
                "prohibited": PROHIBITED_ATTRIBUTES,
                "extra_attributes": "record-and-permit",
            },
        )
        self.assertEqual(
            target["float_call_abi"],
            {
                "kind": "softfp",
                "hard_float_tag": 28,
                "hard_float_tag_present": False,
            },
        )

        toolchain = validated["toolchain"]
        self.assertEqual(toolchain["archive_basename"], ARCHIVE_BASENAME)
        self.assertEqual(toolchain["release_url"], RELEASE_URL)
        self.assertEqual(toolchain["archive_url"], ARCHIVE_URL)
        self.assertEqual(toolchain["checksum_url"], CHECKSUM_URL)
        self.assertEqual(toolchain["archive_sha256"], ARCHIVE_SHA256)
        self.assertEqual(
            toolchain["checksum_record"],
            ARCHIVE_SHA256 + " *" + ARCHIVE_BASENAME,
        )
        self.assertEqual(toolchain["target_triple"], "arm-none-eabi")
        self.assertEqual(toolchain["release"], "15.2.Rel1")

        build = validated["build"]
        self.assertEqual(build["compile_flags"], COMPILE_FLAGS)
        self.assertEqual(
            build["link"],
            {
                "driver": "arm-none-eabi-ld",
                "mode": ["-r"],
                "output_type": "ET_REL",
                "output_suffix": ".o",
            },
        )
        self.assertNotIn("undefined_symbol_allowlist", build)
        self.assertEqual(
            tuple(validated["safety"]),
            SAFETY_FIELDS,
        )
        self.assertEqual(
            tuple(validated["safety"][field] for field in SAFETY_FIELDS),
            (0, 0, 0, 0),
        )

    def test_target_identity_elf_and_attributes_fail_closed(self):
        """Break caught: a different library or incompatible ARM ABI is accepted."""
        mutations = [
            lambda value: value["target"].__setitem__("sha256", "0" * 64),
            lambda value: value["target"]["elf"].__setitem__("class", "ELF64"),
            lambda value: value["target"]["elf"].__setitem__("data", "big-endian"),
            lambda value: value["target"]["elf"].__setitem__("machine", "AArch64"),
            lambda value: value["target"]["elf"].__setitem__("eabi_version", 4),
            lambda value: value["target"]["attribute_policy"]["mandatory"].pop(),
            lambda value: value["target"]["attribute_policy"]["prohibited"].clear(),
            lambda value: value["target"]["attribute_policy"].__setitem__(
                "extra_attributes", "reject"
            ),
            lambda value: value["target"]["float_call_abi"].__setitem__(
                "hard_float_tag_present", True
            ),
            lambda value: value["target"]["float_call_abi"].__setitem__(
                "hard_float_tag", 28.0
            ),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                self._assert_rejected(mutate)

    def test_attribute_policy_rejects_mandatory_or_prohibited_drift_but_records_extras(self):
        """Break caught: hard-float slips through or benign GCC metadata is discarded."""
        module = self._module()
        self.assertTrue(
            hasattr(module, "validate_arm_target_attributes"),
            "missing validate_arm_target_attributes",
        )
        benign = {"tag": 34, "name": "Tag_CPU_unaligned_access", "value": "v6"}
        self.assertEqual(
            module.validate_arm_target_attributes(TARGET_ATTRIBUTES + [benign]),
            {"mandatory": TARGET_ATTRIBUTES, "extra": [benign]},
        )
        mutations = []
        missing = copy.deepcopy(TARGET_ATTRIBUTES)
        missing.pop()
        mutations.append(missing)
        changed = copy.deepcopy(TARGET_ATTRIBUTES)
        changed[0]["value"] = "v6"
        mutations.append(changed)
        renumbered = copy.deepcopy(TARGET_ATTRIBUTES)
        renumbered[0]["tag"] = 5
        mutations.append(renumbered)
        wrong_type = copy.deepcopy(TARGET_ATTRIBUTES)
        wrong_type[5]["value"] = 4.0
        mutations.append(wrong_type)
        prohibited = copy.deepcopy(TARGET_ATTRIBUTES)
        prohibited.append(
            {"tag": 28, "name": "Tag_ABI_VFP_args", "value": "VFP registers"}
        )
        mutations.append(prohibited)
        for index, attributes in enumerate(mutations):
            with self.subTest(mutation=index), self.assertRaises(
                module.CreativeLookArmTargetProfileError
            ):
                module.validate_arm_target_attributes(attributes)

    def test_official_toolchain_checksum_contract_fails_closed(self):
        """Break caught: an unauthenticated toolchain source or digest is accepted."""
        mutations = [
            lambda value: value["toolchain"].__setitem__("archive_sha256", "xyz"),
            lambda value: value["toolchain"].__setitem__("archive_sha256", "0" * 64),
            lambda value: value["toolchain"].__setitem__("checksum_record", "malformed"),
            lambda value: value["toolchain"].__setitem__(
                "archive_basename", "unofficial.zip"
            ),
            lambda value: value["toolchain"].__setitem__(
                "archive_url", value["toolchain"]["archive_url"].replace("https://", "http://")
            ),
            lambda value: value["toolchain"].__setitem__(
                "checksum_url", "https://example.com/toolchain.sha256asc"
            ),
            lambda value: value["toolchain"].__setitem__(
                "release_url", "https://example.com/release"
            ),
            lambda value: value["toolchain"].__setitem__("target_triple", "arm-linux-gnueabi"),
            lambda value: value["toolchain"].__setitem__("release", "15.1.Rel1"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                self._assert_rejected(mutate)

    def test_compile_link_and_output_contract_fails_closed(self):
        """Break caught: target/hardening flags or relocatable-only output weakens."""
        for flag in COMPILE_FLAGS:
            with self.subTest(omitted_flag=flag):
                self._assert_rejected(
                    lambda value, flag=flag: value["build"]["compile_flags"].remove(flag)
                )
        mutations = [
            lambda value: value["build"]["compile_flags"].append("-mfloat-abi=hard"),
            lambda value: value["build"]["compile_flags"].append("-Os"),
            lambda value: value["build"]["link"].__setitem__("mode", []),
            lambda value: value["build"]["link"].__setitem__("mode", ["-shared"]),
            lambda value: value["build"]["link"].__setitem__("output_type", "ET_DYN"),
            lambda value: value["build"]["link"].__setitem__("output_suffix", ".so"),
            lambda value: value["build"].__setitem__("undefined_symbol_allowlist", []),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                self._assert_rejected(mutate)

    def test_safety_narrative_digest_and_schema_fail_closed(self):
        """Break caught: target runtime readiness is promoted or canonical text drifts."""
        for field in SAFETY_FIELDS:
            with self.subTest(safety=field):
                self._assert_rejected(
                    lambda value, field=field: value["safety"].__setitem__(field, 1)
                )
                self._assert_rejected(
                    lambda value, field=field: value["safety"].__setitem__(field, False)
                )
        mutations = [
            lambda value: value.__setitem__("extra", True),
            lambda value: value.__setitem__("schema_version", 2),
            lambda value: value.__setitem__("conclusion", "Target runtime is ready."),
            lambda value: value.__setitem__("narrative_sha256", "0" * 64),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                self._assert_rejected(mutate)
        for malformed in ("0" * 64, 7, None):
            with self.subTest(contract_sha256=malformed):
                self._assert_rejected_without_digest_refresh(
                    lambda value, malformed=malformed: value.__setitem__(
                        "contract_sha256", malformed
                    )
                )

    def test_json_object_member_order_is_not_a_target_contract_change(self):
        """Break caught: harmless JSON object reordering is rejected as ABI drift."""
        module = self._module()
        document = self._document()
        reordered = dict(reversed(tuple(document.items())))
        reordered["target"] = dict(reversed(tuple(reordered["target"].items())))
        reordered["safety"] = dict(reversed(tuple(reordered["safety"].items())))
        contract = copy.deepcopy(reordered)
        contract.pop("contract_sha256")
        reordered["contract_sha256"] = hashlib.sha256(
            (json.dumps(contract, sort_keys=True, separators=(",", ":")) + "\n").encode(
                "utf-8"
            )
        ).hexdigest()
        self.assertEqual(
            module.validate_creative_look_arm_target_profile(reordered), reordered
        )


class CreativeLookArmTargetBuilderTests(unittest.TestCase):
    def _exporter(self):
        self.assertTrue(EXPORTER_PATH.is_file(), str(EXPORTER_PATH))
        spec = importlib.util.spec_from_file_location(
            "export_a6400_creative_look_arm_target", EXPORTER_PATH
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def _profile(self):
        return json.loads(PROFILE_PATH.read_text(encoding="utf-8"))

    def _require_real_toolchain(self):
        gcc = TOOLCHAIN_ROOT / "bin" / "arm-none-eabi-gcc.exe"
        if not gcc.is_file():
            self.skipTest(
                "pinned Arm 15.2.Rel1 toolchain absent; publication requires a real local run"
            )

    def _module(self):
        spec = importlib.util.spec_from_file_location(
            "creative_look_arm_target_profile", MODULE_PATH
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def _document(self):
        return self._profile()

    def _assert_rejected(self, mutate):
        module = self._module()
        candidate = copy.deepcopy(self._document())
        mutate(candidate)
        contract = copy.deepcopy(candidate)
        contract.pop("contract_sha256", None)
        candidate["contract_sha256"] = hashlib.sha256(
            (json.dumps(contract, sort_keys=True, separators=(",", ":")) + "\n").encode(
                "utf-8"
            )
        ).hexdigest()
        with self.assertRaises(module.CreativeLookArmTargetProfileError):
            module.validate_creative_look_arm_target_profile(candidate)

    def test_real_pinned_toolchain_build_exports_normalized_evidence(self):
        """Break caught: no real ARM object/evidence is produced by the pinned tools."""
        module = self._exporter()
        self._require_real_toolchain()
        self.assertTrue(TOOLCHAIN_ROOT.is_dir(), str(TOOLCHAIN_ROOT))
        with tempfile.TemporaryDirectory(prefix="creative-look-arm-task2-") as directory:
            output_dir = Path(directory)
            output_path = output_dir / "creative_look_arm_target.o"
            before = set(output_dir.rglob("*"))
            evidence = module.build_creative_look_arm_target(
                repo_root=ROOT,
                toolchain_root=TOOLCHAIN_ROOT,
                output_path=output_path,
                profile_path=PROFILE_PATH,
            )
            after = set(output_dir.rglob("*"))

            self.assertEqual(before, set())
            self.assertTrue(output_path.is_file())
            self.assertTrue(after)
            self.assertTrue(all(path.is_relative_to(output_dir) for path in after))
            self.assertEqual(evidence["schema_version"], 1)
            self.assertEqual(evidence["scope"], "offline-static-arm-target-object")
            self.assertFalse(evidence["camera_executed"])
            self.assertEqual(
                [item["path"] for item in evidence["inputs"]["sources"]],
                ["native/a6400_creative_look/" + path.name for path in PRODUCTION_SOURCES],
            )
            self.assertEqual(
                [item["path"] for item in evidence["inputs"]["headers"]],
                ["native/a6400_creative_look/" + path.name for path in PUBLIC_HEADERS],
            )
            self.assertEqual(evidence["build"]["compile_flags"], COMPILE_FLAGS)
            self.assertEqual(evidence["build"]["link_mode"], ["-r"])
            self.assertEqual(evidence["elf"]["type"], "ET_REL")
            self.assertEqual(
                {key: evidence["elf"][key] for key in ("class", "data", "machine", "eabi_version")},
                {"class": "ELF32", "data": "little-endian", "machine": "ARM", "eabi_version": 5},
            )
            self.assertEqual(evidence["undefined_symbols"], [])
            self.assertEqual(evidence["abi_layouts"], ABI_LAYOUTS)
            self.assertEqual(evidence["attributes"]["mandatory"], TARGET_ATTRIBUTES)
            self.assertNotIn("Tag_ABI_VFP_args", json.dumps(evidence["attributes"]))
            self.assertEqual(evidence["safety_scan"]["forbidden_matches"], [])
            self.assertRegex(evidence["raw_record_sha256"], r"^[0-9a-f]{64}$")
            raw_path = output_dir / "creative_look_arm_target.raw.json"
            self.assertTrue(raw_path.is_file())
            self.assertEqual(
                hashlib.sha256(raw_path.read_bytes()).hexdigest(),
                evidence["raw_record_sha256"],
            )

            serialized = json.dumps(evidence, sort_keys=True)
            for absolute in (ROOT, TOOLCHAIN_ROOT, output_dir):
                self.assertNotIn(str(absolute), serialized)
                self.assertNotIn(str(absolute).replace("\\", "/"), serialized)
            self.assertEqual(self._profile()["build_evidence"], evidence)

    def test_request_contract_rejects_flag_link_input_tool_and_output_mutations(self):
        """Break caught: a non-profile build or unsafe output can enter the gate."""
        module = self._exporter()
        self._require_real_toolchain()
        valid = {
            "repo_root": ROOT,
            "toolchain_root": TOOLCHAIN_ROOT,
            "output_path": Path(tempfile.gettempdir()) / "creative_look_arm_target.o",
            "profile_path": PROFILE_PATH,
        }
        flag_mutations = []
        hard = list(COMPILE_FLAGS)
        hard[hard.index("-mfloat-abi=softfp")] = "-mfloat-abi=hard"
        flag_mutations.append(hard)
        armv6 = list(COMPILE_FLAGS)
        armv6[armv6.index("-march=armv7-a")] = "-march=armv6"
        flag_mutations.append(armv6)
        no_thumb = [flag for flag in COMPILE_FLAGS if flag != "-mthumb"]
        flag_mutations.append(no_thumb)
        os_flags = [
            flag
            for flag in COMPILE_FLAGS
            if flag not in ("-O2", "-finline-stringops=memcpy")
        ] + ["-Os"]
        flag_mutations.append(os_flags)
        for index, flags in enumerate(flag_mutations):
            with self.subTest(flag_mutation=index), self.assertRaises(
                module.ArmTargetBuildError
            ):
                module.validate_compile_flags(flags)

        for mode in ([], ["-shared"], ["-e", "0"]):
            with self.subTest(link_mode=mode), self.assertRaises(
                module.ArmTargetBuildError
            ):
                module.validate_link_mode(mode)
        for suffix in (".so", ".elf", ".bin", ".pkg"):
            with self.subTest(suffix=suffix), self.assertRaises(
                module.ArmTargetBuildError
            ):
                module.validate_output_path(Path(tempfile.gettempdir()) / ("target" + suffix))
        aliased_output = (
            Path(tempfile.gettempdir())
            / ".."
            / Path(tempfile.gettempdir()).name
            / "creative_look_arm_target.o"
        )
        with self.assertRaises(module.ArmTargetBuildError):
            module.validate_output_path(aliased_output)
        with self.assertRaises(module.ArmTargetBuildError):
            module.validate_output_path(
                ROOT / "creative_look_arm_target.o", repo_root=ROOT
            )

        with tempfile.TemporaryDirectory(prefix="creative-look-arm-tools-") as directory:
            empty_root = Path(directory).resolve()
            with self.assertRaises(module.ArmTargetBuildError):
                module.resolve_toolchain_tools(empty_root)
        with self.assertRaises(module.ArmTargetBuildError):
            module.resolve_toolchain_tools(Path("relative-toolchain"))
        with self.assertRaises(module.ArmTargetBuildError):
            module.resolve_toolchain_tools(
                TOOLCHAIN_ROOT,
                tool_overrides={"gcc": Path("arm-none-eabi-gcc")},
            )
        with self.assertRaises(module.ArmTargetBuildError):
            module.resolve_toolchain_tools(
                TOOLCHAIN_ROOT,
                tool_overrides={"gcc": Path(os.environ.get("COMSPEC", "C:/Windows/System32/cmd.exe"))},
            )
        for target, version in (("x86_64-w64-mingw32", "15.2.1"), ("arm-none-eabi", "14.3.1")):
            with self.subTest(target=target, version=version), self.assertRaises(
                module.ArmTargetBuildError
            ):
                module.validate_compiler_identity(target, version)

        with self.assertRaises(module.ArmTargetBuildError):
            module.validate_production_inputs(
                ROOT,
                PRODUCTION_SOURCES + (Path(__file__).resolve(),),
                PUBLIC_HEADERS,
            )
        with self.assertRaises(module.ArmTargetBuildError):
            module.validate_production_inputs(ROOT, PRODUCTION_SOURCES, PUBLIC_HEADERS[:-1])

    def test_symbol_abi_attribute_and_safety_mutations_fail_closed(self):
        """Break caught: dependencies, ABI drift, or operational APIs are filtered."""
        module = self._exporter()
        module.validate_undefined_symbols([])
        for symbols in (["deliberate_undefined"], ["__aeabi_idiv"], ["memcpy"]):
            with self.subTest(undefined=symbols), self.assertRaises(
                module.ArmTargetBuildError
            ):
                module.validate_undefined_symbols(symbols)
        with self.assertRaises(module.ArmTargetBuildError):
            module.validate_defined_symbols(["cl_init", "__aeabi_idiv"])
        valid_sections = "  [ 1] .text PROGBITS 00000000 000034 000004 00 AX 0 0 2\n"
        self.assertEqual(module._parse_sections(valid_sections), [".text"])
        forbidden_families = (
            ".init",
            ".fini",
            ".init_array",
            ".fini_array",
            ".ctors",
            ".dtors",
            ".dynamic",
            ".dynsym",
            ".interp",
        )
        for forbidden_section in tuple(
            variant
            for family in forbidden_families
            for variant in (family, family + ".task2_mutation")
        ):
            mutated_sections = valid_sections + (
                f"  [ 2] {forbidden_section} PROGBITS 00000000 000038 000004 00 AX 0 0 4\n"
            )
            with self.subTest(section=forbidden_section), self.assertRaises(
                module.ArmTargetBuildError
            ):
                module._parse_sections(mutated_sections)
        valid_symbols = (
            "   0: 00000000     0 NOTYPE  LOCAL  DEFAULT  UND\n"
            "   1: 00000100     4 FUNC    GLOBAL DEFAULT    1 cl_init\n"
            "   2: 00000104     4 FUNC    GLOBAL DEFAULT    1 cl_bridge_open\n"
        )
        self.assertEqual(module.validate_full_symbol_table(valid_symbols), 3)
        for mutation in (
            "   3: 00000108     4 FUNC    LOCAL  DEFAULT    1 _init\n",
            "   3: 00000000     0 NOTYPE  GLOBAL DEFAULT  UND deliberate_undefined\n",
            "   3: 00000108     4 FUNC    LOCAL  DEFAULT    1 __aeabi_hidden\n",
        ):
            with self.subTest(symbol_row=mutation.strip()), self.assertRaises(
                module.ArmTargetBuildError
            ):
                module.validate_full_symbol_table(valid_symbols + mutation)

        module.validate_abi_layouts(ABI_LAYOUTS)
        for name in ABI_LAYOUTS:
            mutated = copy.deepcopy(ABI_LAYOUTS)
            field = "offset" if name == "cl_bridge.adapters" else "size"
            mutated[name][field] += 1
            with self.subTest(layout=name), self.assertRaises(
                module.ArmTargetBuildError
            ):
                module.validate_abi_layouts(mutated)

        source = PRODUCTION_SOURCES[0].read_text(encoding="utf-8")
        for forbidden in module.FORBIDDEN_SOURCE_TOKENS:
            with self.subTest(forbidden=forbidden), self.assertRaisesRegex(
                module.ArmTargetBuildError, "forbidden"
            ):
                module.scan_source_text(PRODUCTION_SOURCES[0], source + "\n" + forbidden)

    def test_profile_build_evidence_mutations_are_rejected(self):
        """Break caught: tracked normalized evidence can drift independently."""
        module = self._module()
        document = self._document()
        self.assertIn("build_evidence", document)
        mutations = [
            lambda value: value["build_evidence"]["build"]["compile_flags"].__setitem__(8, "-Os"),
            lambda value: value["build_evidence"]["undefined_symbols"].append("memcpy"),
            lambda value: value["build_evidence"]["elf"].__setitem__("type", "ET_DYN"),
            lambda value: value["build_evidence"]["abi_layouts"]["cl_bridge"].__setitem__("size", 691),
            lambda value: value["build_evidence"]["inputs"]["sources"].append(
                {"path": "native/a6400_creative_look/unapproved.c", "sha256": "0" * 64}
            ),
            lambda value: value["build_evidence"].__setitem__("raw_record_sha256", "0" * 64),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                self._assert_rejected(mutate)

    def test_failed_post_link_inspection_publishes_no_object_or_raw_record(self):
        """Break caught: a failed inspection leaves a seemingly usable artifact."""
        module = self._exporter()
        self._require_real_toolchain()
        with tempfile.TemporaryDirectory(prefix="creative-look-arm-atomic-") as directory:
            output = Path(directory) / "creative_look_arm_target.o"
            raw = Path(directory) / "creative_look_arm_target.raw.json"
            with mock.patch.object(
                module,
                "_parse_elf_header",
                side_effect=module.ArmTargetBuildError("mutated ELF"),
            ):
                with self.assertRaises(module.ArmTargetBuildError):
                    module.build_creative_look_arm_target(
                        repo_root=ROOT,
                        toolchain_root=TOOLCHAIN_ROOT,
                        output_path=output,
                        profile_path=PROFILE_PATH,
                    )
            self.assertFalse(output.exists())
            self.assertFalse(raw.exists())
    def test_fresh_evidence_must_equal_profile_before_publication(self):
        """Break caught: a fresh build can publish evidence different from tracked."""
        module = self._exporter()
        self._require_real_toolchain()
        profile_module = self._module()
        mutated_profile = self._profile()
        mutated_profile["build_evidence"]["object"]["sha256"] = "0" * 64
        raw = copy.deepcopy(mutated_profile["build_evidence"])
        raw.pop("raw_record_sha256")
        mutated_profile["build_evidence"]["raw_record_sha256"] = hashlib.sha256(
            (json.dumps(raw, sort_keys=True, separators=(",", ":")) + "\n").encode()
        ).hexdigest()
        with tempfile.TemporaryDirectory(prefix="creative-look-arm-evidence-") as directory:
            output = Path(directory) / "creative_look_arm_target.o"
            raw_path = Path(directory) / "creative_look_arm_target.raw.json"
            with mock.patch.object(
                module,
                "_load_profile",
                return_value=(profile_module, mutated_profile),
            ):
                with self.assertRaisesRegex(
                    module.ArmTargetBuildError, "tracked build evidence"
                ):
                    module.build_creative_look_arm_target(
                        repo_root=ROOT,
                        toolchain_root=TOOLCHAIN_ROOT,
                        output_path=output,
                        profile_path=PROFILE_PATH,
                    )
            self.assertFalse(output.exists())
            self.assertFalse(raw_path.exists())

    def test_input_aliases_and_unbounded_subprocesses_are_rejected(self):
        """Break caught: resolving first hides path identity or permits a hung tool."""
        module = self._exporter()
        aliased = (
            NATIVE_ROOT
            / ".."
            / "a6400_creative_look"
            / PRODUCTION_SOURCES[0].name
        )
        with self.assertRaises(module.ArmTargetBuildError):
            module.validate_production_inputs(
                ROOT,
                (aliased,) + PRODUCTION_SOURCES[1:],
                PUBLIC_HEADERS,
            )

        completed = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(module.subprocess, "run", return_value=completed) as run:
            module._run_raw(
                [TOOLCHAIN_ROOT / "bin" / "arm-none-eabi-gcc.exe", "--version"],
                cwd=ROOT,
                environment={},
            )
        self.assertEqual(run.call_args.kwargs["timeout"], module.COMMAND_TIMEOUT_SECONDS)

    def test_real_os_and_injected_symbol_mutations_are_observed_and_rejected(self):
        """Break caught: runtime dependencies are hidden instead of naturally found."""
        module = self._exporter()
        self._require_real_toolchain()
        tools = module.resolve_toolchain_tools(TOOLCHAIN_ROOT)
        environment = dict(os.environ)
        for key in module.COMPILER_ENVIRONMENT_KEYS:
            environment.pop(key, None)
        environment["PATH"] = str((TOOLCHAIN_ROOT / "bin").resolve())

        def run(argv, cwd):
            return subprocess.run(
                [str(item) for item in argv],
                cwd=str(cwd),
                env=environment,
                shell=False,
                check=True,
                capture_output=True,
                text=True,
                timeout=module.COMMAND_TIMEOUT_SECONDS,
            )

        os_flags = [
            flag
            for flag in COMPILE_FLAGS
            if flag not in ("-O2", "-finline-stringops=memcpy")
        ]
        os_flags.insert(8, "-Os")
        with tempfile.TemporaryDirectory(prefix="creative-look-arm-os-") as directory:
            temporary = Path(directory)
            objects = []
            for source in PRODUCTION_SOURCES:
                output = temporary / (source.stem + ".o")
                run(
                    [
                        tools["gcc"],
                        *os_flags,
                        "-I",
                        NATIVE_ROOT,
                        "-c",
                        source,
                        "-o",
                        output,
                    ],
                    ROOT,
                )
                objects.append(output)
            combined = temporary / "os-mutation.o"
            run([tools["ld"], "-r", "-o", combined, *objects], ROOT)
            undefined = {
                line.split()[0]
                for line in run([tools["nm"], "-u", "-P", combined], ROOT).stdout.splitlines()
                if line.strip()
            }
            self.assertEqual(undefined, {"__aeabi_idiv", "memcpy"})
            with self.assertRaises(module.ArmTargetBuildError):
                module.validate_undefined_symbols(sorted(undefined))

            mutation_source = temporary / "undefined-mutation.c"
            mutation_source.write_text(
                "extern int deliberate_undefined(void);\n"
                "extern int __aeabi_task2_reference(void);\n"
                "int task2_mutation(void) {\n"
                "  return deliberate_undefined() + __aeabi_task2_reference();\n"
                "}\n",
                encoding="utf-8",
            )
            mutation_object = temporary / "undefined-mutation.o"
            run(
                [tools["gcc"], *COMPILE_FLAGS, "-c", mutation_source, "-o", mutation_object],
                ROOT,
            )
            injected = {
                line.split()[0]
                for line in run(
                    [tools["nm"], "-u", "-P", mutation_object], ROOT
                ).stdout.splitlines()
                if line.strip()
            }
            self.assertEqual(
                injected, {"__aeabi_task2_reference", "deliberate_undefined"}
            )
            with self.assertRaises(module.ArmTargetBuildError):
                module.validate_undefined_symbols(sorted(injected))

    def test_missing_or_substituted_tools_fail_before_any_execution(self):
        """Break caught: an unauthenticated tool is executed before its hash gate."""
        module = self._exporter()
        with tempfile.TemporaryDirectory(prefix="creative-look-empty-toolchain-") as directory:
            with mock.patch.object(module.subprocess, "run") as run:
                with self.assertRaises(module.ArmTargetBuildError):
                    module.resolve_toolchain_tools(Path(directory).resolve())
            run.assert_not_called()

        if not TOOLCHAIN_ROOT.is_dir():
            return
        aliased_root = TOOLCHAIN_ROOT / ".." / TOOLCHAIN_ROOT.name
        with mock.patch.object(module.subprocess, "run") as run:
            with self.assertRaisesRegex(module.ArmTargetBuildError, "root path"):
                module.resolve_toolchain_tools(aliased_root)
        run.assert_not_called()

        substituted = TOOLCHAIN_ROOT / "bin" / "arm-none-eabi-nm.exe"
        with mock.patch.object(module.subprocess, "run") as run:
            with self.assertRaisesRegex(module.ArmTargetBuildError, "objdump path"):
                module.resolve_toolchain_tools(
                    TOOLCHAIN_ROOT,
                    tool_overrides={"objdump": substituted},
                )
        run.assert_not_called()

        alternate = (
            TOOLCHAIN_ROOT
            / "bin"
            / ".."
            / "bin"
            / "arm-none-eabi-objdump.exe"
        )
        self.assertEqual(
            hashlib.sha256(alternate.read_bytes()).hexdigest(),
            module.PINNED_TOOL_HASHES["objdump"],
        )
        with mock.patch.object(module.subprocess, "run") as run:
            with self.assertRaisesRegex(module.ArmTargetBuildError, "exact pinned"):
                module.resolve_toolchain_tools(
                    TOOLCHAIN_ROOT,
                    tool_overrides={"objdump": alternate},
                )
        run.assert_not_called()

    def test_toolchain_reparse_root_is_rejected_before_execution_when_supported(self):
        """Break caught: a junction/symlink hides the configured toolchain identity."""
        module = self._exporter()
        self._require_real_toolchain()
        with tempfile.TemporaryDirectory(prefix="creative-look-toolchain-link-") as directory:
            link = Path(directory) / "toolchain-link"
            try:
                link.symlink_to(TOOLCHAIN_ROOT, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"directory symlink unsupported: {error}")
            with mock.patch.object(module.subprocess, "run") as run:
                with self.assertRaises(module.ArmTargetBuildError):
                    module.resolve_toolchain_tools(link)
            run.assert_not_called()

    def test_interrupted_final_object_publish_cleans_evidence_and_object(self):
        """Break caught: interruption between the two replaces exposes an object."""
        module = self._exporter()
        self._require_real_toolchain()
        real_replace = module.os.replace
        calls = []

        def interrupt_second(source, destination):
            calls.append((Path(source), Path(destination)))
            if len(calls) == 2:
                raise KeyboardInterrupt("publication mutation")
            return real_replace(source, destination)

        with tempfile.TemporaryDirectory(prefix="creative-look-arm-interrupt-") as directory:
            output = Path(directory) / "creative_look_arm_target.o"
            raw = Path(directory) / "creative_look_arm_target.raw.json"
            with mock.patch.object(module.os, "replace", side_effect=interrupt_second):
                with self.assertRaises(KeyboardInterrupt):
                    module.build_creative_look_arm_target(
                        repo_root=ROOT,
                        toolchain_root=TOOLCHAIN_ROOT,
                        output_path=output,
                        profile_path=PROFILE_PATH,
                    )
            self.assertEqual([path.name for _, path in calls], [raw.name, output.name])
            self.assertFalse(output.exists())
            self.assertFalse(raw.exists())


class CreativeLookTargetShellMissingExportTests(unittest.TestCase):
    def test_target_shell_files_and_required_exports_exist(self):
        """Break caught: the neutral target-owned shell ABI is absent."""
        self.assertTrue(TARGET_HEADER.is_file(), str(TARGET_HEADER))
        self.assertTrue(TARGET_SOURCE.is_file(), str(TARGET_SOURCE))
        source = TARGET_SOURCE.read_text(encoding="utf-8")
        exports = (
            "cl_target_shell_size",
            "cl_target_shell_alignment",
            "cl_target_shell_init",
            "cl_target_shell_open",
            "cl_target_shell_close",
            "cl_target_shell_deliver",
            "cl_target_shell_copied_frame",
            "cl_target_shell_bridge_state",
            "cl_target_shell_last_report",
            "cl_target_shell_identity",
        )
        for export in exports:
            with self.subTest(export=export):
                self.assertIn(export + "(", source)


class CreativeLookTargetShellTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._temporary = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        directory = Path(cls._temporary.name)
        cls.clobber_source = directory / "target-shell-stack-clobber.c"
        cls.clobber_source.write_text(
            "#include <stddef.h>\n"
            "void cl_target_test_clobber_stack(void) {\n"
            "  volatile unsigned char bytes[4096]; size_t i;\n"
            "  for (i = 0; i < sizeof(bytes); ++i) bytes[i] = (unsigned char)i;\n"
            "}\n",
            encoding="utf-8",
        )
        sources = [
            native_abi.CORE_SOURCE,
            native_abi.VIEW_SOURCE,
            NATIVE_ROOT / "creative_look_bridge.c",
            TARGET_SOURCE,
            cls.clobber_source,
        ]
        cls.library_path = native_abi.compile_shared_library(
            directory, "creative_look_target", sources
        )
        cls.library = ctypes.CDLL(str(cls.library_path))
        native_abi.configure_core_exports(cls.library)
        native_abi.configure_view_exports(cls.library)
        configure_target_exports(cls.library)
        cls.library.cl_target_test_clobber_stack.argtypes = []
        cls.library.cl_target_test_clobber_stack.restype = None

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "library", None) is not None:
            native_abi.unload_library(cls, "library")
        cls._temporary.cleanup()

    def tearDown(self):
        errors = []
        for value in self.__dict__.values():
            errors.extend(getattr(value, "_native_callback_errors", ()))
        self.assertEqual(errors, [])

    def _fresh(self, **kwargs):
        fixture = TargetShellFixture(self.library, **kwargs)
        manifest_before = bytes(fixture.manifest)
        adapters_before = bytes(fixture.adapters)
        self.assertEqual(fixture.initialize(), bridge_abi.CL_OK)
        self.assertEqual(bytes(fixture.manifest), manifest_before)
        self.assertEqual(bytes(fixture.adapters), adapters_before)
        fixture.expected_manifest_bytes = manifest_before
        self._assert_safety_zero(fixture)
        return fixture

    def _assert_safety_zero(self, fixture):
        for manifest in (fixture.manifest, fixture.shell.bridge.manifest):
            self.assertEqual(
                tuple(getattr(manifest, field) for field in SAFETY_FIELDS),
                (0, 0, 0, 0),
            )

    def _assert_manifest_identity(self, fixture):
        self.assertEqual(fixture._native_callback_errors, [])
        self.assertEqual(bytes(fixture.manifest), fixture.expected_manifest_bytes)
        self.assertEqual(
            bytes(fixture.shell.bridge.manifest),
            fixture.expected_manifest_bytes,
        )
        self._assert_safety_zero(fixture)

    @staticmethod
    def _literal_state(
        *,
        selected_look=0,
        screen=bridge_abi.CL_SCREEN_CATALOG,
        orientation=0,
        editing_axis=bridge_abi.CL_UNSET,
        custom_bases=None,
        adjustments=None,
    ):
        state = native_abi.NativeState()
        state.selected_look = selected_look
        state.screen = screen
        state.orientation = orientation
        state.editing_axis = editing_axis
        for slot, value in enumerate(custom_bases or (bridge_abi.CL_UNSET,) * 6):
            state.custom_bases[slot] = value
        rows = adjustments or ((bridge_abi.CL_AXIS_DEFAULT,) * 8,) * 18
        for look, row in enumerate(rows):
            for axis, value in enumerate(row):
                state.adjustments[look][axis] = value
        state.modes = 0
        return state

    @staticmethod
    def _literal_blob(state):
        payload = bytearray(160)
        payload[:5] = b"CLK1\x01"
        payload[5:10] = bytes(
            (
                state.selected_look,
                state.screen,
                state.orientation,
                state.editing_axis,
                state.modes,
            )
        )
        payload[10:16] = bytes(state.custom_bases)
        payload[16:160] = bytes(state.adjustments)
        return bytes(payload) + zlib.crc32(payload).to_bytes(4, "little")

    @staticmethod
    def _literal_snapshot(state, effective_base, revision):
        snapshot = bridge_abi.ProcessingSnapshot()
        snapshot.abi_version = bridge_abi.CL_BRIDGE_ABI_VERSION
        snapshot.effective_base = effective_base
        snapshot.output_mask = bridge_abi.CL_BRIDGE_OUTPUT_MASK
        snapshot.processing_revision = revision
        snapshot.state = state
        snapshot.reserved[0] = 0
        return snapshot

    @staticmethod
    def _literal_default_frame():
        frame = native_abi.NativeFrame()
        frame.width = 1600000
        frame.height = 900000
        frame.columns = 6
        frame.count = 18
        coordinates = (
            (40000, 22500),
            (296533, 22500),
            (553067, 22500),
            (809600, 22500),
            (1066133, 22500),
            (1322667, 22500),
            (40000, 311100),
            (296533, 311100),
            (553067, 311100),
            (809600, 311100),
            (1066133, 311100),
            (1322667, 311100),
            (40000, 599700),
            (296533, 599700),
            (553067, 599700),
            (809600, 599700),
            (1066133, 599700),
            (1322667, 599700),
        )
        for look, (x, y) in enumerate(coordinates):
            element = frame.elements[look]
            element.x = x
            element.y = y
            element.width = 237333
            element.height = 277800
            element.value = look if look < 12 else bridge_abi.CL_AXIS_DEFAULT
            element.status = bridge_abi.CL_OK
            element.kind = bridge_abi.CL_UI_KIND_LOOK
            element.action = 1
            element.primary = look
            element.enabled = 1
            element.modified = 0
        for index in (18, 19):
            frame.elements[index].kind = bridge_abi.CL_UI_KIND_ACTION
        return frame

    def _assert_full_state(self, fixture, expected_state):
        self.assertEqual(bytes(self._state(fixture)), bytes(expected_state))

    def _assert_open_evidence(self, fixture, result, report):
        expected = self._literal_state()
        self.assertEqual(result, bridge_abi.CL_OK)
        self._assert_full_state(fixture, expected)
        self.assertEqual(
            fixture.calls,
            ["load", "save", "model", "live_view", "still_jpeg", "movie"],
        )
        self.assertEqual(fixture.saved_blobs, [self._literal_blob(expected)])
        self.assertEqual(
            (report.attempted, report.succeeded, report.failed, report.dirty),
            (0x3F, 0x3F, 0, 0),
        )
        self.assertEqual(
            (report.state_revision, report.processing_revision, report.state_committed, report.opened),
            (1, 1, 1, 1),
        )
        snapshots = [fixture.model_snapshots[-1]] + [
            snapshot for _, snapshot in fixture.output_snapshots[-3:]
        ]
        expected_snapshot = self._literal_snapshot(expected, 0, 1)
        self.assertEqual([kind for kind, _ in fixture.output_snapshots], [0, 1, 2])
        for snapshot in snapshots:
            self.assertEqual(bytes(snapshot), bytes(expected_snapshot))
        self.assertEqual(
            bytes(fixture.shell.bridge.retained_processing_snapshot),
            bytes(expected_snapshot),
        )
        self._assert_manifest_identity(fixture)

    def _transition_baseline(self, fixture):
        return {
            "calls": len(fixture.calls),
            "saved": len(fixture.saved_blobs),
            "model": len(fixture.model_snapshots),
            "output": len(fixture.output_snapshots),
            "state_revision": fixture.shell.bridge.state_revision,
            "processing_revision": fixture.shell.bridge.processing_revision,
        }

    def _assert_transition_evidence(
        self,
        fixture,
        baseline,
        result,
        report,
        expected_state,
        *,
        processing,
        effective_base=None,
    ):
        self.assertEqual(result, bridge_abi.CL_OK)
        self._assert_full_state(fixture, expected_state)
        expected_mask = 0x3F if processing else 0x03
        expected_calls = (
            ["save", "model", "live_view", "still_jpeg", "movie"]
            if processing
            else ["save"]
        )
        self.assertEqual(fixture.calls[baseline["calls"] :], expected_calls)
        self.assertEqual(len(fixture.saved_blobs), baseline["saved"] + 1)
        self.assertEqual(fixture.saved_blobs[-1], self._literal_blob(expected_state))
        self.assertEqual(
            (report.attempted, report.succeeded, report.failed, report.dirty),
            (expected_mask, expected_mask, 0, 0),
        )
        expected_processing_revision = baseline["processing_revision"] + (
            1 if processing else 0
        )
        self.assertEqual(
            (report.state_revision, report.processing_revision, report.state_committed),
            (baseline["state_revision"] + 1, expected_processing_revision, 1),
        )
        if processing:
            self.assertEqual(len(fixture.model_snapshots), baseline["model"] + 1)
            self.assertEqual(len(fixture.output_snapshots), baseline["output"] + 3)
            self.assertEqual(
                [kind for kind, _ in fixture.output_snapshots[-3:]], [0, 1, 2]
            )
            expected_snapshot = self._literal_snapshot(
                expected_state, effective_base, expected_processing_revision
            )
            snapshots = [fixture.model_snapshots[-1]] + [
                snapshot for _, snapshot in fixture.output_snapshots[-3:]
            ]
            for snapshot in snapshots:
                self.assertEqual(bytes(snapshot), bytes(expected_snapshot))
            self.assertEqual(
                bytes(fixture.shell.bridge.retained_processing_snapshot),
                bytes(expected_snapshot),
            )
        else:
            self.assertEqual(len(fixture.model_snapshots), baseline["model"])
            self.assertEqual(len(fixture.output_snapshots), baseline["output"])
        self._assert_manifest_identity(fixture)

    def _state(self, fixture):
        pointer = self.library.cl_target_shell_bridge_state(
            ctypes.byref(fixture.shell)
        )
        self.assertTrue(pointer)
        self.assertEqual(
            ctypes.addressof(pointer.contents),
            ctypes.addressof(fixture.shell.bridge.state),
        )
        return pointer.contents

    def _frame(self, fixture):
        pointer = self.library.cl_target_shell_copied_frame(
            ctypes.byref(fixture.shell)
        )
        self.assertTrue(pointer)
        self.assertEqual(
            ctypes.addressof(pointer.contents),
            ctypes.addressof(fixture.shell.copied_frame),
        )
        return pointer.contents

    def _element(self, fixture, action, *, primary=None, value=None):
        frame = self._frame(fixture)
        matches = []
        for element in tuple(frame.elements)[: frame.count]:
            if element.action != action:
                continue
            if primary is not None and element.primary != primary:
                continue
            if value is not None and element.value != value:
                continue
            matches.append(element)
        self.assertEqual(len(matches), 1, (action, primary, value))
        return matches[0]

    def _touch(self, fixture, action, *, primary=None, value=None):
        element = self._element(
            fixture, action, primary=primary, value=value
        )
        event = bridge_abi.InputEvent(
            element.x + element.width // 2,
            element.y + element.height // 2,
            bridge_abi.CL_INPUT_TOUCH,
            0,
            (ctypes.c_uint8 * 2)(0, 0),
        )
        return fixture.deliver(event)

    def _orient(self, fixture, orientation):
        event = bridge_abi.InputEvent(
            0,
            0,
            bridge_abi.CL_INPUT_ORIENTATION,
            orientation,
            (ctypes.c_uint8 * 2)(0, 0),
        )
        return fixture.deliver(event)

    def test_host_abi_identity_and_accessor_marker_contract_are_exact(self):
        """Break caught: pointer-width layout drifts or invalid shells leak access."""
        self.assertEqual((ctypes.sizeof(TargetShell), ctypes.alignment(TargetShell)), (1272, 8))
        self.assertEqual(TargetShell.bridge.offset, 0)
        self.assertEqual(TargetShell.copied_frame.offset, 752)
        self.assertEqual(TargetShell.retained_sink.offset, 1248)
        self.assertEqual(TargetShell.retained_sink_context.offset, 1256)
        self.assertEqual(TargetShell.initialization_marker.offset, 1264)
        self.assertEqual(TargetShell.frame_valid.offset, 1268)
        self.assertEqual(TargetShell.delivering.offset, 1269)
        self.assertEqual((ctypes.sizeof(TargetIdentity), ctypes.alignment(TargetIdentity)), (32, 8))
        self.assertEqual(TargetIdentity.publication_status.offset, 24)
        self.assertEqual(self.library.cl_target_shell_size(), 1272)
        self.assertEqual(self.library.cl_target_shell_alignment(), 8)

        identity_pointer = self.library.cl_target_shell_identity()
        self.assertTrue(identity_pointer)
        identity = identity_pointer.contents
        self.assertEqual(identity.logical_alias, b"view/CREATIVE_LOOK")
        self.assertEqual(identity.component_label, b"viewCreativeLook.so")
        self.assertEqual(
            identity.proposed_factory_label, b"ViewCreativeLookToInstance"
        )
        self.assertEqual(
            identity.publication_status,
            TARGET_PUBLICATION_PROPOSED_UNPUBLISHED,
        )

        shell = TargetShell()
        self.assertFalse(
            self.library.cl_target_shell_copied_frame(ctypes.byref(shell))
        )
        self.assertFalse(
            self.library.cl_target_shell_bridge_state(ctypes.byref(shell))
        )
        self.assertFalse(
            self.library.cl_target_shell_last_report(ctypes.byref(shell))
        )
        shell.initialization_marker = TARGET_SHELL_INITIALIZATION_MARKER
        self.assertFalse(
            self.library.cl_target_shell_bridge_state(ctypes.byref(shell))
        )
        fixture = self._fresh()
        self.assertEqual(
            fixture.shell.initialization_marker,
            TARGET_SHELL_INITIALIZATION_MARKER,
        )
        self.assertFalse(
            self.library.cl_target_shell_copied_frame(
                ctypes.byref(fixture.shell)
            )
        )
        self.assertTrue(
            self.library.cl_target_shell_last_report(ctypes.byref(fixture.shell))
        )

    def test_init_is_zero_first_use_atomic_and_copies_only_allowed_adapters(self):
        """Break caught: init clears live bytes, accepts shell-owned entries, or aliases caller data."""
        fixture = TargetShellFixture(self.library)
        reportless_shell = TargetShell()
        self.assertEqual(
            self.library.cl_target_shell_init(
                None,
                ctypes.byref(fixture.manifest),
                ctypes.byref(fixture.adapters),
            ),
            bridge_abi.CL_ERR_ARGUMENT,
        )
        self.assertEqual(
            self.library.cl_target_shell_init(
                ctypes.byref(reportless_shell), None, ctypes.byref(fixture.adapters)
            ),
            bridge_abi.CL_ERR_MANIFEST,
        )
        self.assertEqual(bytes(reportless_shell), bytes(TargetShell()))
        self.assertEqual(
            self.library.cl_target_shell_init(
                ctypes.byref(reportless_shell), ctypes.byref(fixture.manifest), None
            ),
            bridge_abi.CL_ERR_BINDING,
        )
        self.assertEqual(bytes(reportless_shell), bytes(TargetShell()))
        for safety_field in SAFETY_FIELDS:
            invalid_manifest = bridge_abi.IntegrationManifest.from_buffer_copy(
                fixture.manifest
            )
            setattr(invalid_manifest, safety_field, 1)
            shell_before = bytes(reportless_shell)
            manifest_before = bytes(invalid_manifest)
            with self.subTest(safety_field=safety_field):
                self.assertEqual(
                    self.library.cl_target_shell_init(
                        ctypes.byref(reportless_shell),
                        ctypes.byref(invalid_manifest),
                        ctypes.byref(fixture.adapters),
                    ),
                    bridge_abi.CL_ERR_MANIFEST,
                )
                self.assertEqual(bytes(reportless_shell), shell_before)
                self.assertEqual(bytes(invalid_manifest), manifest_before)

        poisoned = TargetShell()
        ctypes.memset(ctypes.byref(poisoned), 0xA5, ctypes.sizeof(poisoned))
        fixture = TargetShellFixture(self.library)
        before = bytes(poisoned)
        self.assertEqual(
            self.library.cl_target_shell_init(
                ctypes.byref(poisoned),
                ctypes.byref(fixture.manifest),
                ctypes.byref(fixture.adapters),
            ),
            bridge_abi.CL_ERR_STATE,
        )
        self.assertEqual(bytes(poisoned), before)

        callbacks = [
            native_abi.retain_callback(fixture, bridge_abi.LifecycleOpenCallback, lambda _c, _s: 0),
            native_abi.retain_callback(fixture, bridge_abi.LifecycleCloseCallback, lambda _c: 0),
            native_abi.retain_callback(fixture, native_abi.PresentCallback, lambda _c, _f: 0),
            native_abi.retain_callback(fixture, bridge_abi.InputAttachCallback, lambda _c, _s, _x: 0),
            native_abi.retain_callback(fixture, bridge_abi.InputDetachCallback, lambda _c: 0),
        ]
        mutations = (
            lambda adapters: setattr(adapters.lifecycle, "context", 1),
            lambda adapters: setattr(adapters.lifecycle, "open", callbacks[0]),
            lambda adapters: setattr(adapters.lifecycle, "close", callbacks[1]),
            lambda adapters: setattr(adapters.presentation, "context", 2),
            lambda adapters: setattr(adapters.presentation, "present", callbacks[2]),
            lambda adapters: setattr(adapters.input, "context", 3),
            lambda adapters: setattr(adapters.input, "attach", callbacks[3]),
            lambda adapters: setattr(adapters.input, "detach", callbacks[4]),
        )
        for index, mutate in enumerate(mutations):
            candidate = TargetShellFixture(self.library)
            adapters = bridge_abi.BridgeAdapters.from_buffer_copy(candidate.adapters)
            mutate(adapters)
            shell_before = bytes(candidate.shell)
            manifest_before = bytes(candidate.manifest)
            adapters_before = bytes(adapters)
            with self.subTest(shell_owned_entry=index):
                self.assertEqual(
                    candidate.initialize(adapters=ctypes.byref(adapters)),
                    bridge_abi.CL_ERR_BINDING,
                )
                self.assertEqual(bytes(candidate.shell), shell_before)
                self.assertEqual(bytes(candidate.manifest), manifest_before)
                self.assertEqual(bytes(adapters), adapters_before)

        fixture = self._fresh()
        shell_address = ctypes.addressof(fixture.shell)
        self.assertEqual(fixture.shell.bridge.adapters.lifecycle.context, shell_address)
        self.assertEqual(fixture.shell.bridge.adapters.presentation.context, shell_address)
        self.assertEqual(fixture.shell.bridge.adapters.input.context, shell_address)
        self.assertTrue(fixture.shell.bridge.adapters.lifecycle.open)
        self.assertTrue(fixture.shell.bridge.adapters.lifecycle.close)
        self.assertTrue(fixture.shell.bridge.adapters.presentation.present)
        self.assertTrue(fixture.shell.bridge.adapters.input.attach)
        self.assertTrue(fixture.shell.bridge.adapters.input.detach)
        self.assertEqual(
            fixture.shell.bridge.adapters.persistence.context,
            fixture.contexts["persistence"],
        )
        self.assertEqual(
            fixture.shell.bridge.adapters.model.context, fixture.contexts["model"]
        )
        self.assertEqual(
            fixture.shell.bridge.adapters.output.context, fixture.contexts["output"]
        )

        ctypes.memset(ctypes.byref(fixture.adapters), 0, ctypes.sizeof(fixture.adapters))
        self.assertEqual(fixture.open()[0], bridge_abi.CL_OK)
        self.assertEqual(fixture.calls[:2], ["load", "save"])
        self.assertEqual(fixture.close()[0], bridge_abi.CL_OK)

    def test_reinit_is_guarded_alias_safe_and_resets_history_only_on_success(self):
        """Break caught: live state is erased or an in-shell manifest alias is invalidated before copying."""
        fixture = self._fresh()
        before = bytes(fixture.shell)
        self.assertEqual(fixture.initialize(), bridge_abi.CL_ERR_STATE)
        self.assertEqual(bytes(fixture.shell), before)
        self.assertEqual(fixture.open()[0], bridge_abi.CL_OK)
        before = bytes(fixture.shell)
        self.assertEqual(fixture.initialize(), bridge_abi.CL_ERR_ALREADY_OPEN)
        self.assertEqual(bytes(fixture.shell), before)
        self.assertEqual(fixture.close()[0], bridge_abi.CL_OK)
        historical_frame = bytes(self._frame(fixture))

        embedded_adapters = ctypes.byref(fixture.shell.bridge.adapters)
        before = bytes(fixture.shell)
        self.assertEqual(
            fixture.initialize(adapters=embedded_adapters),
            bridge_abi.CL_ERR_BINDING,
        )
        self.assertEqual(bytes(fixture.shell), before)
        self.assertEqual(bytes(self._frame(fixture)), historical_frame)

        external_owner = TargetShellFixture(self.library)
        external_adapters = external_owner.adapters
        manifest_alias = ctypes.byref(fixture.shell.bridge.manifest)
        self.assertEqual(
            fixture.initialize(
                manifest=manifest_alias,
                adapters=ctypes.byref(external_adapters),
            ),
            bridge_abi.CL_OK,
        )
        self.assertFalse(
            self.library.cl_target_shell_copied_frame(ctypes.byref(fixture.shell))
        )

        failed = TargetShellFixture(self.library, load_result=73)
        self.assertEqual(failed.initialize(), bridge_abi.CL_OK)
        self.assertEqual(failed.open()[0], bridge_abi.CL_ERR_ADAPTER)
        self.assertEqual((failed.shell.bridge.opened, failed.shell.bridge.input_attached), (0, 0))
        self.assertFalse(failed.shell.retained_sink)
        self.assertFalse(
            self.library.cl_target_shell_copied_frame(
                ctypes.byref(failed.shell)
            )
        )
        self.assertEqual(failed.initialize(), bridge_abi.CL_OK)
        self._assert_safety_zero(failed)

    def test_open_copies_frame_and_close_keeps_history_but_invalidates_delivery(self):
        """Break caught: the shell retains the bridge's stack frame or treats close diagnostics as liveness."""
        fixture = self._fresh()
        ctypes.memset(
            ctypes.byref(fixture.shell.copied_frame),
            0xA5,
            ctypes.sizeof(fixture.shell.copied_frame),
        )
        before_manifest = bytes(fixture.manifest)
        result, report = fixture.open()
        self._assert_open_evidence(fixture, result, report)
        self.assertEqual((report.opened, fixture.shell.bridge.opened, fixture.shell.bridge.input_attached), (1, 1, 1))
        self.assertTrue(fixture.shell.retained_sink)
        self.assertEqual(
            fixture.shell.retained_sink_context,
            ctypes.addressof(fixture.shell.bridge),
        )
        frame_pointer = self.library.cl_target_shell_copied_frame(ctypes.byref(fixture.shell))
        frame_address = ctypes.addressof(frame_pointer.contents)
        shell_address = ctypes.addressof(fixture.shell)
        self.assertEqual(frame_address, ctypes.addressof(fixture.shell.copied_frame))
        self.assertGreaterEqual(frame_address, shell_address)
        self.assertLessEqual(frame_address + ctypes.sizeof(native_abi.NativeFrame), shell_address + ctypes.sizeof(TargetShell))
        self.assertEqual(frame_address % ctypes.alignment(native_abi.NativeFrame), 0)
        copied = bytes(frame_pointer.contents)
        self.assertEqual(copied, bytes(self._literal_default_frame()))
        self.assertEqual(
            (
                frame_pointer.contents.width,
                frame_pointer.contents.height,
                frame_pointer.contents.columns,
                frame_pointer.contents.count,
            ),
            (1600000, 900000, 6, 18),
        )
        for _ in range(8):
            self.library.cl_target_test_clobber_stack()
        self.assertEqual(bytes(self._frame(fixture)), copied)
        self.assertEqual(bytes(fixture.manifest), before_manifest)
        self._assert_safety_zero(fixture)

        calls = tuple(fixture.calls)
        before = bytes(fixture.shell)
        second = bridge_abi.BridgeReport()
        ctypes.memset(ctypes.byref(second), 0x4A, ctypes.sizeof(second))
        self.assertEqual(
            self.library.cl_target_shell_open(ctypes.byref(fixture.shell), ctypes.byref(second)),
            bridge_abi.CL_ERR_ALREADY_OPEN,
        )
        self.assertEqual((bytes(fixture.shell), tuple(fixture.calls)), (before, calls))

        close_result, close_report = fixture.close()
        self.assertEqual(close_result, bridge_abi.CL_OK)
        self.assertEqual((fixture.shell.bridge.opened, fixture.shell.bridge.input_attached), (0, 0))
        self.assertFalse(fixture.shell.retained_sink)
        self.assertFalse(fixture.shell.retained_sink_context)
        self._assert_safety_zero(fixture)
        self.assertEqual(bytes(self._frame(fixture)), copied)
        last = self.library.cl_target_shell_last_report(ctypes.byref(fixture.shell))
        self.assertEqual(ctypes.addressof(last.contents), ctypes.addressof(fixture.shell.bridge.last_report))
        self.assertEqual(bytes(last.contents), bytes(close_report))
        event = bridge_abi.InputEvent(0, 0, bridge_abi.CL_INPUT_ORIENTATION, 1, (ctypes.c_uint8 * 2)(0, 0))
        stale_report = bridge_abi.BridgeReport()
        before = (bytes(fixture.shell), bytes(stale_report))
        self.assertEqual(fixture.deliver(event, stale_report)[0], bridge_abi.CL_ERR_NOT_OPEN)
        self.assertEqual((bytes(fixture.shell), bytes(stale_report)), before)

    def test_post_attach_sync_errors_remain_deliverable_until_completed_close(self):
        """Break caught: an error return is mistaken for a failed admission and drops the sink."""
        failure_bits = {
            "save": 0x02,
            "model": 0x04,
            "live_view": 0x08,
            "still_jpeg": 0x10,
            "movie": 0x20,
        }
        for callback_name, failure_bit in failure_bits.items():
            with self.subTest(callback=callback_name):
                fixture = self._fresh(callback_results={callback_name: 71})
                result, report = fixture.open()
                self.assertEqual(result, bridge_abi.CL_ERR_ADAPTER)
                self.assertEqual(
                    (
                        report.attempted,
                        report.succeeded,
                        report.failed,
                        report.dirty,
                        report.state_committed,
                        report.opened,
                        report.state_revision,
                        report.processing_revision,
                    ),
                    (
                        0x3F,
                        0x3F ^ failure_bit,
                        failure_bit,
                        failure_bit,
                        1,
                        1,
                        1,
                        1,
                    ),
                )
                self.assertEqual(
                    fixture.calls,
                    ["load", "save", "model", "live_view", "still_jpeg", "movie"],
                )
                self.assertEqual((fixture.shell.bridge.opened, fixture.shell.bridge.input_attached), (1, 1))
                self.assertTrue(fixture.shell.retained_sink)
                self._assert_manifest_identity(fixture)

                fixture.callback_results[callback_name] = 0
                baseline = self._transition_baseline(fixture)
                delivered, delivery_report = self._touch(
                    fixture, 1, primary=1
                )
                expected = self._literal_state(
                    selected_look=1,
                    screen=bridge_abi.CL_SCREEN_EDITOR,
                )
                self._assert_transition_evidence(
                    fixture,
                    baseline,
                    delivered,
                    delivery_report,
                    expected,
                    processing=True,
                    effective_base=1,
                )
                self.assertEqual(fixture.shell.bridge.dirty_mask, 0)
                self.assertEqual(fixture.close()[0], bridge_abi.CL_OK)
                self.assertFalse(fixture.shell.retained_sink)
                self._assert_manifest_identity(fixture)

    def test_deliver_uses_only_retained_pair_and_rejects_invalid_or_stale_events_atomically(self):
        """Break caught: delivery bypasses the retained sink or stores/accepts malformed event pointers."""
        fixture = self._fresh()
        event = bridge_abi.InputEvent(0, 0, bridge_abi.CL_INPUT_ORIENTATION, 1, (ctypes.c_uint8 * 2)(0, 0))
        report = bridge_abi.BridgeReport()
        ctypes.memset(ctypes.byref(report), 0x31, ctypes.sizeof(report))
        before = (bytes(fixture.shell), bytes(report))
        self.assertEqual(fixture.deliver(event, report)[0], bridge_abi.CL_ERR_NOT_OPEN)
        self.assertEqual((bytes(fixture.shell), bytes(report)), before)
        self.assertEqual(fixture.open()[0], bridge_abi.CL_OK)

        poison_calls = []
        poison = native_abi.retain_callback(
            fixture,
            bridge_abi.InputSinkCallback,
            lambda context, event_pointer, _report: poison_calls.append(
                (context, event_pointer.contents.value)
            ) or 77,
        )
        retained_sink_address = ctypes.cast(
            fixture.shell.retained_sink, ctypes.c_void_p
        ).value
        retained_context = fixture.shell.retained_sink_context
        fixture.shell.retained_sink = poison
        fixture.shell.retained_sink_context = 0x77778888
        before_state = bytes(fixture.shell.bridge.state)
        poison_report = bridge_abi.BridgeReport()
        ctypes.memset(ctypes.byref(poison_report), 0x42, ctypes.sizeof(poison_report))
        before_report = bytes(poison_report)
        self.assertEqual(fixture.deliver(event, poison_report)[0], 77)
        self.assertEqual(poison_calls, [(0x77778888, 1)])
        self.assertEqual(bytes(fixture.shell.bridge.state), before_state)
        self.assertEqual(bytes(poison_report), before_report)
        fixture.shell.retained_sink = bridge_abi.InputSinkCallback(
            retained_sink_address
        )
        fixture.shell.retained_sink_context = retained_context
        self.assertEqual(fixture.deliver(event)[0], bridge_abi.CL_OK)
        event.value = 2
        self.assertEqual(self._state(fixture).orientation, 1)

        invalid_events = (
            bridge_abi.InputEvent(0, 0, 9, 0, (ctypes.c_uint8 * 2)(0, 0)),
            bridge_abi.InputEvent(0, 0, bridge_abi.CL_INPUT_TOUCH, 1, (ctypes.c_uint8 * 2)(0, 0)),
            bridge_abi.InputEvent(1, 0, bridge_abi.CL_INPUT_ORIENTATION, 1, (ctypes.c_uint8 * 2)(0, 0)),
            bridge_abi.InputEvent(0, 0, bridge_abi.CL_INPUT_ORIENTATION, 3, (ctypes.c_uint8 * 2)(0, 0)),
            bridge_abi.InputEvent(0, 0, bridge_abi.CL_INPUT_ORIENTATION, 1, (ctypes.c_uint8 * 2)(1, 0)),
        )
        for invalid in invalid_events:
            invalid_report = bridge_abi.BridgeReport()
            ctypes.memset(ctypes.byref(invalid_report), 0x29, ctypes.sizeof(invalid_report))
            before = (
                bytes(fixture.shell.bridge.state),
                fixture.shell.bridge.state_revision,
                fixture.shell.bridge.processing_revision,
                fixture.shell.bridge.dirty_mask,
                bytes(fixture.shell.copied_frame),
                ctypes.cast(fixture.shell.retained_sink, ctypes.c_void_p).value,
                fixture.shell.retained_sink_context,
                tuple(fixture.calls),
            )
            with self.subTest(event=bytes(invalid)):
                self.assertEqual(fixture.deliver(invalid, invalid_report)[0], bridge_abi.CL_ERR_ARGUMENT)
                self.assertEqual(invalid_report.transition_result, bridge_abi.CL_ERR_ARGUMENT)
                self.assertEqual(invalid_report.state_committed, 0)
                self.assertEqual(
                    bytes(
                        self.library.cl_target_shell_last_report(
                            ctypes.byref(fixture.shell)
                        ).contents
                    ),
                    bytes(invalid_report),
                )
                self.assertEqual(
                    (
                        bytes(fixture.shell.bridge.state),
                        fixture.shell.bridge.state_revision,
                        fixture.shell.bridge.processing_revision,
                        fixture.shell.bridge.dirty_mask,
                        bytes(fixture.shell.copied_frame),
                        ctypes.cast(fixture.shell.retained_sink, ctypes.c_void_p).value,
                        fixture.shell.retained_sink_context,
                        tuple(fixture.calls),
                    ),
                    before,
                )

        null_report = bridge_abi.BridgeReport()
        ctypes.memset(ctypes.byref(null_report), 0x27, ctypes.sizeof(null_report))
        before_shell = bytes(fixture.shell)
        self.assertEqual(
            self.library.cl_target_shell_deliver(ctypes.byref(fixture.shell), None, ctypes.byref(null_report)),
            bridge_abi.CL_ERR_ARGUMENT,
        )
        self.assertEqual(bytes(fixture.shell), before_shell)
        self.assertEqual(
            self.library.cl_target_shell_deliver(ctypes.byref(fixture.shell), ctypes.byref(event), None),
            bridge_abi.CL_ERR_ARGUMENT,
        )
        self.assertEqual(bytes(fixture.shell), before_shell)
        self.assertEqual(fixture.close()[0], bridge_abi.CL_OK)

    def test_reentrant_delivery_and_close_are_busy_and_preserve_the_retained_sink(self):
        """Break caught: a nested callback clears sink ownership or completes close while busy."""
        callbacks = (
            "load",
            "save",
            "model",
            "live_view",
            "still_jpeg",
            "movie",
        )
        fixture = self._fresh(
            reenter_deliver_on=callbacks,
            reenter_close_on=callbacks,
        )
        self.assertEqual(fixture.open()[0], bridge_abi.CL_OK)
        self.assertTrue(fixture.shell.retained_sink)
        self.assertTrue(fixture.reentry)
        for callback_name, operation, result, atomic in fixture.reentry:
            with self.subTest(callback=callback_name, operation=operation):
                self.assertEqual(result, bridge_abi.CL_ERR_BUSY)
                self.assertTrue(atomic)
        sink = fixture.shell.retained_sink
        context = fixture.shell.retained_sink_context
        fixture.reentry.clear()
        result, _report = self._orient(fixture, 1)
        self.assertEqual(result, bridge_abi.CL_OK)
        self.assertTrue(fixture.reentry)
        self.assertEqual(
            ctypes.cast(fixture.shell.retained_sink, ctypes.c_void_p).value,
            ctypes.cast(sink, ctypes.c_void_p).value,
        )
        self.assertEqual(fixture.shell.retained_sink_context, context)
        self.assertEqual(fixture.close()[0], bridge_abi.CL_OK)

    def test_all_looks_custom_bases_axes_and_orientations_flow_only_through_shell_delivery(self):
        """Break caught: a catalog/editor case is unreachable through the shell-retained sink."""
        fixture = self._fresh()
        open_result, open_report = fixture.open()
        self._assert_open_evidence(fixture, open_result, open_report)
        for look in tuple(range(1, 12)) + (0,):
            with self.subTest(built_in=look):
                baseline = self._transition_baseline(fixture)
                result, report = self._touch(fixture, 1, primary=look)
                expected = self._literal_state(
                    selected_look=look,
                    screen=bridge_abi.CL_SCREEN_EDITOR,
                )
                self._assert_transition_evidence(
                    fixture,
                    baseline,
                    result,
                    report,
                    expected,
                    processing=True,
                    effective_base=look,
                )
                baseline = self._transition_baseline(fixture)
                result, report = self._touch(
                    fixture, bridge_abi.CL_UI_ACTION_CATALOG
                )
                expected = self._literal_state(selected_look=look)
                self._assert_transition_evidence(
                    fixture,
                    baseline,
                    result,
                    report,
                    expected,
                    processing=False,
                )
        self.assertEqual(fixture.close()[0], bridge_abi.CL_OK)
        self._assert_manifest_identity(fixture)

        for slot in range(6):
            for base in range(12):
                with self.subTest(custom_slot=slot, base=base):
                    custom = self._fresh()
                    open_result, open_report = custom.open()
                    self._assert_open_evidence(custom, open_result, open_report)
                    look = 12 + slot
                    baseline = self._transition_baseline(custom)
                    result, report = self._touch(custom, 1, primary=look)
                    expected = self._literal_state(
                        selected_look=look,
                        screen=bridge_abi.CL_SCREEN_CUSTOM_BASE,
                    )
                    self._assert_transition_evidence(
                        custom,
                        baseline,
                        result,
                        report,
                        expected,
                        processing=False,
                    )
                    expected_bases = [bridge_abi.CL_UNSET] * 6
                    expected_bases[slot] = base
                    baseline = self._transition_baseline(custom)
                    result, report = self._touch(custom, 2, primary=base)
                    expected = self._literal_state(
                        selected_look=look,
                        screen=bridge_abi.CL_SCREEN_EDITOR,
                        custom_bases=expected_bases,
                    )
                    self._assert_transition_evidence(
                        custom,
                        baseline,
                        result,
                        report,
                        expected,
                        processing=True,
                        effective_base=base,
                    )
                    self.assertEqual(custom.close()[0], bridge_abi.CL_OK)
                    self._assert_manifest_identity(custom)

        axes = self._fresh()
        open_result, open_report = axes.open()
        self._assert_open_evidence(axes, open_result, open_report)
        baseline = self._transition_baseline(axes)
        result, report = self._touch(axes, 1, primary=0)
        expected_rows = [[bridge_abi.CL_AXIS_DEFAULT] * 8 for _ in range(18)]
        expected = self._literal_state(
            screen=bridge_abi.CL_SCREEN_EDITOR,
            adjustments=expected_rows,
        )
        self._assert_transition_evidence(
            axes,
            baseline,
            result,
            report,
            expected,
            processing=False,
        )
        for axis, minimum, maximum in bridge_abi.AXIS_CASES:
            for value in (minimum, bridge_abi.CL_AXIS_DEFAULT, maximum):
                with self.subTest(axis=axis, value=value):
                    baseline = self._transition_baseline(axes)
                    result, report = self._touch(axes, 3, primary=axis)
                    expected = self._literal_state(
                        screen=bridge_abi.CL_SCREEN_AXIS_PICKER,
                        editing_axis=axis,
                        adjustments=expected_rows,
                    )
                    self._assert_transition_evidence(
                        axes,
                        baseline,
                        result,
                        report,
                        expected,
                        processing=False,
                    )
                    baseline = self._transition_baseline(axes)
                    result, report = self._touch(
                        axes, 4, primary=axis, value=value
                    )
                    expected_rows[0][axis] = value
                    expected = self._literal_state(
                        screen=bridge_abi.CL_SCREEN_EDITOR,
                        adjustments=expected_rows,
                    )
                    self._assert_transition_evidence(
                        axes,
                        baseline,
                        result,
                        report,
                        expected,
                        processing=True,
                        effective_base=0,
                    )
        self.assertEqual(axes.close()[0], bridge_abi.CL_OK)
        self._assert_manifest_identity(axes)

        orientations = self._fresh()
        open_result, open_report = orientations.open()
        self._assert_open_evidence(orientations, open_result, open_report)
        expected_sizes = {1: (900000, 1600000), 2: (900000, 1600000), 0: (1600000, 900000)}
        for orientation in (1, 2, 0):
            with self.subTest(orientation=orientation):
                baseline = self._transition_baseline(orientations)
                result, report = self._orient(orientations, orientation)
                expected = self._literal_state(orientation=orientation)
                self._assert_transition_evidence(
                    orientations,
                    baseline,
                    result,
                    report,
                    expected,
                    processing=False,
                )
                self.assertEqual((self._frame(orientations).width, self._frame(orientations).height), expected_sizes[orientation])
        self.assertEqual(orientations.close()[0], bridge_abi.CL_OK)
        self._assert_manifest_identity(orientations)

    def test_tampered_shell_owned_wrapper_is_rejected_until_exact_identity_is_restored(self):
        """Break caught: public operations trust a replaced shell-owned adapter."""
        fixture = self._fresh()
        self.assertEqual(fixture.open()[0], bridge_abi.CL_OK)
        original_address = ctypes.cast(
            fixture.shell.bridge.adapters.input.detach, ctypes.c_void_p
        ).value
        tampered_detach = native_abi.retain_callback(
            fixture,
            bridge_abi.InputDetachCallback,
            lambda _context: 73,
        )
        fixture.shell.bridge.adapters.input.detach = tampered_detach
        report = bridge_abi.BridgeReport()
        ctypes.memset(ctypes.byref(report), 0x43, ctypes.sizeof(report))
        before = (bytes(fixture.shell), bytes(report), tuple(fixture.calls))
        self.assertEqual(
            self.library.cl_target_shell_close(
                ctypes.byref(fixture.shell), ctypes.byref(report)
            ),
            bridge_abi.CL_ERR_STATE,
        )
        self.assertEqual(
            (bytes(fixture.shell), bytes(report), tuple(fixture.calls)), before
        )
        self.assertFalse(
            self.library.cl_target_shell_bridge_state(ctypes.byref(fixture.shell))
        )
        restored_detach = bridge_abi.InputDetachCallback(original_address)
        fixture._native_callbacks.append(restored_detach)
        fixture.shell.bridge.adapters.input.detach = restored_detach
        self.assertEqual(fixture.close()[0], bridge_abi.CL_OK)
        self.assertEqual(
            (fixture.shell.bridge.opened, fixture.shell.bridge.input_attached),
            (0, 0),
        )
        self.assertFalse(fixture.shell.retained_sink)
        self.assertFalse(fixture.shell.retained_sink_context)
        self._assert_manifest_identity(fixture)

    def test_null_calls_and_corrupted_markers_are_rejected_without_mutation(self):
        """Break caught: accessors trust only the outer marker or null APIs write outputs."""
        fixture = self._fresh()
        relocated = TargetShell.from_buffer_copy(fixture.shell)
        relocated_report = bridge_abi.BridgeReport()
        ctypes.memset(
            ctypes.byref(relocated_report), 0x53, ctypes.sizeof(relocated_report)
        )
        relocation_event = bridge_abi.InputEvent(
            0,
            0,
            bridge_abi.CL_INPUT_ORIENTATION,
            1,
            (ctypes.c_uint8 * 2)(0, 0),
        )
        relocated_before = bytes(relocated)
        original_before = bytes(fixture.shell)
        report_before = bytes(relocated_report)
        self.assertFalse(
            self.library.cl_target_shell_copied_frame(ctypes.byref(relocated))
        )
        self.assertFalse(
            self.library.cl_target_shell_bridge_state(ctypes.byref(relocated))
        )
        self.assertFalse(
            self.library.cl_target_shell_last_report(ctypes.byref(relocated))
        )
        for operation in (
            lambda: self.library.cl_target_shell_init(
                ctypes.byref(relocated),
                ctypes.byref(fixture.manifest),
                ctypes.byref(fixture.adapters),
            ),
            lambda: self.library.cl_target_shell_open(
                ctypes.byref(relocated), ctypes.byref(relocated_report)
            ),
            lambda: self.library.cl_target_shell_close(
                ctypes.byref(relocated), ctypes.byref(relocated_report)
            ),
            lambda: self.library.cl_target_shell_deliver(
                ctypes.byref(relocated),
                ctypes.byref(relocation_event),
                ctypes.byref(relocated_report),
            ),
        ):
            with self.subTest(relocated_operation=operation):
                self.assertEqual(operation(), bridge_abi.CL_ERR_STATE)
                self.assertEqual(bytes(relocated), relocated_before)
                self.assertEqual(bytes(fixture.shell), original_before)
                self.assertEqual(bytes(relocated_report), report_before)

        report = bridge_abi.BridgeReport()
        ctypes.memset(ctypes.byref(report), 0x6A, ctypes.sizeof(report))
        before = bytes(report)
        self.assertEqual(self.library.cl_target_shell_open(None, ctypes.byref(report)), bridge_abi.CL_ERR_ARGUMENT)
        self.assertEqual(self.library.cl_target_shell_close(None, ctypes.byref(report)), bridge_abi.CL_ERR_ARGUMENT)
        self.assertEqual(bytes(report), before)
        shell_before = bytes(fixture.shell)
        self.assertEqual(self.library.cl_target_shell_open(ctypes.byref(fixture.shell), None), bridge_abi.CL_ERR_ARGUMENT)
        self.assertEqual(self.library.cl_target_shell_close(ctypes.byref(fixture.shell), None), bridge_abi.CL_ERR_ARGUMENT)
        self.assertEqual(bytes(fixture.shell), shell_before)

        fixture.shell.bridge.initialization_marker ^= 1
        corrupted = bytes(fixture.shell)
        self.assertFalse(self.library.cl_target_shell_copied_frame(ctypes.byref(fixture.shell)))
        self.assertFalse(self.library.cl_target_shell_bridge_state(ctypes.byref(fixture.shell)))
        self.assertFalse(self.library.cl_target_shell_last_report(ctypes.byref(fixture.shell)))
        self.assertEqual(self.library.cl_target_shell_open(ctypes.byref(fixture.shell), ctypes.byref(report)), bridge_abi.CL_ERR_STATE)
        self.assertEqual(bytes(fixture.shell), corrupted)


class CreativeLookTargetShellCompileTests(unittest.TestCase):
    def _run_clean(self, command, label):
        completed = subprocess.run(
            [str(item) for item in command],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, f"{label}: {completed.stderr or completed.stdout}")
        self.assertEqual(completed.stdout, "", label)
        self.assertEqual(completed.stderr, "", label)

    def test_target_shell_strict_hosted_freestanding_analyzer_and_host_link_are_clean(self):
        """Break caught: the shell adds warnings, runtime dependencies, or direct core/event bypasses."""
        sources = (
            native_abi.CORE_SOURCE,
            native_abi.VIEW_SOURCE,
            NATIVE_ROOT / "creative_look_bridge.c",
            TARGET_SOURCE,
        )
        with tempfile.TemporaryDirectory(prefix="creative-look-target-task3-") as directory_name:
            directory = Path(directory_name)
            hosted = directory / "creative-look-target.dll"
            self._run_clean([*native_abi.strict_c99_command(), "-shared", "-o", hosted, *sources], "hosted shell")
            objects = []
            target_object = None
            for source in sources:
                hosted_object = directory / f"{source.stem}-hosted.o"
                self._run_clean([*native_abi.strict_c99_command(), "-c", source, "-o", hosted_object], f"hosted {source.name}")
                freestanding = directory / f"{source.stem}-freestanding.o"
                self._run_clean([*native_abi.strict_c99_command(), "-ffreestanding", "-fno-builtin", "-c", source, "-o", freestanding], f"freestanding {source.name}")
                objects.append(freestanding)
                if source == TARGET_SOURCE:
                    target_object = freestanding
            combined = native_abi.link_relocatable(directory, "creative-look-target", objects)
            native_abi.assert_no_undefined_symbols(combined, "host core/view/bridge/target")
            analyzer = directory / "creative-look-target-analyzer.o"
            self._run_clean([*native_abi.strict_c99_command(), "-fanalyzer", "-c", TARGET_SOURCE, "-o", analyzer], "target analyzer")

            nm = shutil.which("nm")
            self.assertIsNotNone(nm)
            undefined = subprocess.run([nm, "-u", "-P", target_object], cwd=ROOT, capture_output=True, text=True, check=True).stdout
            allowed_undefined = {
                "cl_bridge_init",
                "cl_bridge_open",
                "cl_bridge_close",
                "cl_bridge_state",
                "cl_bridge_last_report",
            }

            def assert_neutral_undefined(symbol_text):
                names = {
                    line.split()[0]
                    for line in symbol_text.splitlines()
                    if line.strip()
                }
                self.assertTrue(names <= allowed_undefined, names)

            assert_neutral_undefined(undefined)
            with self.assertRaises(AssertionError):
                assert_neutral_undefined(
                    undefined + "cl_bridge_handle_event U         \n"
                )
            defined = subprocess.run([nm, "-g", "--defined-only", "-P", target_object], cwd=ROOT, capture_output=True, text=True, check=True).stdout
            def assert_no_factory_export(symbol_text):
                names = {
                    line.split()[0]
                    for line in symbol_text.splitlines()
                    if line.strip()
                }
                self.assertNotIn("ViewCreativeLookToInstance", names)

            assert_no_factory_export(defined)
            with self.assertRaises(AssertionError):
                assert_no_factory_export(
                    defined + "ViewCreativeLookToInstance T 0 0\n"
                )

    def test_real_arm_probe_pins_target_shell_and_identity_layouts(self):
        """Break caught: the public shell record changes under the pinned 32-bit target ABI."""
        gcc = TOOLCHAIN_ROOT / "bin" / "arm-none-eabi-gcc.exe"
        if not gcc.is_file():
            self.skipTest("pinned Arm toolchain absent; publication requires this real gate")
        with tempfile.TemporaryDirectory(prefix="creative-look-target-abi-") as directory_name:
            directory = Path(directory_name)
            probe = directory / "target-shell-abi-probe.c"
            probe.write_text(
                '#include <stddef.h>\n#include "creative_look_target.h"\n'
                '#define CL_ALIGNOF(type) offsetof(struct { char c; type value; }, value)\n'
                'typedef char a0[(sizeof(cl_target_shell)==1200u)?1:-1];\n'
                'typedef char a1[(CL_ALIGNOF(cl_target_shell)==4u)?1:-1];\n'
                'typedef char a2[(offsetof(cl_target_shell,bridge)==CL_TARGET_SHELL_ARM_BRIDGE_OFFSET && CL_TARGET_SHELL_ARM_BRIDGE_OFFSET==0u)?1:-1];\n'
                'typedef char a3[(offsetof(cl_target_shell,copied_frame)==CL_TARGET_SHELL_ARM_FRAME_OFFSET && CL_TARGET_SHELL_ARM_FRAME_OFFSET==692u)?1:-1];\n'
                'typedef char a4[(offsetof(cl_target_shell,retained_sink)==CL_TARGET_SHELL_ARM_SINK_OFFSET && CL_TARGET_SHELL_ARM_SINK_OFFSET==1184u)?1:-1];\n'
                'typedef char a5[(offsetof(cl_target_shell,retained_sink_context)==CL_TARGET_SHELL_ARM_SINK_CONTEXT_OFFSET && CL_TARGET_SHELL_ARM_SINK_CONTEXT_OFFSET==1188u)?1:-1];\n'
                'typedef char a6[(offsetof(cl_target_shell,initialization_marker)==CL_TARGET_SHELL_ARM_MARKER_OFFSET && CL_TARGET_SHELL_ARM_MARKER_OFFSET==1192u)?1:-1];\n'
                'typedef char a7[(offsetof(cl_target_shell,frame_valid)==CL_TARGET_SHELL_ARM_FRAME_VALID_OFFSET && CL_TARGET_SHELL_ARM_FRAME_VALID_OFFSET==1196u)?1:-1];\n'
                'typedef char a8[(offsetof(cl_target_shell,delivering)==CL_TARGET_SHELL_ARM_DELIVERING_OFFSET && CL_TARGET_SHELL_ARM_DELIVERING_OFFSET==1197u)?1:-1];\n'
                'typedef char b0[(sizeof(cl_target_identity)==16u)?1:-1];\n'
                'typedef char b1[(CL_ALIGNOF(cl_target_identity)==4u)?1:-1];\n'
                'typedef char b2[(offsetof(cl_target_identity,publication_status)==CL_TARGET_IDENTITY_ARM_STATUS_OFFSET && CL_TARGET_IDENTITY_ARM_STATUS_OFFSET==12u)?1:-1];\n'
                'static size_t (*const p_size)(void)=cl_target_shell_size;\n'
                'static size_t (*const p_align)(void)=cl_target_shell_alignment;\n'
                'static cl_result (*const p_init)(cl_target_shell *,const cl_integration_manifest *,const cl_bridge_adapters *)=cl_target_shell_init;\n'
                'static cl_result (*const p_open)(cl_target_shell *,cl_bridge_report *)=cl_target_shell_open;\n'
                'static cl_result (*const p_close)(cl_target_shell *,cl_bridge_report *)=cl_target_shell_close;\n'
                'static cl_result (*const p_deliver)(cl_target_shell *,const cl_input_event *,cl_bridge_report *)=cl_target_shell_deliver;\n'
                'static const cl_view_frame *(*const p_frame)(const cl_target_shell *)=cl_target_shell_copied_frame;\n'
                'static const cl_state *(*const p_state)(const cl_target_shell *)=cl_target_shell_bridge_state;\n'
                'static const cl_bridge_report *(*const p_report)(const cl_target_shell *)=cl_target_shell_last_report;\n'
                'static const cl_target_identity *(*const p_identity)(void)=cl_target_shell_identity;\n'
                'int cl_target_probe_use(void) { return p_size != 0 && p_align != 0 && p_init != 0 && p_open != 0 && p_close != 0 && p_deliver != 0 && p_frame != 0 && p_state != 0 && p_report != 0 && p_identity != 0; }\n',
                encoding="utf-8",
            )
            output = directory / "target-shell-abi-probe.o"
            self._run_clean([gcc, *COMPILE_FLAGS, "-I", NATIVE_ROOT, "-c", probe, "-o", output], "ARM shell ABI probe")
            target_object = directory / "creative-look-target.o"
            self._run_clean([gcc, *COMPILE_FLAGS, "-I", NATIVE_ROOT, "-c", TARGET_SOURCE, "-o", target_object], "ARM shell object")
            nm = TOOLCHAIN_ROOT / "bin" / "arm-none-eabi-nm.exe"
            completed = subprocess.run([nm, "-u", "-P", target_object], cwd=ROOT, capture_output=True, text=True, check=True)
            undefined = {line.split()[0] for line in completed.stdout.splitlines() if line.strip()}
            self.assertTrue(undefined)
            self.assertTrue(undefined <= {"cl_bridge_init", "cl_bridge_open", "cl_bridge_close", "cl_bridge_state", "cl_bridge_last_report"}, undefined)
            self.assertNotIn("cl_bridge_handle_event", undefined)

    def test_target_source_has_only_neutral_metadata_not_runtime_publication(self):
        """Break caught: the neutral shell silently grows a Sony loader/runtime binding."""
        combined = TARGET_HEADER.read_text(encoding="utf-8") + "\n" + TARGET_SOURCE.read_text(encoding="utf-8")
        for forbidden in (
            "dlopen(", "dlsym(", "IdSoTable", "IdGenerator", "openView(",
            "/setting", "Backup", "MprIf", "EncodeStill", "libusb", "/dev/",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, combined)
        self.assertEqual(combined.count("ViewCreativeLookToInstance"), 1)


if __name__ == "__main__":
    unittest.main()
