"""Fail-closed tests for the Creative Look ARM target/toolchain profile."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
PROFILE_PATH = ROOT / "analysis" / "a6400-creative-look-arm-target-profile.json"
MODULE_PATH = ROOT / "pmca" / "analysis" / "creative_look_arm_target_profile.py"
EXPORTER_PATH = ROOT / "tools" / "static" / "export_a6400_creative_look_arm_target.py"
TOOLCHAIN_ROOT = ROOT / ".artifacts" / "toolchains" / "15.2.rel1-extracted"
NATIVE_ROOT = ROOT / "native" / "a6400_creative_look"

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


if __name__ == "__main__":
    unittest.main()
