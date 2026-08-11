"""Fail-closed tests for the Creative Look ARM target/toolchain profile."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PROFILE_PATH = ROOT / "analysis" / "a6400-creative-look-arm-target-profile.json"
MODULE_PATH = ROOT / "pmca" / "analysis" / "creative_look_arm_target_profile.py"

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


if __name__ == "__main__":
    unittest.main()
