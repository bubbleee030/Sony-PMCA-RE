"""Validate the pinned Creative Look ARM target/toolchain profile."""
from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path


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
ATTRIBUTE_POLICY = {
    "mandatory": TARGET_ATTRIBUTES,
    "prohibited": PROHIBITED_ATTRIBUTES,
    "extra_attributes": "record-and-permit",
}
SAFETY_FIELDS = (
    "processing_binding_proven",
    "recovery_validated",
    "camera_test_eligible",
    "installable",
)
READINESS = "PINNED_ARM_TARGET_PROFILE_ONLY__NO_TARGET_OBJECT_OR_RUNTIME"
CONCLUSION = (
    "The official Arm GNU Toolchain acquisition contract and the "
    "alpha 6400-compatible ARMv7-A/Thumb-2 softfp ET_REL profile are pinned "
    "for offline static use only. Mandatory attributes and the absence of "
    "hard-float argument passing are enforced, while benign compiler "
    "attributes are recorded. No toolchain archive, target object, Sony "
    "runtime binding, processing binding, recovery validation, camera-test "
    "eligibility, or installability is established by this profile."
)

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class CreativeLookArmTargetProfileError(ValueError):
    """Raised when the target/toolchain profile exceeds its static contract."""


def canonical_digest(value: object) -> str:
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def _exact_dict(value: object, fields: tuple[str, ...], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != set(fields):
        raise CreativeLookArmTargetProfileError(f"{label} fields differ")
    return value


def _same_typed_structure(value: object, expected: object) -> bool:
    if type(value) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(value) == set(expected) and all(
            _same_typed_structure(value[key], expected[key]) for key in expected
        )
    if isinstance(expected, list):
        return len(value) == len(expected) and all(
            _same_typed_structure(item, wanted)
            for item, wanted in zip(value, expected)
        )
    return value == expected


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _profile_without_contract_digest(document: dict) -> dict:
    profile = copy.deepcopy(document)
    profile.pop("contract_sha256", None)
    return profile


def validate_arm_target_attributes(attributes: object) -> dict:
    """Require mandatory ABI attributes, forbid hard-float, and record extras."""
    if not isinstance(attributes, list) or len(attributes) > 256:
        raise CreativeLookArmTargetProfileError("ARM attribute record is invalid")
    normalized = []
    seen_tags = set()
    for attribute in attributes:
        item = _exact_dict(attribute, ("tag", "name", "value"), "ARM attribute")
        if (
            type(item["tag"]) is not int
            or item["tag"] <= 0
            or not isinstance(item["name"], str)
            or not item["name"].startswith("Tag_")
            or type(item["value"]) not in (str, int, bool)
            or item["tag"] in seen_tags
        ):
            raise CreativeLookArmTargetProfileError("ARM attribute record is invalid")
        if item["tag"] == 28 or item["name"] == "Tag_ABI_VFP_args":
            raise CreativeLookArmTargetProfileError("hard-float attribute is prohibited")
        seen_tags.add(item["tag"])
        normalized.append(copy.deepcopy(item))

    mandatory = []
    mandatory_tags = {item["tag"] for item in TARGET_ATTRIBUTES}
    for expected in TARGET_ATTRIBUTES:
        matches = [item for item in normalized if item["tag"] == expected["tag"]]
        if len(matches) != 1 or not _same_typed_structure(matches[0], expected):
            raise CreativeLookArmTargetProfileError("mandatory ARM attribute differs")
        mandatory.append(copy.deepcopy(expected))
    return {
        "mandatory": mandatory,
        "extra": [
            copy.deepcopy(item) for item in normalized if item["tag"] not in mandatory_tags
        ],
    }


def normalize_creative_look_arm_target_profile(document: object) -> dict:
    """Validate and copy the exact offline ARM target/toolchain profile."""
    profile = _exact_dict(
        document,
        (
            "schema_version",
            "analysis_scope",
            "camera_policy",
            "camera_executed",
            "target",
            "toolchain",
            "build",
            "safety",
            "readiness",
            "conclusion",
            "narrative_sha256",
            "contract_sha256",
        ),
        "profile",
    )
    if (
        type(profile["schema_version"]) is not int
        or profile["schema_version"] != 1
        or profile["analysis_scope"] != "offline-static-arm-target-profile"
        or profile["camera_policy"] != "physically-disconnected"
        or profile["camera_executed"] is not False
    ):
        raise CreativeLookArmTargetProfileError("profile scope differs")

    target = _exact_dict(
        profile["target"],
        ("module", "sha256", "elf", "attribute_policy", "float_call_abi"),
        "target",
    )
    if (
        target["module"] != "lib/viewUnified2.so"
        or target["sha256"] != TARGET_SHA256
        or not _is_sha256(target["sha256"])
    ):
        raise CreativeLookArmTargetProfileError("target identity differs")
    elf = _exact_dict(
        target["elf"],
        ("class", "data", "machine", "eabi_version"),
        "ELF",
    )
    if not _same_typed_structure(elf, {
        "class": "ELF32",
        "data": "little-endian",
        "machine": "ARM",
        "eabi_version": 5,
    }):
        raise CreativeLookArmTargetProfileError("ELF target differs")
    if not _same_typed_structure(target["attribute_policy"], ATTRIBUTE_POLICY):
        raise CreativeLookArmTargetProfileError("ARM attribute policy differs")
    float_abi = _exact_dict(
        target["float_call_abi"],
        ("kind", "hard_float_tag", "hard_float_tag_present"),
        "float call ABI",
    )
    if not _same_typed_structure(float_abi, {
        "kind": "softfp",
        "hard_float_tag": 28,
        "hard_float_tag_present": False,
    }):
        raise CreativeLookArmTargetProfileError("float call ABI differs")

    toolchain = _exact_dict(
        profile["toolchain"],
        (
            "vendor",
            "release",
            "target_triple",
            "archive_basename",
            "release_url",
            "archive_url",
            "checksum_url",
            "archive_sha256",
            "checksum_record",
        ),
        "toolchain",
    )
    expected_toolchain = {
        "vendor": "Arm",
        "release": "15.2.Rel1",
        "target_triple": "arm-none-eabi",
        "archive_basename": ARCHIVE_BASENAME,
        "release_url": RELEASE_URL,
        "archive_url": ARCHIVE_URL,
        "checksum_url": CHECKSUM_URL,
        "archive_sha256": ARCHIVE_SHA256,
        "checksum_record": ARCHIVE_SHA256 + " *" + ARCHIVE_BASENAME,
    }
    if not _same_typed_structure(toolchain, expected_toolchain) or not _is_sha256(
        toolchain["archive_sha256"]
    ):
        raise CreativeLookArmTargetProfileError("official toolchain contract differs")

    build = _exact_dict(profile["build"], ("compile_flags", "link"), "build")
    if not _same_typed_structure(build["compile_flags"], COMPILE_FLAGS):
        raise CreativeLookArmTargetProfileError("compile flags differ")
    link = _exact_dict(
        build["link"],
        ("driver", "mode", "output_type", "output_suffix"),
        "link",
    )
    if not _same_typed_structure(link, {
        "driver": "arm-none-eabi-ld",
        "mode": ["-r"],
        "output_type": "ET_REL",
        "output_suffix": ".o",
    }):
        raise CreativeLookArmTargetProfileError("relocatable link contract differs")

    safety = _exact_dict(profile["safety"], SAFETY_FIELDS, "safety")
    if any(type(safety[field]) is not int or safety[field] != 0 for field in SAFETY_FIELDS):
        raise CreativeLookArmTargetProfileError("safety gate promoted")
    if profile["readiness"] != READINESS or profile["conclusion"] != CONCLUSION:
        raise CreativeLookArmTargetProfileError("fail-closed narrative differs")
    narrative_sha256 = hashlib.sha256(CONCLUSION.encode("utf-8")).hexdigest()
    if profile["narrative_sha256"] != narrative_sha256:
        raise CreativeLookArmTargetProfileError("narrative digest differs")
    if (
        not _is_sha256(profile["contract_sha256"])
        or profile["contract_sha256"]
        != canonical_digest(_profile_without_contract_digest(profile))
    ):
        raise CreativeLookArmTargetProfileError("contract digest differs")
    return copy.deepcopy(profile)


def validate_creative_look_arm_target_profile(document: object) -> dict:
    """Public alias for exact profile validation."""
    return normalize_creative_look_arm_target_profile(document)


def load_creative_look_arm_target_profile(path: Path) -> dict:
    """Load one local JSON profile without any network or toolchain side effect."""
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CreativeLookArmTargetProfileError("target profile cannot be loaded") from error
    return validate_creative_look_arm_target_profile(document)
