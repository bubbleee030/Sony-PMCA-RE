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
BUILD_SOURCE_HASHES = {
    "native/a6400_creative_look/creative_look_core.c": "c1ac9571c1ab1a70955a4d7c6a1a56118f7fa95e06174f310ae6e1e619dec9e5",
    "native/a6400_creative_look/creative_look_view.c": "c50346138d9e14f1e5af050a03018ef8decd1d520abb10fbe6e7f8aa8e3c0090",
    "native/a6400_creative_look/creative_look_bridge.c": "2d96193e572f381c04636538f68eb71528dae3ecfcebb0c9f4c26c46b31e5d51",
}
BUILD_HEADER_HASHES = {
    "native/a6400_creative_look/creative_look_core.h": "1e82df201879666999373ebfcedfad12da7e9ffdf455708ff3ad93de20c95982",
    "native/a6400_creative_look/creative_look_view.h": "aef9b5536d5eea531905c12f8efa1118175ea3873df66358c62ce5a06c8e9378",
    "native/a6400_creative_look/creative_look_bridge.h": "44004ec81d0d1853be07d625517e2f0e6fc3c396bb023c87f67b4377b9aa1cd0",
}
BUILD_TOOL_PATHS = {
    "gcc": "$TOOLCHAIN/bin/arm-none-eabi-gcc.exe",
    "ld": "$TOOLCHAIN/bin/arm-none-eabi-ld.exe",
    "readelf": "$TOOLCHAIN/bin/arm-none-eabi-readelf.exe",
    "nm": "$TOOLCHAIN/bin/arm-none-eabi-nm.exe",
    "objdump": "$TOOLCHAIN/bin/arm-none-eabi-objdump.exe",
    "cc1": "$TOOLCHAIN/libexec/gcc/arm-none-eabi/15.2.1/cc1.exe",
    "as": "$TOOLCHAIN/arm-none-eabi/bin/as.exe",
}
BUILD_TOOL_HASHES = {
    "gcc": "accf3766d0b53850fcc09ed6b150d44925f9c2f4923f83935692d0e96559d001",
    "ld": "94749493e74a5fa5de5b2eb7bb0a7f9d04e07694d35668dca93b75b18f35ec7e",
    "readelf": "bea94d5da605962fdcdd5b8cb8d4ba9a60017148a59df9c4fbd6aae10852e470",
    "nm": "e5278fc0ff7e6ff95640797d16b02a68613cc999d5f17123eedbf9fbd0142415",
    "objdump": "925cf2bd2d20a5ad4a54886da8ab21dc3de286c489532035f29ec6f092e1e962",
    "cc1": "ea2b9723ab09655cfd89c08b67f9b4b806d01dca7471059baf4f586a6d7459c4",
    "as": "1ddac30cb2e3d7ad5f045dae045c2eb2fc42b3084f011605c664fc0af9f03092",
}
BUILD_ABI_LAYOUTS = {
    "cl_state": {"size": 155, "alignment": 1},
    "cl_binding_record": {"size": 36, "alignment": 1},
    "cl_integration_manifest": {"size": 228, "alignment": 2},
    "cl_processing_snapshot": {"size": 164, "alignment": 4},
    "cl_bridge_report": {"size": 64, "alignment": 4},
    "cl_bridge_adapters": {"size": 60, "alignment": 4},
    "cl_bridge": {"size": 692, "alignment": 4},
    "cl_bridge.adapters": {"offset": 632},
}
BUILD_COMMAND_PURPOSES = (
    "identify:gcc",
    "identify:ld",
    "identify:readelf",
    "identify:nm",
    "identify:objdump",
    "identify:as",
    "compile:creative_look_core.c",
    "compile:creative_look_view.c",
    "compile:creative_look_bridge.c",
    "compile:test-only-abi-probe",
    "link:natural-relocatable",
    "inspect:undefined-symbols",
    "inspect:defined-symbols",
    "inspect:elf-header",
    "inspect:arm-attributes",
    "inspect:sections",
    "inspect:relocations",
    "inspect:symbol-table",
    "inspect:object-format",
)
READINESS = "ARM_TARGET_OBJECT_COMPILED__RUNTIME_UNBOUND"
CONCLUSION = (
    "The portable Creative Look core, view, and bridge were compiled with the "
    "pinned official Arm GNU Toolchain as one naturally linked ARMv7-A/Thumb-2 "
    "softfp ET_REL object for offline static inspection. The target ABI probe, "
    "empty undefined-symbol result, mandatory attributes, benign extra "
    "attributes, and normalized build evidence are recorded. No Sony runtime "
    "binding, processing binding, recovery validation, camera-test eligibility, "
    "or installability is established by this target object."
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


def _walk_strings(value: object):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _walk_strings(key)
            yield from _walk_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_strings(item)


def _validate_build_evidence(evidence: object) -> None:
    record = _exact_dict(
        evidence,
        (
            "schema_version",
            "scope",
            "camera_executed",
            "tools",
            "inputs",
            "build",
            "commands",
            "object",
            "elf",
            "attributes",
            "abi_layouts",
            "sections",
            "relocations",
            "defined_symbols",
            "undefined_symbols",
            "safety_scan",
            "raw_record_sha256",
        ),
        "build evidence",
    )
    if (
        type(record["schema_version"]) is not int
        or record["schema_version"] != 1
        or record["scope"] != "offline-static-arm-target-object"
        or record["camera_executed"] is not False
    ):
        raise CreativeLookArmTargetProfileError("build evidence scope differs")
    for value in _walk_strings(record):
        if value.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:[\\/]", value):
            raise CreativeLookArmTargetProfileError("absolute path in build evidence")

    tools = record["tools"]
    if not isinstance(tools, list) or [item.get("role") for item in tools if isinstance(item, dict)] != list(BUILD_TOOL_PATHS):
        raise CreativeLookArmTargetProfileError("build tool set differs")
    for item in tools:
        tool = _exact_dict(item, ("role", "path", "sha256", "version"), "build tool")
        role = tool["role"]
        if (
            tool["path"] != BUILD_TOOL_PATHS[role]
            or tool["sha256"] != BUILD_TOOL_HASHES[role]
            or not isinstance(tool["version"], str)
            or not tool["version"]
        ):
            raise CreativeLookArmTargetProfileError("build tool identity differs")

    inputs = _exact_dict(record["inputs"], ("sources", "headers"), "build inputs")
    for field, expected in (("sources", BUILD_SOURCE_HASHES), ("headers", BUILD_HEADER_HASHES)):
        items = inputs[field]
        if not isinstance(items, list) or len(items) != len(expected):
            raise CreativeLookArmTargetProfileError("build input set differs")
        observed = {}
        for item in items:
            source = _exact_dict(item, ("path", "sha256"), "build input")
            if source["path"] in observed or not _is_sha256(source["sha256"]):
                raise CreativeLookArmTargetProfileError("build input record differs")
            observed[source["path"]] = source["sha256"]
        if observed != expected:
            raise CreativeLookArmTargetProfileError("build input identity differs")

    evidence_build = _exact_dict(record["build"], ("compile_flags", "link_mode"), "evidence build")
    if not _same_typed_structure(evidence_build, {"compile_flags": COMPILE_FLAGS, "link_mode": ["-r"]}):
        raise CreativeLookArmTargetProfileError("evidence build contract differs")
    commands = record["commands"]
    if not isinstance(commands, list) or tuple(item.get("purpose") for item in commands if isinstance(item, dict)) != BUILD_COMMAND_PURPOSES:
        raise CreativeLookArmTargetProfileError("build command sequence differs")
    for item in commands:
        command = _exact_dict(
            item,
            ("purpose", "argv", "returncode", "stdout_sha256", "stderr_sha256"),
            "build command",
        )
        if (
            not isinstance(command["argv"], list)
            or not command["argv"]
            or not all(isinstance(argument, str) and argument for argument in command["argv"])
            or type(command["returncode"]) is not int
            or command["returncode"] != 0
            or not _is_sha256(command["stdout_sha256"])
            or not _is_sha256(command["stderr_sha256"])
        ):
            raise CreativeLookArmTargetProfileError("build command record differs")

    object_record = _exact_dict(record["object"], ("path", "sha256"), "target object")
    if object_record["path"] != "$OUTPUT/creative_look_arm_target.o" or not _is_sha256(object_record["sha256"]):
        raise CreativeLookArmTargetProfileError("target object identity differs")
    if not _same_typed_structure(record["elf"], {
        "class": "ELF32",
        "data": "little-endian",
        "machine": "ARM",
        "eabi_version": 5,
        "type": "ET_REL",
    }):
        raise CreativeLookArmTargetProfileError("built ELF differs")
    attributes = _exact_dict(record["attributes"], ("mandatory", "extra"), "built attributes")
    validated_attributes = validate_arm_target_attributes(attributes["mandatory"] + attributes["extra"])
    if not _same_typed_structure(attributes, validated_attributes):
        raise CreativeLookArmTargetProfileError("built ARM attributes differ")
    if not _same_typed_structure(record["abi_layouts"], BUILD_ABI_LAYOUTS):
        raise CreativeLookArmTargetProfileError("built ABI layout differs")
    if (
        not isinstance(record["sections"], list)
        or ".text" not in record["sections"]
        or ".ARM.attributes" not in record["sections"]
        or not isinstance(record["relocations"], list)
        or not all(isinstance(item, str) and "R_ARM_" in item for item in record["relocations"])
    ):
        raise CreativeLookArmTargetProfileError("section or relocation evidence differs")
    defined = record["defined_symbols"]
    if (
        not isinstance(defined, list)
        or defined != sorted(set(defined))
        or "cl_init" not in defined
        or "cl_bridge_open" not in defined
        or any(symbol.startswith("__aeabi_") or symbol in ("_start", "_init", "_fini") for symbol in defined)
        or record["undefined_symbols"] != []
    ):
        raise CreativeLookArmTargetProfileError("symbol evidence differs")
    safety = _exact_dict(record["safety_scan"], ("files", "forbidden_matches"), "safety scan")
    if safety["files"] != list(BUILD_SOURCE_HASHES) + list(BUILD_HEADER_HASHES) or safety["forbidden_matches"] != []:
        raise CreativeLookArmTargetProfileError("safety scan evidence differs")

    raw_digest = record["raw_record_sha256"]
    raw_record = copy.deepcopy(record)
    raw_record.pop("raw_record_sha256")
    if not _is_sha256(raw_digest) or raw_digest != canonical_digest(raw_record):
        raise CreativeLookArmTargetProfileError("raw build record digest differs")


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
            "build_evidence",
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
        or profile["analysis_scope"] != "offline-static-arm-target-object"
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
    _validate_build_evidence(profile["build_evidence"])

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
