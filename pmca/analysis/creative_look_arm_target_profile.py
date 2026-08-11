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
    "native/a6400_creative_look/creative_look_target.c": "8346d8be2326b1b37d1f07e7b20783213d12fc427b86b1d6d3fa8e53e076c7f0",
}
BUILD_HEADER_HASHES = {
    "native/a6400_creative_look/creative_look_core.h": "1e82df201879666999373ebfcedfad12da7e9ffdf455708ff3ad93de20c95982",
    "native/a6400_creative_look/creative_look_view.h": "aef9b5536d5eea531905c12f8efa1118175ea3873df66358c62ce5a06c8e9378",
    "native/a6400_creative_look/creative_look_bridge.h": "44004ec81d0d1853be07d625517e2f0e6fc3c396bb023c87f67b4377b9aa1cd0",
    "native/a6400_creative_look/creative_look_target.h": "2d655ea5820a790ada5f878e7709eb6554d1e89e9b9eb1a77fc4adac73ea7580",
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
    "cl_target_identity": {"size": 16, "alignment": 4},
    "cl_target_identity.logical_alias": {"offset": 0},
    "cl_target_identity.component_label": {"offset": 4},
    "cl_target_identity.proposed_factory_label": {"offset": 8},
    "cl_target_identity.publication_status": {"offset": 12},
    "cl_target_shell": {"size": 1200, "alignment": 4},
    "cl_target_shell.bridge": {"offset": 0},
    "cl_target_shell.copied_frame": {"offset": 692},
    "cl_target_shell.retained_sink": {"offset": 1184},
    "cl_target_shell.retained_sink_context": {"offset": 1188},
    "cl_target_shell.initialization_marker": {"offset": 1192},
    "cl_target_shell.frame_valid": {"offset": 1196},
    "cl_target_shell.delivering": {"offset": 1197},
    "cl_target_shell.reserved": {"offset": 1198},
    "CL_TARGET_SHELL_ABI_VERSION": {"value": 1},
    "CL_TARGET_PUBLICATION_PROPOSED_UNPUBLISHED": {"value": 0},
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
    "compile:creative_look_target.c",
    "inspect-object:creative_look_core.c:undefined-symbols",
    "inspect-object:creative_look_core.c:defined-symbols",
    "inspect-object:creative_look_core.c:symbol-table",
    "inspect-object:creative_look_view.c:undefined-symbols",
    "inspect-object:creative_look_view.c:defined-symbols",
    "inspect-object:creative_look_view.c:symbol-table",
    "inspect-object:creative_look_bridge.c:undefined-symbols",
    "inspect-object:creative_look_bridge.c:defined-symbols",
    "inspect-object:creative_look_bridge.c:symbol-table",
    "inspect-object:creative_look_target.c:undefined-symbols",
    "inspect-object:creative_look_target.c:defined-symbols",
    "inspect-object:creative_look_target.c:symbol-table",
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
EXPECTED_IDENTITY_METADATA = {
    "source": "native/a6400_creative_look/creative_look_target.c",
    "record_symbol": {
        "name": "cl_target_proposed_identity",
        "binding": "LOCAL",
        "type": "OBJECT",
        "size": 16,
        "section_index": 6,
        "section": ".data.rel.ro.local",
        "hex": "00000000140000002800000000000000",
    },
    "accessor_symbol": {
        "name": "cl_target_shell_identity",
        "binding": "GLOBAL",
        "type": "FUNC",
        "size": 12,
        "section_index": 1,
        "section": ".text",
    },
    "string_section": {
        "index": 4,
        "name": ".rodata.str1.4",
        "type": "PROGBITS",
        "flags": "AMS",
        "size": 67,
        "hex": "766965772f43524541544956455f4c4f4f4b00007669657743726561746976654c6f6f6b2e736f005669657743726561746976654c6f6f6b546f496e7374616e636500",
        "sha256": "867511a4abb0a3b53fbc6930013e2dc31d6542a3466bc195560c59add950cf67",
    },
    "record_section": {
        "index": 6,
        "name": ".data.rel.ro.local",
        "type": "PROGBITS",
        "flags": "WA",
    },
    "literals": [
        {
            "field": "logical_alias",
            "value": "view/CREATIVE_LOOK",
            "record_offset": 0,
            "string_offset": 0,
            "source_occurrences": 1,
            "object_occurrences": 1,
            "section_occurrences": 1,
        },
        {
            "field": "component_label",
            "value": "viewCreativeLook.so",
            "record_offset": 4,
            "string_offset": 20,
            "source_occurrences": 1,
            "object_occurrences": 1,
            "section_occurrences": 1,
        },
        {
            "field": "proposed_factory_label",
            "value": "ViewCreativeLookToInstance",
            "record_offset": 8,
            "string_offset": 40,
            "source_occurrences": 1,
            "object_occurrences": 1,
            "section_occurrences": 1,
        },
    ],
    "record_relocations": [
        {
            "relocation_section": ".rel.data.rel.ro.local",
            "source_section": ".data.rel.ro.local",
            "offset": 0,
            "type": "R_ARM_ABS32",
            "symbol": ".rodata.str1.4",
            "addend": 0,
        },
        {
            "relocation_section": ".rel.data.rel.ro.local",
            "source_section": ".data.rel.ro.local",
            "offset": 4,
            "type": "R_ARM_ABS32",
            "symbol": ".rodata.str1.4",
            "addend": 20,
        },
        {
            "relocation_section": ".rel.data.rel.ro.local",
            "source_section": ".data.rel.ro.local",
            "offset": 8,
            "type": "R_ARM_ABS32",
            "symbol": ".rodata.str1.4",
            "addend": 40,
        },
    ],
    "accessor_relocation": {
        "relocation_section": ".rel.text",
        "source_section": ".text",
        "offset": 13504,
        "type": "R_ARM_REL32",
        "symbol": ".data.rel.ro.local",
    },
    "factory_symbol_occurrences": 0,
}
BUILD_SECTIONS_SHA256 = "15f7fdcb5f2a3caada92cfd88bbaff41e4231aabd1cca387a7d601b6b6974e94"
BUILD_RELOCATIONS_SHA256 = "93cce4b8f8858cc6b81593df79c7f262e2510c78c7b27eaa0f2f69c89b8846ee"
BUILD_SYMBOL_TABLE_SHA256 = "e2af6de51002114fc68c2ad9359f9b48e013ad176965b041f2056f39d2c70711"
BUILD_DEFINED_SYMBOLS_SHA256 = "c92bfdb5b50530b6de2a94782cf29f71169ca7b8ea7d61a0e473157325bbfddd"
BUILD_COMMANDS_SHA256 = "9551b0ee0f6448d6d98e992ce813dbed5b160d421b985574ef4b6fc86d2befc6"
BUILD_OBJECT_SHA256 = "1f03b1ab4c722d4f266d272d21bbef230838f621baa079386c324a3c20666a33"
BUILD_RAW_RECORD_SHA256 = "e4aa64123bb839650b244351bad7b49fb6b1c6a2239e798bc32533f35cc08b50"
BUILD_OBJECTS_SHA256 = "64b2040474a0b6e81780576e64041d381a0ad03fee378634e8deb5344ae775ad"
BUILD_ABI_PROBE = {
    "path": "$BUILD/creative_look_arm_abi_probe.c",
    "source_sha256": "d0195680332b413812b3030078f4358ebed0826c771fb406fff162eb784048eb",
    "object_path": "$BUILD/creative_look_arm_abi_probe.o",
    "object_sha256": "02d75da7425c0de488ef82dec58e53a78c6e17f5ce3dbfe53847500b5442b544",
    "linked": False,
}
BUILD_INCLUDE_CLOSURE_SHA256 = "627e96eeb35004af2ad15cb789d158fe5ae945dd712ce99580b0535b1ee63312"
READINESS = "ARM_TARGET_OBJECT_COMPILED__RUNTIME_UNBOUND"
CONCLUSION = (
    "The portable Creative Look core, view, bridge, and neutral target shell were compiled with the "
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


def _expected_build_command_argv() -> list[tuple[str, list[str]]]:
    gcc = BUILD_TOOL_PATHS["gcc"]
    native = "native/a6400_creative_look"
    commands = [
        (f"identify:{role}", [BUILD_TOOL_PATHS[role], "--version"])
        for role in ("gcc", "ld", "readelf", "nm", "objdump", "as")
    ]
    for source_path in BUILD_SOURCE_HASHES:
        name = source_path.rsplit("/", 1)[-1]
        commands.append(
            (
                f"compile:{name}",
                [
                    gcc,
                    *COMPILE_FLAGS,
                    "-I",
                    native,
                    "-c",
                    source_path,
                    "-o",
                    f"$BUILD/{name[:-2]}.o",
                ],
            )
        )
    for source_path in BUILD_SOURCE_HASHES:
        name = source_path.rsplit("/", 1)[-1]
        object_path = f"$BUILD/{name[:-2]}.o"
        commands.extend(
            (
                (
                    f"inspect-object:{name}:undefined-symbols",
                    [BUILD_TOOL_PATHS["nm"], "-u", "-P", object_path],
                ),
                (
                    f"inspect-object:{name}:defined-symbols",
                    [BUILD_TOOL_PATHS["nm"], "-g", "--defined-only", "-P", object_path],
                ),
                (
                    f"inspect-object:{name}:symbol-table",
                    [BUILD_TOOL_PATHS["readelf"], "-sW", object_path],
                ),
            )
        )
    commands.extend(
        (
            (
                "compile:test-only-abi-probe",
                [
                    gcc,
                    *COMPILE_FLAGS,
                    "-I",
                    native,
                    "-c",
                    "$BUILD/creative_look_arm_abi_probe.c",
                    "-o",
                    "$BUILD/creative_look_arm_abi_probe.o",
                ],
            ),
            (
                "link:natural-relocatable",
                [
                    BUILD_TOOL_PATHS["ld"],
                    "-r",
                    "-o",
                    "$OUTPUT/creative_look_arm_target.o",
                    *[
                        f"$BUILD/{path.rsplit('/', 1)[-1][:-2]}.o"
                        for path in BUILD_SOURCE_HASHES
                    ],
                ],
            ),
            (
                "inspect:undefined-symbols",
                [BUILD_TOOL_PATHS["nm"], "-u", "-P", "$OUTPUT/creative_look_arm_target.o"],
            ),
            (
                "inspect:defined-symbols",
                [BUILD_TOOL_PATHS["nm"], "-g", "--defined-only", "-P", "$OUTPUT/creative_look_arm_target.o"],
            ),
            (
                "inspect:elf-header",
                [BUILD_TOOL_PATHS["readelf"], "-hW", "$OUTPUT/creative_look_arm_target.o"],
            ),
            (
                "inspect:arm-attributes",
                [BUILD_TOOL_PATHS["readelf"], "-AW", "$OUTPUT/creative_look_arm_target.o"],
            ),
            (
                "inspect:sections",
                [BUILD_TOOL_PATHS["readelf"], "-SW", "$OUTPUT/creative_look_arm_target.o"],
            ),
            (
                "inspect:relocations",
                [BUILD_TOOL_PATHS["readelf"], "-rW", "$OUTPUT/creative_look_arm_target.o"],
            ),
            (
                "inspect:symbol-table",
                [BUILD_TOOL_PATHS["readelf"], "-sW", "$OUTPUT/creative_look_arm_target.o"],
            ),
            (
                "inspect:object-format",
                [BUILD_TOOL_PATHS["objdump"], "-f", "$OUTPUT/creative_look_arm_target.o"],
            ),
        )
    )
    return commands


def validate_build_commands(commands: object) -> None:
    """Require every compile/link/inspection command and target exactly."""
    if not isinstance(commands, list):
        raise CreativeLookArmTargetProfileError("build command sequence differs")
    expected = _expected_build_command_argv()
    observed = []
    for item in commands:
        if not isinstance(item, dict):
            raise CreativeLookArmTargetProfileError("build command sequence differs")
        observed.append((item.get("purpose"), item.get("argv")))
    if observed != expected or tuple(purpose for purpose, _ in expected) != BUILD_COMMAND_PURPOSES:
        raise CreativeLookArmTargetProfileError("build command sequence differs")


def _validate_build_evidence(evidence: object) -> None:
    record = _exact_dict(
        evidence,
        (
            "schema_version",
            "scope",
            "camera_executed",
            "tools",
            "inputs",
            "include_closure",
            "build",
            "commands",
            "abi_probe",
            "objects",
            "object",
            "elf",
            "attributes",
            "abi_layouts",
            "sections",
            "relocations",
            "symbol_table",
            "defined_symbols",
            "undefined_symbols",
            "identity_metadata",
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
    validate_build_commands(commands)
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
    if canonical_digest(commands) != BUILD_COMMANDS_SHA256:
        raise CreativeLookArmTargetProfileError("build command evidence differs")

    include_closure = record["include_closure"]
    if not isinstance(include_closure, list) or len(include_closure) != 8:
        raise CreativeLookArmTargetProfileError("include closure differs")
    for item in include_closure:
        include = _exact_dict(item, ("path", "quoted", "system"), "include closure")
        if (
            include["path"] not in (set(BUILD_SOURCE_HASHES) | set(BUILD_HEADER_HASHES))
            or not isinstance(include["quoted"], list)
            or not all(name in {path.rsplit('/', 1)[-1] for path in BUILD_HEADER_HASHES} for name in include["quoted"])
            or not isinstance(include["system"], list)
            or not all(name in ("limits.h", "stddef.h", "stdint.h") for name in include["system"])
        ):
            raise CreativeLookArmTargetProfileError("include closure differs")
    if canonical_digest(include_closure) != BUILD_INCLUDE_CLOSURE_SHA256:
        raise CreativeLookArmTargetProfileError("include closure differs")

    if not _same_typed_structure(record["abi_probe"], BUILD_ABI_PROBE):
        raise CreativeLookArmTargetProfileError("ABI probe evidence differs")

    objects = record["objects"]
    if not isinstance(objects, list) or len(objects) != len(BUILD_SOURCE_HASHES):
        raise CreativeLookArmTargetProfileError("production object set differs")
    for item, source in zip(objects, BUILD_SOURCE_HASHES):
        object_item = _exact_dict(
            item,
            (
                "source",
                "path",
                "sha256",
                "undefined_symbols",
                "defined_symbols",
                "symbol_table",
            ),
            "production object",
        )
        name = source.rsplit("/", 1)[-1][:-2] + ".o"
        if (
            object_item["source"] != source
            or object_item["path"] != "$BUILD/" + name
            or not _is_sha256(object_item["sha256"])
            or not isinstance(object_item["undefined_symbols"], list)
            or object_item["undefined_symbols"] != sorted(set(object_item["undefined_symbols"]))
            or not isinstance(object_item["defined_symbols"], list)
            or object_item["defined_symbols"] != sorted(set(object_item["defined_symbols"]))
            or not isinstance(object_item["symbol_table"], list)
            or not object_item["symbol_table"]
        ):
            raise CreativeLookArmTargetProfileError("production object set differs")
        for symbol in object_item["symbol_table"]:
            _exact_dict(
                symbol,
                ("name", "value", "size", "type", "binding", "visibility", "section_index", "section"),
                "production object symbol",
            )
    if canonical_digest(objects) != BUILD_OBJECTS_SHA256:
        raise CreativeLookArmTargetProfileError("production object set differs")

    object_record = _exact_dict(record["object"], ("path", "sha256"), "target object")
    if (
        object_record["path"] != "$OUTPUT/creative_look_arm_target.o"
        or object_record["sha256"] != BUILD_OBJECT_SHA256
        or not _is_sha256(object_record["sha256"])
    ):
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
    sections = record["sections"]
    if not isinstance(sections, list) or not sections:
        raise CreativeLookArmTargetProfileError("section or relocation evidence differs")
    for index, item in enumerate(sections):
        section = _exact_dict(
            item,
            ("index", "name", "type", "offset", "size", "flags", "link", "info", "alignment"),
            "section evidence",
        )
        if (
            section["index"] != index
            or not isinstance(section["name"], str)
            or not isinstance(section["type"], str)
            or not isinstance(section["flags"], str)
            or any(type(section[field]) is not int or section[field] < 0 for field in ("offset", "size", "link", "info", "alignment"))
        ):
            raise CreativeLookArmTargetProfileError("section evidence differs")
    if (
        not any(item["name"] == ".text" and "X" in item["flags"] for item in sections)
        or not any(item["name"] == ".ARM.attributes" for item in sections)
        or canonical_digest(sections) != BUILD_SECTIONS_SHA256
    ):
        raise CreativeLookArmTargetProfileError("section evidence differs")

    relocations = record["relocations"]
    if not isinstance(relocations, list) or not relocations:
        raise CreativeLookArmTargetProfileError("relocation evidence differs")
    for item in relocations:
        relocation = _exact_dict(
            item,
            (
                "relocation_section",
                "source_section",
                "offset",
                "type",
                "symbol_value",
                "symbol",
                "addend",
                "encoded_source_word",
            ),
            "relocation evidence",
        )
        if (
            not isinstance(relocation["relocation_section"], str)
            or not isinstance(relocation["source_section"], str)
            or type(relocation["offset"]) is not int
            or relocation["offset"] < 0
            or not isinstance(relocation["type"], str)
            or not relocation["type"].startswith("R_ARM_")
            or type(relocation["symbol_value"]) is not int
            or not isinstance(relocation["symbol"], str)
            or type(relocation["addend"]) not in (int, type(None))
            or not isinstance(relocation["encoded_source_word"], str)
            or re.fullmatch(r"[0-9a-f]{8}", relocation["encoded_source_word"]) is None
        ):
            raise CreativeLookArmTargetProfileError("relocation evidence differs")
    if canonical_digest(relocations) != BUILD_RELOCATIONS_SHA256:
        raise CreativeLookArmTargetProfileError("relocation evidence differs")

    symbols = record["symbol_table"]
    if not isinstance(symbols, list) or not symbols:
        raise CreativeLookArmTargetProfileError("symbol table evidence differs")
    for item in symbols:
        symbol = _exact_dict(
            item,
            ("name", "value", "size", "type", "binding", "visibility", "section_index", "section"),
            "symbol table evidence",
        )
        if (
            not isinstance(symbol["name"], str)
            or not symbol["name"]
            or type(symbol["value"]) is not int
            or type(symbol["size"]) is not int
            or not isinstance(symbol["type"], str)
            or not isinstance(symbol["binding"], str)
            or not isinstance(symbol["visibility"], str)
            or type(symbol["section_index"]) not in (int, str)
            or type(symbol["section"]) not in (str, type(None))
        ):
            raise CreativeLookArmTargetProfileError("symbol table evidence differs")
    if canonical_digest(symbols) != BUILD_SYMBOL_TABLE_SHA256:
        raise CreativeLookArmTargetProfileError("symbol table evidence differs")
    defined = record["defined_symbols"]
    if (
        not isinstance(defined, list)
        or defined != sorted(set(defined))
        or "cl_init" not in defined
        or "cl_bridge_open" not in defined
        or any(symbol.startswith("__aeabi_") or symbol in ("_start", "_init", "_fini") for symbol in defined)
        or canonical_digest(defined) != BUILD_DEFINED_SYMBOLS_SHA256
        or record["undefined_symbols"] != []
    ):
        raise CreativeLookArmTargetProfileError("symbol evidence differs")
    if not _same_typed_structure(record["identity_metadata"], EXPECTED_IDENTITY_METADATA):
        raise CreativeLookArmTargetProfileError("identity metadata evidence differs")
    safety = _exact_dict(record["safety_scan"], ("files", "forbidden_matches"), "safety scan")
    if safety["files"] != list(BUILD_SOURCE_HASHES) + list(BUILD_HEADER_HASHES) or safety["forbidden_matches"] != []:
        raise CreativeLookArmTargetProfileError("safety scan evidence differs")

    raw_digest = record["raw_record_sha256"]
    raw_record = copy.deepcopy(record)
    raw_record.pop("raw_record_sha256")
    if (
        not _is_sha256(raw_digest)
        or raw_digest != BUILD_RAW_RECORD_SHA256
        or raw_digest != canonical_digest(raw_record)
    ):
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
