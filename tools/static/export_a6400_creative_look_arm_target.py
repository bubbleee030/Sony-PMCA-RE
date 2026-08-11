#!/usr/bin/env python3
"""Build and inspect the portable Creative Look code as one ARM ET_REL object.

This exporter is deliberately offline and target-execution free.  It accepts an
explicit extracted Arm toolchain directory, compiles only the pinned production
allowlist, and records normalized static evidence without embedding user paths
or object bytes.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable, Mapping, Sequence


TOOL_NAMES = {
    "gcc": "arm-none-eabi-gcc.exe",
    "ld": "arm-none-eabi-ld.exe",
    "readelf": "arm-none-eabi-readelf.exe",
    "nm": "arm-none-eabi-nm.exe",
    "objdump": "arm-none-eabi-objdump.exe",
}
PINNED_TOOL_PATHS = {
    "gcc": Path("bin/arm-none-eabi-gcc.exe"),
    "ld": Path("bin/arm-none-eabi-ld.exe"),
    "readelf": Path("bin/arm-none-eabi-readelf.exe"),
    "nm": Path("bin/arm-none-eabi-nm.exe"),
    "objdump": Path("bin/arm-none-eabi-objdump.exe"),
    "cc1": Path("libexec/gcc/arm-none-eabi/15.2.1/cc1.exe"),
    "as": Path("arm-none-eabi/bin/as.exe"),
}
PINNED_TOOL_HASHES = {
    "gcc": "accf3766d0b53850fcc09ed6b150d44925f9c2f4923f83935692d0e96559d001",
    "ld": "94749493e74a5fa5de5b2eb7bb0a7f9d04e07694d35668dca93b75b18f35ec7e",
    "readelf": "bea94d5da605962fdcdd5b8cb8d4ba9a60017148a59df9c4fbd6aae10852e470",
    "nm": "e5278fc0ff7e6ff95640797d16b02a68613cc999d5f17123eedbf9fbd0142415",
    "objdump": "925cf2bd2d20a5ad4a54886da8ab21dc3de286c489532035f29ec6f092e1e962",
    "cc1": "ea2b9723ab09655cfd89c08b67f9b4b806d01dca7471059baf4f586a6d7459c4",
    "as": "1ddac30cb2e3d7ad5f045dae045c2eb2fc42b3084f011605c664fc0af9f03092",
}
COMMAND_TIMEOUT_SECONDS = 60
PUBLIC_OUTPUT_NAME = "creative_look_arm_target.o"
SOURCE_NAMES = (
    "creative_look_core.c",
    "creative_look_view.c",
    "creative_look_bridge.c",
    "creative_look_target.c",
)
HEADER_NAMES = (
    "creative_look_core.h",
    "creative_look_view.h",
    "creative_look_bridge.h",
    "creative_look_target.h",
)
EXPECTED_COMPILE_FLAGS = [
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
EXPECTED_ABI_LAYOUTS = {
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
FORBIDDEN_SOURCE_IDENTIFIERS = (
    "malloc",
    "calloc",
    "realloc",
    "free",
    "fopen",
    "socket",
    "connect",
    "dlopen",
    "dlsym",
    "GetProcAddress",
    "LoadLibrary",
    "CreateProcess",
    "ShellExecute",
    "CreateFile",
    "DeviceIoControl",
    "CreateThread",
    "_beginthread",
    "pthread",
    "libusb",
    "nflasha",
    "updater",
    "firmware_package",
    "partition_write",
    "IdSoTable",
    "IdGenerator",
    "openView",
    "Backup",
    "Fsys",
    "MprIf",
    "EncodeStill",
    "EncodeMovie",
    "ImageProcessor",
    "SonyEncoder",
    "SonyProcessing",
    "flash_write",
    "flash_erase",
    "package_install",
    "package_write",
    "device_write",
)
FORBIDDEN_SOURCE_STRING_FRAGMENTS = (
    "/dev/",
    "/setting",
    "Sony/",
    "Backup/",
    "Fsys/",
    "firmware_package",
    "partition_write",
    "IdSoTable",
    "IdGenerator",
    "openView",
    "MprIf",
    "EncodeStill",
    "EncodeMovie",
    "ImageProcessor",
    "GetProcAddress",
    "SonyEncoder",
    "SonyProcessing",
    "flash_write",
    "flash_erase",
    "package_install",
    "package_write",
    "device_write",
)
FORBIDDEN_SOURCE_TOKENS = (
    *FORBIDDEN_SOURCE_IDENTIFIERS,
    *FORBIDDEN_SOURCE_STRING_FRAGMENTS,
)
IDENTITY_LITERALS = (
    ("logical_alias", "view/CREATIVE_LOOK", 0, 0),
    ("component_label", "viewCreativeLook.so", 4, 0x14),
    ("proposed_factory_label", "ViewCreativeLookToInstance", 8, 0x28),
)
PROPOSED_FACTORY_LABEL = IDENTITY_LITERALS[-1][1]
APPROVED_SYSTEM_HEADERS = ("limits.h", "stddef.h", "stdint.h")
FORBIDDEN_SYMBOL_FRAGMENTS = (
    "__aeabi_",
    "ViewCreativeLookToInstance",
    "dlopen",
    "dlsym",
    "GetProcAddress",
    "IdSoTable",
    "IdGenerator",
    "openView",
    "Backup",
    "Fsys",
    "MprIf",
    "EncodeStill",
    "EncodeMovie",
    "ImageProcessor",
    "DeviceIoControl",
    "libusb",
    "nflasha",
    "updater",
    "firmware_package",
    "partition_write",
    "flash_write",
    "flash_erase",
    "package_install",
    "package_write",
    "device_write",
    "SonyEncoder",
    "SonyProcessing",
)
FORBIDDEN_EXACT_DEFINED_SYMBOLS = (
    "_start",
    "_init",
    "_fini",
    "calloc",
    "connect",
    "dlopen",
    "dlsym",
    "fopen",
    "free",
    "malloc",
    "memcpy",
    "memmove",
    "memset",
    "open",
    "popen",
    "realloc",
    "socket",
    "system",
)
COMPILER_ENVIRONMENT_KEYS = (
    "CFLAGS",
    "CPPFLAGS",
    "LDFLAGS",
    "GCC_EXEC_PREFIX",
    "GCC_COLORS",
    "COMPILER_PATH",
    "LIBRARY_PATH",
    "CPATH",
    "C_INCLUDE_PATH",
    "CPLUS_INCLUDE_PATH",
    "OBJC_INCLUDE_PATH",
    "DEPENDENCIES_OUTPUT",
    "SUNPRO_DEPENDENCIES",
)
ATTRIBUTE_TAGS = {
    "Tag_CPU_raw_name": 4,
    "Tag_CPU_name": 5,
    "Tag_CPU_arch": 6,
    "Tag_CPU_arch_profile": 7,
    "Tag_ARM_ISA_use": 8,
    "Tag_THUMB_ISA_use": 9,
    "Tag_FP_arch": 10,
    "Tag_Advanced_SIMD_arch": 12,
    "Tag_ABI_PCS_R9_use": 14,
    "Tag_ABI_PCS_RW_data": 15,
    "Tag_ABI_PCS_RO_data": 16,
    "Tag_ABI_PCS_GOT_use": 17,
    "Tag_ABI_PCS_wchar_t": 18,
    "Tag_ABI_FP_rounding": 19,
    "Tag_ABI_FP_denormal": 20,
    "Tag_ABI_FP_exceptions": 21,
    "Tag_ABI_FP_user_exceptions": 22,
    "Tag_ABI_FP_number_model": 23,
    "Tag_ABI_align_needed": 24,
    "Tag_ABI_align_preserved": 25,
    "Tag_ABI_enum_size": 26,
    "Tag_ABI_HardFP_use": 27,
    "Tag_ABI_VFP_args": 28,
    "Tag_ABI_WMMX_args": 29,
    "Tag_ABI_optimization_goals": 30,
    "Tag_CPU_unaligned_access": 34,
    "Tag_ABI_FP_16bit_format": 38,
}


class ArmTargetBuildError(RuntimeError):
    """Raised when a build input or observed target property is unsafe."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fsync_file(path: Path) -> None:
    with path.open("r+b") as stream:
        stream.flush()
        os.fsync(stream.fileno())


def _canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _has_reparse_component(path: Path) -> bool:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            metadata = os.lstat(current)
        except OSError as error:
            raise ArmTargetBuildError("path component cannot be inspected") from error
        file_attributes = getattr(metadata, "st_file_attributes", 0)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if stat.S_ISLNK(metadata.st_mode) or (
            reparse_flag and file_attributes & reparse_flag
        ):
            return True
    return False


def _require_regular_file(path: Path, root: Path, label: str) -> Path:
    if not path.is_absolute():
        raise ArmTargetBuildError(f"{label} path must be absolute")
    try:
        resolved = path.resolve(strict=True)
        resolved_root = root.resolve(strict=True)
    except OSError as error:
        raise ArmTargetBuildError(f"{label} is missing") from error
    if os.path.normcase(str(path)) != os.path.normcase(str(resolved)):
        raise ArmTargetBuildError(f"{label} path is aliased or symlinked")
    if _has_reparse_component(path):
        raise ArmTargetBuildError(f"{label} path contains a reparse component")
    if not _is_within(resolved, resolved_root):
        raise ArmTargetBuildError(f"{label} is outside its approved root")
    if path.is_symlink() or not resolved.is_file():
        raise ArmTargetBuildError(f"{label} must be a regular non-symlink file")
    mode = resolved.stat().st_mode
    if not stat.S_ISREG(mode):
        raise ArmTargetBuildError(f"{label} must be a regular file")
    return resolved


def _compiler_environment(toolchain_root: Path) -> dict[str, str]:
    environment = dict(os.environ)
    for key in COMPILER_ENVIRONMENT_KEYS:
        environment.pop(key, None)
    environment["PATH"] = str((toolchain_root / "bin").resolve())
    environment["LC_ALL"] = "C"
    environment["LANG"] = "C"
    return environment


def _run_raw(
    argv: Sequence[Path | str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
) -> subprocess.CompletedProcess[str]:
    if not argv or not Path(argv[0]).is_absolute():
        raise ArmTargetBuildError("commands require an absolute executable")
    try:
        completed = subprocess.run(
            [str(item) for item in argv],
            cwd=str(cwd),
            env=dict(environment),
            shell=False,
            stdin=subprocess.DEVNULL,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ArmTargetBuildError("command could not complete safely") from error
    if completed.returncode != 0:
        diagnostic = (completed.stderr or completed.stdout).strip()
        raise ArmTargetBuildError(
            f"command failed ({completed.returncode}): {diagnostic or 'no diagnostic'}"
        )
    return completed


def validate_compiler_identity(target: str, version: str) -> None:
    if target.strip() != "arm-none-eabi":
        raise ArmTargetBuildError("compiler target is not arm-none-eabi")
    if version.strip() != "15.2.1":
        raise ArmTargetBuildError("compiler version is not the pinned 15.2.1")


def resolve_toolchain_tools(
    toolchain_root: Path,
    *,
    tool_overrides: Mapping[str, Path] | None = None,
) -> dict[str, Path]:
    root_argument = Path(toolchain_root)
    if not root_argument.is_absolute():
        raise ArmTargetBuildError("toolchain root must be absolute")
    try:
        root = root_argument.resolve(strict=True)
    except OSError as error:
        raise ArmTargetBuildError("toolchain root is missing") from error
    if os.path.normcase(str(root_argument)) != os.path.normcase(str(root)):
        raise ArmTargetBuildError("toolchain root path is aliased or symlinked")
    if not root.is_dir() or root_argument.is_symlink() or _has_reparse_component(root_argument):
        raise ArmTargetBuildError("toolchain root must be a real directory")
    overrides = dict(tool_overrides or {})
    if not set(overrides) <= set(TOOL_NAMES):
        raise ArmTargetBuildError("unknown tool override")
    tools = {}
    for role, relative in PINNED_TOOL_PATHS.items():
        expected_path = root / relative
        candidate = Path(overrides.get(role, expected_path))
        if os.path.normcase(str(candidate)) != os.path.normcase(str(expected_path)):
            raise ArmTargetBuildError(f"{role} path is not the exact pinned role path")
        tools[role] = _require_regular_file(candidate, root, role)
    for role, path in tools.items():
        if _sha256_file(path) != PINNED_TOOL_HASHES[role]:
            raise ArmTargetBuildError(f"{role} hash differs from the pinned toolchain")

    environment = _compiler_environment(root)
    target = _run_raw(
        [tools["gcc"], "-dumpmachine"], cwd=root, environment=environment
    ).stdout.strip()
    version = _run_raw(
        [tools["gcc"], "-dumpfullversion"], cwd=root, environment=environment
    ).stdout.strip()
    validate_compiler_identity(target, version)
    for role in ("cc1", "as"):
        printed = _run_raw(
            [tools["gcc"], f"-print-prog-name={role}"],
            cwd=root,
            environment=environment,
        ).stdout.strip()
        candidate = Path(printed)
        if not candidate.is_absolute():
            raise ArmTargetBuildError(f"compiler resolved {role} by PATH")
        try:
            candidate = candidate.resolve(strict=True)
        except OSError as error:
            raise ArmTargetBuildError(f"compiler-resolved {role} is missing") from error
        resolved_helper = _require_regular_file(candidate, root, role)
        if resolved_helper != tools[role]:
            raise ArmTargetBuildError(f"compiler-resolved {role} path differs")
    return tools


def validate_compile_flags(flags: Sequence[str]) -> list[str]:
    normalized = list(flags)
    if normalized != EXPECTED_COMPILE_FLAGS:
        raise ArmTargetBuildError("compile flags differ from the pinned profile")
    return normalized


def validate_link_mode(mode: Sequence[str]) -> list[str]:
    normalized = list(mode)
    if normalized != ["-r"]:
        raise ArmTargetBuildError("only natural relocatable linking is permitted")
    return normalized


def validate_output_path(output_path: Path, *, repo_root: Path | None = None) -> Path:
    candidate = Path(output_path)
    if not candidate.is_absolute():
        raise ArmTargetBuildError("output path must be absolute")
    if candidate.name != PUBLIC_OUTPUT_NAME:
        raise ArmTargetBuildError("only the named .o relocatable output is permitted")
    try:
        parent = candidate.parent.resolve(strict=True)
    except OSError as error:
        raise ArmTargetBuildError("output parent is missing") from error
    if os.path.normcase(str(candidate.parent)) != os.path.normcase(str(parent)):
        raise ArmTargetBuildError("output parent is aliased or symlinked")
    temporary_root = Path(tempfile.gettempdir()).resolve(strict=True)
    approved = _is_within(parent, temporary_root)
    if repo_root is not None:
        repository = Path(repo_root).resolve(strict=True)
        inside_repository = _is_within(parent, repository)
        inside_artifact_root = False
        artifact_root = repository / ".artifacts" / "analysis-output"
        if artifact_root.is_dir() and not artifact_root.is_symlink():
            resolved_artifact_root = artifact_root.resolve(strict=True)
            if os.path.normcase(str(artifact_root)) == os.path.normcase(
                str(resolved_artifact_root)
            ):
                inside_artifact_root = _is_within(parent, resolved_artifact_root)
        if inside_repository and not inside_artifact_root:
            approved = False
        else:
            approved = approved or inside_artifact_root
    if not approved:
        raise ArmTargetBuildError("output is outside approved temp/artifact roots")
    if candidate.exists() or candidate.is_symlink():
        raise ArmTargetBuildError("output path must not already exist")
    return parent / candidate.name


def _approved_inputs(repo_root: Path) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    native = repo_root / "native" / "a6400_creative_look"
    return (
        tuple(native / name for name in SOURCE_NAMES),
        tuple(native / name for name in HEADER_NAMES),
    )


def validate_production_inputs(
    repo_root: Path,
    source_paths: Sequence[Path],
    header_paths: Sequence[Path],
) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    root_argument = Path(repo_root)
    if not root_argument.is_absolute():
        raise ArmTargetBuildError("repository root must be absolute")
    try:
        root = root_argument.resolve(strict=True)
    except OSError as error:
        raise ArmTargetBuildError("repository root is missing") from error
    approved_sources, approved_headers = _approved_inputs(root)
    source_arguments = tuple(Path(path) for path in source_paths)
    header_arguments = tuple(Path(path) for path in header_paths)
    for path in source_arguments + header_arguments:
        if not path.is_absolute():
            raise ArmTargetBuildError("production input path must be absolute")
        try:
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise ArmTargetBuildError("production input is missing") from error
        if os.path.normcase(str(path)) != os.path.normcase(str(resolved)):
            raise ArmTargetBuildError("production input path is aliased or symlinked")
    sources = tuple(path.resolve(strict=True) for path in source_arguments)
    headers = tuple(path.resolve(strict=True) for path in header_arguments)
    if sources != approved_sources or headers != approved_headers:
        raise ArmTargetBuildError("production input allowlist differs")
    for path in sources + headers:
        _require_regular_file(path, root, "production input")
    return sources, headers


def _strip_c_comments(text: str) -> str:
    """Remove comments without treating comment markers inside literals as syntax."""
    output = []
    index = 0
    state = "code"
    while index < len(text):
        character = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if character == "/" and following == "*":
                output.extend("  ")
                index += 2
                state = "block"
                continue
            if character == "/" and following == "/":
                output.extend("  ")
                index += 2
                state = "line"
                continue
            output.append(character)
            if character == '"':
                state = "string"
            elif character == "'":
                state = "character"
            index += 1
            continue
        if state == "block":
            if character == "*" and following == "/":
                output.extend("  ")
                index += 2
                state = "code"
            else:
                output.append("\n" if character == "\n" else " ")
                index += 1
            continue
        if state == "line":
            output.append("\n" if character == "\n" else " ")
            index += 1
            if character == "\n":
                state = "code"
            continue
        output.append(character)
        index += 1
        if character == "\\" and index < len(text):
            output.append(text[index])
            index += 1
        elif (state == "string" and character == '"') or (
            state == "character" and character == "'"
        ):
            state = "code"
    if state == "block":
        raise ArmTargetBuildError("source text has an unterminated block comment")
    return "".join(output)


def _c_phase_two(text: str) -> str:
    if re.search(r"\?\?[=/\\'()!<>-]", text):
        raise ArmTargetBuildError("C trigraphs are not permitted")
    if text.endswith("\\"):
        raise ArmTargetBuildError("C line splice is incomplete")
    return re.sub(r"\\\r?\n", "", text)


_C_STRING = r'(?:u8|[LuU])?"(?:\\.|[^"\\])*"'


def _decode_c_string(literal: str) -> str:
    match = re.fullmatch(r'(?:u8|[LuU])?"((?:\\.|[^"\\])*)"', literal)
    if match is None:
        raise ArmTargetBuildError("C string literal is malformed")
    body = match.group(1)
    output = []
    index = 0
    simple = {
        "a": "\a",
        "b": "\b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "v": "\v",
        "\\": "\\",
        "'": "'",
        '"': '"',
        "?": "?",
    }
    while index < len(body):
        if body[index] != "\\":
            output.append(body[index])
            index += 1
            continue
        index += 1
        if index >= len(body):
            raise ArmTargetBuildError("C string escape is incomplete")
        escape = body[index]
        if escape in simple:
            output.append(simple[escape])
            index += 1
            continue
        if escape in "01234567":
            end = index + 1
            while end < len(body) and end < index + 3 and body[end] in "01234567":
                end += 1
            output.append(chr(int(body[index:end], 8)))
            index = end
            continue
        if escape == "x":
            end = index + 1
            while end < len(body) and body[end] in "0123456789abcdefABCDEF":
                end += 1
            if end == index + 1:
                raise ArmTargetBuildError("C hexadecimal escape is empty")
            output.append(chr(int(body[index + 1 : end], 16)))
            index = end
            continue
        if escape in ("u", "U"):
            digits = 4 if escape == "u" else 8
            end = index + 1 + digits
            value = body[index + 1 : end]
            if len(value) != digits or re.fullmatch(r"[0-9a-fA-F]+", value) is None:
                raise ArmTargetBuildError("C universal escape is malformed")
            try:
                output.append(chr(int(value, 16)))
            except ValueError as error:
                raise ArmTargetBuildError("C universal escape is invalid") from error
            index = end
            continue
        if escape in ("\n", "\r"):
            index += 1
            if escape == "\r" and index < len(body) and body[index] == "\n":
                index += 1
            continue
        raise ArmTargetBuildError("unsupported C string escape")
    return "".join(output)


def _c_string_groups(text: str) -> list[str]:
    groups = []
    for match in re.finditer(rf"(?:{_C_STRING}\s*)+", text):
        groups.append(
            "".join(
                _decode_c_string(literal)
                for literal in re.findall(_C_STRING, match.group())
            )
        )
    return groups


def _forbidden_fragment(value: str) -> str | None:
    folded = value.casefold()
    for forbidden in FORBIDDEN_SOURCE_IDENTIFIERS + FORBIDDEN_SOURCE_STRING_FRAGMENTS:
        if forbidden.casefold() in folded:
            return forbidden
    return None


def scan_source_text(path: Path, text: str) -> None:
    if not isinstance(text, str):
        raise ArmTargetBuildError("source text is invalid")
    uncommented = _strip_c_comments(_c_phase_two(text))
    string_groups = _c_string_groups(uncommented)
    without_strings = re.sub(_C_STRING, " ", uncommented)
    if "##" in without_strings or "%:%:" in without_strings:
        raise ArmTargetBuildError("forbidden preprocessor token paste")
    identifiers = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", without_strings)
    for identifier in identifiers:
        folded = identifier.casefold()
        for forbidden in FORBIDDEN_SOURCE_IDENTIFIERS:
            if forbidden.casefold() in folded:
                raise ArmTargetBuildError(
                    f"forbidden production capability {forbidden!r} in {Path(path).name}"
                )
    for value in string_groups:
        forbidden = _forbidden_fragment(value)
        if forbidden is not None:
            raise ArmTargetBuildError(
                f"forbidden production capability {forbidden!r} in {Path(path).name}"
            )
    folded_source = uncommented.casefold()
    for forbidden in FORBIDDEN_SOURCE_STRING_FRAGMENTS:
        if forbidden.casefold() in folded_source:
            raise ArmTargetBuildError(
                f"forbidden production capability {forbidden!r} in {Path(path).name}"
            )


def scan_object_data(value: bytes) -> None:
    """Reject operational Sony/loader/device strings embedded in the object."""
    if not isinstance(value, bytes):
        raise ArmTargetBuildError("object data is invalid")
    folded = value.lower()
    for forbidden in FORBIDDEN_SOURCE_IDENTIFIERS + FORBIDDEN_SOURCE_STRING_FRAGMENTS:
        if forbidden == PROPOSED_FACTORY_LABEL:
            continue
        normalized = forbidden.casefold()
        encodings = (
            normalized.encode("ascii"),
            normalized.encode("utf-16le"),
            normalized.encode("utf-32le"),
        )
        if any(encoded in folded for encoded in encodings):
            raise ArmTargetBuildError(
                f"forbidden production capability {forbidden!r} in object data"
            )


def scan_include_text(
    path: Path, text: str, approved_local_headers: Mapping[str, Path]
) -> dict:
    uncommented = _strip_c_comments(_c_phase_two(text))
    quoted = []
    system = []
    for line in uncommented.splitlines():
        directive = re.match(r"^\s*(?:#|%:)\s*include\b(.*?)\s*$", line)
        if directive is None:
            continue
        operand = directive.group(1).strip()
        match = re.fullmatch(r'([<"])([^>"]+)[>"]', operand)
        if match is None:
            raise ArmTargetBuildError("include directive is not a literal")
        delimiter, name = match.groups()
        if delimiter == '"':
            approved = approved_local_headers.get(name)
            if approved is None or path.parent / name != approved:
                raise ArmTargetBuildError(f"unapproved quoted include {name}")
            quoted.append(name)
        else:
            if name not in APPROVED_SYSTEM_HEADERS:
                raise ArmTargetBuildError(f"unapproved system include {name}")
            system.append(name)
    return {"quoted": quoted, "system": system}


def validate_include_closure(
    repo_root: Path, inputs: Sequence[Path], approved_headers: Sequence[Path]
) -> list[dict]:
    approved = {path.name: path for path in approved_headers}
    if len(approved) != len(approved_headers):
        raise ArmTargetBuildError("approved header names are not unique")
    records = []
    for path in inputs:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise ArmTargetBuildError("production input cannot be read") from error
        includes = scan_include_text(path, text, approved)
        records.append(
            {
                "path": path.relative_to(repo_root).as_posix(),
                "quoted": includes["quoted"],
                "system": includes["system"],
            }
        )
    return records


def validate_undefined_symbols(symbols: Sequence[str]) -> None:
    if list(symbols) != []:
        raise ArmTargetBuildError("combined object has undefined symbols")


def validate_defined_symbols(symbols: Sequence[str]) -> None:
    for symbol in symbols:
        lowered = symbol.lower()
        if (
            symbol in FORBIDDEN_EXACT_DEFINED_SYMBOLS
            or any(fragment.lower() in lowered for fragment in FORBIDDEN_SYMBOL_FRAGMENTS)
        ):
            raise ArmTargetBuildError(f"combined object defines forbidden symbol {symbol}")


def validate_production_object_symbols(
    source_name: str,
    undefined_symbols: Sequence[str],
    defined_symbols: Sequence[str],
    symbol_table: Sequence[Mapping[str, object]],
) -> None:
    for name in list(undefined_symbols) + list(defined_symbols) + [
        str(record.get("name", "")) for record in symbol_table
    ]:
        lowered = name.casefold()
        if any(fragment.casefold() in lowered for fragment in FORBIDDEN_SYMBOL_FRAGMENTS):
            raise ArmTargetBuildError(f"production object has forbidden symbol {name}")
    if source_name == "creative_look_target.c":
        expected_undefined = {
            "cl_bridge_close",
            "cl_bridge_init",
            "cl_bridge_last_report",
            "cl_bridge_open",
            "cl_bridge_state",
        }
        if set(undefined_symbols) != expected_undefined:
            raise ArmTargetBuildError("target shell object dependency set differs")
        prohibited_direct = {
            "cl_bridge_handle_event",
            "cl_assign_custom",
            "cl_handle_event",
            "cl_set_adjustment",
            "cl_set_orientation",
            "cl_set_screen",
            "cl_set_selected",
        }
        if prohibited_direct & (
            set(undefined_symbols) | set(defined_symbols)
        ):
            raise ArmTargetBuildError("target shell object bypasses the bridge")


def validate_abi_layouts(layouts: Mapping[str, Mapping[str, int]]) -> dict:
    if layouts != EXPECTED_ABI_LAYOUTS:
        raise ArmTargetBuildError("ARM ABI layout differs")
    return copy.deepcopy(EXPECTED_ABI_LAYOUTS)


def _load_profile_module(repo_root: Path):
    module_path = repo_root / "pmca" / "analysis" / "creative_look_arm_target_profile.py"
    spec = importlib.util.spec_from_file_location(
        "creative_look_arm_target_profile_for_export", module_path
    )
    if spec is None or spec.loader is None:
        raise ArmTargetBuildError("target profile validator cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_profile(repo_root: Path, profile_path: Path) -> tuple[object, dict]:
    profile_file = _require_regular_file(Path(profile_path), repo_root, "profile")
    try:
        document = json.loads(profile_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ArmTargetBuildError("target profile cannot be loaded") from error
    module = _load_profile_module(repo_root)
    try:
        if "build_evidence" in document:
            validated = module.validate_creative_look_arm_target_profile(document)
        else:
            validated = module.validate_creative_look_arm_target_profile(document)
    except Exception as error:
        raise ArmTargetBuildError("target profile validation failed") from error
    return module, validated


def _normalize_argument(
    value: Path | str,
    *,
    repo_root: Path,
    toolchain_root: Path,
    output_root: Path,
    build_root: Path,
) -> str:
    normalized = str(value).replace("\\", "/")
    replacements = sorted(
        (
            (str(build_root).replace("\\", "/"), "$BUILD"),
            (str(output_root).replace("\\", "/"), "$OUTPUT"),
            (str(toolchain_root).replace("\\", "/"), "$TOOLCHAIN"),
            (str(repo_root).replace("\\", "/"), "$REPO"),
        ),
        key=lambda item: len(item[0]),
        reverse=True,
    )
    for absolute, replacement in replacements:
        if normalized.casefold().startswith(absolute.casefold()):
            normalized = replacement + normalized[len(absolute) :]
            break
    if normalized == "$BUILD/" + PUBLIC_OUTPUT_NAME:
        normalized = "$OUTPUT/" + PUBLIC_OUTPUT_NAME
    return normalized


def _normalize_text(
    value: str,
    *,
    repo_root: Path,
    toolchain_root: Path,
    output_root: Path,
    build_root: Path,
) -> str:
    normalized = value.replace("\\", "/")
    replacements = sorted(
        (
            (str(build_root).replace("\\", "/"), "$BUILD"),
            (str(output_root).replace("\\", "/"), "$OUTPUT"),
            (str(toolchain_root).replace("\\", "/"), "$TOOLCHAIN"),
            (str(repo_root).replace("\\", "/"), "$REPO"),
        ),
        key=lambda item: len(item[0]),
        reverse=True,
    )
    for absolute, replacement in replacements:
        normalized = re.sub(re.escape(absolute), replacement, normalized, flags=re.IGNORECASE)
    normalized = normalized.replace(
        "$BUILD/" + PUBLIC_OUTPUT_NAME,
        "$OUTPUT/" + PUBLIC_OUTPUT_NAME,
    )
    return normalized


def _run_recorded(
    argv: Sequence[Path | str],
    *,
    purpose: str,
    cwd: Path,
    environment: Mapping[str, str],
    command_records: list[dict],
    repo_root: Path,
    toolchain_root: Path,
    output_root: Path,
    build_root: Path,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = _run_raw(argv, cwd=cwd, environment=environment)
    except ArmTargetBuildError:
        raise
    command_records.append(
        {
            "purpose": purpose,
            "argv": [
                _normalize_argument(
                    item,
                    repo_root=repo_root,
                    toolchain_root=toolchain_root,
                    output_root=output_root,
                    build_root=build_root,
                )
                for item in argv
            ],
            "returncode": completed.returncode,
            "stdout_sha256": _sha256_bytes(
                _normalize_text(
                    completed.stdout,
                    repo_root=repo_root,
                    toolchain_root=toolchain_root,
                    output_root=output_root,
                    build_root=build_root,
                ).encode("utf-8")
            ),
            "stderr_sha256": _sha256_bytes(
                _normalize_text(
                    completed.stderr,
                    repo_root=repo_root,
                    toolchain_root=toolchain_root,
                    output_root=output_root,
                    build_root=build_root,
                ).encode("utf-8")
            ),
        }
    )
    return completed


def _abi_probe_source(layouts: Mapping[str, Mapping[str, int]]) -> str:
    validate_abi_layouts(layouts)
    lines = [
        "#include <stddef.h>",
        '#include "creative_look_target.h"',
        "#define CL_ASSERT(name, condition) typedef char name[(condition) ? 1 : -1]",
        "#define CL_ALIGNOF(type) offsetof(struct { char prefix; type value; }, value)",
    ]
    for index, (name, record) in enumerate(layouts.items()):
        if "value" in record:
            lines.append(
                f"CL_ASSERT(cl_probe_value_{index}, {name} == {record['value']});"
            )
        elif "." in name:
            structure, field = name.split(".", 1)
            lines.append(
                f"CL_ASSERT(cl_probe_offset_{index}, offsetof({structure}, {field}) == {record['offset']});"
            )
        else:
            lines.append(
                f"CL_ASSERT(cl_probe_size_{index}, sizeof({name}) == {record['size']});"
            )
            lines.append(
                f"CL_ASSERT(cl_probe_align_{index}, CL_ALIGNOF({name}) == {record['alignment']});"
            )
    lines.extend(
        (
            "static size_t (*const cl_probe_size_fn)(void) = cl_target_shell_size;",
            "static size_t (*const cl_probe_alignment_fn)(void) = cl_target_shell_alignment;",
            "static cl_result (*const cl_probe_init_fn)(cl_target_shell *, const cl_integration_manifest *, const cl_bridge_adapters *) = cl_target_shell_init;",
            "static cl_result (*const cl_probe_open_fn)(cl_target_shell *, cl_bridge_report *) = cl_target_shell_open;",
            "static cl_result (*const cl_probe_close_fn)(cl_target_shell *, cl_bridge_report *) = cl_target_shell_close;",
            "static cl_result (*const cl_probe_deliver_fn)(cl_target_shell *, const cl_input_event *, cl_bridge_report *) = cl_target_shell_deliver;",
            "static const cl_view_frame *(*const cl_probe_frame_fn)(const cl_target_shell *) = cl_target_shell_copied_frame;",
            "static const cl_state *(*const cl_probe_state_fn)(const cl_target_shell *) = cl_target_shell_bridge_state;",
            "static const cl_bridge_report *(*const cl_probe_report_fn)(const cl_target_shell *) = cl_target_shell_last_report;",
            "static const cl_target_identity *(*const cl_probe_identity_fn)(void) = cl_target_shell_identity;",
            "int cl_arm_abi_probe_anchor(void) {",
            "    return cl_probe_size_fn != 0 && cl_probe_alignment_fn != 0 &&",
            "        cl_probe_init_fn != 0 && cl_probe_open_fn != 0 &&",
            "        cl_probe_close_fn != 0 && cl_probe_deliver_fn != 0 &&",
            "        cl_probe_frame_fn != 0 && cl_probe_state_fn != 0 &&",
            "        cl_probe_report_fn != 0 && cl_probe_identity_fn != 0;",
            "}",
        )
    )
    return "\n".join(lines) + "\n"


def _parse_elf_header(text: str) -> dict:
    def field(label: str) -> str:
        match = re.search(rf"^\s*{re.escape(label)}:\s*(.+?)\s*$", text, re.MULTILINE)
        if match is None:
            raise ArmTargetBuildError(f"readelf header lacks {label}")
        return match.group(1)

    elf_class = field("Class")
    data_raw = field("Data")
    type_raw = field("Type")
    machine = field("Machine")
    flags = field("Flags")
    observed = {
        "class": elf_class,
        "data": "little-endian" if "little endian" in data_raw else data_raw,
        "machine": machine,
        "eabi_version": 5 if "Version5 EABI" in flags else 0,
        "type": "ET_REL" if type_raw.startswith("REL ") else type_raw.split()[0],
    }
    expected = {
        "class": "ELF32",
        "data": "little-endian",
        "machine": "ARM",
        "eabi_version": 5,
        "type": "ET_REL",
    }
    if observed != expected:
        raise ArmTargetBuildError("combined object ELF contract differs")
    return observed


def _normalize_attribute_value(name: str, raw: str) -> str | int:
    value = raw.strip().strip('"')
    if name in ("Tag_ABI_PCS_wchar_t", "Tag_ABI_enum_size"):
        if value == "int":
            return 4
        match = re.search(r"\d+", value)
        if match is None:
            raise ArmTargetBuildError(f"invalid value for {name}")
        return int(match.group())
    if name == "Tag_ABI_align_needed":
        match = re.search(r"\d+", value)
        if match is None:
            raise ArmTargetBuildError(f"invalid value for {name}")
        return int(match.group())
    return value


def _parse_attributes(text: str, profile_module: object) -> dict:
    attributes = []
    for match in re.finditer(r"^\s*(Tag_[A-Za-z0-9_]+):\s*(.*?)\s*$", text, re.MULTILINE):
        name, raw = match.groups()
        if name not in ATTRIBUTE_TAGS:
            raise ArmTargetBuildError(f"unknown ARM attribute {name}")
        attributes.append(
            {
                "tag": ATTRIBUTE_TAGS[name],
                "name": name,
                "value": _normalize_attribute_value(name, raw),
            }
        )
    try:
        return profile_module.validate_arm_target_attributes(attributes)
    except Exception as error:
        raise ArmTargetBuildError("ARM attributes differ") from error


def _parse_sections(text: str) -> list[dict]:
    sections = []
    seen_names = set()
    known_types = {
        "NULL",
        "PROGBITS",
        "SYMTAB",
        "STRTAB",
        "RELA",
        "REL",
        "DYNAMIC",
        "NOTE",
        "NOBITS",
        "PREINIT_ARRAY",
        "INIT_ARRAY",
        "FINI_ARRAY",
        "ARM_ATTRIBUTES",
        "GROUP",
        "SYMTAB_SHNDX",
    }
    for line in text.splitlines():
        match = re.match(r"^\s*\[\s*(\d+)\]\s+(.*?)\s*$", line)
        if match is None:
            continue
        index = int(match.group(1))
        fields = match.group(2).split()
        if not fields:
            raise ArmTargetBuildError("section table row is malformed")
        name = ""
        if fields[0] not in known_types:
            name = fields.pop(0)
        if len(fields) < 8 or fields[0] not in known_types:
            raise ArmTargetBuildError("section table row is malformed")
        section_type = fields.pop(0)
        try:
            int(fields.pop(0), 16)  # address is intentionally not evidence
            offset = int(fields.pop(0), 16)
            size = int(fields.pop(0), 16)
            int(fields.pop(0), 16)  # entry size
            if len(fields) == 4:
                flags = fields.pop(0)
            elif len(fields) == 3:
                flags = ""
            else:
                raise ValueError
            link, info, alignment = (int(value, 10) for value in fields)
        except ValueError as error:
            raise ArmTargetBuildError("section table row is malformed") from error
        if index != len(sections):
            raise ArmTargetBuildError("section table indices are not complete")
        if name and name in seen_names:
            raise ArmTargetBuildError("section names are not unique")
        seen_names.add(name)
        sections.append(
            {
                "index": index,
                "name": name,
                "type": section_type,
                "offset": offset,
                "size": size,
                "flags": flags,
                "link": link,
                "info": info,
                "alignment": alignment,
            }
        )
    if not sections:
        raise ArmTargetBuildError("section table is empty")
    forbidden = {
        ".dynamic",
        ".dynsym",
        ".fini",
        ".fini_array",
        ".init",
        ".init_array",
        ".preinit_array",
        ".interp",
        ".ctors",
        ".dtors",
    }
    matches = sorted(
        section["name"]
        for section in sections
        if any(
            section["name"] == forbidden_name
            or section["name"].startswith(forbidden_name + ".")
            for forbidden_name in forbidden
        )
    )
    forbidden_types = {"DYNAMIC", "PREINIT_ARRAY", "INIT_ARRAY", "FINI_ARRAY"}
    typed = [section["name"] or f"#{section['index']}" for section in sections if section["type"] in forbidden_types]
    writable_executable = [section["name"] for section in sections if "W" in section["flags"] and "X" in section["flags"]]
    if matches or typed or writable_executable:
        raise ArmTargetBuildError(
            "combined object has dynamic/initializer/unsafe sections: "
            + ", ".join(matches + typed + writable_executable)
        )
    return sections


def _section_data(object_data: bytes, sections: Sequence[Mapping[str, object]]) -> dict[str, bytes]:
    result = {}
    for section in sections:
        name = section["name"]
        offset = section["offset"]
        size = section["size"]
        if not isinstance(name, str) or type(offset) is not int or type(size) is not int:
            raise ArmTargetBuildError("section evidence is malformed")
        if offset < 0 or size < 0 or offset + size > len(object_data):
            raise ArmTargetBuildError("section extends beyond the object")
        result[name] = object_data[offset : offset + size]
    return result


def _parse_relocations(
    text: str,
    sections: Sequence[Mapping[str, object]],
    section_data: Mapping[str, bytes],
) -> list[dict]:
    section_by_name = {item["name"]: item for item in sections}
    section_by_index = {item["index"]: item for item in sections}
    records = []
    active_name = None
    active_expected = 0
    active_seen = 0
    header_count = 0
    seen_headers = set()
    for line in text.splitlines():
        header = re.match(
            r"^Relocation section '(\S+)' .* contains (\d+) entr(?:y|ies):$",
            line.strip(),
        )
        if header is not None:
            if active_name is not None and active_seen != active_expected:
                raise ArmTargetBuildError("relocation row count differs")
            active_name = header.group(1)
            if active_name in seen_headers:
                raise ArmTargetBuildError("relocation section is duplicated")
            seen_headers.add(active_name)
            active_expected = int(header.group(2))
            active_seen = 0
            header_count += 1
            relocation_section = section_by_name.get(active_name)
            if relocation_section is None or relocation_section["type"] not in ("REL", "RELA"):
                raise ArmTargetBuildError("relocation section is absent from section table")
            continue
        stripped = line.strip()
        if re.match(r"^[0-9a-fA-F]{8}\s", stripped) is None:
            continue
        if active_name is None:
            raise ArmTargetBuildError("relocation row has no section header")
        fields = stripped.split()
        if len(fields) < 5 or not fields[2].startswith("R_ARM_"):
            raise ArmTargetBuildError("relocation row is malformed")
        try:
            offset = int(fields[0], 16)
            symbol_value = int(fields[3], 16)
        except ValueError as error:
            raise ArmTargetBuildError("relocation row is malformed") from error
        relocation_section = section_by_name[active_name]
        source_section = section_by_index.get(relocation_section["info"])
        if source_section is None:
            raise ArmTargetBuildError("relocation source section is missing")
        source = section_data.get(source_section["name"])
        if not isinstance(source, bytes) or offset < 0 or offset + 4 > len(source):
            raise ArmTargetBuildError("relocation source operand is out of bounds")
        addend = None
        if len(fields) > 5:
            if len(fields) != 7 or fields[5] not in ("+", "-"):
                raise ArmTargetBuildError("relocation addend is malformed")
            try:
                magnitude = int(fields[6], 16)
            except ValueError as error:
                raise ArmTargetBuildError("relocation addend is malformed") from error
            addend = magnitude if fields[5] == "+" else -magnitude
        records.append(
            {
                "relocation_section": active_name,
                "source_section": source_section["name"],
                "offset": offset,
                "type": fields[2],
                "symbol_value": symbol_value,
                "symbol": fields[4],
                "addend": addend,
                "encoded_source_word": source[offset : offset + 4].hex(),
            }
        )
        active_seen += 1
    if active_name is not None and active_seen != active_expected:
        raise ArmTargetBuildError("relocation row count differs")
    expected_headers = {
        item["name"] for item in sections if item["type"] in ("REL", "RELA")
    }
    if seen_headers != expected_headers:
        raise ArmTargetBuildError("relocation section coverage differs")
    if header_count == 0 or not records:
        raise ArmTargetBuildError("relocation table is empty")
    return records


def _parse_nm_symbols(text: str) -> list[str]:
    symbols = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            symbols.append(stripped.split()[0])
    return sorted(set(symbols))


def _parse_symbol_table(
    text: str, sections: Sequence[Mapping[str, object]] | None = None
) -> list[dict]:
    entries = 0
    records = []
    section_by_index = {item["index"]: item["name"] for item in sections or ()}
    for line in text.splitlines():
        match = re.match(
            r"^\s*(\d+):\s+([0-9a-fA-F]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.*?))?\s*$",
            line,
        )
        if match is None:
            if re.match(r"^\s*\d+:\s", line):
                raise ArmTargetBuildError("full symbol table row is malformed")
            continue
        entries += 1
        _, value_raw, size_raw, symbol_type, binding, visibility, index_raw, name = match.groups()
        name = (name or "").strip()
        if not name:
            continue
        try:
            section_index: int | str = int(index_raw, 10)
        except ValueError:
            section_index = index_raw
        records.append(
            {
                "name": name,
                "value": int(value_raw, 16),
                "size": int(size_raw, 10),
                "type": symbol_type,
                "binding": binding,
                "visibility": visibility,
                "section_index": section_index,
                "section": section_by_index.get(section_index),
            }
        )
    if entries == 0:
        raise ArmTargetBuildError("full symbol table is empty")
    return records


def validate_full_symbol_table(
    text: str, sections: Sequence[Mapping[str, object]] | None = None
) -> list[dict]:
    """Validate every local/global readelf symbol, including named UND rows."""
    records = _parse_symbol_table(text, sections)
    defined_names = set()
    for record in records:
        name = record["name"]
        if record["section_index"] == "UND":
            raise ArmTargetBuildError(f"full symbol table has undefined symbol {name}")
        defined_names.add(name)
        lowered = name.casefold()
        if (
            name in FORBIDDEN_EXACT_DEFINED_SYMBOLS
            or any(fragment.casefold() in lowered for fragment in FORBIDDEN_SYMBOL_FRAGMENTS)
        ):
            raise ArmTargetBuildError(f"full symbol table has forbidden symbol {name}")
    if not {"cl_init", "cl_bridge_open"} <= defined_names:
        raise ArmTargetBuildError("full symbol table is incomplete")
    return records


def validate_relocation_capabilities(relocations: Sequence[Mapping[str, object]]) -> None:
    if not relocations:
        raise ArmTargetBuildError("relocation inventory is empty")
    for relocation in relocations:
        symbol = relocation.get("symbol")
        if not isinstance(symbol, str) or not symbol:
            raise ArmTargetBuildError("relocation symbol operand is missing")
        folded = symbol.casefold()
        if any(fragment.casefold() in folded for fragment in FORBIDDEN_SYMBOL_FRAGMENTS):
            raise ArmTargetBuildError(
                f"relocation targets forbidden symbol {symbol}"
            )


def _validate_identity_accessor_relocation(
    accessor: Mapping[str, object],
    relocations: Sequence[Mapping[str, object]],
    record_section_name: str,
) -> Mapping[str, object]:
    value = accessor.get("value")
    size = accessor.get("size")
    if type(value) is not int or type(size) is not int or size <= 0:
        raise ArmTargetBuildError("identity accessor symbol differs")
    start = value & ~1
    end = start + size
    inside = [
        relocation
        for relocation in relocations
        if relocation.get("source_section") == ".text"
        and type(relocation.get("offset")) is int
        and start <= relocation["offset"] < end
    ]
    references = [
        relocation
        for relocation in relocations
        if relocation.get("source_section") == ".text"
        and relocation.get("symbol") == record_section_name
    ]
    if len(inside) != 1 or len(references) != 1 or inside[0] is not references[0]:
        raise ArmTargetBuildError("identity accessor relocation differs")
    relocation = inside[0]
    if relocation.get("type") != "R_ARM_REL32":
        raise ArmTargetBuildError("identity accessor relocation differs")
    return relocation


def _validate_factory_reference_boundary(
    relocations: Sequence[Mapping[str, object]],
    string_section_name: str,
    expected_record_relocation: Mapping[str, object],
) -> None:
    references = []
    for relocation in relocations:
        if relocation.get("symbol") != string_section_name:
            continue
        encoded = relocation.get("encoded_source_word")
        if not isinstance(encoded, str) or re.fullmatch(r"[0-9a-f]{8}", encoded) is None:
            raise ArmTargetBuildError("factory relocation operand differs")
        implicit_addend = int.from_bytes(bytes.fromhex(encoded), "little")
        explicit_addend = relocation.get("addend")
        if implicit_addend == 0x28 or explicit_addend == 0x28:
            references.append(relocation)
    if len(references) != 1 or references[0] is not expected_record_relocation:
        raise ArmTargetBuildError("factory metadata has an extra relocation reference")


def _identity_metadata(
    *,
    repo_root: Path,
    sources: Sequence[Path],
    object_data: bytes,
    sections: Sequence[Mapping[str, object]],
    section_data: Mapping[str, bytes],
    relocations: Sequence[Mapping[str, object]],
    symbols: Sequence[Mapping[str, object]],
) -> dict:
    def only_symbol(name: str) -> Mapping[str, object]:
        matches = [record for record in symbols if record["name"] == name]
        if len(matches) != 1:
            raise ArmTargetBuildError(f"identity symbol {name} differs")
        return matches[0]

    proposed = only_symbol("cl_target_proposed_identity")
    accessor = only_symbol("cl_target_shell_identity")
    record_section = next(
        (item for item in sections if item["name"] == ".data.rel.ro.local"), None
    )
    string_section = next(
        (item for item in sections if item["name"] == ".rodata.str1.4"), None
    )
    if record_section is None or string_section is None:
        raise ArmTargetBuildError("identity sections are missing")
    if (
        string_section["index"] != 4
        or string_section["type"] != "PROGBITS"
        or string_section["flags"] != "AMS"
        or "A" not in string_section["flags"]
        or "W" in string_section["flags"]
        or "X" in string_section["flags"]
    ):
        raise ArmTargetBuildError("identity strings are not read-only alloc metadata")
    if (
        record_section["index"] != 6
        or record_section["type"] != "PROGBITS"
        or record_section["flags"] != "WA"
        or "X" in record_section["flags"]
    ):
        raise ArmTargetBuildError("identity record section differs")
    expected_proposed = {
        "name": "cl_target_proposed_identity",
        "binding": "LOCAL",
        "type": "OBJECT",
        "size": 16,
        "section_index": record_section["index"],
        "section": record_section["name"],
    }
    observed_proposed = {
        key: proposed[key]
        for key in ("name", "binding", "type", "size", "section_index", "section")
    }
    if observed_proposed != expected_proposed or proposed["value"] != 0:
        raise ArmTargetBuildError("identity record symbol differs")
    expected_accessor = {
        "name": "cl_target_shell_identity",
        "binding": "GLOBAL",
        "type": "FUNC",
        "size": 12,
        "section_index": 1,
        "section": ".text",
    }
    observed_accessor = {
        key: accessor[key]
        for key in ("name", "binding", "type", "size", "section_index", "section")
    }
    if observed_accessor != expected_accessor:
        raise ArmTargetBuildError("identity accessor symbol differs")

    record_bytes = section_data[record_section["name"]]
    expected_record_hex = "00000000140000002800000000000000"
    if len(record_bytes) != 16 or record_bytes.hex() != expected_record_hex:
        raise ArmTargetBuildError("identity pointer record bytes differ")

    source_occurrences = {}
    for source in sources:
        text = source.read_text(encoding="utf-8")
        for _, value, _, _ in IDENTITY_LITERALS:
            source_occurrences[value] = source_occurrences.get(value, 0) + text.count(
                f'"{value}"'
            )
    string_bytes = section_data[string_section["name"]]
    expected_string_hex = (
        "766965772f43524541544956455f4c4f4f4b0000766965774372656174697665"
        "4c6f6f6b2e736f005669657743726561746976654c6f6f6b546f496e7374616e"
        "636500"
    )
    if (
        string_section["size"] != 67
        or len(string_bytes) != 67
        or string_bytes.hex() != expected_string_hex
        or _sha256_bytes(string_bytes)
        != "867511a4abb0a3b53fbc6930013e2dc31d6542a3466bc195560c59add950cf67"
    ):
        raise ArmTargetBuildError("identity string section differs")
    literal_records = []
    for field, value, record_offset, string_offset in IDENTITY_LITERALS:
        encoded = value.encode("ascii") + b"\0"
        if (
            source_occurrences.get(value) != 1
            or object_data.count(encoded) != 1
            or string_bytes.count(encoded) != 1
            or string_bytes[string_offset : string_offset + len(encoded)] != encoded
        ):
            raise ArmTargetBuildError(f"identity literal {field} differs")
        literal_records.append(
            {
                "field": field,
                "value": value,
                "record_offset": record_offset,
                "string_offset": string_offset,
                "source_occurrences": 1,
                "object_occurrences": 1,
                "section_occurrences": 1,
            }
        )

    record_relocations = []
    for _, _, record_offset, string_offset in IDENTITY_LITERALS:
        matches = [
            relocation
            for relocation in relocations
            if relocation["source_section"] == record_section["name"]
            and relocation["offset"] == record_offset
        ]
        if len(matches) != 1:
            raise ArmTargetBuildError("identity record relocation differs")
        relocation = matches[0]
        encoded_addend = int.from_bytes(
            bytes.fromhex(relocation["encoded_source_word"]), "little"
        )
        if (
            relocation["relocation_section"] != ".rel.data.rel.ro.local"
            or relocation["type"] != "R_ARM_ABS32"
            or relocation["symbol"] != string_section["name"]
            or encoded_addend != string_offset
        ):
            raise ArmTargetBuildError("identity record relocation differs")
        record_relocations.append(
            {
                "relocation_section": relocation["relocation_section"],
                "source_section": relocation["source_section"],
                "offset": record_offset,
                "type": relocation["type"],
                "symbol": relocation["symbol"],
                "addend": encoded_addend,
            }
        )
    if len([item for item in relocations if item["source_section"] == record_section["name"]]) != 3:
        raise ArmTargetBuildError("identity record has extra references")
    expected_factory_relocation = next(
        item
        for item in relocations
        if item["source_section"] == record_section["name"] and item["offset"] == 8
    )
    _validate_factory_reference_boundary(
        relocations, string_section["name"], expected_factory_relocation
    )

    accessor_relocation = _validate_identity_accessor_relocation(
        accessor, relocations, record_section["name"]
    )

    factory_symbol_occurrences = sum(
        PROPOSED_FACTORY_LABEL.casefold() in record["name"].casefold()
        for record in symbols
    )
    if factory_symbol_occurrences != 0:
        raise ArmTargetBuildError("proposed factory label became a symbol")
    return {
        "source": "native/a6400_creative_look/creative_look_target.c",
        "record_symbol": {**expected_proposed, "hex": expected_record_hex},
        "accessor_symbol": expected_accessor,
        "string_section": {
            **{
                key: string_section[key]
                for key in ("index", "name", "type", "flags", "size")
            },
            "hex": expected_string_hex,
            "sha256": _sha256_bytes(string_bytes),
        },
        "record_section": {
            key: record_section[key] for key in ("index", "name", "type", "flags")
        },
        "literals": literal_records,
        "record_relocations": record_relocations,
        "accessor_relocation": {
            key: accessor_relocation[key]
            for key in (
                "relocation_section",
                "source_section",
                "offset",
                "type",
                "symbol",
            )
        },
        "factory_symbol_occurrences": 0,
    }


def _tool_records(
    tools: Mapping[str, Path],
    *,
    root: Path,
    environment: Mapping[str, str],
    command_records: list[dict],
    repo_root: Path,
    output_root: Path,
    build_root: Path,
) -> list[dict]:
    records = []
    for role in ("gcc", "ld", "readelf", "nm", "objdump", "cc1", "as"):
        path = tools[role]
        if role == "cc1":
            records.append(
                {
                    "role": role,
                    "path": _normalize_argument(
                        path,
                        repo_root=repo_root,
                        toolchain_root=root,
                        output_root=output_root,
                        build_root=build_root,
                    ),
                    "sha256": _sha256_file(path),
                    "version": "arm-none-eabi GCC internal 15.2.1",
                }
            )
            continue
        completed = _run_recorded(
            [path, "--version"],
            purpose=f"identify:{role}",
            cwd=root,
            environment=environment,
            command_records=command_records,
            repo_root=repo_root,
            toolchain_root=root,
            output_root=output_root,
            build_root=build_root,
        )
        version_lines = (completed.stdout or completed.stderr).splitlines()
        if not version_lines:
            raise ArmTargetBuildError(f"{role} did not report a version")
        version = version_lines[0]
        records.append(
            {
                "role": role,
                "path": _normalize_argument(
                    path,
                    repo_root=repo_root,
                    toolchain_root=root,
                    output_root=output_root,
                    build_root=build_root,
                ),
                "sha256": _sha256_file(path),
                "version": version,
            }
        )
    return records


def build_creative_look_arm_target(
    *,
    repo_root: Path,
    toolchain_root: Path,
    output_path: Path,
    profile_path: Path,
    source_paths: Sequence[Path] | None = None,
    header_paths: Sequence[Path] | None = None,
    compile_flags: Sequence[str] | None = None,
    link_mode: Sequence[str] | None = None,
    tool_overrides: Mapping[str, Path] | None = None,
    abi_layouts: Mapping[str, Mapping[str, int]] | None = None,
) -> dict:
    """Compile, naturally combine, inspect, and record the exact Task 2 object."""
    root_argument = Path(repo_root)
    if not root_argument.is_absolute():
        raise ArmTargetBuildError("repository root must be absolute")
    try:
        root = root_argument.resolve(strict=True)
    except OSError as error:
        raise ArmTargetBuildError("repository root is missing") from error
    output = validate_output_path(Path(output_path), repo_root=root)
    toolchain = Path(toolchain_root)
    tools = resolve_toolchain_tools(toolchain, tool_overrides=tool_overrides)
    toolchain = toolchain.resolve(strict=True)
    profile_module, profile = _load_profile(root, Path(profile_path))

    approved_sources, approved_headers = _approved_inputs(root)
    sources, headers = validate_production_inputs(
        root,
        approved_sources if source_paths is None else source_paths,
        approved_headers if header_paths is None else header_paths,
    )
    flags = validate_compile_flags(
        profile["build"]["compile_flags"] if compile_flags is None else compile_flags
    )
    mode = validate_link_mode(
        profile["build"]["link"]["mode"] if link_mode is None else link_mode
    )
    layouts = validate_abi_layouts(
        EXPECTED_ABI_LAYOUTS if abi_layouts is None else abi_layouts
    )
    input_hashes_before = {path: _sha256_file(path) for path in sources + headers}
    include_closure = validate_include_closure(root, sources + headers, headers)
    for path in sources + headers:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise ArmTargetBuildError("production input cannot be read") from error
        scan_source_text(path, text)

    environment = _compiler_environment(toolchain)
    command_records: list[dict] = []
    output_root = output.parent
    native_relative = Path("native") / "a6400_creative_look"
    raw_path = output.with_name(output.stem + ".raw.json")
    if raw_path.exists() or raw_path.is_symlink():
        raise ArmTargetBuildError("raw evidence path must not already exist")

    with tempfile.TemporaryDirectory(prefix="creative-look-arm-build-", dir=output_root) as temporary:
        build_root = Path(temporary).resolve()
        staged_output = build_root / PUBLIC_OUTPUT_NAME
        staged_raw = build_root / "creative_look_arm_target.raw.json"
        tool_records = _tool_records(
            tools,
            root=toolchain,
            environment=environment,
            command_records=command_records,
            repo_root=root,
            output_root=output_root,
            build_root=build_root,
        )
        objects = []
        for source in sources:
            object_path = build_root / (source.stem + ".o")
            argv: list[Path | str] = [tools["gcc"], *flags]
            argv.extend(["-I", native_relative, "-c", source.relative_to(root), "-o", object_path])
            _run_recorded(
                argv,
                purpose=f"compile:{source.name}",
                cwd=root,
                environment=environment,
                command_records=command_records,
                repo_root=root,
                toolchain_root=toolchain,
                output_root=output_root,
                build_root=build_root,
            )
            objects.append(object_path)

        production_object_records = []
        for source, object_path in zip(sources, objects):
            object_undefined = _parse_nm_symbols(
                _run_recorded(
                    [tools["nm"], "-u", "-P", object_path],
                    purpose=f"inspect-object:{source.name}:undefined-symbols",
                    cwd=root,
                    environment=environment,
                    command_records=command_records,
                    repo_root=root,
                    toolchain_root=toolchain,
                    output_root=output_root,
                    build_root=build_root,
                ).stdout
            )
            object_defined = _parse_nm_symbols(
                _run_recorded(
                    [tools["nm"], "-g", "--defined-only", "-P", object_path],
                    purpose=f"inspect-object:{source.name}:defined-symbols",
                    cwd=root,
                    environment=environment,
                    command_records=command_records,
                    repo_root=root,
                    toolchain_root=toolchain,
                    output_root=output_root,
                    build_root=build_root,
                ).stdout
            )
            object_symbols = _parse_symbol_table(
                _run_recorded(
                    [tools["readelf"], "-sW", object_path],
                    purpose=f"inspect-object:{source.name}:symbol-table",
                    cwd=root,
                    environment=environment,
                    command_records=command_records,
                    repo_root=root,
                    toolchain_root=toolchain,
                    output_root=output_root,
                    build_root=build_root,
                ).stdout
            )
            validate_production_object_symbols(
                source.name, object_undefined, object_defined, object_symbols
            )
            production_object_records.append(
                {
                    "source": source.relative_to(root).as_posix(),
                    "path": "$BUILD/" + object_path.name,
                    "sha256": _sha256_file(object_path),
                    "undefined_symbols": object_undefined,
                    "defined_symbols": object_defined,
                    "symbol_table": object_symbols,
                }
            )

        probe_path = build_root / "creative_look_arm_abi_probe.c"
        probe_source = _abi_probe_source(layouts)
        probe_path.write_text(probe_source, encoding="utf-8", newline="\n")
        probe_object = build_root / "creative_look_arm_abi_probe.o"
        _run_recorded(
            [
                tools["gcc"],
                *flags,
                "-I",
                native_relative,
                "-c",
                probe_path,
                "-o",
                probe_object,
            ],
            purpose="compile:test-only-abi-probe",
            cwd=root,
            environment=environment,
            command_records=command_records,
            repo_root=root,
            toolchain_root=toolchain,
            output_root=output_root,
            build_root=build_root,
        )
        _run_recorded(
            [tools["ld"], *mode, "-o", staged_output, *objects],
            purpose="link:natural-relocatable",
            cwd=root,
            environment=environment,
            command_records=command_records,
            repo_root=root,
            toolchain_root=toolchain,
            output_root=output_root,
            build_root=build_root,
        )

        undefined_result = _run_recorded(
            [tools["nm"], "-u", "-P", staged_output],
            purpose="inspect:undefined-symbols",
            cwd=root,
            environment=environment,
            command_records=command_records,
            repo_root=root,
            toolchain_root=toolchain,
            output_root=output_root,
            build_root=build_root,
        )
        normalized_undefined = undefined_result.stdout.replace("\r\n", "\n")
        if normalized_undefined != "":
            raise ArmTargetBuildError("nm -u output is not byte-for-byte empty")
        undefined_symbols: list[str] = []
        validate_undefined_symbols(undefined_symbols)

        defined_result = _run_recorded(
            [tools["nm"], "-g", "--defined-only", "-P", staged_output],
            purpose="inspect:defined-symbols",
            cwd=root,
            environment=environment,
            command_records=command_records,
            repo_root=root,
            toolchain_root=toolchain,
            output_root=output_root,
            build_root=build_root,
        )
        defined_symbols = _parse_nm_symbols(defined_result.stdout)
        validate_defined_symbols(defined_symbols)

        header_text = _run_recorded(
            [tools["readelf"], "-hW", staged_output],
            purpose="inspect:elf-header",
            cwd=root,
            environment=environment,
            command_records=command_records,
            repo_root=root,
            toolchain_root=toolchain,
            output_root=output_root,
            build_root=build_root,
        ).stdout
        attributes_text = _run_recorded(
            [tools["readelf"], "-AW", staged_output],
            purpose="inspect:arm-attributes",
            cwd=root,
            environment=environment,
            command_records=command_records,
            repo_root=root,
            toolchain_root=toolchain,
            output_root=output_root,
            build_root=build_root,
        ).stdout
        sections_text = _run_recorded(
            [tools["readelf"], "-SW", staged_output],
            purpose="inspect:sections",
            cwd=root,
            environment=environment,
            command_records=command_records,
            repo_root=root,
            toolchain_root=toolchain,
            output_root=output_root,
            build_root=build_root,
        ).stdout
        relocations_text = _run_recorded(
            [tools["readelf"], "-rW", staged_output],
            purpose="inspect:relocations",
            cwd=root,
            environment=environment,
            command_records=command_records,
            repo_root=root,
            toolchain_root=toolchain,
            output_root=output_root,
            build_root=build_root,
        ).stdout
        symbol_table_text = _run_recorded(
            [tools["readelf"], "-sW", staged_output],
            purpose="inspect:symbol-table",
            cwd=root,
            environment=environment,
            command_records=command_records,
            repo_root=root,
            toolchain_root=toolchain,
            output_root=output_root,
            build_root=build_root,
        ).stdout
        objdump_text = _run_recorded(
            [tools["objdump"], "-f", staged_output],
            purpose="inspect:object-format",
            cwd=root,
            environment=environment,
            command_records=command_records,
            repo_root=root,
            toolchain_root=toolchain,
            output_root=output_root,
            build_root=build_root,
        ).stdout
        if "file format elf32-littlearm" not in objdump_text:
            raise ArmTargetBuildError("objdump object format differs")

        object_data = staged_output.read_bytes()
        scan_object_data(object_data)
        sections = _parse_sections(sections_text)
        data_by_section = _section_data(object_data, sections)
        relocations = _parse_relocations(
            relocations_text, sections, data_by_section
        )
        validate_relocation_capabilities(relocations)
        symbol_table = validate_full_symbol_table(symbol_table_text, sections)
        identity_metadata = _identity_metadata(
            repo_root=root,
            sources=sources + headers,
            object_data=object_data,
            sections=sections,
            section_data=data_by_section,
            relocations=relocations,
            symbols=symbol_table,
        )

        input_hashes_after = {path: _sha256_file(path) for path in sources + headers}
        if input_hashes_after != input_hashes_before:
            raise ArmTargetBuildError("production inputs changed during the build")
        second_tools = resolve_toolchain_tools(toolchain)
        if second_tools != tools:
            raise ArmTargetBuildError("tool resolution changed during the build")
        tool_hashes_after = {role: _sha256_file(path) for role, path in tools.items()}
        if tool_hashes_after != {item["role"]: item["sha256"] for item in tool_records}:
            raise ArmTargetBuildError("toolchain changed during the build")

        def input_records(paths: Iterable[Path]) -> list[dict]:
            return [
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": input_hashes_before[path],
                }
                for path in paths
            ]

        raw_record = {
            "schema_version": 1,
            "scope": "offline-static-arm-target-object",
            "camera_executed": False,
            "tools": tool_records,
            "inputs": {
                "sources": input_records(sources),
                "headers": input_records(headers),
            },
            "include_closure": include_closure,
            "build": {"compile_flags": flags, "link_mode": mode},
            "commands": command_records,
            "abi_probe": {
                "path": "$BUILD/creative_look_arm_abi_probe.c",
                "source_sha256": _sha256_bytes(probe_source.encode("utf-8")),
                "object_path": "$BUILD/creative_look_arm_abi_probe.o",
                "object_sha256": _sha256_file(probe_object),
                "linked": False,
            },
            "objects": production_object_records,
            "object": {
                "path": "$OUTPUT/" + output.name,
                "sha256": _sha256_file(staged_output),
            },
            "elf": _parse_elf_header(header_text),
            "attributes": _parse_attributes(attributes_text, profile_module),
            "abi_layouts": layouts,
            "sections": sections,
            "relocations": relocations,
            "symbol_table": symbol_table,
            "defined_symbols": defined_symbols,
            "undefined_symbols": undefined_symbols,
            "identity_metadata": identity_metadata,
            "safety_scan": {
                "files": [path.relative_to(root).as_posix() for path in sources + headers],
                "forbidden_matches": [],
            },
        }
        raw_bytes = _canonical_bytes(raw_record)
        evidence = copy.deepcopy(raw_record)
        evidence["raw_record_sha256"] = _sha256_bytes(raw_bytes)
        if evidence != profile.get("build_evidence"):
            raise ArmTargetBuildError("fresh evidence differs from tracked build evidence")

        staged_raw.write_bytes(raw_bytes)
        _fsync_file(staged_output)
        _fsync_file(staged_raw)
        if (
            _sha256_file(staged_output) != raw_record["object"]["sha256"]
            or staged_raw.read_bytes() != raw_bytes
            or json.loads(staged_raw.read_text(encoding="utf-8")) != raw_record
        ):
            raise ArmTargetBuildError("staged object/evidence join differs")
        try:
            os.replace(staged_raw, raw_path)
            os.replace(staged_output, output)
            final_raw_bytes = raw_path.read_bytes()
            if (
                _sha256_file(output) != raw_record["object"]["sha256"]
                or final_raw_bytes != raw_bytes
                or json.loads(final_raw_bytes) != raw_record
            ):
                raise ArmTargetBuildError("published object/evidence join differs")
        except BaseException as error:
            cleanup_errors = []
            for published in (raw_path, output):
                if not published.exists():
                    continue
                try:
                    published.unlink()
                except OSError as cleanup_error:
                    cleanup_errors.append(cleanup_error)
            if cleanup_errors:
                raise ArmTargetBuildError(
                    "publication failed and exact artifact cleanup failed"
                ) from cleanup_errors[0]
            if isinstance(error, (KeyboardInterrupt, SystemExit, GeneratorExit)):
                raise
            raise ArmTargetBuildError("atomic publication failed") from error
        return evidence


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--toolchain-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--profile", required=True, type=Path)
    arguments = parser.parse_args(argv)
    evidence = build_creative_look_arm_target(
        repo_root=arguments.repo_root,
        toolchain_root=arguments.toolchain_root,
        output_path=arguments.output,
        profile_path=arguments.profile,
    )
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
