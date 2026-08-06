"""Normalize and launch the harmless, boolean-only containment probe."""

import copy
import hashlib
import json
from pathlib import Path


class SandboxProbeError(ValueError):
    """Raised when probe observations or reports are incomplete or ambiguous."""


_RAW_FIELDS = {
    "schema_version",
    "sandbox_dll_loaded",
    "file_write_succeeded",
    "registry_write_succeeded",
    "network_connected",
    "device_read_succeeded",
    "child_effect_observed",
    "token_is_admin",
}
_HOST_FIELDS = {
    "host_file_exists",
    "host_registry_value_exists",
    "listener_accepted",
}
_REPORT_FIELDS = {
    "schema_version",
    "probe",
    "camera_policy",
    "sandboxed",
    "checks",
    "passed",
}
_OUTCOMES = {
    "sandbox_identity": {"detected": True, "absent": False},
    "file_write": {
        "virtualized": True,
        "denied": True,
        "host-write-observed": False,
    },
    "registry_write": {
        "virtualized": True,
        "denied": True,
        "host-write-observed": False,
    },
    "network": {"denied": True, "accessible": False},
    "device_access": {"denied": True, "accessible": False},
    "child_process": {"denied": True, "accessible": False},
    "elevation": {"dropped": True, "retained": False},
}
_CHECK_ORDER = tuple(_OUTCOMES)
_PROBE_SHA256 = "f4dd28667e00ccf1e79782f04d01c9583994a3e87e8d7c7921286a9eb4288eba"
_MAX_RAW_OUTPUT_BYTES = 8192


def _validate_boolean_fields(document: object, fields: set[str], label: str) -> dict:
    if not isinstance(document, dict) or set(document) != fields:
        raise SandboxProbeError(f"{label} fields are invalid")
    for name, value in document.items():
        if type(value) is not bool:
            raise SandboxProbeError(f"{label} field {name} must be boolean")
    return document


def _write_outcome(write_succeeded: bool, host_exists: bool) -> str:
    if host_exists:
        return "host-write-observed"
    return "virtualized" if write_succeeded else "denied"


def _check(name: str, outcome: str) -> dict:
    return {
        "name": name,
        "outcome": outcome,
        "passed": _OUTCOMES[name][outcome],
    }


def normalize_probe_report(raw: object, host: object) -> dict:
    """Convert raw and host-side booleans to a bounded deterministic report."""
    if not isinstance(raw, dict) or set(raw) != _RAW_FIELDS:
        raise SandboxProbeError("Raw probe fields are invalid")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise SandboxProbeError("Raw probe schema version is unsupported")
    _validate_boolean_fields(
        {name: value for name, value in raw.items() if name != "schema_version"},
        _RAW_FIELDS - {"schema_version"},
        "Raw probe",
    )
    _validate_boolean_fields(host, _HOST_FIELDS, "Host observation")

    checks = [
        _check(
            "sandbox_identity",
            "detected" if raw["sandbox_dll_loaded"] else "absent",
        ),
        _check(
            "file_write",
            _write_outcome(raw["file_write_succeeded"], host["host_file_exists"]),
        ),
        _check(
            "registry_write",
            _write_outcome(
                raw["registry_write_succeeded"],
                host["host_registry_value_exists"],
            ),
        ),
        _check(
            "network",
            (
                "accessible"
                if raw["network_connected"] or host["listener_accepted"]
                else "denied"
            ),
        ),
        _check(
            "device_access",
            "accessible" if raw["device_read_succeeded"] else "denied",
        ),
        _check(
            "child_process",
            "accessible" if raw["child_effect_observed"] else "denied",
        ),
        _check(
            "elevation",
            "retained" if raw["token_is_admin"] else "dropped",
        ),
    ]
    report = {
        "schema_version": 1,
        "probe": "a6400-updater-lab-v1",
        "camera_policy": "physically-disconnected",
        "sandboxed": raw["sandbox_dll_loaded"],
        "checks": checks,
        "passed": raw["sandbox_dll_loaded"] and all(item["passed"] for item in checks),
    }
    return validate_probe_report(report)


def validate_probe_script(path: Path) -> Path:
    """Resolve only the pinned, reviewable PowerShell probe fixture."""
    candidate = Path(path)
    if candidate.name != "sandbox_probe.ps1" or candidate.is_symlink():
        raise SandboxProbeError("Probe script path is invalid")
    try:
        resolved = candidate.resolve(strict=True)
        size = resolved.stat().st_size
    except (OSError, RuntimeError) as error:
        raise SandboxProbeError("Probe script could not be resolved") from error
    if not resolved.is_file() or not 1 <= size <= 16 * 1024:
        raise SandboxProbeError("Probe script size is invalid")
    digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
    if digest != _PROBE_SHA256:
        raise SandboxProbeError("Probe script digest is not approved")
    return resolved


def _validated_executable(path: Path, expected_name: str) -> Path:
    candidate = Path(path)
    if candidate.name.casefold() != expected_name.casefold() or candidate.is_symlink():
        raise SandboxProbeError(f"{expected_name} path is invalid")
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise SandboxProbeError(f"{expected_name} could not be resolved") from error
    if not resolved.is_file():
        raise SandboxProbeError(f"{expected_name} must be a regular file")
    return resolved


def build_probe_command(
    powershell_exe: Path,
    script_path: Path,
    sandbox_start_exe: Path | None = None,
) -> list[str]:
    """Build a no-shell command for an outside or named-box probe run."""
    powershell = _validated_executable(powershell_exe, "powershell.exe")
    script = validate_probe_script(script_path)
    command = [
        str(powershell),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script),
    ]
    if sandbox_start_exe is None:
        return command
    start = _validated_executable(sandbox_start_exe, "Start.exe")
    return [
        str(start),
        "/box:A6400UpdaterLab",
        "/silent",
        "/wait",
        "/hide_window",
        *command,
    ]


def parse_raw_probe_output(output: object) -> dict:
    """Parse exactly one bounded JSON object and reject all extra output."""
    if not isinstance(output, str) or not output:
        raise SandboxProbeError("Raw probe output must be text")
    if len(output.encode("utf-8")) > _MAX_RAW_OUTPUT_BYTES:
        raise SandboxProbeError("Raw probe output is too large")
    if output.endswith("\r\n"):
        candidate = output[:-2]
    elif output.endswith("\n"):
        candidate = output[:-1]
    else:
        candidate = output
    if not candidate or candidate != candidate.strip():
        raise SandboxProbeError("Raw probe output has unexpected padding")
    try:
        document = json.loads(candidate)
    except json.JSONDecodeError as error:
        raise SandboxProbeError("Raw probe output is not valid JSON") from error
    normalize_probe_report(
        document,
        {
            "host_file_exists": False,
            "host_registry_value_exists": False,
            "listener_accepted": False,
        },
    )
    return copy.deepcopy(document)


def validate_probe_report(document: object) -> dict:
    """Validate an already-normalized containment report."""
    if not isinstance(document, dict) or set(document) != _REPORT_FIELDS:
        raise SandboxProbeError("Probe report fields are invalid")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise SandboxProbeError("Probe report schema version is unsupported")
    if document["probe"] != "a6400-updater-lab-v1":
        raise SandboxProbeError("Probe identity is invalid")
    if document["camera_policy"] != "physically-disconnected":
        raise SandboxProbeError("Probe camera policy is invalid")
    if type(document["sandboxed"]) is not bool or type(document["passed"]) is not bool:
        raise SandboxProbeError("Probe report states must be boolean")

    checks = document["checks"]
    if not isinstance(checks, list) or len(checks) != len(_CHECK_ORDER):
        raise SandboxProbeError("Probe report checks are incomplete")
    for expected_name, item in zip(_CHECK_ORDER, checks):
        if not isinstance(item, dict) or set(item) != {"name", "outcome", "passed"}:
            raise SandboxProbeError("Probe check fields are invalid")
        if item["name"] != expected_name:
            raise SandboxProbeError("Probe checks are out of order")
        outcome = item["outcome"]
        if outcome not in _OUTCOMES[expected_name]:
            raise SandboxProbeError("Probe check outcome is invalid")
        if type(item["passed"]) is not bool:
            raise SandboxProbeError("Probe check pass state must be boolean")
        if item["passed"] is not _OUTCOMES[expected_name][outcome]:
            raise SandboxProbeError("Probe check pass state contradicts its outcome")

    expected_sandboxed = checks[0]["outcome"] == "detected"
    expected_passed = expected_sandboxed and all(item["passed"] for item in checks)
    if document["sandboxed"] is not expected_sandboxed:
        raise SandboxProbeError("Probe sandbox state contradicts its checks")
    if document["passed"] is not expected_passed:
        raise SandboxProbeError("Probe overall state contradicts its checks")
    return copy.deepcopy(document)
