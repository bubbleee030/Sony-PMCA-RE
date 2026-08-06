"""Bound and normalize Sandboxie monitor evidence for the Sony updater."""

import copy
import hashlib
import json
import re
from pathlib import Path


class TraceError(ValueError):
    """Raised when updater trace evidence is unsafe, ambiguous, or unbounded."""


BOX_NAME = "A6400UpdaterLab"
UPDATER_NAME = "Update_ILCE6400V200.exe"
MAX_EVENTS = 100_000
MAX_MESSAGE_CHARS = 2048
MAX_TARGET_HASHES = 32
MAX_REPORT_BYTES = 256 * 1024
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_EVENT_FIELDS = {"type", "pid", "tid", "box", "process", "message"}
_OBSERVATION_FIELDS = {
    "updater_sha256",
    "sandbox_policy_sha256",
    "camera_present",
    "sandboxed",
    "elevated",
    "network_blocked",
    "launched",
    "termination",
    "exit_code",
    "process_roles",
}
_RUN_FIELDS = {
    "schema_version",
    "updater_sha256",
    "sandbox_policy_sha256",
    "camera_present",
    "sandboxed",
    "elevated",
    "network_blocked",
    "launched",
    "termination",
    "exit_code_class",
    "process_roles",
    "events",
    "boundary",
    "passed",
    "fingerprint_sha256",
}
_REPORT_FIELDS = {
    "schema_version",
    "trace",
    "camera_policy",
    "updater_sha256",
    "sandbox_policy_sha256",
    "run_count",
    "boundary",
    "boundary_reproduced",
    "runs",
    "passed",
}
_TYPE_CATEGORIES = {
    1: "syscall",
    2: "pipe",
    3: "ipc",
    4: "window",
    5: "device-open",
    6: "com",
    7: "runtime-class",
    8: "ignored",
    9: "process-image",
    10: "file",
    11: "registry",
    12: "other",
    13: "network",
    14: "service",
    15: "api",
    16: "rpc",
    17: "dns",
    18: "hook",
}
_CATEGORIES = set(_TYPE_CATEGORIES.values()) | {"device-open"}
_OUTCOMES = {"allowed", "denied", "failed", "observed"}
_PROCESS_ROLES = {"updater", "sandbox-helper", "sandbox-child"}
_TERMINATIONS = {"exited", "timeout-terminated", "launch-failed"}
_ALLOWED_TYPE_BITS = 0xC0FF00FF


def _validated_executable(path: Path, expected_name: str) -> Path:
    candidate = Path(path)
    if candidate.name.casefold() != expected_name.casefold() or candidate.is_symlink():
        raise TraceError(f"{expected_name} path is invalid")
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise TraceError(f"{expected_name} could not be resolved") from error
    if not resolved.is_file():
        raise TraceError(f"{expected_name} must be a regular file")
    return resolved


def build_updater_command(start_exe: Path, updater_exe: Path) -> list[str]:
    """Build the exact no-shell command for the fixed updater sandbox."""
    start = _validated_executable(start_exe, "Start.exe")
    updater = _validated_executable(updater_exe, UPDATER_NAME)
    return [
        str(start),
        f"/box:{BOX_NAME}",
        "/silent",
        "/wait",
        "/hide_window",
        str(updater),
    ]


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise TraceError(f"{label} digest is invalid")
    return value


def _process_role(name: str) -> str:
    folded = name.casefold()
    if folded == UPDATER_NAME.casefold():
        return "updater"
    if folded == "start.exe" or folded.startswith("sandboxie"):
        return "sandbox-helper"
    return "sandbox-child"


def _normalized_target(value: str) -> str:
    target = value.strip().replace("/", "\\").casefold()
    target = re.sub(r"\\users\\[^\\]+", r"\\users\\<user>", target)
    target = re.sub(r"s-1-5-(?:\d+-?)+", "<sid>", target)
    target = re.sub(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        "<guid>",
        target,
    )
    target = re.sub(r"\b(pid|tid|hwnd)\s*[=:]\s*[0-9a-fx]+", r"\1=<id>", target)
    return target


def _event_category(base_type: int, message: str) -> str:
    category = _TYPE_CATEGORIES[base_type]
    normalized = message.casefold().replace("/", "\\")
    if category == "file" and (
        "vid_054c" in normalized
        or "usbpdo" in normalized
        or "\\device\\usb" in normalized
        or "\\\\?\\usb" in normalized
    ):
        return "device-open"
    return category


def _event_outcome(type_value: int) -> str:
    if type_value & 0x00020000 or type_value & 0x00200000:
        return "denied"
    if type_value & 0x00800000:
        return "failed"
    if (
        type_value & 0x00010000
        or type_value & 0x00100000
        or type_value & 0x00400000
    ):
        return "allowed"
    return "observed"


def normalize_monitor_events(events: object) -> list[dict]:
    """Aggregate raw monitor entries without retaining paths, PIDs, or messages."""
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        raise TraceError("Updater monitor event list is invalid")
    groups = {}
    for event in events:
        if not isinstance(event, dict) or set(event) != _EVENT_FIELDS:
            raise TraceError("Updater monitor event fields are invalid")
        if event["box"] != BOX_NAME:
            raise TraceError("Updater monitor event came from another sandbox")
        type_value = event["type"]
        if (
            type(type_value) is not int
            or type_value < 0
            or type_value & ~_ALLOWED_TYPE_BITS
        ):
            raise TraceError("Updater monitor type flags are invalid")
        base_type = type_value & 0xFF
        if base_type not in _TYPE_CATEGORIES:
            raise TraceError("Updater monitor event type is not allowlisted")
        if type(event["pid"]) is not int or event["pid"] <= 0:
            raise TraceError("Updater monitor PID is invalid")
        if type(event["tid"]) is not int or event["tid"] < 0:
            raise TraceError("Updater monitor TID is invalid")
        process = event["process"]
        if (
            not isinstance(process, str)
            or not 1 <= len(process) <= 128
            or not process.isprintable()
            or "/" in process
            or "\\" in process
        ):
            raise TraceError("Updater monitor process name is invalid")
        message = event["message"]
        if (
            not isinstance(message, str)
            or not 1 <= len(message) <= MAX_MESSAGE_CHARS
            or not message.isprintable()
            or "\r" in message
            or "\n" in message
        ):
            raise TraceError("Updater monitor message is invalid")
        category = _event_category(base_type, message)
        outcome = _event_outcome(type_value)
        role = _process_role(process)
        target = _normalized_target(message)
        target_digest = hashlib.sha256(target.encode("utf-8")).hexdigest()
        key = (category, outcome, role)
        group = groups.setdefault(key, {"count": 0, "targets": set()})
        group["count"] += 1
        group["targets"].add(target_digest)

    result = []
    for (category, outcome, role), group in sorted(groups.items()):
        target_hashes = sorted(group["targets"])
        result.append(
            {
                "category": category,
                "outcome": outcome,
                "process_role": role,
                "count": group["count"],
                "unique_target_count": len(target_hashes),
                "target_sha256": target_hashes[:MAX_TARGET_HASHES],
            }
        )
    return result


def _validate_roles(value: object) -> list[str]:
    if (
        not isinstance(value, list)
        or value != sorted(set(value))
        or not set(value) <= _PROCESS_ROLES
    ):
        raise TraceError("Updater trace process roles are invalid")
    return value


def _validate_event_groups(values: object) -> list[dict]:
    if not isinstance(values, list):
        raise TraceError("Updater trace event groups are invalid")
    previous = None
    for item in values:
        fields = {
            "category",
            "outcome",
            "process_role",
            "count",
            "unique_target_count",
            "target_sha256",
        }
        if not isinstance(item, dict) or set(item) != fields:
            raise TraceError("Updater trace event-group fields are invalid")
        if item["category"] not in _CATEGORIES:
            raise TraceError("Updater trace event category is invalid")
        if item["outcome"] not in _OUTCOMES:
            raise TraceError("Updater trace event outcome is invalid")
        if item["process_role"] not in _PROCESS_ROLES:
            raise TraceError("Updater trace process role is invalid")
        if type(item["count"]) is not int or item["count"] <= 0:
            raise TraceError("Updater trace event count is invalid")
        unique_count = item["unique_target_count"]
        targets = item["target_sha256"]
        if (
            type(unique_count) is not int
            or unique_count <= 0
            or not isinstance(targets, list)
            or not 1 <= len(targets) <= MAX_TARGET_HASHES
            or len(targets) > unique_count
            or targets != sorted(set(targets))
        ):
            raise TraceError("Updater trace target summary is invalid")
        for target in targets:
            _digest(target, "Updater trace target")
        key = (item["category"], item["outcome"], item["process_role"])
        if previous is not None and key <= previous:
            raise TraceError("Updater trace event groups are unordered")
        previous = key
    return values


def _exit_code_class(termination: str, exit_code: object) -> str:
    if termination == "exited":
        if type(exit_code) is not int:
            raise TraceError("Exited updater run requires an integer exit code")
        return "zero" if exit_code == 0 else "nonzero"
    if exit_code is not None:
        raise TraceError("Non-exited updater run must not claim an exit code")
    return "not-observed"


def _run_fingerprint(document: dict) -> str:
    payload = {key: value for key, value in document.items() if key != "fingerprint_sha256"}
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def build_no_camera_run(events: object, observation: object) -> dict:
    """Build one normalized run after the physical-disconnect precondition."""
    if not isinstance(observation, dict) or set(observation) != _OBSERVATION_FIELDS:
        raise TraceError("Updater run observation fields are invalid")
    _digest(observation["updater_sha256"], "Updater")
    _digest(observation["sandbox_policy_sha256"], "Sandbox policy")
    for name in (
        "camera_present",
        "sandboxed",
        "elevated",
        "network_blocked",
        "launched",
    ):
        if type(observation[name]) is not bool:
            raise TraceError(f"Updater observation {name} must be boolean")
    if observation["camera_present"]:
        raise TraceError("A Sony camera is present; updater launch is forbidden")
    termination = observation["termination"]
    if termination not in _TERMINATIONS:
        raise TraceError("Updater termination state is invalid")
    if observation["launched"] != (termination != "launch-failed"):
        raise TraceError("Updater launch and termination states contradict")
    exit_class = _exit_code_class(termination, observation["exit_code"])
    roles = _validate_roles(observation["process_roles"])
    normalized = normalize_monitor_events(events)
    device_accessible = any(
        item["category"] == "device-open"
        and item["outcome"] not in {"denied", "failed"}
        for item in normalized
    )
    if not observation["launched"]:
        boundary = "launch-failed"
    elif device_accessible:
        boundary = "device-access-observed"
    else:
        boundary = "no-camera-boundary"
    passed = (
        boundary == "no-camera-boundary"
        and observation["sandboxed"]
        and not observation["elevated"]
        and observation["network_blocked"]
    )
    run = {
        "schema_version": 1,
        "updater_sha256": observation["updater_sha256"],
        "sandbox_policy_sha256": observation["sandbox_policy_sha256"],
        "camera_present": False,
        "sandboxed": observation["sandboxed"],
        "elevated": observation["elevated"],
        "network_blocked": observation["network_blocked"],
        "launched": observation["launched"],
        "termination": termination,
        "exit_code_class": exit_class,
        "process_roles": copy.deepcopy(roles),
        "events": normalized,
        "boundary": boundary,
        "passed": passed,
    }
    run["fingerprint_sha256"] = _run_fingerprint(run)
    return _validate_run(run)


def _validate_run(document: object) -> dict:
    if not isinstance(document, dict) or set(document) != _RUN_FIELDS:
        raise TraceError("Updater normalized run fields are invalid")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise TraceError("Updater normalized run schema is unsupported")
    _digest(document["updater_sha256"], "Updater")
    _digest(document["sandbox_policy_sha256"], "Sandbox policy")
    for name in (
        "camera_present",
        "sandboxed",
        "elevated",
        "network_blocked",
        "launched",
        "passed",
    ):
        if type(document[name]) is not bool:
            raise TraceError(f"Updater normalized run {name} must be boolean")
    if document["camera_present"]:
        raise TraceError("Normalized updater run cannot contain a camera")
    if document["termination"] not in _TERMINATIONS:
        raise TraceError("Updater normalized termination is invalid")
    if document["launched"] != (document["termination"] != "launch-failed"):
        raise TraceError("Updater normalized launch state contradicts termination")
    expected_exit_classes = {
        "exited": {"zero", "nonzero"},
        "timeout-terminated": {"not-observed"},
        "launch-failed": {"not-observed"},
    }
    if document["exit_code_class"] not in expected_exit_classes[document["termination"]]:
        raise TraceError("Updater normalized exit class is invalid")
    _validate_roles(document["process_roles"])
    events = _validate_event_groups(document["events"])
    accessible = any(
        item["category"] == "device-open"
        and item["outcome"] not in {"denied", "failed"}
        for item in events
    )
    expected_boundary = (
        "launch-failed"
        if not document["launched"]
        else "device-access-observed"
        if accessible
        else "no-camera-boundary"
    )
    expected_passed = (
        expected_boundary == "no-camera-boundary"
        and document["sandboxed"]
        and not document["elevated"]
        and document["network_blocked"]
    )
    if document["boundary"] != expected_boundary or document["passed"] is not expected_passed:
        raise TraceError("Updater normalized boundary is contradictory")
    _digest(document["fingerprint_sha256"], "Updater run fingerprint")
    if document["fingerprint_sha256"] != _run_fingerprint(document):
        raise TraceError("Updater normalized run fingerprint is invalid")
    return copy.deepcopy(document)


def validate_no_camera_run(document: object) -> dict:
    """Validate and independently copy one normalized updater run."""
    return _validate_run(document)


def build_reproduced_trace_report(runs: tuple[dict, dict]) -> dict:
    """Combine exactly two runs and require a reproduced safety boundary."""
    if not isinstance(runs, tuple) or len(runs) != 2:
        raise TraceError("Exactly two updater runs are required")
    validated = [_validate_run(run) for run in runs]
    if len({run["updater_sha256"] for run in validated}) != 1:
        raise TraceError("Updater run digests differ")
    if len({run["sandbox_policy_sha256"] for run in validated}) != 1:
        raise TraceError("Sandbox policy digests differ")
    reproduced = (
        validated[0]["boundary"] == validated[1]["boundary"]
        and all(run["passed"] for run in validated)
    )
    boundary = validated[0]["boundary"] if reproduced else "not-reproduced"
    report = {
        "schema_version": 1,
        "trace": "a6400-updater-no-camera-v1",
        "camera_policy": "physically-disconnected",
        "updater_sha256": validated[0]["updater_sha256"],
        "sandbox_policy_sha256": validated[0]["sandbox_policy_sha256"],
        "run_count": 2,
        "boundary": boundary,
        "boundary_reproduced": reproduced,
        "runs": validated,
        "passed": reproduced,
    }
    return validate_updater_trace_report(report)


def validate_updater_trace_report(document: object) -> dict:
    """Validate a two-run, metadata-only no-camera trace report."""
    if not isinstance(document, dict) or set(document) != _REPORT_FIELDS:
        raise TraceError("Updater trace report fields are invalid")
    try:
        size = len(json.dumps(document, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError) as error:
        raise TraceError("Updater trace report is not JSON-compatible") from error
    if size > MAX_REPORT_BYTES:
        raise TraceError("Updater trace report is too large")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise TraceError("Updater trace report schema is unsupported")
    if document["trace"] != "a6400-updater-no-camera-v1":
        raise TraceError("Updater trace identity is invalid")
    if document["camera_policy"] != "physically-disconnected":
        raise TraceError("Updater trace camera policy is invalid")
    _digest(document["updater_sha256"], "Updater")
    _digest(document["sandbox_policy_sha256"], "Sandbox policy")
    if type(document["run_count"]) is not int or document["run_count"] != 2:
        raise TraceError("Updater trace run count is invalid")
    if (
        type(document["boundary_reproduced"]) is not bool
        or type(document["passed"]) is not bool
    ):
        raise TraceError("Updater trace report states must be boolean")
    runs = document["runs"]
    if not isinstance(runs, list) or len(runs) != 2:
        raise TraceError("Updater trace report must contain two runs")
    validated = [_validate_run(run) for run in runs]
    if any(
        run["updater_sha256"] != document["updater_sha256"]
        or run["sandbox_policy_sha256"] != document["sandbox_policy_sha256"]
        for run in validated
    ):
        raise TraceError("Updater trace run provenance differs")
    reproduced = (
        validated[0]["boundary"] == validated[1]["boundary"]
        and all(run["passed"] for run in validated)
    )
    expected_boundary = validated[0]["boundary"] if reproduced else "not-reproduced"
    if (
        document["boundary_reproduced"] is not reproduced
        or document["passed"] is not reproduced
        or document["boundary"] != expected_boundary
    ):
        raise TraceError("Updater trace reproduction state is contradictory")
    return copy.deepcopy(document)
