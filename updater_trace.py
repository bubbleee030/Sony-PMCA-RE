"""Capture the manifest-pinned updater at its disconnected-camera boundary."""

import argparse
import ctypes
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from pmca.analysis.manifest import (
    ManifestError,
    load_manifest,
    verify_manifest_entry,
)
from pmca.analysis.sandbox_policy import (
    SandboxPolicyError,
    build_sandbox_policy,
    render_sandboxie_ini,
)
from pmca.analysis.updater_trace import (
    BOX_NAME,
    MAX_EVENTS,
    TraceError,
    build_no_camera_run,
    build_reproduced_trace_report,
    build_updater_command,
    validate_no_camera_run,
    validate_updater_trace_report,
)


SOURCE_KEY = "a6400-tw-v2.00"
REPORT_NAME = "a6400-updater-no-camera.json"
TRACE_RELATIVE_ROOT = Path(".artifacts") / "sandbox" / "a6400-updater" / "trace"
CREATE_NO_WINDOW = 0x08000000
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TOKEN_QUERY = 0x0008
TOKEN_ELEVATION_CLASS = 20


class _TokenElevation(ctypes.Structure):
    _fields_ = [("TokenIsElevated", ctypes.c_ulong)]


def _process_is_elevated(pid: int) -> bool:
    if type(pid) is not int or pid <= 0:
        raise TraceError("Updater token PID is invalid")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [
        ctypes.c_ulong,
        ctypes.c_int,
        ctypes.c_ulong,
    ]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    advapi32.OpenProcessToken.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.OpenProcessToken.restype = ctypes.c_int
    advapi32.GetTokenInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    advapi32.GetTokenInformation.restype = ctypes.c_int
    process_handle = kernel32.OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        0,
        pid,
    )
    if not process_handle:
        raise TraceError("Updater process token could not be queried")
    token_handle = ctypes.c_void_p()
    try:
        if not advapi32.OpenProcessToken(
            process_handle, TOKEN_QUERY, ctypes.byref(token_handle)
        ):
            raise TraceError("Updater process token could not be opened")
        elevation = _TokenElevation()
        returned = ctypes.c_ulong(0)
        if not advapi32.GetTokenInformation(
            token_handle,
            TOKEN_ELEVATION_CLASS,
            ctypes.byref(elevation),
            ctypes.sizeof(elevation),
            ctypes.byref(returned),
        ):
            raise TraceError("Updater token elevation state could not be read")
        if returned.value != ctypes.sizeof(elevation):
            raise TraceError("Updater token elevation result is ambiguous")
        return bool(elevation.TokenIsElevated)
    finally:
        if token_handle.value:
            kernel32.CloseHandle(token_handle)
        kernel32.CloseHandle(process_handle)


def _atomic_json(path: Path, document: dict) -> None:
    serialized = json.dumps(document, sort_keys=True, indent=2) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _resolved_repository(repository_root: Path) -> Path:
    root = Path(repository_root)
    if root.is_symlink():
        raise TraceError("Repository root must not be a symbolic link")
    try:
        resolved = root.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise TraceError("Repository root could not be resolved") from error
    if not resolved.is_dir():
        raise TraceError("Repository root must be a directory")
    return resolved


def write_trace_report(repository_root: Path, document: dict) -> Path:
    """Atomically write only the fixed committed no-camera report."""
    validate_updater_trace_report(document)
    root = _resolved_repository(repository_root)
    try:
        analysis = (root / "analysis").resolve(strict=True)
        analysis.relative_to(root)
    except (OSError, RuntimeError, ValueError) as error:
        raise TraceError("Repository analysis directory is invalid") from error
    if not analysis.is_dir():
        raise TraceError("Repository analysis directory is unavailable")
    output = analysis / REPORT_NAME
    if output.is_symlink():
        raise TraceError("Updater trace report path must not be a symbolic link")
    _atomic_json(output, document)
    return output


def _run_path(repository_root: Path, requested: Path) -> Path:
    root = _resolved_repository(repository_root)
    trace_root = root / TRACE_RELATIVE_ROOT
    trace_root.mkdir(parents=True, exist_ok=True)
    if trace_root.is_symlink():
        raise TraceError("Updater trace root must not be a symbolic link")
    resolved_trace = trace_root.resolve(strict=True)
    try:
        resolved_trace.relative_to(root)
        resolved = Path(requested).resolve(strict=False)
        resolved.relative_to(resolved_trace)
    except (OSError, RuntimeError, ValueError) as error:
        raise TraceError("Updater run output escapes its trace root") from error
    if resolved.name not in {"run-1.json", "run-2.json"} or resolved.parent != resolved_trace:
        raise TraceError("Updater run output name is not approved")
    if resolved.is_symlink():
        raise TraceError("Updater run output must not be a symbolic link")
    return resolved


def write_normalized_run(
    repository_root: Path, output: Path, document: dict
) -> Path:
    validate_no_camera_run(document)
    resolved = _run_path(repository_root, output)
    _atomic_json(resolved, document)
    return resolved


def load_normalized_run(repository_root: Path, path: Path) -> dict:
    resolved = _run_path(repository_root, path)
    try:
        if resolved.stat().st_size > 256 * 1024:
            raise TraceError("Updater normalized run is too large")
        document = json.loads(resolved.read_text(encoding="utf-8"))
    except TraceError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise TraceError("Updater normalized run could not be loaded") from error
    return validate_no_camera_run(document)


def _validated_tool(path: Path, expected_name: str) -> Path:
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


def _text_command(arguments: list[str], timeout: int = 15) -> list[str]:
    try:
        result = subprocess.run(
            arguments,
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise TraceError("Required host query could not be executed") from error
    if result.returncode != 0:
        raise TraceError("Required host query returned an error")
    return result.stdout.splitlines()


def verify_loaded_policy(
    sbie_ini: Path, repository_root: Path
) -> tuple[dict, str]:
    """Require the active box to equal the exact updater policy."""
    tool = _validated_tool(sbie_ini, "SbieIni.exe")
    policy = build_sandbox_policy("updater")
    rendered = render_sandboxie_ini(policy, repository_root)
    expected = {}
    for line in rendered.splitlines()[1:]:
        name, value = line.split("=", 1)
        expected[name] = value
    actual_names = set(_text_command([str(tool), "query", BOX_NAME]))
    if actual_names != set(expected):
        raise TraceError("Loaded updater sandbox setting names differ")
    for name, expected_value in expected.items():
        values = _text_command([str(tool), "query", BOX_NAME, name])
        if values != [expected_value]:
            raise TraceError(f"Loaded updater sandbox setting {name} differs")
    serialized = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    return policy, hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def sony_camera_count() -> int:
    """Return a bounded count of present Sony USB vendor IDs."""
    system_root = os.environ.get("SystemRoot")
    if not system_root:
        raise TraceError("Windows system root is unavailable")
    powershell = _validated_tool(
        Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe",
        "powershell.exe",
    )
    script = (
        "$ErrorActionPreference='Stop'; "
        "$devices=@(Get-PnpDevice -PresentOnly | "
        "Where-Object { $_.InstanceId -match 'VID_054C' }); "
        "Write-Output $devices.Count"
    )
    lines = _text_command(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ],
        timeout=30,
    )
    if len(lines) != 1:
        raise TraceError("Sony device enumeration output is ambiguous")
    try:
        count = int(lines[0], 10)
    except ValueError as error:
        raise TraceError("Sony device enumeration output is invalid") from error
    if not 0 <= count <= 64:
        raise TraceError("Sony device enumeration count is invalid")
    return count


class SandboxieMonitor:
    """Minimal ctypes binding to Sandboxie's official scoped monitor API."""

    def __init__(self, sbie_dll: Path):
        dll_path = _validated_tool(sbie_dll, "SbieDll.dll")
        try:
            self._dll = ctypes.WinDLL(str(dll_path))
        except (OSError, AttributeError) as error:
            raise TraceError("Sandboxie monitor library could not be loaded") from error
        wchar_pointer = ctypes.POINTER(ctypes.c_wchar)
        self._control = self._dll.SbieApi_MonitorControl
        self._control.argtypes = [
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.POINTER(ctypes.c_ulong),
        ]
        self._control.restype = ctypes.c_long
        self._get = self._dll.SbieApi_MonitorGetEx
        self._get.argtypes = [
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.POINTER(ctypes.c_ulong),
            wchar_pointer,
        ]
        self._get.restype = ctypes.c_long
        self._enum = self._dll.SbieApi_EnumProcessEx
        self._enum.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_ubyte,
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.POINTER(ctypes.c_ulong),
        ]
        self._enum.restype = ctypes.c_long
        self._query = self._dll.SbieApi_QueryProcessEx
        self._query.argtypes = [
            ctypes.c_void_p,
            ctypes.c_ulong,
            wchar_pointer,
            wchar_pointer,
            wchar_pointer,
            ctypes.POINTER(ctypes.c_ulong),
        ]
        self._query.restype = ctypes.c_long
        self._enabled = False

    def enable(self) -> None:
        new_state = ctypes.c_ulong(1)
        old_state = ctypes.c_ulong(0)
        if self._control(ctypes.byref(new_state), ctypes.byref(old_state)) != 0:
            raise TraceError("Sandboxie monitor could not be enabled")
        if old_state.value:
            raise TraceError("Another Sandboxie monitor consumer is active")
        self._enabled = True

    def disable(self) -> None:
        if not self._enabled:
            return
        new_state = ctypes.c_ulong(0)
        if self._control(ctypes.byref(new_state), None) != 0:
            raise TraceError("Sandboxie monitor could not be disabled")
        self._enabled = False

    def drain(self, maximum: int = MAX_EVENTS) -> list[tuple[int, int, int, str]]:
        if not self._enabled or type(maximum) is not int or maximum <= 0:
            raise TraceError("Sandboxie monitor drain state is invalid")
        events = []
        while len(events) < maximum:
            type_value = ctypes.c_ulong(0)
            pid = ctypes.c_ulong(0)
            tid = ctypes.c_ulong(0)
            message = ctypes.create_unicode_buffer(1024)
            status = self._get(
                ctypes.byref(type_value),
                ctypes.byref(pid),
                ctypes.byref(tid),
                message,
            )
            if status != 0 or not type_value.value or not message.value:
                break
            events.append((type_value.value, pid.value, tid.value, message.value))
        if len(events) == maximum:
            raise TraceError("Sandboxie monitor event bound was reached")
        return events

    def processes(self) -> dict[int, dict]:
        capacity = 512
        pids = (ctypes.c_ulong * capacity)()
        count = ctypes.c_ulong(capacity)
        status = self._enum(
            BOX_NAME,
            0,
            0xFFFFFFFF,
            pids,
            ctypes.byref(count),
        )
        if status != 0 or count.value > capacity:
            raise TraceError("Sandboxie process enumeration failed")
        processes = {}
        for index in range(count.value):
            pid = pids[index]
            box = ctypes.create_unicode_buffer(34)
            image = ctypes.create_unicode_buffer(260)
            sid = ctypes.create_unicode_buffer(96)
            session = ctypes.c_ulong(0)
            status = self._query(
                ctypes.c_void_p(pid),
                260,
                box,
                image,
                sid,
                ctypes.byref(session),
            )
            if status != 0:
                continue
            process_name = Path(image.value).name
            if (
                box.value != BOX_NAME
                or not process_name
                or len(process_name) > 128
                or not process_name.isprintable()
            ):
                raise TraceError("Sandboxie process identity is invalid")
            processes[pid] = {
                "box": box.value,
                "process": process_name,
            }
        return processes


def _process_role(name: str) -> str:
    folded = name.casefold()
    if folded == "update_ilce6400v200.exe":
        return "updater"
    if folded == "start.exe" or folded.startswith("sandboxie"):
        return "sandbox-helper"
    return "sandbox-child"


def _terminate_box(start_exe: Path) -> None:
    try:
        result = subprocess.run(
            [str(start_exe), f"/box:{BOX_NAME}", "/terminate"],
            shell=False,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            creationflags=CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise TraceError("Sandboxie box termination failed") from error
    if result.returncode != 0:
        raise TraceError("Sandboxie box termination returned an error")


def capture_sandboxie_run(
    sbie_dll: Path,
    start_exe: Path,
    updater_exe: Path,
    updater_sha256: str,
    policy_sha256: str,
    timeout_seconds: int,
) -> dict:
    """Capture one bounded run entirely through the named sandbox."""
    if type(timeout_seconds) is not int or not 5 <= timeout_seconds <= 120:
        raise TraceError("Updater timeout must be between 5 and 120 seconds")
    command = build_updater_command(start_exe, updater_exe)
    start = Path(command[0])
    monitor = SandboxieMonitor(sbie_dll)
    if monitor.processes():
        raise TraceError("Updater sandbox is not empty before launch")
    raw_events = []
    unresolved = []
    process_cache = {}
    process_roles = set()
    updater_elevations = {}
    timed_out = False
    process = None
    monitor.enable()
    try:
        monitor.drain()
        process = subprocess.Popen(
            command,
            shell=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=CREATE_NO_WINDOW,
        )
        deadline = time.monotonic() + timeout_seconds
        while True:
            current = monitor.processes()
            process_cache.update(current)
            for pid, value in current.items():
                role = _process_role(value["process"])
                process_roles.add(role)
                if role == "updater" and pid not in updater_elevations:
                    updater_elevations[pid] = _process_is_elevated(pid)
            capacity = MAX_EVENTS - len(raw_events) - len(unresolved)
            if capacity <= 0:
                raise TraceError("Updater monitor event bound was reached")
            for type_value, pid, tid, message in monitor.drain(capacity):
                identity = process_cache.get(pid)
                if identity is None:
                    unresolved.append((type_value, pid, tid, message))
                    continue
                raw_events.append(
                    {
                        "type": type_value,
                        "pid": pid,
                        "tid": tid,
                        "box": identity["box"],
                        "process": identity["process"],
                        "message": message,
                    }
                )
            if process.poll() is not None and not current:
                break
            if time.monotonic() >= deadline:
                timed_out = True
                _terminate_box(start)
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired as error:
                    raise TraceError("Updater supervisor survived box termination") from error
                break
            time.sleep(0.02)

        for _ in range(10):
            current = monitor.processes()
            process_cache.update(current)
            capacity = MAX_EVENTS - len(raw_events) - len(unresolved)
            if capacity <= 0:
                raise TraceError("Updater monitor event bound was reached")
            for type_value, pid, tid, message in monitor.drain(capacity):
                identity = process_cache.get(pid)
                if identity is None:
                    unresolved.append((type_value, pid, tid, message))
                    continue
                raw_events.append(
                    {
                        "type": type_value,
                        "pid": pid,
                        "tid": tid,
                        "box": identity["box"],
                        "process": identity["process"],
                        "message": message,
                    }
                )
            if not current:
                break
            time.sleep(0.05)
        if monitor.processes():
            _terminate_box(start)
            time.sleep(0.2)
        if monitor.processes():
            raise TraceError("Updater sandbox is not empty after capture")
    finally:
        monitor.disable()

    remaining = []
    for type_value, pid, tid, message in unresolved:
        identity = process_cache.get(pid)
        if identity is None:
            remaining.append(pid)
            continue
        raw_events.append(
            {
                "type": type_value,
                "pid": pid,
                "tid": tid,
                "box": identity["box"],
                "process": identity["process"],
                "message": message,
            }
        )
    if remaining and updater_elevations:
        raise TraceError("Updater monitor events could not be scoped to a process")
    launched = bool(updater_elevations)
    if launched and any(updater_elevations.values()):
        raise TraceError("Updater process retained an elevated token")
    if not launched:
        termination = "launch-failed"
        exit_code = None
    elif timed_out:
        termination = "timeout-terminated"
        exit_code = None
    else:
        termination = "exited"
        exit_code = process.returncode
    observation = {
        "updater_sha256": updater_sha256,
        "sandbox_policy_sha256": policy_sha256,
        "camera_present": False,
        "sandboxed": launched,
        "elevated": False,
        "network_blocked": True,
        "launched": launched,
        "termination": termination,
        "exit_code": exit_code,
        "process_roles": sorted(process_roles),
    }
    return build_no_camera_run(raw_events, observation)


def _manifest_entry(manifest_path: Path) -> dict:
    manifest = load_manifest(manifest_path)
    matches = [
        entry
        for entry in manifest["artifacts"]
        if entry["source_key"] == SOURCE_KEY
    ]
    if len(matches) != 1:
        raise TraceError("Manifest lacks one unique alpha 6400 updater")
    return matches[0]


def _capture(args: argparse.Namespace) -> None:
    if sony_camera_count() != 0:
        raise TraceError("A present Sony USB device blocks updater capture")
    entry = _manifest_entry(args.manifest)
    verify_manifest_entry(entry, args.input, args.artifacts_root)
    _, policy_digest = verify_loaded_policy(
        args.sbie_ini, args.repository_root
    )
    run = capture_sandboxie_run(
        args.sbie_dll,
        args.start,
        args.input,
        entry["sha256"],
        policy_digest,
        args.timeout_seconds,
    )
    if sony_camera_count() != 0:
        raise TraceError("A Sony USB device appeared during updater capture")
    output = write_normalized_run(
        args.repository_root,
        args.run_output,
        run,
    )
    print(
        f"run={output} boundary={run['boundary']} passed={str(run['passed']).lower()} "
        f"termination={run['termination']} event_groups={len(run['events'])} "
        "camera=disconnected raw_trace_persisted=false"
    )


def _combine(args: argparse.Namespace) -> None:
    first = load_normalized_run(args.repository_root, args.run_one)
    second = load_normalized_run(args.repository_root, args.run_two)
    report = build_reproduced_trace_report((first, second))
    output = write_trace_report(args.repository_root, report)
    print(
        f"report={output} boundary={report['boundary']} "
        f"reproduced={str(report['boundary_reproduced']).lower()} "
        f"passed={str(report['passed']).lower()}"
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    subparsers = parser.add_subparsers(dest="command", required=True)
    capture = subparsers.add_parser("capture", allow_abbrev=False)
    capture.add_argument("--repository-root", type=Path, required=True)
    capture.add_argument("--artifacts-root", type=Path, required=True)
    capture.add_argument("--manifest", type=Path, required=True)
    capture.add_argument("--input", type=Path, required=True)
    capture.add_argument("--sbie-dll", type=Path, required=True)
    capture.add_argument("--sbie-ini", type=Path, required=True)
    capture.add_argument("--start", type=Path, required=True)
    capture.add_argument("--run-output", type=Path, required=True)
    capture.add_argument("--timeout-seconds", type=int, default=30)

    combine = subparsers.add_parser("combine", allow_abbrev=False)
    combine.add_argument("--repository-root", type=Path, required=True)
    combine.add_argument("--run-one", type=Path, required=True)
    combine.add_argument("--run-two", type=Path, required=True)
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "capture":
            _capture(args)
        else:
            _combine(args)
    except (
        ManifestError,
        OSError,
        SandboxPolicyError,
        TraceError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
