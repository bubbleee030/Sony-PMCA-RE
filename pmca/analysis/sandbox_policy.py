"""Exact, fail-closed Sandboxie policy for disconnected updater analysis."""

import copy
import os
import tempfile
from pathlib import Path, PurePosixPath


class SandboxPolicyError(ValueError):
    """Raised when the updater sandbox policy is incomplete or permissive."""


SECTION_NAME = "A6400UpdaterLab"
SANDBOX_ROOT = ".artifacts/sandbox/a6400-updater/box-root"
TRACE_ROOT = ".artifacts/sandbox/a6400-updater/trace"
INI_PATH = ".artifacts/sandbox/a6400-updater/Sandboxie.ini"
_TOP_FIELDS = {
    "schema_version",
    "section",
    "phase",
    "camera_policy",
    "sandbox_root",
    "trace_root",
    "allowed_processes",
    "settings",
}
_PROFILE_PROCESSES = {
    "probe": ("Start.exe", "powershell.exe"),
    "updater": ("Start.exe", "Update_ILCE6400V200.exe"),
}
_BASE_SETTINGS = (
    ("Enabled", "y"),
    ("AutoDelete", "n"),
    ("AutoRecover", "n"),
    ("DropAdminRights", "y"),
    ("RestrictDevices", "y"),
    ("SysCallLockDown", "y"),
    ("UseRuleSpecificity", "y"),
    ("AllowRawDiskRead", "n"),
    ("BlockLocalLoop", "y"),
    ("BlockNetParam", "y"),
    ("BlockNetworkFiles", "y"),
    ("AllowNetworkAccess", "*,n"),
    ("NetworkAccess", "*,Block"),
    ("ClosePrintSpooler", "y"),
    ("CopyLimitKb", "65536"),
    ("CopyLimitSilent", "y"),
    ("ProcessLimit", "12"),
    ("NotifyInternetAccessDenied", "y"),
    ("NotifyStartRunAccessDenied", "y"),
)
_UPDATER_TRACE_SETTINGS = (
    ("FileTrace", "adi"),
    ("KeyTrace", "ad"),
    ("PipeTrace", "adi"),
    ("IpcTrace", "ad"),
    ("GuiTrace", "ad"),
    ("ClsidTrace", "ad"),
    ("TraceBufferPages", "2560"),
)


def _settings_for(phase: str) -> tuple[tuple[str, str], ...]:
    try:
        processes = _PROFILE_PROCESSES[phase]
    except (KeyError, TypeError) as error:
        raise SandboxPolicyError("Sandbox phase is not approved") from error
    trace_settings = _UPDATER_TRACE_SETTINGS if phase == "updater" else ()
    return _BASE_SETTINGS + trace_settings + (
        ("ProcessGroup", f"<StartRunAccess>,{','.join(processes)}"),
        ("ClosedIpcPath", "!<StartRunAccess>,*"),
    )


def build_sandbox_policy(phase: str) -> dict:
    """Build the one approved policy for a synthetic probe or updater run."""
    settings = _settings_for(phase)
    return {
        "schema_version": 1,
        "section": SECTION_NAME,
        "phase": phase,
        "camera_policy": "physically-disconnected",
        "sandbox_root": SANDBOX_ROOT,
        "trace_root": TRACE_ROOT,
        "allowed_processes": list(_PROFILE_PROCESSES[phase]),
        "settings": [list(setting) for setting in settings],
    }


def _validate_relative_category(value: object, expected: str, label: str) -> None:
    if not isinstance(value, str) or value != expected or "\\" in value:
        raise SandboxPolicyError(f"Sandbox {label} is invalid")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.parts[:3] != (".artifacts", "sandbox", "a6400-updater")
    ):
        raise SandboxPolicyError(f"Sandbox {label} is invalid")


def validate_sandbox_policy(document: object) -> dict:
    """Return an independent copy only when the policy is exactly approved."""
    if not isinstance(document, dict) or set(document) != _TOP_FIELDS:
        raise SandboxPolicyError("Sandbox policy fields are invalid")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise SandboxPolicyError("Sandbox policy schema version is unsupported")
    if document["section"] != SECTION_NAME:
        raise SandboxPolicyError("Sandbox section is not approved")
    phase = document["phase"]
    if phase not in _PROFILE_PROCESSES:
        raise SandboxPolicyError("Sandbox phase is not approved")
    if document["camera_policy"] != "physically-disconnected":
        raise SandboxPolicyError("Camera must remain physically disconnected")
    _validate_relative_category(document["sandbox_root"], SANDBOX_ROOT, "root")
    _validate_relative_category(document["trace_root"], TRACE_ROOT, "trace root")

    allowed = document["allowed_processes"]
    if allowed != list(_PROFILE_PROCESSES[phase]):
        raise SandboxPolicyError("Sandbox process allowlist is invalid")
    settings = document["settings"]
    expected_settings = [list(setting) for setting in _settings_for(phase)]
    if settings != expected_settings:
        raise SandboxPolicyError("Sandbox settings are not the exact approved policy")

    return copy.deepcopy(document)


def _resolved_repository_root(repository_root: Path) -> Path:
    root = Path(repository_root)
    if root.is_symlink():
        raise SandboxPolicyError("Repository root must not be a symlink")
    try:
        resolved = root.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise SandboxPolicyError("Repository root could not be resolved") from error
    if not resolved.is_dir():
        raise SandboxPolicyError("Repository root must be a directory")
    return resolved


def _resolved_child(root: Path, relative: str) -> Path:
    path = (root / PurePosixPath(relative)).resolve(strict=False)
    try:
        path.relative_to(root)
    except ValueError as error:
        raise SandboxPolicyError("Sandbox path escapes the repository") from error
    current = root
    for part in path.relative_to(root).parts:
        current = current / part
        if current.exists() and current.is_symlink():
            raise SandboxPolicyError("Sandbox paths must not contain symlinks")
    return path


def render_sandboxie_ini(document: object, repository_root: Path) -> str:
    """Render a deterministic single-section Sandboxie configuration."""
    policy = validate_sandbox_policy(document)
    root = _resolved_repository_root(repository_root)
    sandbox_root = _resolved_child(root, policy["sandbox_root"])
    lines = [f"[{policy['section']}]", "Enabled=y", f"FileRootPath={sandbox_root}"]
    lines.extend(
        f"{name}={value}"
        for name, value in policy["settings"]
        if name != "Enabled"
    )
    return "\n".join(lines) + "\n"


def write_sandboxie_ini(
    output_path: Path,
    document: object,
    repository_root: Path,
) -> None:
    """Atomically write only the ignored local policy file."""
    policy = validate_sandbox_policy(document)
    root = _resolved_repository_root(repository_root)
    expected = _resolved_child(root, INI_PATH)
    try:
        requested = Path(output_path).resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise SandboxPolicyError("Sandbox output path could not be resolved") from error
    if requested != expected:
        raise SandboxPolicyError("Sandbox policy output path is not approved")
    rendered = render_sandboxie_ini(policy, root)
    expected.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=expected.parent,
        prefix=f".{expected.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, expected)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
