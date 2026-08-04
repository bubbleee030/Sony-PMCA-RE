"""Pinned, no-shell historical firmware tool baseline execution."""

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .manifest import sha256_file


MAX_CAPTURED_TEXT = 64 * 1024
MAX_TIMEOUT_SECONDS = 1800
_COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
_GITHUB_PATTERN = re.compile(
    r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?\Z"
)


class ToolError(ValueError):
    """Raised when a pinned tool baseline violates an offline safety boundary."""


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    repo_url: str
    commit: str
    entrypoint: str


TOOL_SPECS = {
    "ma1co-fwtool": ToolSpec(
        "ma1co-fwtool",
        "https://github.com/ma1co/fwtool.py.git",
        "cdba742b73eed5981480c326aeb30033aabf0223",
        "fwtool.py",
    ),
    "joeording3-fwtool": ToolSpec(
        "joeording3-fwtool",
        "https://github.com/joeording3/fwtool.py.git",
        "c351060721547f6b65d6c969d863f486662f9424",
        "fwtool.py",
    ),
    "ironpayne22-fwtool": ToolSpec(
        "ironpayne22-fwtool",
        "https://github.com/ironpayne22/fwtool.py.git",
        "bc32b106833f64bf105164d49f2f181b0cf39a47",
        "fwtool.py",
    ),
}


def validate_tool_spec(spec: object) -> ToolSpec:
    if not isinstance(spec, ToolSpec):
        raise ToolError("Tool specification must be a ToolSpec")
    if (
        not isinstance(spec.name, str)
        or not 1 <= len(spec.name) <= 64
        or not spec.name.isprintable()
    ):
        raise ToolError("Tool name must be bounded printable text")
    if not isinstance(spec.repo_url, str) or not _GITHUB_PATTERN.fullmatch(
        spec.repo_url
    ):
        raise ToolError("Tool repository must be an HTTPS GitHub URL")
    if not isinstance(spec.commit, str) or not _COMMIT_PATTERN.fullmatch(spec.commit):
        raise ToolError("Tool commit must be forty lowercase hexadecimal characters")
    if not isinstance(spec.entrypoint, str) or "\\" in spec.entrypoint:
        raise ToolError("Tool entrypoint must be a relative POSIX path")
    entrypoint = PurePosixPath(spec.entrypoint)
    if (
        entrypoint.is_absolute()
        or not entrypoint.parts
        or any(part in {"", ".", ".."} for part in entrypoint.parts)
    ):
        raise ToolError("Tool entrypoint must be a relative POSIX path")
    return spec


def _artifacts_root(path: Path) -> Path:
    for candidate in (path, *path.parents):
        if candidate.name.casefold() == ".artifacts":
            return candidate
    raise ToolError("Tool path must be below an .artifacts directory")


def _reject_symlink_chain(root: Path, path: Path) -> None:
    current = root
    if current.is_symlink():
        raise ToolError("Tool paths must not contain symlinks")
    relative = path.relative_to(root)
    for part in relative.parts:
        current = current / part
        if current.exists() and current.is_symlink():
            raise ToolError("Tool paths must not contain symlinks")


def _validate_existing_path(path: Path, subtree: str, directory: bool) -> Path:
    path = Path(path)
    root = _artifacts_root(path)
    try:
        resolved_root = root.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ToolError("Required tool path could not be resolved") from error
    _reject_symlink_chain(root, path)
    try:
        relative = resolved_path.relative_to(resolved_root)
    except ValueError as error:
        raise ToolError("Tool path escapes the artifacts root") from error
    if not relative.parts or relative.parts[0].casefold() != subtree.casefold():
        raise ToolError(f"Tool path must be below .artifacts/{subtree}")
    if directory and not resolved_path.is_dir():
        raise ToolError("Tool checkout must be a directory")
    if not directory and not resolved_path.is_file():
        raise ToolError("Tool input must be a regular file")
    return resolved_path


def _validate_output_dir(path: Path) -> Path:
    path = Path(path)
    root = _artifacts_root(path)
    try:
        resolved_root = root.resolve(strict=True)
        resolved_path = path.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise ToolError("Tool output path could not be resolved") from error
    _reject_symlink_chain(root, path)
    try:
        relative = resolved_path.relative_to(resolved_root)
    except ValueError as error:
        raise ToolError("Tool output escapes the artifacts root") from error
    if not relative.parts or relative.parts[0].casefold() != "tool-output":
        raise ToolError("Tool output must be below .artifacts/tool-output")
    if resolved_path.exists():
        if not resolved_path.is_dir() or any(resolved_path.iterdir()):
            raise ToolError("Tool output directory must be absent or empty")
    else:
        resolved_path.mkdir(parents=True)
    return resolved_path


def _validate_python(path: Path) -> Path:
    path = Path(path)
    if path.is_symlink():
        raise ToolError("Python executable must not be a symlink")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ToolError("Python executable could not be resolved") from error
    if not resolved.is_file():
        raise ToolError("Python executable must be a regular file")
    return resolved


def _captured_text(completed: subprocess.CompletedProcess) -> str:
    values = []
    for value in (completed.stdout, completed.stderr):
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        if isinstance(value, str):
            values.append(value)
    return "\n".join(values)[:MAX_CAPTURED_TEXT]


def _classify(exit_code: int, captured: str) -> tuple[str, str, str]:
    lowered = captured.casefold()
    patterns = (
        (
            "unknown exe file",
            "wrapper-parsing",
            "unknown-installer",
            "tool rejected the updater wrapper format",
        ),
        (
            "no decrypter found",
            "decrypter-selection",
            "no-decrypter",
            "tool reported no compatible decrypter",
        ),
        (
            "invalid data file",
            "dat-parsing",
            "invalid-dat",
            "tool rejected the DAT container",
        ),
        (
            "failed to decrypt",
            "decryption",
            "decryption-failed",
            "tool reported a decryption failure",
        ),
        (
            "invalid partition",
            "partition-parsing",
            "invalid-partition",
            "tool rejected the partition table",
        ),
        (
            "usage:",
            "wrapper-parsing",
            "cli-error",
            "tool rejected the configured unpack command",
        ),
    )
    for phrase, stage, error_class, summary in patterns:
        if phrase in lowered:
            return stage, error_class, summary
    if exit_code == 0:
        return "extraction", "none", "tool completed its unpack command"
    return "process", "nonzero-exit", "tool exited without an allowlisted diagnostic"


def run_unpack_baseline(
    spec: ToolSpec,
    python: Path,
    checkout: Path,
    input_path: Path,
    output_dir: Path,
    timeout_seconds: int = 300,
) -> dict:
    """Run one pinned unpack command and return only normalized metadata."""
    spec = validate_tool_spec(spec)
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise ToolError("Tool timeout is outside the supported range")
    resolved_python = _validate_python(python)
    resolved_checkout = _validate_existing_path(checkout, "tools", directory=True)
    resolved_input = _validate_existing_path(
        input_path, "analysis-inputs", directory=False
    )
    resolved_output = _validate_output_dir(output_dir)
    entrypoint = (resolved_checkout / spec.entrypoint).resolve(strict=True)
    _reject_symlink_chain(resolved_checkout, entrypoint)
    if not entrypoint.is_file():
        raise ToolError("Tool entrypoint must be a regular file")

    command = [
        str(resolved_python),
        str(entrypoint),
        "unpack",
        "-f",
        str(resolved_input),
        "-o",
        str(resolved_output),
    ]
    digest = sha256_file(resolved_input)
    try:
        completed = subprocess.run(
            command,
            shell=False,
            cwd=str(resolved_checkout),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "tool": spec.name,
            "commit": spec.commit,
            "input_sha256": digest,
            "exit_code": None,
            "timed_out": True,
            "stage": "process",
            "error_class": "timeout",
            "safe_summary": "tool exceeded the finite timeout",
        }
    except OSError as error:
        raise ToolError("Pinned tool process could not be started") from error

    stage, error_class, safe_summary = _classify(
        completed.returncode,
        _captured_text(completed),
    )
    return {
        "tool": spec.name,
        "commit": spec.commit,
        "input_sha256": digest,
        "exit_code": completed.returncode,
        "timed_out": False,
        "stage": stage,
        "error_class": error_class,
        "safe_summary": safe_summary,
    }
