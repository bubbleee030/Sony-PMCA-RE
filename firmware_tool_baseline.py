"""Run deterministic matrices for fixed pinned historical firmware tools."""

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from pmca.analysis.manifest import (
    ManifestError,
    load_manifest,
    verify_manifest_entry,
)
from pmca.analysis.report import ReportError, _resolved_report_path
from pmca.analysis.tooling import (
    TOOL_SPECS,
    ToolError,
    run_unpack_baseline,
)


SOURCE_KEYS = ("a6400-tw-v2.00", "a6700-tw-v2.00", "a7v-tw-v2.00")
MAX_REPORT_BYTES = 64 * 1024
_TOP_FIELDS = {"schema_version", "tool", "commit", "results"}
_ITEM_FIELDS = {"source_key", "baseline"}
_BASELINE_FIELDS = {
    "tool",
    "commit",
    "input_sha256",
    "exit_code",
    "timed_out",
    "stage",
    "error_class",
    "safe_summary",
}


class BaselineError(ValueError):
    """Raised when a normalized historical-tool matrix is invalid."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    subparsers = parser.add_subparsers(dest="command", required=True)
    matrix = subparsers.add_parser("matrix", allow_abbrev=False)
    matrix.add_argument("--tool", required=True, choices=tuple(TOOL_SPECS))
    matrix.add_argument("--python", required=True, type=Path)
    matrix.add_argument("--checkout", required=True, type=Path)
    matrix.add_argument("--artifacts-root", required=True, type=Path)
    matrix.add_argument("--manifest", required=True, type=Path)
    matrix.add_argument("--a6400-file", required=True, type=Path)
    matrix.add_argument("--a6700-file", required=True, type=Path)
    matrix.add_argument("--a7v-file", required=True, type=Path)
    matrix.add_argument("--output-root", required=True, type=Path)
    matrix.add_argument("--report", required=True, type=Path)
    matrix.add_argument("--timeout-seconds", type=int, default=300)
    return parser


def validate_baseline_report(document: object) -> dict:
    if not isinstance(document, dict) or set(document) != _TOP_FIELDS:
        raise BaselineError("Baseline report fields do not match schema version 1")
    if document["schema_version"] != 1 or type(document["schema_version"]) is not int:
        raise BaselineError("Unsupported baseline report schema version")
    tool = document["tool"]
    if tool not in TOOL_SPECS:
        raise BaselineError("Baseline tool is not pinned")
    if document["commit"] != TOOL_SPECS[tool].commit:
        raise BaselineError("Baseline commit does not match the pinned tool")
    results = document["results"]
    if not isinstance(results, list) or len(results) != len(SOURCE_KEYS):
        raise BaselineError("Baseline matrix must contain all three sources")
    allowed_stages = {
        "wrapper-parsing",
        "dat-parsing",
        "decrypter-selection",
        "decryption",
        "partition-parsing",
        "extraction",
        "process",
    }
    seen = []
    for item in results:
        if not isinstance(item, dict) or set(item) != _ITEM_FIELDS:
            raise BaselineError("Baseline item fields do not match schema version 1")
        source_key = item["source_key"]
        if source_key not in SOURCE_KEYS:
            raise BaselineError("Baseline source is not approved")
        seen.append(source_key)
        baseline = item["baseline"]
        if not isinstance(baseline, dict) or set(baseline) != _BASELINE_FIELDS:
            raise BaselineError("Nested baseline fields are not exact")
        if baseline["tool"] != tool or baseline["commit"] != document["commit"]:
            raise BaselineError("Nested baseline provenance does not match")
        digest = baseline["input_sha256"]
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise BaselineError("Baseline input digest is invalid")
        if type(baseline["timed_out"]) is not bool:
            raise BaselineError("Baseline timeout state must be boolean")
        exit_code = baseline["exit_code"]
        if exit_code is not None and type(exit_code) is not int:
            raise BaselineError("Baseline exit code must be an integer or null")
        if baseline["timed_out"] != (exit_code is None):
            raise BaselineError("Baseline timeout and exit code disagree")
        if baseline["stage"] not in allowed_stages:
            raise BaselineError("Baseline stage is not allowlisted")
        for field in ("error_class", "safe_summary"):
            value = baseline[field]
            if (
                not isinstance(value, str)
                or not 1 <= len(value) <= 128
                or not value.isprintable()
            ):
                raise BaselineError("Baseline summary text is not bounded")
    if tuple(seen) != SOURCE_KEYS:
        raise BaselineError("Baseline sources must use the fixed order")

    serialized = json.dumps(document, sort_keys=True, indent=2) + "\n"
    if len(serialized.encode("utf-8")) > MAX_REPORT_BYTES:
        raise BaselineError("Baseline report exceeds the metadata size limit")
    return document


def run_matrix(
    tool_key: str,
    python: Path,
    checkout: Path,
    artifacts_root: Path,
    manifest_path: Path,
    inputs: dict[str, Path],
    output_root: Path,
    timeout_seconds: int = 300,
) -> dict:
    if tool_key not in TOOL_SPECS:
        raise BaselineError("Requested tool is not pinned")
    if set(inputs) != set(SOURCE_KEYS):
        raise BaselineError("Matrix inputs must be the three approved sources")
    manifest = load_manifest(manifest_path)
    entries = {entry["source_key"]: entry for entry in manifest["artifacts"]}
    spec = TOOL_SPECS[tool_key]
    results = []
    for source_key in SOURCE_KEYS:
        entry = entries.get(source_key)
        if entry is None:
            raise BaselineError("Manifest is missing a matrix source")
        input_path = inputs[source_key]
        verify_manifest_entry(entry, input_path, artifacts_root)
        baseline = run_unpack_baseline(
            spec,
            python,
            checkout,
            input_path,
            output_root / source_key,
            timeout_seconds=timeout_seconds,
        )
        results.append({"source_key": source_key, "baseline": baseline})
    return validate_baseline_report(
        {
            "schema_version": 1,
            "tool": spec.name,
            "commit": spec.commit,
            "results": results,
        }
    )


def write_baseline_report(path: Path, document: dict, artifacts_root: Path) -> None:
    validate_baseline_report(document)
    resolved_path = _resolved_report_path(path, artifacts_root)
    serialized = json.dumps(document, sort_keys=True, indent=2) + "\n"
    resolved_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=resolved_path.parent,
        prefix=f".{resolved_path.name}.",
        suffix=".tmp",
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, resolved_path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def _matrix(args: argparse.Namespace) -> None:
    inputs = {
        SOURCE_KEYS[0]: args.a6400_file,
        SOURCE_KEYS[1]: args.a6700_file,
        SOURCE_KEYS[2]: args.a7v_file,
    }
    document = run_matrix(
        args.tool,
        args.python,
        args.checkout,
        args.artifacts_root,
        args.manifest,
        inputs,
        args.output_root,
        timeout_seconds=args.timeout_seconds,
    )
    write_baseline_report(args.report, document, args.artifacts_root)
    print(f"tool={document['tool']} results={len(document['results'])}")


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        _matrix(args)
    except (
        BaselineError,
        ManifestError,
        OSError,
        ReportError,
        ToolError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
