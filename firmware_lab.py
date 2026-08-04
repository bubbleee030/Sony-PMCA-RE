"""Run the fixed, offline-only firmware mutation experiment matrix."""

import argparse
import hashlib
import json
import os
import sys
import tempfile
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path

from firmware_tool_baseline import validate_baseline_report
from pmca.analysis.manifest import (
    ManifestError,
    load_manifest,
    verify_manifest_entry,
)
from pmca.analysis.quarantine import (
    Patch,
    QuarantineError,
    apply_quarantined_patches,
)
from pmca.analysis.report import ReportError, _resolved_report_path
from pmca.analysis.signatures import (
    SignatureError,
    classify_patch_impact,
    pe_authenticode_coverage,
)
from pmca.analysis.tooling import (
    TOOL_SPECS,
    ToolError,
    run_quarantined_unpack_baseline,
)


TOOL_KEY = "ma1co-fwtool"
SOURCE_KEYS = ("a6400-tw-v2.00", "a6700-tw-v2.00", "a7v-tw-v2.00")
MAX_REPORT_BYTES = 256 * 1024
_DIGEST_CHARS = frozenset("0123456789abcdef")
_STAGES = {
    "wrapper-parsing",
    "dat-parsing",
    "decrypter-selection",
    "decryption",
    "partition-parsing",
    "extraction",
    "process",
}
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
_RESULT_FIELDS = {
    "experiment_id",
    "source_key",
    "mutation_target",
    "offset",
    "size",
    "parent_sha256",
    "output_sha256",
    "installable",
    "host_signature_impact",
    "historical_tool_before",
    "historical_tool_after",
    "hypothesis_class",
    "discrimination",
    "conclusion",
}


class LabError(ValueError):
    """Raised when the experiment matrix violates an offline safety gate."""


@dataclass(frozen=True, slots=True)
class ExperimentSpec:
    experiment_id: str
    source_key: str
    mutation_target: str
    offset: int
    hypothesis_class: str
    expected_pe_impact: str | None = None


EXPERIMENTS = (
    ExperimentSpec(
        "a6400-pe-certificate-byte",
        SOURCE_KEYS[0],
        "pe-certificate",
        314_220_688,
        "signature",
        "excluded",
    ),
    ExperimentSpec(
        "a6400-pe-overlay-byte",
        SOURCE_KEYS[0],
        "pe-overlay",
        452_608,
        "signature",
        "signed",
    ),
    ExperimentSpec(
        "a6700-datv-version-byte",
        SOURCE_KEYS[1],
        "datv-payload",
        16,
        "model",
    ),
    ExperimentSpec(
        "a6700-udid-field-byte",
        SOURCE_KEYS[1],
        "udid-payload",
        40,
        "model",
    ),
    ExperimentSpec(
        "a6700-fdat-first-block-byte",
        SOURCE_KEYS[1],
        "fdat-payload",
        156,
        "decrypter",
    ),
    ExperimentSpec(
        "a7v-datv-version-byte",
        SOURCE_KEYS[2],
        "datv-payload",
        16,
        "model",
    ),
    ExperimentSpec(
        "a7v-udid-field-byte",
        SOURCE_KEYS[2],
        "udid-payload",
        40,
        "model",
    ),
    ExperimentSpec(
        "a7v-fdat-first-block-byte",
        SOURCE_KEYS[2],
        "fdat-payload",
        148,
        "decrypter",
    ),
)


def _digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _DIGEST_CHARS for character in value)
    )


def mutation_patch(path: Path, spec: ExperimentSpec) -> Patch:
    """Create one deterministic XOR-1 patch pinned to its exact byte preimage."""
    if not isinstance(spec, ExperimentSpec) or type(spec.offset) is not int:
        raise LabError("Experiment specification is invalid")
    try:
        with Path(path).open("rb") as stream:
            stream.seek(spec.offset)
            preimage = stream.read(1)
    except (OSError, ValueError) as error:
        raise LabError("Experiment byte could not be read") from error
    if len(preimage) != 1:
        raise LabError("Experiment offset exceeds the input")
    return Patch(
        spec.offset,
        hashlib.sha256(preimage).hexdigest(),
        bytes((preimage[0] ^ 0x01,)),
    )


def _validate_baseline(value: object, digest: str, tool: str, commit: str) -> dict:
    if not isinstance(value, dict) or set(value) != _BASELINE_FIELDS:
        raise LabError("Historical-tool fields do not match schema version 1")
    if value["tool"] != tool or value["commit"] != commit:
        raise LabError("Historical-tool provenance does not match the report")
    if value["input_sha256"] != digest:
        raise LabError("Historical-tool input digest does not match the experiment")
    if value["stage"] not in _STAGES:
        raise LabError("Historical-tool stage is not allowlisted")
    if type(value["timed_out"]) is not bool:
        raise LabError("Historical-tool timeout state is invalid")
    exit_code = value["exit_code"]
    if exit_code is not None and type(exit_code) is not int:
        raise LabError("Historical-tool exit code is invalid")
    if value["timed_out"] != (exit_code is None):
        raise LabError("Historical-tool timeout and exit code disagree")
    for field in ("error_class", "safe_summary"):
        text = value[field]
        if (
            not isinstance(text, str)
            or not 1 <= len(text) <= 128
            or not text.isprintable()
        ):
            raise LabError("Historical-tool summary is not bounded text")
    return value


def validate_experiment_report(document: object) -> dict:
    top_fields = {
        "schema_version",
        "tool",
        "commit",
        "installable",
        "camera_executed",
        "experiments",
    }
    if not isinstance(document, dict) or set(document) != top_fields:
        raise LabError("Experiment report fields do not match schema version 1")
    if document["schema_version"] != 1 or type(document["schema_version"]) is not int:
        raise LabError("Unsupported experiment report schema version")
    if document["tool"] != TOOL_KEY:
        raise LabError("Experiment report tool is not the fixed pinned tool")
    commit = document["commit"]
    if (
        not isinstance(commit, str)
        or len(commit) != 40
        or any(character not in _DIGEST_CHARS for character in commit)
    ):
        raise LabError("Experiment report commit is invalid")
    if document["installable"] is not False or document["camera_executed"] is not False:
        raise LabError("Experiment report must remain offline and non-installable")
    results = document["experiments"]
    if not isinstance(results, list) or len(results) != len(EXPERIMENTS):
        raise LabError("Experiment report must contain the fixed matrix")
    for value, spec in zip(results, EXPERIMENTS):
        if not isinstance(value, dict) or set(value) != _RESULT_FIELDS:
            raise LabError("Experiment result fields do not match schema version 1")
        expected = {
            "experiment_id": spec.experiment_id,
            "source_key": spec.source_key,
            "mutation_target": spec.mutation_target,
            "offset": spec.offset,
            "size": 1,
            "hypothesis_class": spec.hypothesis_class,
        }
        if any(value[field] != expected_value for field, expected_value in expected.items()):
            raise LabError("Experiment result does not match the fixed specification")
        if not _digest(value["parent_sha256"]) or not _digest(value["output_sha256"]):
            raise LabError("Experiment digest is invalid")
        if value["parent_sha256"] == value["output_sha256"]:
            raise LabError("Experiment output must differ from its parent")
        if value["installable"] is not False:
            raise LabError("Experiment result must be non-installable")
        expected_impact = spec.expected_pe_impact or "not-applicable"
        if value["host_signature_impact"] != expected_impact:
            raise LabError("Experiment host-signature impact is unexpected")
        before = _validate_baseline(
            value["historical_tool_before"],
            value["parent_sha256"],
            document["tool"],
            document["commit"],
        )
        after = _validate_baseline(
            value["historical_tool_after"],
            value["output_sha256"],
            document["tool"],
            document["commit"],
        )
        stage_changed = (before["stage"], before["error_class"]) != (
            after["stage"],
            after["error_class"],
        )
        expected_discrimination = (
            "candidate-stage-shift"
            if stage_changed
            else "none-at-historical-tool-stopping-layer"
        )
        expected_conclusion = (
            "mutation changed the pinned-tool stopping layer; cause remains unconfirmed"
            if stage_changed
            else "mutation did not move the pinned tool beyond its prior stopping layer"
        )
        if value["discrimination"] != expected_discrimination:
            raise LabError("Experiment discrimination does not follow its tool result")
        if value["conclusion"] != expected_conclusion:
            raise LabError("Experiment conclusion does not follow its tool result")
    serialized = json.dumps(document, sort_keys=True, indent=2) + "\n"
    if len(serialized.encode("utf-8")) > MAX_REPORT_BYTES:
        raise LabError("Experiment report exceeds the metadata size limit")
    return document


def _baseline_by_source(path: Path) -> tuple[str, dict[str, dict]]:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise LabError("Historical-tool baseline report could not be read") from error
    document = validate_baseline_report(document)
    if document["tool"] != TOOL_KEY:
        raise LabError("Historical baseline is not from the fixed tool")
    return document["commit"], {
        item["source_key"]: item["baseline"] for item in document["results"]
    }


def run_experiment_matrix(
    python: Path,
    checkout: Path,
    artifacts_root: Path,
    manifest_path: Path,
    baseline_report: Path,
    inputs: dict[str, Path],
    tool_output_root: Path,
    timeout_seconds: int = 300,
) -> dict:
    """Build and test eight one-byte quarantine variants without camera access."""
    if set(inputs) != set(SOURCE_KEYS):
        raise LabError("Experiment inputs must be the three fixed sources")
    manifest = load_manifest(manifest_path)
    entries = {entry["source_key"]: entry for entry in manifest["artifacts"]}
    for source_key in SOURCE_KEYS:
        entry = entries.get(source_key)
        if entry is None:
            raise LabError("Manifest is missing an experiment source")
        verify_manifest_entry(entry, inputs[source_key], artifacts_root)
    commit, before_by_source = _baseline_by_source(baseline_report)
    spec_tool = TOOL_SPECS[TOOL_KEY]
    if commit != spec_tool.commit:
        raise LabError("Historical baseline commit is not currently pinned")
    coverage = pe_authenticode_coverage(inputs[SOURCE_KEYS[0]])
    results = []
    for spec in EXPERIMENTS:
        source = Path(inputs[spec.source_key])
        patch = mutation_patch(source, spec)
        if spec.expected_pe_impact is None:
            impact = "not-applicable"
        else:
            impacts = classify_patch_impact((patch,), coverage)
            impact = impacts[0]
            if impact != spec.expected_pe_impact:
                raise LabError("PE mutation does not match its expected coverage")
        output = (
            Path(artifacts_root)
            / "quarantine"
            / f"{spec.experiment_id}_NOT_FOR_INSTALL{source.suffix}"
        )
        quarantine = apply_quarantined_patches(
            source,
            artifacts_root,
            output,
            (patch,),
            spec.experiment_id,
        )
        after = run_quarantined_unpack_baseline(
            spec_tool,
            python,
            checkout,
            output,
            Path(tool_output_root) / spec.experiment_id,
            timeout_seconds=timeout_seconds,
        )
        before = before_by_source[spec.source_key]
        stage_changed = (before["stage"], before["error_class"]) != (
            after["stage"],
            after["error_class"],
        )
        results.append(
            {
                "experiment_id": spec.experiment_id,
                "source_key": spec.source_key,
                "mutation_target": spec.mutation_target,
                "offset": spec.offset,
                "size": 1,
                "parent_sha256": quarantine["parent_sha256"],
                "output_sha256": quarantine["output_sha256"],
                "installable": False,
                "host_signature_impact": impact,
                "historical_tool_before": before,
                "historical_tool_after": after,
                "hypothesis_class": spec.hypothesis_class,
                "discrimination": (
                    "candidate-stage-shift"
                    if stage_changed
                    else "none-at-historical-tool-stopping-layer"
                ),
                "conclusion": (
                    "mutation changed the pinned-tool stopping layer; cause remains unconfirmed"
                    if stage_changed
                    else "mutation did not move the pinned tool beyond its prior stopping layer"
                ),
            }
        )
    return validate_experiment_report(
        {
            "schema_version": 1,
            "tool": TOOL_KEY,
            "commit": commit,
            "installable": False,
            "camera_executed": False,
            "experiments": results,
        }
    )


def refresh_experiment_tool_results(
    document: dict,
    python: Path,
    checkout: Path,
    artifacts_root: Path,
    tool_output_root: Path,
    timeout_seconds: int = 300,
) -> dict:
    """Reclassify existing quarantined outputs without rebuilding or modifying them."""
    refreshed = deepcopy(validate_experiment_report(document))
    spec_tool = TOOL_SPECS[TOOL_KEY]
    if refreshed["commit"] != spec_tool.commit:
        raise LabError("Experiment report commit is not currently pinned")
    suffixes = {
        SOURCE_KEYS[0]: ".exe",
        SOURCE_KEYS[1]: ".DAT",
        SOURCE_KEYS[2]: ".DAT",
    }
    for value, spec in zip(refreshed["experiments"], EXPERIMENTS):
        quarantine = (
            Path(artifacts_root)
            / "quarantine"
            / f"{spec.experiment_id}_NOT_FOR_INSTALL{suffixes[spec.source_key]}"
        )
        after = run_quarantined_unpack_baseline(
            spec_tool,
            python,
            checkout,
            quarantine,
            Path(tool_output_root) / spec.experiment_id,
            timeout_seconds=timeout_seconds,
        )
        if after["input_sha256"] != value["output_sha256"]:
            raise LabError("Refreshed tool result does not match quarantine digest")
        value["historical_tool_after"] = after
        before = value["historical_tool_before"]
        stage_changed = (before["stage"], before["error_class"]) != (
            after["stage"],
            after["error_class"],
        )
        value["discrimination"] = (
            "candidate-stage-shift"
            if stage_changed
            else "none-at-historical-tool-stopping-layer"
        )
        value["conclusion"] = (
            "mutation changed the pinned-tool stopping layer; cause remains unconfirmed"
            if stage_changed
            else "mutation did not move the pinned tool beyond its prior stopping layer"
        )
    return validate_experiment_report(refreshed)


def write_experiment_report(path: Path, document: dict, artifacts_root: Path) -> None:
    validate_experiment_report(document)
    resolved = _resolved_report_path(path, artifacts_root)
    serialized = json.dumps(document, sort_keys=True, indent=2) + "\n"
    resolved.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=resolved.parent,
        prefix=f".{resolved.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, resolved)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run", allow_abbrev=False)
    run.add_argument("--python", required=True, type=Path)
    run.add_argument("--checkout", required=True, type=Path)
    run.add_argument("--artifacts-root", required=True, type=Path)
    run.add_argument("--manifest", required=True, type=Path)
    run.add_argument("--baseline-report", required=True, type=Path)
    run.add_argument("--a6400-file", required=True, type=Path)
    run.add_argument("--a6700-file", required=True, type=Path)
    run.add_argument("--a7v-file", required=True, type=Path)
    run.add_argument("--tool-output-root", required=True, type=Path)
    run.add_argument("--report", required=True, type=Path)
    run.add_argument("--timeout-seconds", type=int, default=300)
    return parser


def _run(args: argparse.Namespace) -> None:
    document = run_experiment_matrix(
        args.python,
        args.checkout,
        args.artifacts_root,
        args.manifest,
        args.baseline_report,
        {
            SOURCE_KEYS[0]: args.a6400_file,
            SOURCE_KEYS[1]: args.a6700_file,
            SOURCE_KEYS[2]: args.a7v_file,
        },
        args.tool_output_root,
        timeout_seconds=args.timeout_seconds,
    )
    write_experiment_report(args.report, document, args.artifacts_root)
    print(f"experiments={len(document['experiments'])} installable=false camera=false")


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        _run(args)
    except (
        LabError,
        ManifestError,
        OSError,
        QuarantineError,
        ReportError,
        SignatureError,
        ToolError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
