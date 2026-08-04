import hashlib
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from firmware_lab import (
    EXPERIMENTS,
    LabError,
    mutation_patch,
    validate_experiment_report,
)


def _baseline(digest):
    return {
        "tool": "ma1co-fwtool",
        "commit": "a" * 40,
        "input_sha256": digest,
        "exit_code": 1,
        "timed_out": False,
        "stage": "decrypter-selection",
        "error_class": "no-decrypter",
        "safe_summary": "tool reported no compatible decrypter",
    }


def synthetic_report():
    results = []
    for index, spec in enumerate(EXPERIMENTS):
        parent = f"{index:x}" * 64
        output = f"{index + 8:x}" * 64
        before = _baseline(parent)
        after = _baseline(output)
        results.append(
            {
                "experiment_id": spec.experiment_id,
                "source_key": spec.source_key,
                "mutation_target": spec.mutation_target,
                "offset": spec.offset,
                "size": 1,
                "parent_sha256": parent,
                "output_sha256": output,
                "installable": False,
                "host_signature_impact": (
                    spec.expected_pe_impact
                    if spec.expected_pe_impact is not None
                    else "not-applicable"
                ),
                "historical_tool_before": before,
                "historical_tool_after": after,
                "hypothesis_class": spec.hypothesis_class,
                "discrimination": "none-at-historical-tool-stopping-layer",
                "conclusion": (
                    "mutation did not move the pinned tool beyond its prior "
                    "stopping layer"
                ),
            }
        )
    return {
        "schema_version": 1,
        "tool": "ma1co-fwtool",
        "commit": "a" * 40,
        "installable": False,
        "camera_executed": False,
        "experiments": results,
    }


class FirmwareLabTests(unittest.TestCase):
    def test_fixed_matrix_contains_all_eight_named_experiments(self):
        self.assertEqual(
            tuple(spec.experiment_id for spec in EXPERIMENTS),
            (
                "a6400-pe-certificate-byte",
                "a6400-pe-overlay-byte",
                "a6700-datv-version-byte",
                "a6700-udid-field-byte",
                "a6700-fdat-first-block-byte",
                "a7v-datv-version-byte",
                "a7v-udid-field-byte",
                "a7v-fdat-first-block-byte",
            ),
        )

    def test_mutation_patch_is_digest_pinned_and_one_byte(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.bin"
            path.write_bytes(b"\x10\x20\x30")
            spec = deepcopy(EXPERIMENTS[0])
            object.__setattr__(spec, "offset", 1)
            patch = mutation_patch(path, spec)

        self.assertEqual(patch.offset, 1)
        self.assertEqual(patch.expected_sha256, hashlib.sha256(b"\x20").hexdigest())
        self.assertEqual(patch.replacement, b"\x21")

    def test_report_schema_is_exact_and_contains_no_mutation_bytes(self):
        report = validate_experiment_report(synthetic_report())
        serialized = json.dumps(report)

        self.assertFalse(report["installable"])
        self.assertFalse(report["camera_executed"])
        self.assertNotIn("replacement", serialized)
        self.assertNotIn("preimage", serialized)

    def test_installable_reordered_or_wrong_digest_reports_are_rejected(self):
        invalid = []
        installable = synthetic_report()
        installable["installable"] = True
        invalid.append(installable)
        reordered = synthetic_report()
        reordered["experiments"].reverse()
        invalid.append(reordered)
        wrong_digest = synthetic_report()
        wrong_digest["experiments"][0]["historical_tool_after"][
            "input_sha256"
        ] = "f" * 64
        invalid.append(wrong_digest)
        for document in invalid:
            with self.subTest(document=document):
                with self.assertRaises(LabError):
                    validate_experiment_report(document)


if __name__ == "__main__":
    unittest.main()
