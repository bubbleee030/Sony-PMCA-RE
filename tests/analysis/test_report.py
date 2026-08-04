import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pmca.analysis.report import (
    ReportError,
    analyze_verified_artifact,
    write_report,
)


FIRMWARE = b"firmware"


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.workspace = Path(self.temporary_directory.name)
        self.artifacts_root = self.workspace / ".artifacts"
        self.artifact = (
            self.artifacts_root / "sony-firmware" / "fixture" / "fixture.bin"
        )
        self.artifact.parent.mkdir(parents=True)
        self.artifact.write_bytes(FIRMWARE)
        self.digest = hashlib.sha256(FIRMWARE).hexdigest()
        self.entry = {
            "source_key": "fixture",
            "filename": "fixture.bin",
            "measured_size": len(FIRMWARE),
            "sha256": self.digest,
        }
        self.inspection = {
            "source_key": "fixture",
            "format": "opaque-dat",
            "pe": None,
            "entropy": {
                "window_size": 1_048_576,
                "window_count": 1,
                "windows": [{"offset": 0, "size": 8, "entropy": 2.75}],
            },
            "token_hits": [],
        }

    def analyze(self, inspection=None):
        with (
            patch("pmca.analysis.report.verify_manifest_entry"),
            patch(
                "pmca.analysis.report.inspect_artifact",
                return_value=inspection or self.inspection,
            ),
        ):
            return analyze_verified_artifact(
                self.entry, self.artifact, self.artifacts_root
            )

    def test_verification_precedes_inspection_and_input_is_immutable(self):
        order = []
        before = self.artifact.read_bytes()

        with (
            patch(
                "pmca.analysis.report.verify_manifest_entry",
                side_effect=lambda *args: order.append("verify"),
            ),
            patch(
                "pmca.analysis.report.inspect_artifact",
                side_effect=lambda *args: order.append("inspect") or self.inspection,
            ),
        ):
            report = analyze_verified_artifact(
                self.entry, self.artifact, self.artifacts_root
            )

        self.assertEqual(order, ["verify", "inspect"])
        self.assertEqual(self.artifact.read_bytes(), before)
        self.assertEqual(report["sha256"], self.digest)

    def test_changed_input_raises(self):
        def mutate_artifact(*args):
            self.artifact.write_bytes(b"changed!")
            return self.inspection

        with (
            patch("pmca.analysis.report.verify_manifest_entry"),
            patch(
                "pmca.analysis.report.inspect_artifact",
                side_effect=mutate_artifact,
            ),
            self.assertRaises(ReportError),
        ):
            analyze_verified_artifact(
                self.entry, self.artifact, self.artifacts_root
            )

    def test_report_schema_is_fixed_and_deterministic(self):
        first = self.analyze()
        second = self.analyze()

        self.assertEqual(first, second)
        self.assertEqual(
            set(first),
            {
                "schema_version",
                "source_key",
                "filename",
                "size",
                "sha256",
                "format",
                "pe",
                "entropy",
                "token_hits",
            },
        )

    def test_reconstruction_capable_keys_are_rejected_recursively(self):
        for forbidden_key in (
            "raw",
            "bytes",
            "payload",
            "base64",
            "hex_dump",
            "strings",
        ):
            with self.subTest(forbidden_key=forbidden_key):
                inspection = dict(self.inspection)
                inspection["entropy"] = {"nested": [{forbidden_key: "secret"}]}
                with self.assertRaises(ReportError):
                    self.analyze(inspection)

    def test_json_output_is_byte_for_byte_deterministic(self):
        report = self.analyze()
        output = self.workspace / "analysis" / "report.json"

        write_report(output, report, self.artifacts_root)
        first = output.read_bytes()
        write_report(output, report, self.artifacts_root)

        expected = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode(
            "utf-8"
        )
        self.assertEqual(first, expected)
        self.assertEqual(output.read_bytes(), expected)

    def test_report_path_policy_allows_only_analysis_runs_below_artifacts(self):
        report = self.analyze()
        forbidden_paths = (
            self.artifacts_root / "sony-firmware" / "report.json",
            self.artifacts_root / "other" / "report.json",
        )
        for output in forbidden_paths:
            with self.subTest(output=output), self.assertRaises(ReportError):
                write_report(output, report, self.artifacts_root)

        temporary_output = self.artifacts_root / "analysis-runs" / "report.json"
        write_report(temporary_output, report, self.artifacts_root)
        self.assertTrue(temporary_output.is_file())

    def test_report_requires_json_suffix(self):
        with self.assertRaises(ReportError):
            write_report(
                self.workspace / "analysis" / "report.txt",
                self.analyze(),
                self.artifacts_root,
            )


if __name__ == "__main__":
    unittest.main()
