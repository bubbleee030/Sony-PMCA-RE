import copy
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

    def test_artifact_outside_quarantine_is_rejected_before_any_read(self):
        outside = self.workspace / "outside.bin"
        outside.write_bytes(FIRMWARE)

        with (
            patch("pmca.analysis.report.sha256_file") as hash_file,
            patch("pmca.analysis.report.verify_manifest_entry") as verify,
            patch("pmca.analysis.report.inspect_artifact") as inspect,
            self.assertRaises(ReportError),
        ):
            analyze_verified_artifact(self.entry, outside, self.artifacts_root)

        hash_file.assert_not_called()
        verify.assert_not_called()
        inspect.assert_not_called()

    def test_resolved_artifact_path_is_used_for_all_reads(self):
        unresolved = (
            self.artifact.parent / ".." / self.artifact.parent.name / self.artifact.name
        )
        resolved = self.artifact.resolve()
        observed_paths = []

        def hash_file(path):
            observed_paths.append(Path(path))
            return self.digest

        def verify(entry, path, artifacts_root):
            observed_paths.append(Path(path))

        def inspect(path, source_key):
            observed_paths.append(Path(path))
            return self.inspection

        with (
            patch("pmca.analysis.report.sha256_file", side_effect=hash_file),
            patch(
                "pmca.analysis.report.verify_manifest_entry", side_effect=verify
            ),
            patch("pmca.analysis.report.inspect_artifact", side_effect=inspect),
        ):
            analyze_verified_artifact(self.entry, unresolved, self.artifacts_root)

        self.assertEqual(observed_paths, [resolved, resolved, resolved, resolved])

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

    def test_schema_version_boolean_is_rejected(self):
        report = self.analyze()
        report["schema_version"] = True

        with self.assertRaises(ReportError):
            write_report(
                self.workspace / "analysis" / "report.json",
                report,
                self.artifacts_root,
            )

    def test_nested_report_schemas_reject_unknown_members(self):
        valid = self.analyze()
        mutations = []

        entropy = copy.deepcopy(valid)
        entropy["entropy"]["unexpected"] = 1
        mutations.append(entropy)

        window = copy.deepcopy(valid)
        window["entropy"]["windows"][0]["unexpected"] = 1
        mutations.append(window)

        token = copy.deepcopy(valid)
        token["token_hits"] = [
            {"token": "ILCE6400", "count": 1, "offsets": [0], "unexpected": 1}
        ]
        mutations.append(token)

        pe = copy.deepcopy(valid)
        pe["pe"] = {
            "machine": 332,
            "section_count": 5,
            "optional_header_kind": "PE32",
            "certificate_offset": 0,
            "certificate_size": 0,
            "overlay_offset": None,
            "unexpected": 1,
        }
        pe["format"] = "pe"
        mutations.append(pe)

        for report in mutations:
            with self.subTest(report=report), self.assertRaises(ReportError):
                write_report(
                    self.workspace / "analysis" / "report.json",
                    report,
                    self.artifacts_root,
                )

    def test_nested_report_types_and_ranges_are_enforced(self):
        valid = self.analyze()
        mutations = []

        boolean_size = copy.deepcopy(valid)
        boolean_size["size"] = True
        mutations.append(boolean_size)

        invalid_entropy = copy.deepcopy(valid)
        invalid_entropy["entropy"]["windows"][0]["entropy"] = 8.01
        mutations.append(invalid_entropy)

        inconsistent_count = copy.deepcopy(valid)
        inconsistent_count["entropy"]["window_count"] = 2
        mutations.append(inconsistent_count)

        invalid_token = copy.deepcopy(valid)
        invalid_token["token_hits"] = [
            {"token": "NOT-ALLOWLISTED", "count": 1, "offsets": [0]}
        ]
        mutations.append(invalid_token)

        unhashable_format = copy.deepcopy(valid)
        unhashable_format["format"] = []
        mutations.append(unhashable_format)

        unhashable_token = copy.deepcopy(valid)
        unhashable_token["token_hits"] = [
            {"token": [], "count": 1, "offsets": [0]}
        ]
        mutations.append(unhashable_token)

        unhashable_pe_kind = copy.deepcopy(valid)
        unhashable_pe_kind["format"] = "pe"
        unhashable_pe_kind["pe"] = {
            "machine": 332,
            "section_count": 5,
            "optional_header_kind": [],
            "certificate_offset": 0,
            "certificate_size": 0,
            "overlay_offset": None,
        }
        mutations.append(unhashable_pe_kind)

        for report in mutations:
            with self.subTest(report=report), self.assertRaises(ReportError):
                write_report(
                    self.workspace / "analysis" / "report.json",
                    report,
                    self.artifacts_root,
                )

    def test_serialized_report_size_is_bounded(self):
        report = self.analyze()
        report["size"] = 13_000
        report["entropy"] = {
            "window_size": 1,
            "window_count": 13_000,
            "windows": [
                {"offset": offset, "size": 1, "entropy": 0.0}
                for offset in range(13_000)
            ],
        }

        with self.assertRaises(ReportError):
            write_report(
                self.workspace / "analysis" / "oversized.json",
                report,
                self.artifacts_root,
            )

    def test_committed_reports_conform_to_schema(self):
        reports = Path(__file__).parents[2] / "analysis" / "reports"
        for committed in reports.glob("*.json"):
            with self.subTest(committed=committed):
                report = json.loads(committed.read_text(encoding="utf-8"))
                output = self.workspace / "analysis" / committed.name
                write_report(output, report, self.artifacts_root)
                self.assertEqual(output.read_bytes(), committed.read_bytes())

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
