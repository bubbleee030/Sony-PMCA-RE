import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from firmware_updater import main, write_updater_report
from tests.analysis.test_updater_pe import _updater_fixture
from pmca.analysis.updater_pe import inspect_updater_pe


class UpdaterCliTests(unittest.TestCase):
    def test_writer_uses_only_the_fixed_repository_report_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "analysis").mkdir()
            updater = root / "updater.exe"
            updater.write_bytes(_updater_fixture()[0])
            report = inspect_updater_pe(updater)

            output = write_updater_report(root, report)

            self.assertEqual(output, root / "analysis" / "a6400-updater-static.json")
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), report)

    @patch("firmware_updater.write_updater_report")
    @patch("firmware_updater.inspect_updater_pe")
    @patch("firmware_updater.verify_manifest_entry")
    @patch("firmware_updater.load_manifest")
    def test_main_verifies_the_fixed_manifest_entry_before_inspection(
        self, load, verify, inspect, write
    ):
        entry = {"source_key": "a6400-tw-v2.00"}
        load.return_value = {"schema_version": 1, "artifacts": [entry]}
        events = []
        verify.side_effect = lambda *args: events.append("verify")
        expected_document = {
            "schema_version": 1,
            "resources": [],
            "embedded_pe_candidates": [],
        }
        inspect.side_effect = lambda *args: (
            events.append("inspect") or expected_document
        )
        write.return_value = Path("analysis/a6400-updater-static.json")

        result = main(
            [
                "inspect",
                "--repository-root",
                "repo",
                "--artifacts-root",
                "repo/.artifacts",
                "--manifest",
                "repo/analysis/firmware-manifest.json",
                "--input",
                "repo/.artifacts/analysis-inputs/a6400/updater.exe",
            ]
        )

        self.assertEqual(result, 0)
        verify.assert_called_once()
        inspect.assert_called_once()
        self.assertEqual(events, ["verify", "inspect"])
        write.assert_called_once_with(Path("repo"), expected_document)


if __name__ == "__main__":
    unittest.main()
