import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import firmware_inspect
import firmware_manifest


class FirmwareManifestCliTests(unittest.TestCase):
    def test_add_records_entry_in_new_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "fixture.bin"
            manifest_path = root / "manifest.json"
            entry = {"source_key": "fixture", "filename": "fixture.bin"}

            with (
                patch(
                    "firmware_manifest.record_artifact", return_value=entry
                ) as record,
                patch("firmware_manifest.write_manifest") as write,
            ):
                result = firmware_manifest.main(
                    [
                        "add",
                        "--source",
                        "fixture",
                        "--file",
                        str(artifact),
                        "--artifacts-root",
                        str(root),
                        "--manifest",
                        str(manifest_path),
                        "--acquired-at",
                        "2026-08-04T00:00:00Z",
                    ]
                )

        self.assertEqual(result, 0)
        record.assert_called_once_with(
            "fixture",
            artifact,
            root,
            "2026-08-04T00:00:00Z",
        )
        write.assert_called_once_with(
            manifest_path,
            {"schema_version": 1, "artifacts": [entry]},
        )

    def test_verify_selects_entry_by_exact_filename(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "fixture.bin"
            manifest_path = root / "manifest.json"
            entry = {"source_key": "fixture", "filename": "fixture.bin"}

            with (
                patch(
                    "firmware_manifest.load_manifest",
                    return_value={"schema_version": 1, "artifacts": [entry]},
                ) as load,
                patch("firmware_manifest.verify_manifest_entry") as verify,
            ):
                result = firmware_manifest.main(
                    [
                        "verify",
                        "--file",
                        str(artifact),
                        "--artifacts-root",
                        str(root),
                        "--manifest",
                        str(manifest_path),
                    ]
                )

        self.assertEqual(result, 0)
        load.assert_called_once_with(manifest_path)
        verify.assert_called_once_with(entry, artifact, root)

    def test_only_add_and_verify_subcommands_parse(self):
        for subcommand in ("download", "flash", "inspect"):
            with self.subTest(subcommand=subcommand):
                with (
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit),
                ):
                    firmware_manifest.main([subcommand])

    def test_add_rejects_abbreviated_artifacts_root_option(self):
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            firmware_manifest.main(
                [
                    "add",
                    "--source",
                    "fixture",
                    "--file",
                    "fixture.bin",
                    "--art",
                    ".artifacts",
                    "--manifest",
                    "manifest.json",
                    "--acquired-at",
                    "2026-08-04T00:00:00Z",
                ]
            )

    def test_add_rejects_metadata_override_options(self):
        required = [
            "add",
            "--source",
            "fixture",
            "--file",
            "fixture.bin",
            "--artifacts-root",
            ".artifacts",
            "--manifest",
            "manifest.json",
            "--acquired-at",
            "2026-08-04T00:00:00Z",
        ]

        for option in (
            "--url",
            "--download",
            "--camera",
            "--driver",
            "--model",
            "--expected-size",
            "--expected-digest",
        ):
            with self.subTest(option=option):
                with (
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit),
                ):
                    firmware_manifest.main(required + [option, "override"])


class FirmwareInspectCliTests(unittest.TestCase):
    def test_inspect_writes_report_and_prints_only_safe_summary(self):
        entry = {"source_key": "fixture", "filename": "fixture.bin"}
        report = {
            "source_key": "fixture",
            "size": 8,
            "sha256": "a" * 64,
            "format": "opaque-dat",
        }
        artifact = Path(".artifacts/sony-firmware/fixture/fixture.bin")
        artifacts_root = Path(".artifacts")
        manifest = Path("analysis/firmware-manifest.json")
        output = Path("analysis/fixture-report.json")

        stdout = io.StringIO()
        with (
            patch(
                "firmware_inspect.load_manifest",
                return_value={"schema_version": 1, "artifacts": [entry]},
            ),
            patch(
                "firmware_inspect.analyze_verified_artifact", return_value=report
            ) as analyze,
            patch("firmware_inspect.write_report") as write,
            contextlib.redirect_stdout(stdout),
        ):
            result = firmware_inspect.main(
                [
                    "inspect",
                    "--source",
                    "fixture",
                    "--file",
                    str(artifact),
                    "--artifacts-root",
                    str(artifacts_root),
                    "--manifest",
                    str(manifest),
                    "--report",
                    str(output),
                ]
            )

        self.assertEqual(result, 0)
        analyze.assert_called_once_with(entry, artifact, artifacts_root)
        write.assert_called_once_with(output, report, artifacts_root)
        self.assertEqual(
            stdout.getvalue(),
            "source=fixture size=8 "
            f"sha256={'a' * 64} format=opaque-dat report={output}\n",
        )

    def test_only_inspect_subcommand_and_exact_options_parse(self):
        for subcommand in ("download", "flash", "extract", "decrypt"):
            with self.subTest(subcommand=subcommand):
                with (
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit),
                ):
                    firmware_inspect.main([subcommand])

        required = [
            "inspect",
            "--source",
            "fixture",
            "--file",
            "fixture.bin",
            "--artifacts-root",
            ".artifacts",
            "--manifest",
            "manifest.json",
            "--report",
            "report.json",
        ]
        for option in (
            "--url",
            "--usb",
            "--driver",
            "--camera",
            "--patch",
            "--extract",
            "--decrypt",
            "--output-bytes",
            "--token",
        ):
            with self.subTest(option=option):
                with (
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit),
                ):
                    firmware_inspect.main(required + [option, "override"])

        abbreviated = list(required)
        abbreviated[abbreviated.index("--artifacts-root")] = "--art"
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            firmware_inspect.main(abbreviated)

    def test_expected_validation_error_is_one_line_without_traceback(self):
        stderr = io.StringIO()
        with (
            patch(
                "firmware_inspect.load_manifest",
                side_effect=firmware_inspect.ReportError("fixture rejected"),
            ),
            contextlib.redirect_stderr(stderr),
        ):
            result = firmware_inspect.main(
                [
                    "inspect",
                    "--source",
                    "fixture",
                    "--file",
                    "fixture.bin",
                    "--artifacts-root",
                    ".artifacts",
                    "--manifest",
                    "manifest.json",
                    "--report",
                    "report.json",
                ]
            )

        self.assertEqual(result, 1)
        self.assertEqual(stderr.getvalue(), "error: fixture rejected\n")
        self.assertNotIn("Traceback", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
