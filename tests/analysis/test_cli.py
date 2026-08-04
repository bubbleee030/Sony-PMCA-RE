import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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


if __name__ == "__main__":
    unittest.main()
