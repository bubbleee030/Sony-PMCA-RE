import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import call, patch

import creative_look_recipes
import firmware_decisions
import firmware_inspect
import firmware_lab
import firmware_manifest
import firmware_structure

from tests.analysis.test_decisions import synthetic_document


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

    def test_verify_disambiguates_duplicate_filenames_by_full_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "BODYDATA.DAT"
            manifest_path = root / "manifest.json"
            wrong = {"source_key": "a6700", "filename": "BODYDATA.DAT"}
            matching = {"source_key": "a7v", "filename": "BODYDATA.DAT"}

            def verify_entry(entry, _artifact, _root):
                if entry is wrong:
                    raise firmware_manifest.ManifestError("digest mismatch")

            with (
                patch(
                    "firmware_manifest.load_manifest",
                    return_value={
                        "schema_version": 1,
                        "artifacts": [wrong, matching],
                    },
                ),
                patch(
                    "firmware_manifest.verify_manifest_entry",
                    side_effect=verify_entry,
                ) as verify,
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
        self.assertEqual(
            verify.call_args_list,
            [
                call(wrong, artifact, root),
                call(matching, artifact, root),
            ],
        )

    def test_verify_rejects_multiple_full_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "BODYDATA.DAT"
            manifest_path = root / "manifest.json"
            first = {"source_key": "first", "filename": "BODYDATA.DAT"}
            second = {"source_key": "second", "filename": "BODYDATA.DAT"}
            stderr = io.StringIO()

            with (
                patch(
                    "firmware_manifest.load_manifest",
                    return_value={
                        "schema_version": 1,
                        "artifacts": [first, second],
                    },
                ),
                patch("firmware_manifest.verify_manifest_entry") as verify,
                contextlib.redirect_stderr(stderr),
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

        self.assertEqual(result, 1)
        self.assertEqual(verify.call_count, 2)
        self.assertIn("exactly one matching entry", stderr.getvalue())

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

class FirmwareStructureCliTests(unittest.TestCase):
    def test_map_writes_bounded_report_and_prints_safe_summary(self):
        entry = {"source_key": "fixture", "filename": "BODYDATA.DAT"}
        report = {
            "source_key": "fixture",
            "size": 64,
            "sha256": "a" * 64,
            "format": "sony-dat",
            "dat_chunks": [{"kind": "FDAT"}],
            "unknown_ranges": [],
        }
        artifact = Path(".artifacts/analysis-inputs/fixture/BODYDATA.DAT")
        artifacts_root = Path(".artifacts")
        manifest = Path("analysis/firmware-manifest.json")
        output = Path("analysis/structures/fixture.json")
        stdout = io.StringIO()

        with (
            patch(
                "firmware_structure.load_manifest",
                return_value={"schema_version": 1, "artifacts": [entry]},
            ) as load,
            patch(
                "firmware_structure.build_structure_report",
                return_value=report,
            ) as build,
            patch("firmware_structure.write_structure_report") as write,
            contextlib.redirect_stdout(stdout),
        ):
            result = firmware_structure.main(
                [
                    "map",
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
        load.assert_called_once_with(manifest)
        build.assert_called_once_with(entry, artifact, artifacts_root)
        write.assert_called_once_with(output, report, artifacts_root)
        self.assertEqual(
            stdout.getvalue(),
            "source=fixture size=64 "
            f"sha256={'a' * 64} format=sony-dat "
            f"chunks=1 unknown=0 report={output}\n",
        )

    def test_only_map_and_exact_options_are_available(self):
        for subcommand in ("extract", "decrypt", "patch", "usb", "camera"):
            with self.subTest(subcommand=subcommand):
                with (
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit),
                ):
                    firmware_structure.main([subcommand])

        required = [
            "map",
            "--source",
            "fixture",
            "--file",
            "BODYDATA.DAT",
            "--artifacts-root",
            ".artifacts",
            "--manifest",
            "manifest.json",
            "--report",
            "report.json",
        ]
        for option in (
            "--extract",
            "--decrypt",
            "--patch",
            "--usb",
            "--camera",
            "--token",
            "--output-bytes",
        ):
            with self.subTest(option=option):
                with (
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit),
                ):
                    firmware_structure.main(required + [option, "override"])

        abbreviated = list(required)
        abbreviated[abbreviated.index("--artifacts-root")] = "--art"
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            firmware_structure.main(abbreviated)

    def test_expected_validation_error_is_one_line_without_traceback(self):
        stderr = io.StringIO()
        with (
            patch(
                "firmware_structure.load_manifest",
                side_effect=firmware_structure.StructureError("fixture rejected"),
            ),
            contextlib.redirect_stderr(stderr),
        ):
            result = firmware_structure.main(
                [
                    "map",
                    "--source",
                    "fixture",
                    "--file",
                    "BODYDATA.DAT",
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


class FirmwareDecisionsCliTests(unittest.TestCase):
    def test_render_reads_validated_evidence_and_writes_deterministic_markdown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "feature-evidence.json"
            output = root / "report.md"
            evidence.write_text(
                json.dumps(synthetic_document()), encoding="utf-8"
            )

            result = firmware_decisions.main(
                [
                    "render",
                    "--evidence",
                    str(evidence),
                    "--output",
                    str(output),
                ]
            )

            self.assertEqual(result, 0)
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                firmware_decisions.render_markdown(synthetic_document()),
            )

    def test_only_render_and_exact_options_are_available(self):
        for subcommand in ("camera", "package", "patch", "flash", "download"):
            with self.subTest(subcommand=subcommand):
                with (
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit),
                ):
                    firmware_decisions.main([subcommand])
        required = [
            "render",
            "--evidence",
            "evidence.json",
            "--output",
            "report.md",
        ]
        for option in (
            "--camera",
            "--package",
            "--patch",
            "--executable",
            "--shell",
            "--url",
            "--status",
            "--usb",
        ):
            with self.subTest(option=option):
                with (
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit),
                ):
                    firmware_decisions.main(required + [option, "override"])
        abbreviated = list(required)
        abbreviated[abbreviated.index("--evidence")] = "--evid"
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            firmware_decisions.main(abbreviated)

    def test_oversized_evidence_is_rejected_before_json_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "oversized.json"
            output = root / "report.md"
            evidence.write_bytes(b"{" + (b" " * 2_000_000))
            stderr = io.StringIO()

            with contextlib.redirect_stderr(stderr):
                result = firmware_decisions.main(
                    [
                        "render",
                        "--evidence",
                        str(evidence),
                        "--output",
                        str(output),
                    ]
                )

        self.assertEqual(result, 1)
        self.assertIn("exceeds", stderr.getvalue())
        self.assertNotIn("JSON", stderr.getvalue())
        self.assertFalse(output.exists())

    def test_expected_input_errors_are_one_line_without_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "invalid.json"
            output = root / "report.md"
            evidence.write_text("{}", encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                result = firmware_decisions.main(
                    [
                        "render",
                        "--evidence",
                        str(evidence),
                        "--output",
                        str(output),
                    ]
                )
        self.assertEqual(result, 1)
        self.assertEqual(
            stderr.getvalue(),
            "error: Evidence document does not match schema version 1\n",
        )
        self.assertNotIn("Traceback", stderr.getvalue())
        self.assertFalse(output.exists())

class FirmwareLabCliTests(unittest.TestCase):
    def test_run_writes_only_fixed_offline_matrix_summary(self):
        document = {
            "experiments": [{}] * 8,
            "installable": False,
        }
        stdout = io.StringIO()
        with (
            patch("firmware_lab.run_experiment_matrix", return_value=document) as run,
            patch("firmware_lab.write_experiment_report") as write,
            contextlib.redirect_stdout(stdout),
        ):
            result = firmware_lab.main(
                [
                    "run",
                    "--python",
                    "python.exe",
                    "--checkout",
                    ".artifacts/tools/ma1co-fwtool",
                    "--artifacts-root",
                    ".artifacts",
                    "--manifest",
                    "analysis/firmware-manifest.json",
                    "--baseline-report",
                    "analysis/tool-baselines/ma1co-fwtool.json",
                    "--a6400-file",
                    ".artifacts/analysis-inputs/a6400/Update.exe",
                    "--a6700-file",
                    ".artifacts/analysis-inputs/a6700/BODYDATA.DAT",
                    "--a7v-file",
                    ".artifacts/analysis-inputs/a7v/BODYDATA.DAT",
                    "--tool-output-root",
                    ".artifacts/tool-output/signature-experiments",
                    "--report",
                    "analysis/signature-experiments.json",
                ]
            )

        self.assertEqual(result, 0)
        run.assert_called_once()
        write.assert_called_once()
        self.assertEqual(
            stdout.getvalue(),
            "experiments=8 installable=false camera=false\n",
        )

    def test_only_run_subcommand_is_accepted(self):
        for subcommand in ("flash", "camera", "install", "decrypt"):
            with self.subTest(subcommand=subcommand):
                with (
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit),
                ):
                    firmware_lab.main([subcommand])


class CreativeLookRecipesCliTests(unittest.TestCase):
    def test_render_calls_validated_renderer_and_prints_safe_counts(self):
        document = {"defaults": [{}] * 10, "community_experiments": [{}, {}]}
        stdout = io.StringIO()
        with (
            patch("creative_look_recipes._load", return_value=document) as load,
            patch("creative_look_recipes.render_recipe_guide", return_value="guide") as render,
            patch("creative_look_recipes._write") as write,
            contextlib.redirect_stdout(stdout),
        ):
            result = creative_look_recipes.main(
                [
                    "render",
                    "--recipes",
                    "analysis/creative-look-recipes.json",
                    "--output",
                    "analysis/a6400-creative-look-guide.md",
                ]
            )

        self.assertEqual(result, 0)
        load.assert_called_once()
        render.assert_called_once_with(document)
        write.assert_called_once()
        self.assertEqual(stdout.getvalue(), "looks=10 community=2\n")


if __name__ == "__main__":
    unittest.main()
