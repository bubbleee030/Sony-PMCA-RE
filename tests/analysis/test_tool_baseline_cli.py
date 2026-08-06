import contextlib
import io
import unittest
from unittest.mock import patch

import firmware_tool_baseline


class FirmwareToolBaselineCliTests(unittest.TestCase):
    def test_matrix_writes_only_normalized_report(self):
        document = {
            "schema_version": 1,
            "tool": "ma1co-fwtool",
            "commit": "a" * 40,
            "results": [],
        }
        stdout = io.StringIO()
        with (
            patch("firmware_tool_baseline.run_matrix", return_value=document) as run,
            patch("firmware_tool_baseline.write_baseline_report") as write,
            contextlib.redirect_stdout(stdout),
        ):
            result = firmware_tool_baseline.main(
                [
                    "matrix",
                    "--tool",
                    "ma1co-fwtool",
                    "--python",
                    "python.exe",
                    "--checkout",
                    ".artifacts/tools/ma1co-fwtool",
                    "--artifacts-root",
                    ".artifacts",
                    "--manifest",
                    "analysis/firmware-manifest.json",
                    "--a6400-file",
                    ".artifacts/analysis-inputs/a6400/BODY.exe",
                    "--a6700-file",
                    ".artifacts/analysis-inputs/a6700/BODYDATA.DAT",
                    "--a7v-file",
                    ".artifacts/analysis-inputs/a7v/BODYDATA.DAT",
                    "--output-root",
                    ".artifacts/tool-output/run1/ma1co-fwtool",
                    "--report",
                    "analysis/tool-baselines/ma1co-fwtool.json",
                ]
            )

        self.assertEqual(result, 0)
        self.assertEqual(run.call_count, 1)
        write.assert_called_once()
        self.assertEqual(stdout.getvalue(), "tool=ma1co-fwtool results=0\n")

    def test_only_matrix_and_exact_options_are_accepted(self):
        for subcommand in ("install", "clone", "download", "camera", "flash"):
            with self.subTest(subcommand=subcommand):
                with (
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit),
                ):
                    firmware_tool_baseline.main([subcommand])


if __name__ == "__main__":
    unittest.main()
