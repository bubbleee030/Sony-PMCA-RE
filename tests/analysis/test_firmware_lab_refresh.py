import unittest
from pathlib import Path
from unittest.mock import patch

from firmware_lab import refresh_experiment_tool_results
from pmca.analysis.tooling import TOOL_SPECS
from tests.analysis.test_firmware_lab import synthetic_report


class FirmwareLabRefreshTests(unittest.TestCase):
    def test_refresh_reclassifies_existing_quarantine_without_mutating_it(self):
        document = synthetic_report()
        commit = TOOL_SPECS["ma1co-fwtool"].commit
        document["commit"] = commit
        for item in document["experiments"]:
            item["historical_tool_before"]["commit"] = commit
            item["historical_tool_after"]["commit"] = commit

        outputs = iter(item["output_sha256"] for item in document["experiments"])

        def result(*_args, **_kwargs):
            return {
                "tool": "ma1co-fwtool",
                "commit": commit,
                "input_sha256": next(outputs),
                "exit_code": 1,
                "timed_out": False,
                "stage": "dat-parsing",
                "error_class": "checksum-mismatch",
                "safe_summary": "tool rejected the DAT checksum",
            }

        with patch(
            "firmware_lab.run_quarantined_unpack_baseline",
            side_effect=result,
        ) as run:
            refreshed = refresh_experiment_tool_results(
                document,
                Path("python.exe"),
                Path(".artifacts/tools/ma1co-fwtool"),
                Path(".artifacts"),
                Path(".artifacts/tool-output/refresh"),
            )

        self.assertEqual(run.call_count, 8)
        self.assertTrue(
            all(
                item["historical_tool_after"]["stage"] == "dat-parsing"
                for item in refreshed["experiments"]
            )
        )
        self.assertTrue(
            all(
                item["discrimination"] == "candidate-stage-shift"
                for item in refreshed["experiments"]
            )
        )


if __name__ == "__main__":
    unittest.main()
