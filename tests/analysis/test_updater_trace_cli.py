import json
import tempfile
import unittest
from pathlib import Path

from updater_trace import write_trace_report
from pmca.analysis.updater_trace import (
    build_no_camera_run,
    build_reproduced_trace_report,
)


class UpdaterTraceCliTests(unittest.TestCase):
    def test_writer_uses_only_the_fixed_repository_report_path(self):
        observation = {
            "updater_sha256": "e" * 64,
            "sandbox_policy_sha256": "a" * 64,
            "camera_present": False,
            "sandboxed": True,
            "elevated": False,
            "network_blocked": True,
            "launched": True,
            "termination": "exited",
            "exit_code": 2,
            "process_roles": ["updater"],
        }
        run = build_no_camera_run([], observation)
        report = build_reproduced_trace_report((run, run))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "analysis").mkdir()

            output = write_trace_report(root, report)

            self.assertEqual(
                output,
                root / "analysis" / "a6400-updater-no-camera.json",
            )
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), report)


if __name__ == "__main__":
    unittest.main()
