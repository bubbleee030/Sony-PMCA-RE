import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pmca.analysis.tooling import ToolSpec, run_unpack_baseline


class ToolDiagnosticClassificationTests(unittest.TestCase):
    def test_dat_integrity_diagnostics_are_exactly_classified(self):
        cases = (
            ("Wrong data version", "wrong-data-version"),
            ("'NoneType' object has no attribute 'mode'", "invalid-device-descriptor"),
            ("Wrong checksum", "checksum-mismatch"),
        )
        for index, (message, error_class) in enumerate(cases):
            with self.subTest(message=message), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / ".artifacts"
                checkout = root / "tools" / "fixture"
                source = root / "analysis-inputs" / "fixture" / "input.dat"
                output = root / "tool-output" / f"case-{index}"
                checkout.mkdir(parents=True)
                source.parent.mkdir(parents=True)
                (checkout / "tool.py").write_text("", encoding="utf-8")
                source.write_bytes(b"fixture")
                spec = ToolSpec(
                    "fixture",
                    "https://github.com/example/fixture.git",
                    "a" * 40,
                    "tool.py",
                )
                completed = subprocess.CompletedProcess([], 1, "", message)
                with patch(
                    "pmca.analysis.tooling.subprocess.run",
                    return_value=completed,
                ):
                    result = run_unpack_baseline(
                        spec,
                        Path(sys.executable),
                        checkout,
                        source,
                        output,
                    )

                self.assertEqual(result["stage"], "dat-parsing")
                self.assertEqual(result["error_class"], error_class)


if __name__ == "__main__":
    unittest.main()
