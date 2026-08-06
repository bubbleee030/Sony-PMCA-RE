import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pmca.analysis.tooling import ToolError, ToolSpec, run_unpack_baseline


class ToolingSymlinkTests(unittest.TestCase):
    def test_symlink_checkout_is_rejected_before_process_start(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifacts = root / ".artifacts"
            real_checkout = artifacts / "tools" / "real"
            linked_checkout = artifacts / "tools" / "linked"
            input_path = artifacts / "analysis-inputs" / "fixture" / "input.dat"
            output_dir = artifacts / "tool-output" / "fixture"
            real_checkout.mkdir(parents=True)
            (real_checkout / "tool.py").write_text("raise SystemExit(0)\n")
            input_path.parent.mkdir(parents=True)
            input_path.write_bytes(b"firmware")
            try:
                linked_checkout.symlink_to(real_checkout, target_is_directory=True)
            except (NotImplementedError, OSError) as error:
                self.skipTest(f"Symlink creation is unavailable: {error}")
            spec = ToolSpec(
                "fixture",
                "https://github.com/example/fixture.git",
                "a" * 40,
                "tool.py",
            )

            with patch("pmca.analysis.tooling.subprocess.run") as run:
                with self.assertRaises(ToolError):
                    run_unpack_baseline(
                        spec,
                        Path(sys.executable),
                        linked_checkout,
                        input_path,
                        output_dir,
                    )
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
