import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pmca.analysis.tooling import (
    ToolError,
    ToolSpec,
    run_unpack_baseline,
    validate_tool_spec,
)


class ToolingTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.artifacts = self.root / ".artifacts"
        self.checkout = self.artifacts / "tools" / "fixture"
        self.input_path = (
            self.artifacts / "analysis-inputs" / "fixture" / "BODYDATA.DAT"
        )
        self.output_dir = self.artifacts / "tool-output" / "fixture"
        self.checkout.mkdir(parents=True)
        self.input_path.parent.mkdir(parents=True)
        self.input_path.write_bytes(b"firmware")
        self.spec = ToolSpec(
            name="fixture-tool",
            repo_url="https://github.com/example/fixture.git",
            commit="a" * 40,
            entrypoint="tool.py",
        )

    def _write_tool(self, body: str) -> None:
        (self.checkout / "tool.py").write_text(body, encoding="utf-8")

    def test_provenance_fields_are_exactly_validated(self):
        self.assertIs(validate_tool_spec(self.spec), self.spec)

        invalid = (
            ToolSpec("bad", "http://github.com/example/x", "a" * 40, "tool.py"),
            ToolSpec("bad", "https://example.com/x", "a" * 40, "tool.py"),
            ToolSpec("bad", "https://github.com/example/x", "A" * 40, "tool.py"),
            ToolSpec("bad", "https://github.com/example/x", "a" * 39, "tool.py"),
            ToolSpec("bad", "https://github.com/example/x", "a" * 40, "../tool.py"),
            ToolSpec("bad", "https://github.com/example/x", "a" * 40, "/tool.py"),
        )
        for spec in invalid:
            with self.subTest(spec=spec):
                with self.assertRaises(ToolError):
                    validate_tool_spec(spec)

    def test_runner_uses_exact_argv_without_a_shell(self):
        self._write_tool("raise SystemExit(0)\n")
        completed = subprocess.CompletedProcess([], 3, "No decrypter found\n", "")

        with patch("pmca.analysis.tooling.subprocess.run", return_value=completed) as run:
            result = run_unpack_baseline(
                self.spec,
                Path(sys.executable),
                self.checkout,
                self.input_path,
                self.output_dir,
            )

        command = [
            sys.executable,
            str(self.checkout / "tool.py"),
            "unpack",
            "-f",
            str(self.input_path),
            "-o",
            str(self.output_dir),
        ]
        self.assertEqual(run.call_args.args[0], command)
        self.assertIs(run.call_args.kwargs["shell"], False)
        self.assertEqual(result["stage"], "decrypter-selection")
        self.assertEqual(result["error_class"], "no-decrypter")
        self.assertNotIn("BODYDATA", result["safe_summary"])

    def test_synthetic_tool_exit_and_marker_are_normalized(self):
        self._write_tool(
            "import pathlib, sys\n"
            "out = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])\n"
            "out.mkdir(parents=True, exist_ok=True)\n"
            "(out / 'marker.txt').write_text('harmless', encoding='utf-8')\n"
            "print('No decrypter found')\n"
            "raise SystemExit(3)\n"
        )

        result = run_unpack_baseline(
            self.spec,
            Path(sys.executable),
            self.checkout,
            self.input_path,
            self.output_dir,
        )

        self.assertEqual(
            set(result),
            {
                "tool",
                "commit",
                "input_sha256",
                "exit_code",
                "timed_out",
                "stage",
                "error_class",
                "safe_summary",
            },
        )
        self.assertEqual(result["exit_code"], 3)
        self.assertFalse(result["timed_out"])
        self.assertEqual(result["input_sha256"], hashlib.sha256(b"firmware").hexdigest())
        self.assertEqual(result["safe_summary"], "tool reported no compatible decrypter")
        self.assertEqual((self.output_dir / "marker.txt").read_text(), "harmless")

    def test_paths_outside_required_artifact_subtrees_are_rejected(self):
        outside = self.root / "outside"
        outside.mkdir()
        cases = (
            (outside, self.input_path, self.output_dir),
            (self.checkout, outside / "BODYDATA.DAT", self.output_dir),
            (self.checkout, self.input_path, outside / "output"),
        )
        for checkout, input_path, output_dir in cases:
            with self.subTest(checkout=checkout, input=input_path, output=output_dir):
                with self.assertRaises(ToolError):
                    run_unpack_baseline(
                        self.spec,
                        Path(sys.executable),
                        checkout,
                        input_path,
                        output_dir,
                    )

    def test_timeout_is_normalized_and_process_is_terminated(self):
        self._write_tool("import time\ntime.sleep(5)\n")

        result = run_unpack_baseline(
            self.spec,
            Path(sys.executable),
            self.checkout,
            self.input_path,
            self.output_dir,
            timeout_seconds=1,
        )

        self.assertTrue(result["timed_out"])
        self.assertIsNone(result["exit_code"])
        self.assertEqual(result["stage"], "process")
        self.assertEqual(result["error_class"], "timeout")
        self.assertEqual(result["safe_summary"], "tool exceeded the finite timeout")


if __name__ == "__main__":
    unittest.main()
