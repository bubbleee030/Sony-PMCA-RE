import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pmca.analysis.tooling import (
    ToolError,
    ToolSpec,
    run_quarantined_unpack_baseline,
)


class QuarantinedToolingTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.artifacts = self.root / ".artifacts"
        self.checkout = self.artifacts / "tools" / "fixture"
        self.input_path = (
            self.artifacts / "quarantine" / "fixture_NOT_FOR_INSTALL.bin"
        )
        self.output_dir = self.artifacts / "tool-output" / "quarantine-fixture"
        self.checkout.mkdir(parents=True)
        self.input_path.parent.mkdir(parents=True)
        self.input_path.write_bytes(b"mutated")
        (self.checkout / "tool.py").write_text(
            "raise SystemExit(0)\n", encoding="utf-8"
        )
        self.spec = ToolSpec(
            "fixture-tool",
            "https://github.com/example/fixture.git",
            "a" * 40,
            "tool.py",
        )
        self.sidecar = {
            "schema_version": 1,
            "hypothesis_id": "fixture-hypothesis",
            "parent_sha256": "0" * 64,
            "output_sha256": hashlib.sha256(b"mutated").hexdigest(),
            "installable": False,
            "patches": [
                {
                    "offset": 0,
                    "size": 1,
                    "preimage_sha256": "1" * 64,
                    "replacement_sha256": "2" * 64,
                }
            ],
        }
        self._write_sidecar(self.sidecar)

    def _write_sidecar(self, document):
        self.input_path.with_suffix(self.input_path.suffix + ".json").write_text(
            json.dumps(document), encoding="utf-8"
        )

    def test_runner_accepts_only_digest_matched_non_installable_quarantine(self):
        completed = subprocess.CompletedProcess([], 1, "No decrypter found", "")
        with patch("pmca.analysis.tooling.subprocess.run", return_value=completed):
            result = run_quarantined_unpack_baseline(
                self.spec,
                Path(sys.executable),
                self.checkout,
                self.input_path,
                self.output_dir,
            )

        self.assertEqual(result["input_sha256"], self.sidecar["output_sha256"])
        self.assertEqual(result["stage"], "decrypter-selection")

    def test_missing_tampered_or_installable_sidecar_is_rejected(self):
        sidecar_path = self.input_path.with_suffix(self.input_path.suffix + ".json")
        sidecar_path.unlink()
        invalid = (None, {**self.sidecar, "installable": True}, {
            **self.sidecar,
            "output_sha256": "f" * 64,
        })
        for document in invalid:
            with self.subTest(document=document):
                if document is None:
                    sidecar_path.unlink(missing_ok=True)
                else:
                    self._write_sidecar(document)
                with self.assertRaises(ToolError):
                    run_quarantined_unpack_baseline(
                        self.spec,
                        Path(sys.executable),
                        self.checkout,
                        self.input_path,
                        self.output_dir,
                    )


if __name__ == "__main__":
    unittest.main()
