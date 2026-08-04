import hashlib
import tempfile
import unittest
from pathlib import Path

from pmca.analysis.candidates import CandidateSpec, build_candidate


class UnresolvedCandidateTests(unittest.TestCase):
    def test_unresolved_real_candidate_needs_no_guessed_patch(self):
        with tempfile.TemporaryDirectory() as directory:
            artifacts = Path(directory) / ".artifacts"
            source = artifacts / "analysis-inputs" / "fixture" / "input.bin"
            output = artifacts / "quarantine" / "ui_NOT_FOR_INSTALL.bin"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"authenticated fixture")
            spec = CandidateSpec(
                "a6400-ui-port",
                hashlib.sha256(source.read_bytes()).hexdigest(),
                (),
                ("vertical-layout-selection", "signature-layer"),
            )

            result = build_candidate(spec, source, artifacts, output)

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["reason_codes"], ["unresolved-dependencies"])
        self.assertEqual(
            result["unresolved_dependencies"],
            ["vertical-layout-selection", "signature-layer"],
        )


if __name__ == "__main__":
    unittest.main()
