import hashlib
import tempfile
import unittest
from pathlib import Path

from pmca.analysis.candidates import CandidateSpec, build_candidate
from pmca.analysis.quarantine import Patch


class CandidateBuilderTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.artifacts = self.root / ".artifacts"
        self.source = (
            self.artifacts / "analysis-inputs" / "synthetic" / "input.bin"
        )
        self.output = (
            self.artifacts
            / "quarantine"
            / "synthetic-candidate_NOT_FOR_INSTALL.bin"
        )
        self.source.parent.mkdir(parents=True)
        self.source.write_bytes(b"0123456789abcdef")
        self.parent_digest = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.patch = Patch(
            4,
            hashlib.sha256(b"45").hexdigest(),
            b"XY",
        )

    def _spec(self, **changes):
        values = {
            "source_key": "synthetic",
            "parent_sha256": self.parent_digest,
            "patches": (self.patch,),
            "unresolved_dependencies": (),
        }
        values.update(changes)
        return CandidateSpec(**values)

    def test_dependency_complete_synthetic_candidate_is_quarantined(self):
        result = build_candidate(
            self._spec(),
            self.source,
            self.artifacts,
            self.output,
        )

        self.assertEqual(result["status"], "built-quarantined")
        self.assertFalse(result["installable"])
        self.assertEqual(result["source_key"], "synthetic")
        self.assertTrue(self.output.exists())
        self.assertEqual(self.output.read_bytes(), b"0123XY6789abcdef")

    def test_parent_digest_mismatch_is_structured_rejection(self):
        result = build_candidate(
            self._spec(parent_sha256="0" * 64),
            self.source,
            self.artifacts,
            self.output,
        )

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["reason_codes"], ["parent-digest-mismatch"])
        self.assertFalse(result["installable"])
        self.assertFalse(self.output.exists())

    def test_unresolved_dependencies_include_unknown_range_evidence(self):
        unresolved = (
            "architecture-compatibility",
            "evidence-for-unknown-range",
        )
        result = build_candidate(
            self._spec(unresolved_dependencies=unresolved),
            self.source,
            self.artifacts,
            self.output,
        )

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["reason_codes"], ["unresolved-dependencies"])
        self.assertEqual(result["unresolved_dependencies"], list(unresolved))
        self.assertFalse(self.output.exists())

    def test_wrong_preimage_is_structured_rejection(self):
        result = build_candidate(
            self._spec(patches=(Patch(4, "0" * 64, b"XY"),)),
            self.source,
            self.artifacts,
            self.output,
        )

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["reason_codes"], ["quarantine-gate-rejected"])
        self.assertFalse(self.output.exists())

    def test_unsafe_output_is_structured_rejection(self):
        unsafe = self.root / "candidate.bin"
        result = build_candidate(
            self._spec(),
            self.source,
            self.artifacts,
            unsafe,
        )

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["reason_codes"], ["quarantine-gate-rejected"])
        self.assertFalse(unsafe.exists())

    def test_invalid_or_duplicate_dependencies_are_rejected(self):
        for dependencies in (("",), ("same", "same")):
            with self.subTest(dependencies=dependencies):
                result = build_candidate(
                    self._spec(unresolved_dependencies=dependencies),
                    self.source,
                    self.artifacts,
                    self.output,
                )
                self.assertEqual(result["status"], "rejected")
                self.assertEqual(result["reason_codes"], ["invalid-specification"])


if __name__ == "__main__":
    unittest.main()
