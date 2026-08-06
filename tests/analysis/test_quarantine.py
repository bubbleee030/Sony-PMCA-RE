import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from pmca.analysis.quarantine import (
    Patch,
    QuarantineError,
    apply_quarantined_patches,
)


class QuarantinePatchTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.artifacts = self.root / ".artifacts"
        self.source = self.artifacts / "analysis-inputs" / "fixture" / "input.bin"
        self.output = (
            self.artifacts / "quarantine" / "fixture_NOT_FOR_INSTALL.bin"
        )
        self.source.parent.mkdir(parents=True)
        self.source.write_bytes(b"0123456789abcdef")

    def _patch(self, offset=4, preimage=b"45", replacement=b"XY"):
        return Patch(offset, hashlib.sha256(preimage).hexdigest(), replacement)

    def test_success_changes_only_requested_bytes_and_preserves_source(self):
        before = hashlib.sha256(self.source.read_bytes()).hexdigest()

        sidecar = apply_quarantined_patches(
            self.source,
            self.artifacts,
            self.output,
            (self._patch(),),
            "synthetic-change",
        )

        self.assertEqual(self.source.read_bytes(), b"0123456789abcdef")
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(), before)
        self.assertEqual(self.output.read_bytes(), b"0123XY6789abcdef")
        self.assertFalse(sidecar["installable"])
        self.assertEqual(sidecar["parent_sha256"], before)

    def test_wrong_paths_and_missing_warning_name_are_rejected(self):
        outside = self.root / "outside.bin"
        outside.write_bytes(self.source.read_bytes())
        original = self.artifacts / "sony-firmware" / "fixture" / "input.bin"
        original.parent.mkdir(parents=True)
        original.write_bytes(self.source.read_bytes())
        invalid = (
            (outside, self.output),
            (original, self.output),
            (self.source, self.root / "outside_NOT_FOR_INSTALL.bin"),
            (self.source, self.artifacts / "quarantine" / "candidate.bin"),
        )
        for source, output in invalid:
            with self.subTest(source=source, output=output):
                with self.assertRaises(QuarantineError):
                    apply_quarantined_patches(
                        source,
                        self.artifacts,
                        output,
                        (self._patch(),),
                        "invalid-path",
                    )

    def test_overlap_wrong_preimage_and_out_of_range_are_rejected(self):
        invalid_patch_sets = (
            (self._patch(4, b"45", b"XY"), self._patch(5, b"56", b"ZZ")),
            (Patch(4, "0" * 64, b"XY"),),
            (self._patch(15, b"f", b"XY"),),
        )
        for patches in invalid_patch_sets:
            with self.subTest(patches=patches):
                with self.assertRaises(QuarantineError):
                    apply_quarantined_patches(
                        self.source,
                        self.artifacts,
                        self.output,
                        patches,
                        "invalid-patch",
                    )
                self.assertFalse(self.output.exists())

    def test_duplicate_hypothesis_id_is_rejected(self):
        apply_quarantined_patches(
            self.source,
            self.artifacts,
            self.output,
            (self._patch(),),
            "duplicate-id",
        )
        second = self.artifacts / "quarantine" / "second_NOT_FOR_INSTALL.bin"

        with self.assertRaises(QuarantineError):
            apply_quarantined_patches(
                self.source,
                self.artifacts,
                second,
                (self._patch(),),
                "duplicate-id",
            )

    def test_sidecar_contains_hashes_not_replacement_bytes(self):
        patch = self._patch(4, b"456789", b"SECRET")
        sidecar = apply_quarantined_patches(
            self.source,
            self.artifacts,
            self.output,
            (patch,),
            "sidecar-safety",
        )
        serialized = json.dumps(sidecar)

        self.assertNotIn("SECRET", serialized)
        self.assertNotIn("replacement", serialized.replace("replacement_sha256", ""))
        self.assertEqual(sidecar["patches"][0]["size"], 6)

    def test_symlink_source_is_rejected(self):
        linked = self.artifacts / "analysis-inputs" / "fixture" / "linked.bin"
        try:
            linked.symlink_to(self.source)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"Symlink creation is unavailable: {error}")

        with self.assertRaises(QuarantineError):
            apply_quarantined_patches(
                linked,
                self.artifacts,
                self.output,
                (self._patch(),),
                "symlink-source",
            )


if __name__ == "__main__":
    unittest.main()
