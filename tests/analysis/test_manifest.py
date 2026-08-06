import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pmca.analysis.manifest import (
    ManifestError,
    load_manifest,
    record_artifact,
    verify_manifest_entry,
    write_manifest,
)
from pmca.analysis.sources import SourceError, SourceSpec


ACQUIRED_AT = "2026-08-04T00:00:00Z"
FIRMWARE = b"firmware"
SOURCE = SourceSpec(
    model="ILCE-FIXTURE",
    region="TW",
    version="2.00",
    filename="fixture.bin",
    advertised_size=len(FIRMWARE),
    release_date="2026-08-04",
    page_url="https://www.sony.com.tw/fixture",
)


def get_fixture_source(key):
    if key == "fixture":
        return SOURCE
    raise SourceError("Firmware source is not allowlisted")


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.workspace = Path(self.temporary_directory.name)
        self.artifacts_root = self.workspace / ".artifacts"
        self.artifacts_root.mkdir()
        self.artifact = self.artifacts_root / SOURCE.filename
        self.artifact.write_bytes(FIRMWARE)
        self.source_patch = patch(
            "pmca.analysis.manifest.get_source", side_effect=get_fixture_source
        )
        self.source_patch.start()
        self.addCleanup(self.source_patch.stop)

    def _record(self, artifact=None, artifacts_root=None):
        return record_artifact(
            "fixture",
            artifact or self.artifact,
            artifacts_root or self.artifacts_root,
            ACQUIRED_AT,
        )

    def _make_symlink(self, link, target, target_is_directory=False):
        try:
            link.symlink_to(target, target_is_directory=target_is_directory)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"Symlink creation is unavailable: {error}")

    def test_record_artifact_rejects_root_not_named_artifacts(self):
        untrusted_root = self.workspace / "firmware"
        untrusted_root.mkdir()
        artifact = untrusted_root / SOURCE.filename
        artifact.write_bytes(FIRMWARE)

        with self.assertRaises(ManifestError):
            self._record(artifact=artifact, artifacts_root=untrusted_root)
    def test_record_artifact_rejects_outside_root(self):
        outside_file = self.workspace / SOURCE.filename
        outside_file.write_bytes(FIRMWARE)

        with self.assertRaises(ManifestError):
            self._record(artifact=outside_file)

    def test_record_artifact_rejects_symlink(self):
        real_artifact = self.artifacts_root / "real" / SOURCE.filename
        real_artifact.parent.mkdir()
        real_artifact.write_bytes(FIRMWARE)
        linked_file = self.artifacts_root / "linked" / SOURCE.filename
        linked_file.parent.mkdir()
        self._make_symlink(linked_file, real_artifact)

        with self.assertRaises(ManifestError):
            self._record(artifact=linked_file)

    def test_record_artifact_rejects_symlink_root(self):
        real_root = self.workspace / "real-artifacts"
        real_root.mkdir()
        (real_root / SOURCE.filename).write_bytes(FIRMWARE)
        linked_root = self.workspace / "symlink-case" / ".artifacts"
        linked_root.parent.mkdir()
        self._make_symlink(linked_root, real_root, target_is_directory=True)

        with self.assertRaises(ManifestError):
            self._record(
                artifact=linked_root / SOURCE.filename,
                artifacts_root=linked_root,
            )

    def test_record_artifact_rejects_wrong_filename_and_size(self):
        wrong_name = self.artifacts_root / "wrong-name.bin"
        wrong_name.write_bytes(FIRMWARE)
        wrong_size = self.artifacts_root / "wrong-size" / SOURCE.filename
        wrong_size.parent.mkdir()
        wrong_size.write_bytes(b"short")

        for candidate in (wrong_name, wrong_size):
            with self.subTest(candidate=candidate):
                with self.assertRaises(ManifestError):
                    self._record(artifact=candidate)

    def test_record_artifact_rejects_invalid_acquired_at(self):
        invalid_timestamps = (
            "2026-08-04T00:00:00",
            "not-a-timestamp",
            "2026-08-04T00:00:00Z\nforged",
            "x" * 65,
        )

        for acquired_at in invalid_timestamps:
            with self.subTest(acquired_at=acquired_at):
                with self.assertRaises(ManifestError):
                    record_artifact(
                        "fixture",
                        self.artifact,
                        self.artifacts_root,
                        acquired_at,
                    )
    def test_record_and_verify_round_trip(self):
        entry = self._record()

        self.assertEqual(
            set(entry),
            {
                "source_key",
                "manufacturer",
                "model",
                "region",
                "version",
                "source_page",
                "filename",
                "advertised_size",
                "release_date",
                "measured_size",
                "sha256",
                "acquired_at",
            },
        )
        self.assertEqual(entry["source_key"], "fixture")
        self.assertEqual(entry["sha256"], hashlib.sha256(FIRMWARE).hexdigest())
        verify_manifest_entry(entry, self.artifact, self.artifacts_root)

    def test_verify_rejects_changed_bytes(self):
        entry = self._record()
        self.artifact.write_bytes(b"changed!")

        with self.assertRaises(ManifestError):
            verify_manifest_entry(entry, self.artifact, self.artifacts_root)

    def test_verify_rejects_manifest_metadata_override(self):
        entry = self._record()

        for field, value in (
            ("manufacturer", "Not Sony"),
            ("model", "ILCE-OTHER"),
            ("region", "US"),
            ("version", "9.99"),
            ("source_page", "https://example.invalid/firmware"),
            ("advertised_size", 1),
            ("release_date", "1999-01-01"),
        ):
            with self.subTest(field=field):
                changed_entry = dict(entry)
                changed_entry[field] = value
                with self.assertRaises(ManifestError):
                    verify_manifest_entry(
                        changed_entry, self.artifact, self.artifacts_root
                    )

    def test_write_and_load_manifest_are_deterministic(self):
        manifest_path = self.workspace / "analysis" / "firmware-manifest.json"
        manifest = {"artifacts": [self._record()], "schema_version": 1}

        write_manifest(manifest_path, manifest)
        first_bytes = manifest_path.read_bytes()
        write_manifest(manifest_path, manifest)

        expected = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode(
            "utf-8"
        )
        self.assertEqual(first_bytes, expected)
        self.assertEqual(manifest_path.read_bytes(), expected)
        self.assertEqual(load_manifest(manifest_path), manifest)

    def test_load_manifest_rejects_invalid_schema_and_duplicate_sources(self):
        entry = self._record()
        invalid_documents = (
            {"schema_version": 2, "artifacts": []},
            {"schema_version": 1, "artifacts": [], "extra": True},
            {"schema_version": 1},
            {
                "schema_version": 1,
                "artifacts": [entry, dict(entry)],
            },
        )

        for index, document in enumerate(invalid_documents):
            with self.subTest(document=document):
                path = self.workspace / f"invalid-{index}.json"
                path.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaises(ManifestError):
                    load_manifest(path)

    def test_load_manifest_rejects_unknown_or_tampered_source_metadata(self):
        entry = self._record()
        invalid_entries = []
        unknown = dict(entry)
        unknown["source_key"] = "unknown"
        invalid_entries.append(unknown)
        tampered = dict(entry)
        tampered["model"] = "ILCE-TAMPERED"
        invalid_entries.append(tampered)

        for index, invalid_entry in enumerate(invalid_entries):
            with self.subTest(entry=invalid_entry):
                path = self.workspace / f"invalid-source-{index}.json"
                path.write_text(
                    json.dumps({"schema_version": 1, "artifacts": [invalid_entry]}),
                    encoding="utf-8",
                )
                with self.assertRaises((ManifestError, SourceError)):
                    load_manifest(path)

    def test_load_manifest_rejects_duplicate_json_members(self):
        path = self.workspace / "duplicate-members.json"
        path.write_text(
            '{"schema_version":1,"schema_version":1,"artifacts":[]}',
            encoding="utf-8",
        )

        with self.assertRaises(ManifestError):
            load_manifest(path)

    def test_load_manifest_rejects_oversized_input_before_json_parsing(self):
        path = self.workspace / "oversized.json"
        path.write_bytes(b" " * (128 * 1024 + 1))

        with patch("pmca.analysis.manifest.json.loads") as loads:
            with self.assertRaises(ManifestError):
                load_manifest(path)

        loads.assert_not_called()

    def test_write_manifest_rejects_path_below_artifacts(self):
        manifest_path = self.artifacts_root / "firmware-manifest.json"

        with self.assertRaises(ManifestError):
            write_manifest(
                manifest_path,
                {"schema_version": 1, "artifacts": []},
            )
        self.assertFalse(manifest_path.exists())


if __name__ == "__main__":
    unittest.main()
