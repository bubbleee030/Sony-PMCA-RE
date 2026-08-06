import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pmca.analysis.stock_restore as stock_restore
from pmca.analysis.stock_restore import (
    StockRestoreError,
    validate_stock_restore_bundle,
    verify_file,
    verify_stock_restore_files,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
BUNDLE_PATH = REPOSITORY_ROOT / "analysis" / "a6400-stock-200-bundle.json"


class StockRestoreTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(BUNDLE_PATH.read_text(encoding="utf-8"))

    def test_bundle_is_exact_regional_v200_source(self):
        validated = validate_stock_restore_bundle(self.document)

        self.assertEqual(validated["model"], "ILCE-6400")
        self.assertEqual(validated["model_id"], "0x81030011")
        self.assertEqual(validated["region"], "TW")
        self.assertEqual(validated["region_code"], 0)
        self.assertEqual(validated["version"], "2.00")
        self.assertEqual(validated["source_kind"], "official-sony-updater")
        self.assertFalse(validated["camera_executed"])
        self.assertFalse(validated["installable"])

    def test_bundle_pins_outer_and_embedded_container_identity(self):
        validated = validate_stock_restore_bundle(self.document)
        components = {item["id"]: item for item in validated["components"]}

        outer = components["outer-updater"]
        self.assertEqual(outer["filename"], "Update_ILCE6400V200.exe")
        self.assertEqual(outer["size"], 314230712)
        self.assertEqual(
            outer["sha256"],
            "ea460cbec5f8b62119630f0a653eeca4f4ffad887670e60c0fd9c0345e6b30a6",
        )

        embedded = components["embedded-firmware-container"]
        self.assertEqual(embedded["container_id"], "outer-updater")
        self.assertEqual(embedded["outer_offset"], 715220)
        self.assertEqual(embedded["container_prefix_size"], 120)
        self.assertEqual(embedded["container_size"], 304833928)
        self.assertEqual(embedded["fdat_size"], 304833808)
        self.assertEqual(
            embedded["sha256"],
            "78a6881eddd16609758951c80d533ac82042858eac919bd94453941ba6b766f2",
        )

    def test_bundle_requires_official_provenance_and_component_manifest(self):
        validated = validate_stock_restore_bundle(self.document)

        self.assertEqual(
            validated["acquisition_provenance"]["official_url"],
            "https://www.sony.com.tw/zh/electronics/support/e-mount-body-ilce-6000-series/ilce-6400/downloads/00016145",
        )
        self.assertEqual(
            validated["references"]["target_component_manifest"],
            "analysis/a6400-target-features.json",
        )
        self.assertEqual(
            set(validated["references"]),
            {
                "acquisition_manifest",
                "outer_static_report",
                "target_component_manifest",
            },
        )

    def test_bundle_rejects_raw_firmware_material_recursively(self):
        candidates = []

        candidate = copy.deepcopy(self.document)
        candidate["raw_payload"] = "forbidden"
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["acquisition_provenance"]["key_material"] = "forbidden"
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["components"][0]["hex_dump"] = "forbidden"
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["components"][0]["unexpected"] = b"firmware bytes"
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                StockRestoreError
            ):
                validate_stock_restore_bundle(candidate)

    def test_bundle_rejects_missing_duplicate_or_reordered_components(self):
        candidates = []

        candidate = copy.deepcopy(self.document)
        candidate["components"].pop()
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["components"][1] = copy.deepcopy(candidate["components"][0])
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["components"].reverse()
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                StockRestoreError
            ):
                validate_stock_restore_bundle(candidate)

    def test_bundle_rejects_identity_geometry_and_provenance_drift(self):
        candidates = []

        for field, value in (
            ("model_id", "0x00000000"),
            ("region", "US"),
            ("region_code", 1),
            ("version", "2.01"),
            ("source_kind", "local-copy"),
        ):
            candidate = copy.deepcopy(self.document)
            candidate[field] = value
            candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["components"][0]["sha256"] = "0" * 64
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["components"][1]["outer_offset"] += 1
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["components"][1]["container_size"] -= 1
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["acquisition_provenance"]["acquired_at"] = "unknown"
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["references"]["target_component_manifest"] = "elsewhere.json"
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                StockRestoreError
            ):
                validate_stock_restore_bundle(candidate)

    def test_bundle_rejects_boolean_region_code(self):
        candidate = copy.deepcopy(self.document)
        candidate["region_code"] = False

        with self.assertRaises(StockRestoreError):
            validate_stock_restore_bundle(candidate)

    def test_bundle_cross_checks_manifest_digest_and_version(self):
        manifest_entry, outer_report, target_report = stock_restore._validated_sources()
        candidates = []

        candidate = copy.deepcopy(manifest_entry)
        candidate["sha256"] = "0" * 64
        candidates.append(candidate)

        candidate = copy.deepcopy(manifest_entry)
        candidate["version"] = "2.01"
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), patch.object(
                stock_restore,
                "_validated_sources",
                return_value=(candidate, outer_report, target_report),
            ), self.assertRaises(StockRestoreError):
                validate_stock_restore_bundle(self.document)

    def test_bundle_rejects_absolute_or_escaping_ignored_paths(self):
        candidates = []
        for value in (
            "C:/firmware/Update_ILCE6400V200.exe",
            "/firmware/Update_ILCE6400V200.exe",
            "../Update_ILCE6400V200.exe",
            "a6400-tw-v2.00/../../Update_ILCE6400V200.exe",
            ".artifacts/sony-firmware/a6400-tw-v2.00/Update_ILCE6400V200.exe",
        ):
            candidate = copy.deepcopy(self.document)
            candidate["components"][0]["relative_path"] = value
            candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                StockRestoreError
            ):
                validate_stock_restore_bundle(candidate)

    def test_bundle_rejects_camera_or_installability_promotion(self):
        for field in ("camera_executed", "installable"):
            candidate = copy.deepcopy(self.document)
            candidate[field] = True
            with self.subTest(field=field), self.assertRaises(StockRestoreError):
                validate_stock_restore_bundle(candidate)

    def test_validated_bundle_is_an_isolated_copy(self):
        validated = validate_stock_restore_bundle(self.document)
        validated["components"][0]["filename"] = "changed.exe"

        self.assertEqual(
            self.document["components"][0]["filename"],
            "Update_ILCE6400V200.exe",
        )

    def test_verify_file_checks_size_and_digest_without_returning_bytes(self):
        data = b"bounded test fixture"
        expected = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as temp_directory:
            path = Path(temp_directory) / "fixture.bin"
            path.write_bytes(data)

            self.assertIsNone(verify_file(path, len(data), expected))
            with self.assertRaises(StockRestoreError):
                verify_file(path, len(data) + 1, expected)
            with self.assertRaises(StockRestoreError):
                verify_file(path, len(data), "0" * 64)

    def test_on_disk_verifier_authenticates_existing_ignored_original(self):
        artifact_root = REPOSITORY_ROOT / ".artifacts" / "sony-firmware"
        if not artifact_root.is_dir():
            self.skipTest("ignored stock artifact is not present")

        verified = verify_stock_restore_files(self.document, artifact_root)

        self.assertEqual(
            list(verified), ["outer-updater", "embedded-firmware-container"]
        )
        self.assertEqual(verified["outer-updater"]["size"], 314230712)
        self.assertEqual(
            verified["embedded-firmware-container"]["size"], 304833928
        )
        self.assertNotIn("path", verified["outer-updater"])
        self.assertNotIn("data", verified["embedded-firmware-container"])

    def test_on_disk_verifier_rejects_root_outside_ignored_stock_directory(self):
        with tempfile.TemporaryDirectory() as temp_directory:
            with self.assertRaises(StockRestoreError):
                verify_stock_restore_files(self.document, Path(temp_directory))

    def test_on_disk_verifier_rejects_reparse_ancestor_spelling(self):
        sources = stock_restore._validated_sources()
        with tempfile.TemporaryDirectory() as temp_directory:
            repository_root = Path(temp_directory) / "repository"
            artifact_root = repository_root / ".artifacts" / "sony-firmware"
            artifact_root.mkdir(parents=True)
            outer_path = (
                artifact_root
                / "a6400-tw-v2.00"
                / "Update_ILCE6400V200.exe"
            )
            outer_path.parent.mkdir()
            outer_path.write_bytes(b"")
            alias = repository_root / ".artifacts" / "stock-root-alias"
            try:
                alias.symlink_to(artifact_root, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"directory symlinks are unavailable: {error}")

            disguised_root = alias / ".." / "sony-firmware"
            embedded_digest = self.document["components"][1]["sha256"]
            with patch.object(
                stock_restore, "_REPOSITORY_ROOT", repository_root
            ), patch.object(
                stock_restore, "_validated_sources", return_value=sources
            ), patch.object(
                stock_restore, "verify_file", return_value=None
            ), patch.object(
                stock_restore, "_sha256_range", return_value=embedded_digest
            ), self.assertRaises(StockRestoreError):
                verify_stock_restore_files(self.document, disguised_root)

    def test_on_disk_verifier_rejects_canonical_reparse_ancestor(self):
        sources = stock_restore._validated_sources()
        with tempfile.TemporaryDirectory() as temp_directory:
            temporary_root = Path(temp_directory)
            repository_root = temporary_root / "repository"
            repository_root.mkdir()
            real_artifacts = temporary_root / "real-artifacts"
            artifact_root = real_artifacts / "sony-firmware"
            artifact_root.mkdir(parents=True)
            outer_path = (
                artifact_root
                / "a6400-tw-v2.00"
                / "Update_ILCE6400V200.exe"
            )
            outer_path.parent.mkdir()
            outer_path.write_bytes(b"")
            artifacts_link = repository_root / ".artifacts"
            try:
                artifacts_link.symlink_to(real_artifacts, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"directory symlinks are unavailable: {error}")

            canonical_spelling = repository_root / ".artifacts" / "sony-firmware"
            embedded_digest = self.document["components"][1]["sha256"]
            with patch.object(
                stock_restore, "_REPOSITORY_ROOT", repository_root
            ), patch.object(
                stock_restore, "_validated_sources", return_value=sources
            ), patch.object(
                stock_restore, "verify_file", return_value=None
            ), patch.object(
                stock_restore, "_sha256_range", return_value=embedded_digest
            ), self.assertRaises(StockRestoreError):
                verify_stock_restore_files(self.document, canonical_spelling)


if __name__ == "__main__":
    unittest.main()
