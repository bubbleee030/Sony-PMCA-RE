import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from pmca.analysis.creative_look_sources import (
    CreativeLookSourceError,
    classify_artifact,
    validate_creative_look_sources,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SOURCES_PATH = REPOSITORY_ROOT / "analysis" / "a6400-creative-look-sources.json"
SOURCE_IDS = [
    "a6400-tw-v2.00",
    "a6400a-eu-v1.01",
    "a6700-tw-v2.00",
    "a7v-tw-v2.00",
]


class CreativeLookArtifactClassificationTests(unittest.TestCase):
    def test_authenticated_opaque_source_has_no_executable_evidence(self):
        payload = b"synthetic opaque firmware fixture"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "BODYDATA.DAT"
            path.write_bytes(payload)

            result = classify_artifact(
                path,
                expected_size=len(payload),
                expected_sha256=hashlib.sha256(payload).hexdigest(),
                extracted=False,
            )

        self.assertEqual(result["state"], "AUTHENTICATED_OPAQUE")
        self.assertFalse(result["executable_evidence_available"])

    def test_authenticated_extracted_source_requires_ignored_decrypted_root(self):
        payload = b"synthetic extracted module fixture"
        decrypted_root = REPOSITORY_ROOT / ".artifacts" / "decrypted"
        decrypted_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=decrypted_root) as directory:
            path = Path(directory) / "fixture.so"
            path.write_bytes(payload)

            result = classify_artifact(
                path,
                expected_size=len(payload),
                expected_sha256=hashlib.sha256(payload).hexdigest(),
                extracted=True,
            )

        self.assertEqual(result["state"], "AUTHENTICATED_EXTRACTED")
        self.assertTrue(result["executable_evidence_available"])

    def test_missing_source_is_unavailable(self):
        result = classify_artifact(
            None,
            expected_size=1,
            expected_sha256="00" * 32,
            extracted=False,
        )

        self.assertEqual(
            result,
            {"state": "UNAVAILABLE", "executable_evidence_available": False},
        )

    def test_digest_size_and_extracted_path_mismatches_fail_closed(self):
        payload = b"synthetic mismatch fixture"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.so"
            path.write_bytes(payload)
            candidates = (
                (len(payload) + 1, hashlib.sha256(payload).hexdigest(), False),
                (len(payload), "00" * 32, False),
                (len(payload), hashlib.sha256(payload).hexdigest(), True),
            )
            for expected_size, expected_sha256, extracted in candidates:
                with self.subTest(
                    expected_size=expected_size,
                    expected_sha256=expected_sha256,
                    extracted=extracted,
                ), self.assertRaises(CreativeLookSourceError):
                    classify_artifact(
                        path,
                        expected_size=expected_size,
                        expected_sha256=expected_sha256,
                        extracted=extracted,
                    )


class CreativeLookSourcesReportTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(SOURCES_PATH.read_text(encoding="utf-8"))

    def test_committed_report_separates_target_extracted_and_opaque_donors(self):
        validated = validate_creative_look_sources(self.document)

        self.assertEqual([item["id"] for item in validated["sources"]], SOURCE_IDS)
        self.assertEqual(
            [item["state"] for item in validated["sources"]],
            [
                "AUTHENTICATED_EXTRACTED",
                "AUTHENTICATED_EXTRACTED",
                "AUTHENTICATED_OPAQUE",
                "AUTHENTICATED_OPAQUE",
            ],
        )
        self.assertEqual(
            [item["executable_evidence_available"] for item in validated["sources"]],
            [True, True, False, False],
        )
        self.assertTrue(validated["sources"][0]["extracted_evidence"])
        self.assertTrue(validated["sources"][1]["extracted_evidence"])
        self.assertEqual(validated["sources"][2]["extracted_evidence"], [])
        self.assertEqual(validated["sources"][3]["extracted_evidence"], [])

    def test_state_and_executable_availability_cannot_disagree(self):
        candidates = []

        candidate = copy.deepcopy(self.document)
        candidate["sources"][2]["executable_evidence_available"] = True
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["sources"][0]["state"] = "AUTHENTICATED_OPAQUE"
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["sources"][3]["extracted_evidence"] = [
            {
                "artifact_kind": "module",
                "name": "lib/CautionConfig.so",
                "size": 1,
                "sha256": "00" * 32,
            }
        ]
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                CreativeLookSourceError
            ):
                validate_creative_look_sources(candidate)

    def test_report_rejects_absolute_paths_and_raw_or_reconstructive_fields(self):
        candidates = []

        candidate = copy.deepcopy(self.document)
        candidate["sources"][0]["committed_evidence"][0] = (
            "C:/Users/Bubble/ChatGPT/analysis/firmware-manifest.json"
        )
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["sources"][0]["artifact"]["raw_payload"] = "forbidden"
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["sources"][1]["ignored_path"] = ".artifacts/decrypted/source"
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                CreativeLookSourceError
            ):
                validate_creative_look_sources(candidate)

    def test_report_rejects_identity_or_evidence_membership_changes(self):
        candidates = []

        candidate = copy.deepcopy(self.document)
        candidate["sources"][0]["model"] = "ILCE-7M5"
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["sources"] = list(reversed(candidate["sources"]))
        candidates.append(candidate)

        candidate = copy.deepcopy(self.document)
        candidate["sources"][1]["committed_evidence"] = []
        candidates.append(candidate)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                CreativeLookSourceError
            ):
                validate_creative_look_sources(candidate)

    def test_validated_report_is_a_deep_copy(self):
        validated = validate_creative_look_sources(self.document)
        validated["sources"][0]["creative_look_limit"] = "changed"

        self.assertNotEqual(
            validated["sources"][0]["creative_look_limit"],
            self.document["sources"][0]["creative_look_limit"],
        )


if __name__ == "__main__":
    unittest.main()
