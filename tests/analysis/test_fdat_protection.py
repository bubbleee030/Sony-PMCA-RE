import ast
import hashlib
import io
import json
import unittest
from pathlib import Path

from pmca.analysis.fdat_protection import (
    ProtectionError,
    characterize_fdat_region,
    classify_trailer_geometry,
    validate_protection_report,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = REPOSITORY_ROOT / "analysis" / "donor-fdat-protection.json"


class FdatProtectionTests(unittest.TestCase):
    def test_known_trailer_geometries_are_discriminated_by_1024_alignment(self):
        self.assertEqual(
            classify_trailer_geometry(3 * 1024 + 0x110),
            [
                {
                    "encrypted_size": 3072,
                    "prefix_size": 16,
                    "suffix_size": 256,
                    "trailer_size": 272,
                }
            ],
        )
        self.assertEqual(
            classify_trailer_geometry(2 * 1024 + 0x190),
            [
                {
                    "encrypted_size": 2048,
                    "prefix_size": 16,
                    "suffix_size": 384,
                    "trailer_size": 400,
                }
            ],
        )

    def test_characterizer_returns_statistics_without_raw_region_bytes(self):
        prefix = bytes(range(16))
        suffix = b"\1" * 256
        region = prefix + b"\0" * (2 * 1024) + suffix
        stream = io.BytesIO(b"outside" + region + b"after")
        original_position = stream.tell()

        result = characterize_fdat_region(stream, 7, len(region))

        self.assertEqual(stream.tell(), original_position)
        self.assertEqual(result["size"], len(region))
        self.assertTrue(result["aes_block_aligned"])
        self.assertEqual(result["sample_profile"]["sample_bytes"], len(region))
        self.assertEqual(result["sample_profile"]["total_16_byte_blocks"], 145)
        self.assertEqual(result["sample_profile"]["unique_16_byte_blocks"], 3)
        self.assertEqual(result["sample_profile"]["adjacent_equal_16_byte_blocks"], 142)
        self.assertEqual(result["trailer_candidates"][0]["trailer_size"], 0x110)
        boundary = result["boundary_metadata"]
        self.assertEqual(boundary["prefix_sha256"], hashlib.sha256(prefix).hexdigest())
        self.assertEqual(boundary["prefix_unique_bytes"], 16)
        self.assertFalse(boundary["prefix_all_zero"])
        self.assertEqual(boundary["suffix_sha256"], hashlib.sha256(suffix).hexdigest())
        self.assertEqual(boundary["suffix_unique_bytes"], 1)
        self.assertFalse(boundary["suffix_all_zero"])
        self.assertFalse(boundary["cryptographic_role_established"])
        self.assertNotIn("raw", json.dumps(result).casefold())
        self.assertNotIn("hex", json.dumps(result).casefold())

    def test_characterizer_rejects_unbounded_or_truncated_regions(self):
        cases = [
            (io.BytesIO(b"x" * 64), -1, 16),
            (io.BytesIO(b"x" * 64), 0, 0),
            (io.BytesIO(b"x" * 64), 48, 32),
            (io.BytesIO(b"x" * 64), 0, True),
        ]
        for stream, offset, size in cases:
            with self.subTest(offset=offset, size=size):
                with self.assertRaises(ProtectionError):
                    characterize_fdat_region(stream, offset, size)

    def test_module_has_no_key_or_decryption_backend(self):
        source_path = REPOSITORY_ROOT / "pmca" / "analysis" / "fdat_protection.py"
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".", 1)[0])

        self.assertTrue(imported_roots.isdisjoint({"Crypto", "Cryptodome", "ctypes"}))
        folded = source.casefold()
        for forbidden in ("aes.new", "decrypt(", "private_key", "deviceiocontrol"):
            self.assertNotIn(forbidden, folded)

    def test_committed_report_preserves_the_provenance_and_failure_split(self):
        document = json.loads(REPORT_PATH.read_text(encoding="utf-8"))

        self.assertEqual(validate_protection_report(document), document)
        self.assertFalse(document["camera_executed"])
        self.assertFalse(document["installable"])
        artifacts = {item["source_key"]: item for item in document["artifacts"]}
        self.assertEqual(
            artifacts["a6700-tw-v2.00"]["profile"]["trailer_candidates"][0]["trailer_size"],
            0x110,
        )
        self.assertEqual(
            artifacts["a7v-tw-v2.00"]["profile"]["trailer_candidates"][0]["trailer_size"],
            0x190,
        )
        self.assertEqual(
            artifacts["a7s3-jp-v2.15"]["profile"]["trailer_candidates"][0]["trailer_size"],
            0x110,
        )
        self.assertEqual(
            artifacts["a7s3-jp-v3.01"]["profile"]["trailer_candidates"][0]["trailer_size"],
            0x110,
        )
        for source_key in ("a7s3-jp-v2.15", "a7s3-jp-v3.01"):
            boundary = artifacts[source_key]["profile"]["boundary_metadata"]
            self.assertFalse(boundary["prefix_all_zero"])
            self.assertFalse(boundary["suffix_all_zero"])
            self.assertFalse(boundary["cryptographic_role_established"])
        self.assertNotEqual(
            artifacts["a7s3-jp-v2.15"]["profile"]["boundary_metadata"]["prefix_sha256"],
            artifacts["a7s3-jp-v3.01"]["profile"]["boundary_metadata"]["prefix_sha256"],
        )
        self.assertNotEqual(
            artifacts["a7s3-jp-v2.15"]["profile"]["boundary_metadata"]["suffix_sha256"],
            artifacts["a7s3-jp-v3.01"]["profile"]["boundary_metadata"]["suffix_sha256"],
        )
        probes = {item["source_key"]: item for item in document["historical_tool_probe"]["results"]}
        self.assertEqual(probes["a6700-tw-v2.00"]["shared_stage_result"], "HEADER_MATCH")
        self.assertEqual(probes["a6700-tw-v2.00"]["model_id"], "0x20030001")
        self.assertEqual(probes["a7v-tw-v2.00"]["shared_stage_result"], "HEADER_MISMATCH")
        self.assertIsNone(probes["a7v-tw-v2.00"]["model_id"])
        self.assertEqual(probes["a7s3-jp-v2.15"]["shared_stage_result"], "HEADER_MATCH")
        self.assertEqual(probes["a7s3-jp-v2.15"]["model_id"], "0x91030083")
        self.assertEqual(probes["a7s3-jp-v3.01"]["shared_stage_result"], "HEADER_MATCH")
        self.assertEqual(probes["a7s3-jp-v3.01"]["internal_version"], "3.01")
        self.assertEqual(document["source_survey"]["new_decrypter_paths_found"], 0)

    def test_report_rejects_promoted_or_reconstructive_claims(self):
        document = json.loads(REPORT_PATH.read_text(encoding="utf-8"))

        for field in ("camera_executed", "installable", "decryption_established"):
            candidate = json.loads(json.dumps(document))
            candidate[field] = True
            with self.subTest(field=field), self.assertRaises(ProtectionError):
                validate_protection_report(candidate)

        candidate = json.loads(json.dumps(document))
        candidate["raw_payload"] = "deadbeef"
        with self.assertRaises(ProtectionError):
            validate_protection_report(candidate)


if __name__ == "__main__":
    unittest.main()
