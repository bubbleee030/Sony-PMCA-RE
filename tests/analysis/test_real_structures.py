import json
import unittest
from pathlib import Path

from firmware_structure import validate_structure_report


ROOT = Path(__file__).resolve().parents[2]
STRUCTURE_DIRECTORY = ROOT / "analysis" / "structures"
EXPECTED_CHUNKS = {
    "a6700-tw-v2.00": [
        {"kind": "DATV", "header_offset": 8, "payload_offset": 16, "size": 4},
        {"kind": "PROV", "header_offset": 20, "payload_offset": 28, "size": 4},
        {"kind": "UDID", "header_offset": 32, "payload_offset": 40, "size": 108},
        {
            "kind": "FDAT",
            "header_offset": 148,
            "payload_offset": 156,
            "size": 1_024_017_680,
        },
        {
            "kind": "DEND",
            "header_offset": 1_024_017_836,
            "payload_offset": 1_024_017_844,
            "size": 4,
        },
    ],
    "a7v-tw-v2.00": [
        {"kind": "DATV", "header_offset": 8, "payload_offset": 16, "size": 4},
        {"kind": "PROV", "header_offset": 20, "payload_offset": 28, "size": 4},
        {"kind": "UDID", "header_offset": 32, "payload_offset": 40, "size": 100},
        {
            "kind": "FDAT",
            "header_offset": 140,
            "payload_offset": 148,
            "size": 376_540_560,
        },
        {
            "kind": "DEND",
            "header_offset": 376_540_708,
            "payload_offset": 376_540_716,
            "size": 4,
        },
    ],
}
DENIED_KEYS = {"raw", "bytes", "payload", "base64", "hex_dump", "strings"}


def walk_json(value):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from walk_json(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_json(child)


class RealStructureReportTests(unittest.TestCase):
    def test_dat_maps_match_manifest_and_cover_every_byte(self):
        manifest = json.loads(
            (ROOT / "analysis" / "firmware-manifest.json").read_text(
                encoding="utf-8"
            )
        )
        entries = {entry["source_key"]: entry for entry in manifest["artifacts"]}

        for source_key, expected_chunks in EXPECTED_CHUNKS.items():
            with self.subTest(source_key=source_key):
                path = STRUCTURE_DIRECTORY / f"{source_key}.json"
                serialized = path.read_bytes()
                report = json.loads(serialized.decode("utf-8"))
                entry = entries[source_key]

                self.assertLess(len(serialized), 64 * 1024)
                self.assertIs(validate_structure_report(report), report)
                self.assertEqual(report["source_key"], source_key)
                self.assertEqual(report["size"], entry["measured_size"])
                self.assertEqual(report["sha256"], entry["sha256"])
                self.assertEqual(report["dat_chunks"], expected_chunks)
                self.assertEqual(report["unknown_ranges"], [])

                for value in walk_json(report):
                    if isinstance(value, dict):
                        self.assertTrue(
                            DENIED_KEYS.isdisjoint(
                                key.casefold() for key in value
                            )
                        )
                    if isinstance(value, str):
                        self.assertLessEqual(len(value), 256)


if __name__ == "__main__":
    unittest.main()
