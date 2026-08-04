import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REPORT_DIRECTORY = ROOT / "analysis" / "reports"
REPORT_NAMES = (
    "a6400-tw-v2.00.json",
    "a6700-tw-v2.00.json",
)
REPORT_FIELDS = {
    "schema_version",
    "source_key",
    "filename",
    "size",
    "sha256",
    "format",
    "pe",
    "entropy",
    "token_hits",
}
DENIED_KEYS = {"raw", "bytes", "payload", "base64", "hex_dump", "strings"}
ALLOWED_TOKEN_LABELS = {
    "ILCE-6400",
    "ILCE6400",
    "ILCE-6700",
    "ILCE6700",
    "2.00",
    "BODYDATA.DAT",
    "Update_ILCE6400V200",
}


def walk_json(value):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from walk_json(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_json(child)


class RealReportTests(unittest.TestCase):
    def test_committed_reports_match_manifest_and_remain_bounded(self):
        manifest = json.loads(
            (ROOT / "analysis" / "firmware-manifest.json").read_text(
                encoding="utf-8"
            )
        )
        entries = {entry["source_key"]: entry for entry in manifest["artifacts"]}

        for report_name in REPORT_NAMES:
            with self.subTest(report_name=report_name):
                report_path = REPORT_DIRECTORY / report_name
                serialized = report_path.read_bytes()
                report = json.loads(serialized.decode("utf-8"))
                source_key = report_name.removesuffix(".json")
                entry = entries[source_key]

                self.assertLess(len(serialized), 128 * 1024)
                self.assertEqual(set(report), REPORT_FIELDS)
                self.assertEqual(report["schema_version"], 1)
                self.assertEqual(report["source_key"], source_key)
                self.assertEqual(report["size"], entry["measured_size"])
                self.assertEqual(report["sha256"], entry["sha256"])
                self.assertTrue(
                    all(hit["token"] in ALLOWED_TOKEN_LABELS for hit in report["token_hits"])
                )

                for value in walk_json(report):
                    if isinstance(value, dict):
                        self.assertTrue(DENIED_KEYS.isdisjoint(key.casefold() for key in value))
                    if isinstance(value, str):
                        self.assertLessEqual(len(value), 512)


if __name__ == "__main__":
    unittest.main()
