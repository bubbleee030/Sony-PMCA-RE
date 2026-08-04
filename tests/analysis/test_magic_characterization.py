import json
import unittest
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
STRUCTURES = ROOT / "analysis" / "structures"
EXPECTED_COUNTS = {
    "a6400-tw-v2.00": {"gzip": 12, "pe": 4_687, "sony-dat": 1},
    "a6700-tw-v2.00": {"gzip": 66, "pe": 15_766},
    "a7v-tw-v2.00": {"gzip": 25, "pe": 5_753},
}


class RealMagicCharacterizationTests(unittest.TestCase):
    def test_complete_hit_counts_and_embedded_dat_candidate_are_exact(self):
        for source_key, expected_counts in EXPECTED_COUNTS.items():
            with self.subTest(source_key=source_key):
                report = json.loads(
                    (STRUCTURES / f"{source_key}.json").read_text(
                        encoding="utf-8"
                    )
                )
                counts = Counter(hit["label"] for hit in report["magic_hits"])
                sony_dat_offsets = [
                    hit["offset"]
                    for hit in report["magic_hits"]
                    if hit["label"] == "sony-dat"
                ]

                self.assertEqual(dict(counts), expected_counts)
                self.assertEqual(
                    sony_dat_offsets,
                    [715_220] if source_key == "a6400-tw-v2.00" else [],
                )


if __name__ == "__main__":
    unittest.main()
