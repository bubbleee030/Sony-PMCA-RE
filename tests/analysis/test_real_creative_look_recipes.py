import json
import unittest
from pathlib import Path

from pmca.analysis.creative_looks import LOOK_CODES, validate_recipe_document


class RealCreativeLookRecipeTests(unittest.TestCase):
    def test_committed_catalog_has_all_defaults_and_sourced_community_entries(self):
        document = validate_recipe_document(
            json.loads(
                Path("analysis/creative-look-recipes.json").read_text(
                    encoding="utf-8"
                )
            )
        )

        self.assertEqual(
            tuple(item["modern"]["code"] for item in document["defaults"]),
            LOOK_CODES,
        )
        self.assertEqual(len(document["community_experiments"]), 2)
        self.assertTrue(
            all(
                item["source_kind"] == "community-experiment"
                and item["modern"]["source"].startswith("https://")
                for item in document["community_experiments"]
            )
        )
        inferred = {
            item["modern"]["code"]: item["a6400"]
            for item in document["defaults"]
            if item["a6400"]["confidence"] == "INFERRED"
        }
        self.assertEqual(
            {
                code: (
                    value["creative_style"],
                    value["contrast"],
                    value["saturation"],
                    value["sharpness"],
                )
                for code, value in inferred.items()
            },
            {
                "VV2": ("Clear", 0, 1, 0),
                "FL": ("Deep", -1, 0, 0),
                "IN": ("Neutral", -2, -2, -1),
                "SH": ("Light", -1, -1, -1),
            },
        )


if __name__ == "__main__":
    unittest.main()
