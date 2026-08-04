import unittest

from pmca.analysis.features import (
    FEATURE_IDS,
    FeatureBoundary,
    FeatureError,
    FeatureEvidence,
    candidate_readiness,
    validate_compatibility_matrix,
)


COMPATIBILITY = {
    "architecture": "synthetic architecture observation",
    "imports": "synthetic import observation",
    "relocations": "synthetic relocation observation",
    "memory": "synthetic memory observation",
    "display_geometry": "synthetic display observation",
    "input_coordinates": "synthetic input observation",
    "dependent_services": "synthetic service observation",
    "signature_layer": "synthetic signature observation",
}


def _evidence(level="CONFIRMED", source=None):
    return {
        "level": level,
        "source": source or "https://helpguide.sony.net/fixture",
        "claim": "bounded synthetic observation",
    }


def synthetic_matrix():
    features = []
    for index, feature_id in enumerate(FEATURE_IDS):
        dependency = (FEATURE_IDS[index - 1],) if index else ()
        features.append(
            {
                "id": feature_id,
                "target": "ILCE-6400",
                "dependencies": list(dependency),
                "evidence": [_evidence()],
                "selected_strategy": "a6400-specific-reimplementation",
                "compatibility": dict(COMPATIBILITY),
                "ready": True,
                "unresolved_dependencies": [],
            }
        )
    return {
        "schema_version": 1,
        "strategy_order": [
            "direct-component-reuse",
            "resource-table-transplant",
            "a6400-subsystem-patch",
            "a6400-specific-reimplementation",
        ],
        "features": list(reversed(features)),
        "candidate_result": {
            "schema_version": 1,
            "source_key": "a6400-ui-port",
            "status": "rejected",
            "installable": False,
            "reason_codes": ["unresolved-dependencies"],
            "unresolved_dependencies": ["synthetic-unresolved"],
        },
        "marker_scan": {
            "markers": ["Vertical Display"],
            "scopes": [
                {
                    "source_key": "a6400-tw-v2.00",
                    "scan_scope": "authenticated-container",
                    "ascii_hits": {"Vertical Display": 0},
                    "utf16le_hits": {"Vertical Display": 0},
                }
            ],
            "interpretation": "absence from encrypted data is no result",
        },
    }


class FeatureDependencyTests(unittest.TestCase):
    def test_feature_contract_is_exact(self):
        self.assertEqual(
            FEATURE_IDS,
            (
                "vertical-orientation-state",
                "vertical-layout-selection",
                "vertical-render-transform",
                "vertical-input-transform",
                "touch-menu-widgets",
                "touch-event-routing",
                "creative-look-base-tables",
                "creative-look-adjustment-axes",
            ),
        )

    def test_transitive_readiness_requires_confirmed_evidence(self):
        orientation = FeatureBoundary(
            FEATURE_IDS[0],
            "ILCE-6400",
            (),
            (
                FeatureEvidence(
                    "CONFIRMED",
                    "https://helpguide.sony.net/fixture",
                    "orientation is observed",
                ),
            ),
        )
        layout = FeatureBoundary(
            FEATURE_IDS[1],
            "ILCE-6400",
            (FEATURE_IDS[0],),
            (
                FeatureEvidence(
                    "PARTIAL",
                    "analysis:authenticated-artifacts",
                    "layout is not executable-compatible",
                ),
            ),
        )
        ready, unresolved = candidate_readiness(
            layout,
            {orientation.name: orientation, layout.name: layout},
        )

        self.assertFalse(ready)
        self.assertEqual(unresolved, ("evidence:vertical-layout-selection",))

    def test_matrix_is_normalized_to_feature_order(self):
        normalized = validate_compatibility_matrix(synthetic_matrix())

        self.assertEqual(
            tuple(item["id"] for item in normalized["features"]),
            FEATURE_IDS,
        )

    def test_unknown_level_missing_feature_duplicate_and_cycle_are_rejected(self):
        invalid = []
        unknown_level = synthetic_matrix()
        unknown_level["features"][0]["evidence"][0]["level"] = "CERTAIN"
        invalid.append(unknown_level)
        missing = synthetic_matrix()
        missing["features"].pop()
        invalid.append(missing)
        duplicate_dependency = synthetic_matrix()
        duplicate_dependency["features"][0]["dependencies"] = [
            FEATURE_IDS[0],
            FEATURE_IDS[0],
        ]
        invalid.append(duplicate_dependency)
        cycle = synthetic_matrix()
        by_id = {item["id"]: item for item in cycle["features"]}
        by_id[FEATURE_IDS[0]]["dependencies"] = [FEATURE_IDS[1]]
        invalid.append(cycle)
        for document in invalid:
            with self.subTest(document=document):
                with self.assertRaises(FeatureError):
                    validate_compatibility_matrix(document)

    def test_confirmed_evidence_requires_official_or_authenticated_source(self):
        document = synthetic_matrix()
        document["features"][0]["evidence"][0]["source"] = "analysis:guess"

        with self.assertRaises(FeatureError):
            validate_compatibility_matrix(document)

    def test_insufficient_evidence_blocks_readiness_even_with_confirmation(self):
        document = synthetic_matrix()
        feature = document["features"][0]
        feature["evidence"].append(
            _evidence("INSUFFICIENT_EVIDENCE", "analysis:unresolved-boundary")
        )
        feature["ready"] = False
        feature["unresolved_dependencies"] = [f"evidence:{feature['id']}"]

        normalized = validate_compatibility_matrix(document)
        item = next(value for value in normalized["features"] if value["id"] == feature["id"])
        self.assertFalse(item["ready"])


if __name__ == "__main__":
    unittest.main()
