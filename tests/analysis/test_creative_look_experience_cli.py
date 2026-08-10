import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import creative_look_experience
from pmca.experience.creative_look import CreativeLookExperience, load_experience


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEMO_PATH = (
    REPOSITORY_ROOT
    / "analysis"
    / "a6400-creative-look-offline-experience-demo.json"
)


class CreativeLookExperienceCliTests(unittest.TestCase):
    def test_initialize_orient_frame_and_touch_are_offline_and_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state.json"
            frame = root / "frame.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(
                    creative_look_experience.main(
                        ["initialize", "--state", str(state)]
                    ),
                    0,
                )
                self.assertEqual(
                    creative_look_experience.main(
                        [
                            "orient",
                            "--state",
                            str(state),
                            "--orientation",
                            "portrait_shutter_up",
                        ]
                    ),
                    0,
                )
                self.assertEqual(
                    creative_look_experience.main(
                        ["frame", "--state", str(state), "--output", str(frame)]
                    ),
                    0,
                )

            snapshot = json.loads(frame.read_text(encoding="utf-8"))
            self.assertTrue(snapshot["offline_only"])
            self.assertEqual(snapshot["processing_binding"], "UNBOUND_TARGET")
            self.assertEqual(snapshot["frame"]["orientation"], "portrait_shutter_up")
            self.assertEqual(len(snapshot["frame"]["elements"]), 18)

            experience = load_experience(state)
            x, y = experience.frame().element("look:ST").rect.center
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    creative_look_experience.main(
                        [
                            "touch",
                            "--state",
                            str(state),
                            "--x",
                            str(x),
                            "--y",
                            str(y),
                        ]
                    ),
                    0,
                )
            self.assertEqual(load_experience(state).screen.value, "editor")

    def test_demo_contains_all_orientations_full_catalog_and_safety_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "demo.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    creative_look_experience.main(
                        ["demo", "--output", str(output)]
                    ),
                    0,
                )
            demo = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(demo["schema_version"], 1)
        self.assertTrue(demo["offline_only"])
        self.assertTrue(demo["sample_values_are_product_demo_only"])
        self.assertEqual(demo["processing_binding"], "UNBOUND_TARGET")
        self.assertEqual(
            list(demo["catalog_frames"]),
            ["landscape", "portrait_shutter_up", "portrait_shutter_down"],
        )
        self.assertTrue(
            all(len(frame["elements"]) == 18 for frame in demo["catalog_frames"].values())
        )
        self.assertEqual(demo["sample_state"]["custom_bases"]["Custom1"], "VV")
        self.assertEqual(demo["sample_state"]["adjustments"]["Custom1"]["contrast"], 3)
        self.assertEqual(
            demo["sample_state"]["safety"],
            {
                "recovery_validated": False,
                "camera_test_eligible": False,
                "installable": False,
            },
        )

    def test_cli_exposes_no_camera_firmware_or_install_commands(self):
        for command in ("camera", "firmware", "flash", "install", "updater"):
            with (
                self.subTest(command=command),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                creative_look_experience.main([command])

    def test_frame_refuses_promoted_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state.json"
            output = root / "frame.json"
            document = CreativeLookExperience.new().to_document()
            document["processing_binding"] = "TARGET_NATIVE"
            state.write_text(json.dumps(document), encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                result = creative_look_experience.main(
                    ["frame", "--state", str(state), "--output", str(output)]
                )

        self.assertEqual(result, 1)
        self.assertIn("error:", stderr.getvalue())
        self.assertFalse(output.exists())

    def test_checked_demo_matches_fresh_offline_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "demo.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    creative_look_experience.main(
                        ["demo", "--output", str(output)]
                    ),
                    0,
                )
            fresh = output.read_bytes()

        self.assertEqual(DEMO_PATH.read_bytes(), fresh)


if __name__ == "__main__":
    unittest.main()
