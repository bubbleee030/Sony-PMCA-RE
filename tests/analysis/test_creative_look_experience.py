import json
import tempfile
import unittest
from pathlib import Path

from pmca.analysis.creative_look_stack import (
    AXIS_IDS,
    BUILT_IN_LOOK_IDS,
    CUSTOM_LOOK_IDS,
)
from pmca.experience.creative_look import (
    CreativeLookExperience,
    CreativeLookExperienceError,
    Orientation,
    Screen,
    load_experience,
    save_experience,
)


class CreativeLookExperienceTests(unittest.TestCase):
    def test_catalog_has_all_first_class_entries_and_no_native_claim(self):
        experience = CreativeLookExperience.new()
        frame = experience.frame()

        self.assertEqual(experience.selected_look, "ST")
        self.assertEqual(experience.screen, Screen.CATALOG)
        self.assertEqual(
            [element.identifier.removeprefix("look:") for element in frame.elements],
            [*BUILT_IN_LOOK_IDS, *CUSTOM_LOOK_IDS],
        )
        self.assertEqual(experience.processing_binding, "UNBOUND_TARGET")
        self.assertFalse(experience.camera_test_eligible)
        self.assertFalse(experience.installable)
        self.assertEqual(
            frame.to_document()["coordinate_space"],
            "offline_prototype_logical_units",
        )

    def test_catalog_layouts_are_orientation_specific_and_nonoverlapping(self):
        experience = CreativeLookExperience.new()
        expected = {
            Orientation.LANDSCAPE: (1600, 900, 6),
            Orientation.PORTRAIT_SHUTTER_UP: (900, 1600, 3),
            Orientation.PORTRAIT_SHUTTER_DOWN: (900, 1600, 3),
        }

        for orientation, (width, height, columns) in expected.items():
            with self.subTest(orientation=orientation):
                experience.set_orientation(orientation)
                frame = experience.frame()
                self.assertEqual((frame.width, frame.height), (width, height))
                self.assertEqual(frame.columns, columns)
                self.assertEqual(len(frame.elements), 18)
                for index, left in enumerate(frame.elements):
                    self.assertTrue(left.rect.inside(frame.width, frame.height))
                    for right in frame.elements[index + 1 :]:
                        self.assertFalse(left.rect.overlaps(right.rect))

    def test_touch_drives_catalog_custom_base_and_axis_editing(self):
        experience = CreativeLookExperience.new()
        experience.set_orientation(Orientation.PORTRAIT_SHUTTER_UP)

        self._touch(experience, "look:Custom1")
        self.assertEqual(experience.screen, Screen.CUSTOM_BASE)
        self.assertEqual(experience.selected_look, "Custom1")

        self._touch(experience, "base:VV")
        self.assertEqual(experience.screen, Screen.EDITOR)
        self.assertEqual(experience.custom_bases["Custom1"], "VV")

        self._touch(experience, "axis:contrast")
        self.assertEqual(experience.screen, Screen.AXIS_PICKER)
        self.assertEqual(experience.editing_axis, "contrast")

        self._touch(experience, "axis-value:contrast:3")
        self.assertEqual(experience.screen, Screen.EDITOR)
        self.assertEqual(experience.adjustments["Custom1"]["contrast"], 3)
        self.assertTrue(experience.is_modified("Custom1"))

        self._touch(experience, "action:reset")
        self.assertFalse(experience.is_modified("Custom1"))
        self.assertTrue(
            all(value is None for value in experience.adjustments["Custom1"].values())
        )

    def test_restrictions_are_applied_without_hiding_reference_controls(self):
        experience = CreativeLookExperience.new()
        experience.select_look("BW")

        editor = experience.frame()
        saturation = editor.element("axis:saturation")
        self.assertFalse(saturation.enabled)
        self.assertEqual(saturation.reason, "BW_SE_SATURATION_UNAVAILABLE")
        with self.assertRaises(CreativeLookExperienceError):
            experience.set_axis("saturation", 0)

        experience.select_look("ST")
        experience.set_mode(movie_mode=True)
        sharpness_range = experience.frame().element("axis:sharpness_range")
        self.assertFalse(sharpness_range.enabled)
        self.assertEqual(
            sharpness_range.reason, "MOVIE_SHARPNESS_RANGE_UNAVAILABLE"
        )

        experience.set_mode(intelligent_auto=True)
        self.assertEqual(experience.screen, Screen.CATALOG)
        frame = experience.frame()
        self.assertEqual(len(frame.elements), 18)
        self.assertTrue(all(not element.enabled for element in frame.elements))
        self.assertTrue(
            all(
                element.reason == "CREATIVE_LOOK_MODE_UNAVAILABLE"
                for element in frame.elements
            )
        )

    def test_axis_ranges_and_unknown_defaults_remain_exact(self):
        experience = CreativeLookExperience.new()
        experience.select_look("ST")

        for axis_id in AXIS_IDS:
            self.assertIsNone(experience.adjustments["ST"][axis_id])
        experience.open_axis("sharpness_range")
        picker_ids = {element.identifier for element in experience.frame().elements}
        self.assertIn("axis-value:sharpness_range:default", picker_ids)
        self.assertIn("axis-value:sharpness_range:1", picker_ids)
        self.assertIn("axis-value:sharpness_range:5", picker_ids)
        self.assertNotIn("axis-value:sharpness_range:0", picker_ids)

        experience.set_axis("sharpness_range", 5)
        self.assertEqual(experience.adjustments["ST"]["sharpness_range"], 5)
        experience.set_axis("sharpness_range", None)
        self.assertIsNone(experience.adjustments["ST"]["sharpness_range"])
        with self.assertRaises(CreativeLookExperienceError):
            experience.set_axis("sharpness_range", 0)

        with self.assertRaises(CreativeLookExperienceError):
            experience.touch(True, 10)

    def test_state_round_trip_preserves_custom_slots_orientation_and_values(self):
        experience = CreativeLookExperience.new()
        experience.set_orientation(Orientation.PORTRAIT_SHUTTER_DOWN)
        experience.select_custom_base("Custom3", "FL3")
        experience.select_look("Custom3")
        experience.set_axis("fade", 7)
        experience.set_axis("clarity", 2)
        experience.set_mode(movie_mode=True)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "creative-look-state.json"
            save_experience(path, experience)
            restored = load_experience(path)
            self.assertEqual(restored.to_document(), experience.to_document())
            document = json.loads(path.read_text(encoding="utf-8"))

        self.assertTrue(document["offline_only"])
        self.assertEqual(document["processing_binding"], "UNBOUND_TARGET")
        self.assertEqual(
            document["safety"],
            {
                "recovery_validated": False,
                "camera_test_eligible": False,
                "installable": False,
            },
        )

    def test_state_loader_rejects_promotions_unknown_fields_and_symlinks(self):
        experience = CreativeLookExperience.new()
        candidates = []
        promoted = experience.to_document()
        promoted["processing_binding"] = "TARGET_NATIVE"
        candidates.append(promoted)
        wrong_schema_type = experience.to_document()
        wrong_schema_type["schema_version"] = True
        candidates.append(wrong_schema_type)
        unknown = experience.to_document()
        unknown["camera_command"] = "flash"
        candidates.append(unknown)
        unsafe = experience.to_document()
        unsafe["safety"]["camera_test_eligible"] = True
        candidates.append(unsafe)

        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                CreativeLookExperienceError
            ):
                CreativeLookExperience.from_document(candidate)

        experience.set_mode(intelligent_auto=True)
        with self.assertRaises(CreativeLookExperienceError):
            experience.select_custom_base("Custom1", "ST")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real.json"
            link = root / "link.json"
            real.write_text(json.dumps(experience.to_document()), encoding="utf-8")
            try:
                link.symlink_to(real)
            except OSError:
                self.skipTest("symlinks are unavailable")
            with self.assertRaises(CreativeLookExperienceError):
                load_experience(link)

    @staticmethod
    def _touch(experience, identifier):
        element = experience.frame().element(identifier)
        x, y = element.rect.center
        if not experience.touch(x, y):
            raise AssertionError(f"touch did not activate {identifier}")


if __name__ == "__main__":
    unittest.main()
