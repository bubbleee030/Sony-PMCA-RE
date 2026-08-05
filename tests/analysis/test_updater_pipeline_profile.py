import unittest


class UpdaterPipelineProfileTests(unittest.TestCase):
    def _describe(self, **overrides):
        try:
            from pmca.analysis.updater_pipeline_profile import (
                UpdaterPipelineProfileError,
                describe_updater_pipeline,
            )
        except ModuleNotFoundError as exc:
            self.fail(f"updater pipeline profile is missing: {exc}")
        values = {
            "raw_fdat_bytes": 304_833_808,
            "decoded_fdat_bytes": 303_642_112,
            "header_bytes": 512,
            "updater_image_bytes": 143_360,
            "firmware_archive_bytes": 303_498_240,
            "outer_trailer_bytes": 0x110,
        }
        values.update(overrides)
        return describe_updater_pipeline(**values), UpdaterPipelineProfileError

    def test_profile_requires_generation4_to_legacy_ecb_transcode(self):
        result, _ = self._describe()

        self.assertEqual(result["ciphertext_bytes"], 304_833_536)
        self.assertEqual(result["crypter_decrypt_mode"], "aes-128-ecb")
        self.assertEqual(result["crypter_key_family"], "historical-first-stage")
        self.assertEqual(result["raw_remainder_mode"], "aes-cbc")
        self.assertEqual(
            result["pre_crypter_transform"],
            "generation4-to-legacy-ecb-transcode-required",
        )
        self.assertEqual(
            result["pre_crypter_transform_implementation"], "unresolved"
        )
        self.assertFalse(result["camera_executed"])
        self.assertFalse(result["installable"])

    def test_profile_hard_stops_on_unknown_geometry(self):
        _, error_type = self._describe()
        cases = (
            {"raw_fdat_bytes": 304_833_809},
            {"decoded_fdat_bytes": 303_642_111},
            {"outer_trailer_bytes": 0x190},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides), self.assertRaises(error_type):
                self._describe(**overrides)


if __name__ == "__main__":
    unittest.main()
