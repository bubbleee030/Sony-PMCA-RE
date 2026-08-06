import hashlib
import unittest

from pmca.analysis.creative_style_patch import (
    DEFAULT_GRAPH_SELECTOR_BYTE,
    TARGET_SELECTOR_FILE_OFFSET,
    TYPE_EMNT_SELECTOR_BYTE,
    CreativeStylePatchError,
    patch_creative_style_default_graph,
)


def _fixture(selector_byte=TYPE_EMNT_SELECTOR_BYTE):
    image = bytearray(TARGET_SELECTOR_FILE_OFFSET + 17)
    image[TARGET_SELECTOR_FILE_OFFSET] = selector_byte
    return bytes(image)


class CreativeStylePatchTests(unittest.TestCase):
    def test_changes_only_target_selector_to_default_graph(self):
        source = _fixture()
        expected_sha256 = hashlib.sha256(source).hexdigest()

        patched = patch_creative_style_default_graph(
            source,
            expected_source_sha256=expected_sha256,
            expected_source_size=len(source),
        )

        self.assertEqual(source[TARGET_SELECTOR_FILE_OFFSET], TYPE_EMNT_SELECTOR_BYTE)
        self.assertEqual(patched[TARGET_SELECTOR_FILE_OFFSET], DEFAULT_GRAPH_SELECTOR_BYTE)
        self.assertEqual(
            [index for index, pair in enumerate(zip(source, patched)) if pair[0] != pair[1]],
            [TARGET_SELECTOR_FILE_OFFSET],
        )

    def test_rejects_source_digest_mismatch(self):
        source = _fixture()

        with self.assertRaisesRegex(CreativeStylePatchError, "source SHA-256 mismatch"):
            patch_creative_style_default_graph(
                source,
                expected_source_sha256="00" * 32,
                expected_source_size=len(source),
            )

    def test_rejects_unexpected_selector_byte_even_when_digest_matches(self):
        source = _fixture(selector_byte=0x37)

        with self.assertRaisesRegex(CreativeStylePatchError, "unexpected selector byte"):
            patch_creative_style_default_graph(
                source,
                expected_source_sha256=hashlib.sha256(source).hexdigest(),
                expected_source_size=len(source),
            )

    def test_rejects_source_size_mismatch_before_digest(self):
        source = _fixture()

        with self.assertRaisesRegex(CreativeStylePatchError, "source size mismatch"):
            patch_creative_style_default_graph(
                source,
                expected_source_sha256=hashlib.sha256(source).hexdigest(),
                expected_source_size=len(source) + 1,
            )


if __name__ == "__main__":
    unittest.main()
