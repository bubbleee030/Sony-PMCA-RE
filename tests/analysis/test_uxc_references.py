import unittest
from unittest import mock

from pmca.analysis import uxc_references
from pmca.analysis.uxc_references import (
    MAX_NEEDLES,
    MAX_UXC_SIZE,
    UxcReferenceError,
    scan_exact_references,
)


class UxcReferenceTests(unittest.TestCase):
    def test_finds_exact_name_and_little_endian_class_id_without_promotion(self):
        name = "Layoutlayout_CMN_M_REC_VERTICAL_CLASSICAL_INFO_LR"
        class_id = 0x61DC811C
        blob = b"prefix\x00" + name.encode("utf-8") + b"\x00" + class_id.to_bytes(
            4, "little"
        )

        references = scan_exact_references(blob, (name,), (class_id,))

        self.assertEqual(
            references,
            [
                {
                    "kind": "name",
                    "value": name,
                    "offset": 7,
                    "semantic": "reference-only",
                },
                {
                    "kind": "class-id",
                    "value": "0x61dc811c",
                    "offset": 7 + len(name.encode("utf-8")) + 1,
                    "semantic": "reference-only",
                },
            ],
        )

    def test_reports_duplicate_occurrences_in_deterministic_offset_order(self):
        name = "LayoutOne"
        class_id = 0x10203040
        little = class_id.to_bytes(4, "little")
        blob = b"\x00" + little + b"\x00" + name.encode() + b"\x00" + little

        references = scan_exact_references(blob, (name,), (class_id,))

        self.assertEqual([item["offset"] for item in references], [1, 6, 16])
        self.assertEqual(
            [item["kind"] for item in references],
            ["class-id", "name", "class-id"],
        )

    def test_name_match_requires_exact_utf8_identifier_boundaries(self):
        name = "Layout設定"
        encoded = name.encode("utf-8")
        blob = b"X" + encoded + b"Y\x00" + encoded + b"\x00"

        references = scan_exact_references(blob, (name,), ())

        self.assertEqual(len(references), 1)
        self.assertEqual(references[0]["offset"], len(encoded) + 3)

    def test_class_id_scan_is_little_endian_only(self):
        class_id = 0x12345678
        blob = class_id.to_bytes(4, "big") + class_id.to_bytes(4, "little")

        references = scan_exact_references(blob, (), (class_id,))

        self.assertEqual([item["offset"] for item in references], [4])

    def test_missing_needles_return_empty_results(self):
        self.assertEqual(
            scan_exact_references(b"unrelated", ("LayoutMissing",), (0x11223344,)),
            [],
        )

    def test_rejects_oversized_or_mutable_input_and_invalid_needles(self):
        candidates = [
            (b"\x00" * (MAX_UXC_SIZE + 1), (), ()),
            (bytearray(b"safe"), (), ()),
            (b"safe", ("duplicate", "duplicate"), ()),
            (b"safe", ("",), ()),
            (b"safe", (["not-text"],), ()),
            (b"safe", (), (1, 1)),
            (b"safe", (), ([1],)),
            (b"safe", (), (-1,)),
            (b"safe", (), (0x1_0000_0000,)),
        ]

        for blob, names, class_ids in candidates:
            with self.subTest(blob_type=type(blob), names=names, class_ids=class_ids):
                with self.assertRaises(UxcReferenceError):
                    scan_exact_references(blob, names, class_ids)

    def test_rejects_more_than_the_fixed_needle_cap(self):
        names = tuple(f"Layout{index}" for index in range(MAX_NEEDLES + 1))
        class_ids = tuple(range(MAX_NEEDLES + 1))

        for candidate_names, candidate_class_ids in (
            (names, ()),
            ((), class_ids),
        ):
            with self.subTest(
                names=len(candidate_names), class_ids=len(candidate_class_ids)
            ):
                with self.assertRaises(UxcReferenceError):
                    scan_exact_references(
                        b"bounded", candidate_names, candidate_class_ids
                    )

    def test_rejects_more_than_the_fixed_reference_cap(self):
        class_id = 0x10203040
        blob = class_id.to_bytes(4, "little") * 2

        with mock.patch.object(uxc_references, "MAX_REFERENCES", 1):
            with self.assertRaises(UxcReferenceError):
                scan_exact_references(blob, (), (class_id,))


if __name__ == "__main__":
    unittest.main()
