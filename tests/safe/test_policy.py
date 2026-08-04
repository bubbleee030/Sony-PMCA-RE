import struct
import unittest

from pmca.safe.policy import (
    PolicyViolation,
    validate_identity_query,
    validate_service_read,
)


class PolicyTests(unittest.TestCase):
    def test_allows_only_get_model_info(self):
        payload = struct.pack("<IHH8x", 0, 1, 0)

        result = validate_identity_query(1, payload)

        self.assertEqual(result, "DevInfoSender/GetModelInfo")

    def test_denies_other_external_commands_and_malformed_headers(self):
        denied = [
            (1, struct.pack("<IHH8x", 0, 2, 0)),
            (2, struct.pack("<IHH8x", 0, 1, 0)),
            (1, struct.pack("<IHH8x", 1, 1, 0)),
            (1, struct.pack("<IHH8x", 0, 1, 1)),
            (1, b"short"),
        ]
        for group, payload in denied:
            with self.subTest(group=group, payload=payload):
                with self.assertRaises(PolicyViolation):
                    validate_identity_query(group, payload)

    def test_denies_nonzero_identity_padding(self):
        payload = struct.pack("<IHH8x", 0, 1, 0) + b"\x01"

        with self.assertRaises(PolicyViolation):
            validate_identity_query(1, payload)

    def test_allows_only_read_hasp_selector_zero(self):
        payload = struct.pack("<HHB", 0, 0x001F, 0)

        result = validate_service_read(0x0010, payload, None)

        self.assertEqual(result, "ProductInfo/READ_HASP")

    def test_denies_every_unsafe_service_family(self):
        payload = struct.pack("<HHB", 0, 0x001F, 0)
        for pfunc in (
            0x0020,
            0x0030,
            0x0040,
            0xFF00,
            0xFF01,
            0xFF02,
            0xFF03,
        ):
            with self.subTest(pfunc=pfunc):
                with self.assertRaises(PolicyViolation):
                    validate_service_read(pfunc, payload, None)

    def test_denies_terminal_change_selector_length_and_output_sink(self):
        denied = [
            (0x0010, struct.pack("<HHB", 0, 0x00F1, 0), None),
            (0x0010, struct.pack("<HHB", 0, 0x001F, 1), None),
            (0x0010, struct.pack("<HH", 0, 0x001F), None),
            (0x0010, struct.pack("<HHBB", 0, 0x001F, 0, 0), None),
            (0x0010, struct.pack("<HHB", 0, 0x001F, 0), object()),
        ]
        for pfunc, payload, sink in denied:
            with self.subTest(pfunc=pfunc, payload=payload):
                with self.assertRaises(PolicyViolation):
                    validate_service_read(pfunc, payload, sink)


if __name__ == "__main__":
    unittest.main()
