import unittest

from pmca.analysis.sources import SourceError, get_source


class SourceTests(unittest.TestCase):
    def test_a6400_tw_source_is_exact(self):
        source = get_source("a6400-tw-v2.00")
        self.assertEqual(source.model, "ILCE-6400")
        self.assertEqual(source.region, "TW")
        self.assertEqual(source.version, "2.00")
        self.assertEqual(source.filename, "Update_ILCE6400V200.exe")
        self.assertEqual(source.advertised_size, 314_230_712)
        self.assertEqual(
            source.page_url,
            "https://www.sony.com.tw/zh/electronics/support/"
            "e-mount-body-ilce-6000-series/ilce-6400/downloads/00016145",
        )

    def test_a6700_tw_source_is_exact(self):
        source = get_source("a6700-tw-v2.00")
        self.assertEqual(source.model, "ILCE-6700")
        self.assertEqual(source.region, "TW")
        self.assertEqual(source.version, "2.00")
        self.assertEqual(source.filename, "BODYDATA.DAT")
        self.assertEqual(source.advertised_size, 1_024_017_848)
        self.assertEqual(
            source.page_url,
            "https://www.sony.com.tw/zh/electronics/support/"
            "e-mount-body-ilce-6000-series/ilce-6700/software/00298440",
        )

    def test_unknown_source_fails_closed(self):
        with self.assertRaises(SourceError):
            get_source("a6700-us-latest")


if __name__ == "__main__":
    unittest.main()
