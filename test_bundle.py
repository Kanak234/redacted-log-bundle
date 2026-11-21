import unittest
from bundle import FORMATS, render
import re


class BundleTests(unittest.TestCase):
    def test_overlap(self):
        output, counts = render("abcdef", [(0, 3, "A"), (2, 5, "B")], bytes(32))
        self.assertEqual(counts, {"A+B": 1})
        self.assertRegex(output, r"^\[R-[0-9a-f]{32}\]f$")

    def test_join_and_rotation(self):
        hits = [(0, 1, "X"), (2, 3, "Y")]
        first = render("π π", hits, bytes(32))[0].split()
        self.assertEqual(first[0], first[1])
        self.assertNotEqual(first[0], render("π", [(0, 1, "X")], bytes([1]) * 32)[0])

    def test_empty(self):
        self.assertEqual(render("", [], bytes(32)), ("", {}))

    def test_invalid(self):
        with self.assertRaises(ValueError):
            render("a", [(0, 2, "X")], bytes(32))

    def test_formats(self):
        for pattern, sample in zip(
            FORMATS.values(), ["2345 0000 0000", "ZZZZZ0000Z", "+91 9000000000"]
        ):
            self.assertIsNotNone(re.fullmatch(pattern, sample))
            self.assertIsNone(re.search(pattern, sample + "x"))
