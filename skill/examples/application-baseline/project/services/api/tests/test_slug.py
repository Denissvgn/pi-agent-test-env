import unittest
from slug import slugify


class SlugTests(unittest.TestCase):
    def test_words(self):
        self.assertEqual(slugify("Hello, WORLD!"), "hello-world")

    def test_runs_and_edges(self):
        self.assertEqual(slugify(" --alpha___beta-- "), "alpha-beta")

    def test_empty(self):
        for value in ("", "!!!", "   "):
            self.assertEqual(slugify(value), "")

    def test_ascii_digits(self):
        self.assertEqual(slugify("ITEM 42"), "item-42")

    def test_non_ascii(self):
        self.assertEqual(slugify("caf\u00e9 time"), "caf-time")

    def test_types(self):
        for value in (None, 5, [], b"bytes"):
            with self.assertRaises(TypeError):
                slugify(value)

    def test_idempotent(self):
        for value in ("Clean", " --hello___42", "A B C"):
            result = slugify(value)
            self.assertEqual(slugify(result), result)


if __name__ == "__main__":
    unittest.main()
