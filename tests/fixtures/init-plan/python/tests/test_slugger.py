import unittest

import slugger


class SlugTests(unittest.TestCase):
    def test_lowercase(self):
        self.assertEqual(slugger.slug("A b"), "a-b")
