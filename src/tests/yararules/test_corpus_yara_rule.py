"""
Yara rule test corpus
"""

import unittest
import os
from lib.yaraparse import combine_rules
from lib.yaraparse import parse_yara

current_path = os.path.abspath(os.path.dirname(__file__))
testdir = current_path + "/testdata/"


class TestYaraRules(unittest.TestCase):
    def test_regression(self):

        yara_files = [f for f in os.listdir(testdir) if f.endswith('.yar')]

        for filename in yara_files:
            with open(testdir + filename) as f:
                data = f.read()

            expected_file_txt = filename[:-4] + ".txt"
            self.assert_query(data, expected_file_txt)

    def assert_query(self, data, expected_file_txt):
        try:
            rules = parse_yara(data)
            print(combine_rules(rules).query)

            with open(testdir + expected_file_txt, "rb") as exp:
                expected_data = exp.read().decode("utf-8")
            self.assertEqual(expected_data, combine_rules(rules).query + "\n")
        except Exception as e:
            with open(testdir + expected_file_txt, "rb") as exp:
                expected_data = exp.read().decode("utf-8")
            self.assertEqual(expected_data, str(e) + "\n")


if __name__ == "__main__":
    unittest.main()
