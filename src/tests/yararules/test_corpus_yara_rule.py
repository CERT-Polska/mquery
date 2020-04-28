"""
Yara rule test corpus
"""

import unittest
import os
from lib.yaraparse import combine_rules
from lib.yaraparse import parse_yara


class TestYaraRules(unittest.TestCase):
    def test_regression(self):
        current_path = os.path.abspath(os.path.dirname(__file__))
        testdir = current_path + "/testdata/"

        yara_files = [f for f in os.listdir(testdir) if ".txt" not in f]

        for file in yara_files:
            with open(testdir + file) as f:
                data = f.read()
            rules = parse_yara(data)
            print(combine_rules(rules).query)

            expected_file_txt = file + ".txt"
            with open(testdir + expected_file_txt, "rb") as exp:
                expected_data = exp.read().decode("utf-8")

            self.assertEqual(expected_data, combine_rules(rules).query + "\n")


if __name__ == "__main__":
    unittest.main()
