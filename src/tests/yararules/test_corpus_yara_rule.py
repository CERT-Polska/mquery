"""Yara rule test corpus."""

import unittest
from pathlib import Path
from lib.yaraparse import combine_rules  # type: ignore
from lib.yaraparse import parse_yara  # type: ignore

testdir = Path(__file__).parent / "testdata"


class TestYaraRules(unittest.TestCase):
    def test_regression(self) -> None:
        for yara_path in testdir.glob("*.yar"):
            self.assert_query(yara_path, yara_path.with_suffix(".txt"))

    def assert_query(self, yara_path: Path, results_path: Path) -> None:
        expected_data = results_path.read_text()
        try:
            rules = parse_yara(yara_path.read_text())
            self.assertEqual(expected_data, combine_rules(rules).query + "\n")
        except Exception as e:
            self.assertEqual(expected_data, str(e) + "\n")


if __name__ == "__main__":
    unittest.main()
