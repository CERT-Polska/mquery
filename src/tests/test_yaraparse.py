"""
Unit tests for yaraparse
"""

from lib.yaraparse import ursify_hex
from lib.yaraparse import ursify_plain_string
from yaramod import PlainString
from yaramod import YaraRuleBuilder
import yaramod


def test_literal_with_hex():
    hex_str = "3F2504E0"
    result = ursify_hex(hex_str)

    assert result.query == "{3F2504E0}"


def test_literal_without_hex():
    rule = yaramod.YaraRuleBuilder().with_plain_string("$str", "abc")
    print(rule.plain_string)

    ascii_str = PlainString("$str", "abc")

    result = ursify_plain_string(ascii_str)

    print(f"Result: {result.query}")
