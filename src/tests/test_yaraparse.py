"""Unit tests for yaraparse."""

from lib.yaraparse import ursify_hex, ursify_plain_string, parse_yara
import yaramod


def test_literal():
    hex_str = "3F2504E0"
    result = ursify_hex(hex_str)

    assert result.query == "({3f2504e0})"


def test_literal_wildcard():
    hex_str = "3F25??04E0"
    result = ursify_hex(hex_str)

    assert result.query == "({3f25} & {04e0})"


def test_literal_alternative():
    hex_str = "11(22|33)44"
    result = ursify_hex(hex_str)

    assert result.query == "({11} & {44})"


def test_literal_to_hex():
    rule = yaramod.YaraRuleBuilder().with_plain_string("$str", "abc").get()

    new_file = yaramod.YaraFileBuilder()
    yara_file = new_file.with_rule(rule).get()

    ascii_str = yara_file.rules[0].strings[0]
    result = ursify_plain_string(ascii_str.pure_text, is_ascii=True)

    assert result.query == "{616263}"


def rule_to_query(rule):
    result = parse_yara(rule)
    (rule,) = result
    parsed = rule.parse()
    return parsed.query


def test_condition_gt():
    query = rule_to_query(
        """
    rule test {
        strings:
            $x = "test"
        condition:
            #x > 1
    }"""
    )
    assert query == "{74657374}"


def test_condition_lt():
    query = rule_to_query(
        """
    rule test {
        strings:
            $x = "test"
        condition:
            1 < #x
    }"""
    )
    assert query == "{74657374}"


def test_condition_ge():
    query = rule_to_query(
        """
    rule test {
        strings:
            $x = "test"
        condition:
            #x >= 1
    }"""
    )
    assert query == "{74657374}"


def test_condition_gt_reversed():
    query = rule_to_query(
        """
    rule test {
        strings:
            $x = "test"
        condition:
            1 < #x
    }"""
    )
    assert query == "{74657374}"


def test_condition_eq():
    query = rule_to_query(
        """
    rule test {
        strings:
            $x = "test"
        condition:
            #x == 1
    }"""
    )
    assert query == "{74657374}"


def test_condition_eq_rev():
    query = rule_to_query(
        """
    rule test {
        strings:
            $x = "test"
        condition:
            1 == #x
    }"""
    )
    assert query == "{74657374}"


def test_condition_eq0():
    query = rule_to_query(
        """
    rule test {
        strings:
            $x = "test"
        condition:
            #x == 0
    }"""
    )
    assert query == "{}"


def test_condition_eq_syms():
    query = rule_to_query(
        """
    rule test {
        strings:
            $x = "test"
            $y = "welp"
        condition:
            #x == #y
    }"""
    )
    assert query == "{}"
