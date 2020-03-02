from yaramod import Yaramod  # type: ignore
from yaramod import (
    AndExpression,
    StringCountExpression,
    IntLiteralExpression,
    ParenthesesExpression,
    GtExpression,
    EqExpression,
    OrExpression,
    StringExpression,
    OfExpression,
    StringWildcardExpression,
    StringAtExpression,
)
from yaramod import ThemExpression, SetExpression
import sys
from typing import Optional, List
import re


class YaraParseError(Exception):
    pass


def ursify_hex(hex_str: str) -> str:
    # easier to manage
    hex_str = hex_str.replace(" ", "")

    # alternatives, are nested alternatives a thing?
    hex_parts = re.split(r"\(.*?\)", hex_str)
    hex_parts = [x for y in hex_parts for x in re.split(r"\[[\d-]+\]", y)]

    output: List[str] = []

    for part in hex_parts:
        last_end = None

        # iterate over nibbles
        for i in range(0, len(part), 2):

            if part[i] == "?" or part[i + 1] == "?":
                if last_end is not None:
                    output.append(part[last_end:i])
                last_end = None
            elif last_end is None:
                last_end = i

        if last_end is not None:
            output.append(part[last_end:])

    core = "} & {".join(output)
    return f"{{{core}}}"


def ursify_string(string) -> Optional[str]:
    if string.is_xor or string.is_nocase:
        return None

    if string.is_plain:
        text = string.pure_text
        if string.is_wide:
            text = bytes(x for y in text for x in [y, 0])
        value_safe = text.hex()
        return f"{{{value_safe}}}"
    elif string.is_hex:
        value_safe = string.pure_text.decode()
        return ursify_hex(value_safe)
    elif string.is_regexp:
        # Not supported at this moment
        return None

    return None


def and_expr(condition, rule_strings) -> Optional[str]:
    left = yara_traverse(condition.left_operand, rule_strings)
    right = yara_traverse(condition.right_operand, rule_strings)

    if left and right:
        return f"({left} & {right})"
    elif not left and not right:
        return None
    else:
        return left or right


def or_expr(condition, rule_strings) -> Optional[str]:
    left = yara_traverse(condition.left_operand, rule_strings)
    right = yara_traverse(condition.right_operand, rule_strings)

    if left and right:
        return f"({left} | {right})"
    elif not left and not right:
        return None
    else:
        return left or right


def pare_expr(condition, rule_strings) -> Optional[str]:
    inner = yara_traverse(condition.enclosed_expr, rule_strings)
    if inner:
        return f"({inner})"
    else:
        return None


def str_expr(condition, rule_strings) -> Optional[str]:
    return ursify_string(rule_strings[condition.id])


def str_wild_expr(condition, rule_strings) -> Optional[str]:
    condition_regex = re.escape(condition.text)
    condition_regex = condition_regex.replace("\\*", ".*")
    filtered_strings = [
        v for k, v in rule_strings.items() if re.match(condition_regex, k)
    ]

    ursa_strings = [ursify_string(x) for x in filtered_strings]
    strings = [s for s in ursa_strings if s is not None]

    if strings:
        return ", ".join(strings)
    return None


def of_expr(condition, rule_strings) -> Optional[str]:
    how_many = condition.text[: condition.text.find("of")].strip()
    counter = None

    children = condition.iterated_set
    parsed_elements = []

    if type(children) is SetExpression:
        elements = condition.iterated_set.elements
        parsed_elements = list(
            filter(None, [yara_traverse(e, rule_strings) for e in elements])
        )
    elif type(children) is ThemExpression:
        parsed_elements = list(
            filter(None, [ursify_string(k) for k in rule_strings.values()])
        )
    else:
        raise YaraParseError(f"Unsupported of_expr type: {type(children)}")

    if how_many == "all":
        counter = len(parsed_elements)
    elif how_many == "any":
        counter = 1
    else:
        counter = int(how_many)

    if parsed_elements:
        core = f", ".join(parsed_elements)
        return f"min {counter} of ({core})"
    else:
        return None


def gt_expr(condition, rule_strings) -> Optional[str]:
    left = yara_traverse(condition.left_operand, rule_strings)
    right = yara_traverse(condition.right_operand, rule_strings)
    return left or right


def eq_expr(condition, rule_strings) -> Optional[str]:
    left = yara_traverse(condition.left_operand, rule_strings)
    right = yara_traverse(condition.right_operand, rule_strings)
    return left or right


def str_count_expr(condition, rule_strings) -> Optional[str]:
    fixed_id = "$" + condition.id[1:]
    return ursify_string(rule_strings[fixed_id])


def int_lit_expr(condition, rule_strings) -> Optional[str]:
    # nothing to be done here
    return None


def str_at_expr(condition, rule_strings) -> Optional[str]:
    return ursify_string(rule_strings[condition.id])


CONDITION_HANDLERS = {
    AndExpression: and_expr,
    OrExpression: or_expr,
    ParenthesesExpression: pare_expr,
    StringExpression: str_expr,
    StringWildcardExpression: str_wild_expr,
    OfExpression: of_expr,
    GtExpression: gt_expr,
    EqExpression: eq_expr,
    StringCountExpression: str_count_expr,
    IntLiteralExpression: int_lit_expr,
    StringAtExpression: str_at_expr,
}


def yara_traverse(condition, rule_strings) -> Optional[str]:
    if type(condition) in CONDITION_HANDLERS:
        return CONDITION_HANDLERS[type(condition)](condition, rule_strings)
    else:
        print(f"unsupported expression: {type(condition)}")
        return None


def parse_string(yara_string: str) -> str:
    yar = Yaramod()
    rules = yar.parse_string(yara_string)

    assert len(rules.rules) == 1

    rule = rules.rules[0]

    rule_strings = {}
    for string in rule.strings:
        rule_strings[string.identifier] = string

    result = yara_traverse(rule.condition, rule_strings)
    if result is not None:
        return result
    return "{}"


def main() -> None:
    with open(sys.argv[1], "r") as f:
        data = f.read()

    ursa_query = parse_string(data)
    print(ursa_query)


if __name__ == "__main__":
    main()
