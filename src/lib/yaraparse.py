import argparse
from yaramod import (  # type: ignore
    Yaramod,
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
    IdExpression,
    StringInRangeExpression,
    ThemExpression,
    SetExpression,
)
from typing import Optional, List, Dict
import re


class YaraParseError(Exception):
    pass


class UrsaExpression:
    """ Represents a single Ursadb SELECT expression body. In the future
    this may be represented as an expression tree, for example.

    Examples of valid expressions are:

    "xyz"
    "xyz" & "www"
    ({112233} | "xxx") & "hmm"
    """

    def __init__(self, query: str) -> None:
        self.query = query

    @classmethod
    def and_(cls, *args: "UrsaExpression") -> "UrsaExpression":
        return cls(f"({' & '.join(x.query for x in args)})")

    @classmethod
    def or_(cls, *args: "UrsaExpression") -> "UrsaExpression":
        return cls(f"({' | '.join(x.query for x in args)})")

    @classmethod
    def min_of(cls, howmany: int, *of: "UrsaExpression") -> "UrsaExpression":
        return cls(f"(min {howmany} of ({', '.join(x.query for x in of)}))")


class YaraRuleData:
    def __init__(self, rule, context: Dict[str, "YaraRuleData"]) -> None:
        self.rule = rule
        self.context = context
        self.__parsed: Optional[UrsaExpression] = None

    def __parse_internal(self) -> UrsaExpression:
        strings = {}
        for string in self.rule.strings:
            strings[string.identifier] = string

        parser = RuleParseEngine(strings, self.context)
        result = parser.traverse(self.rule.condition)
        if result is not None:
            return result
        return UrsaExpression("{}")

    def parse(self) -> UrsaExpression:
        if self.__parsed is None:
            self.__parsed = self.__parse_internal()
        return self.__parsed

    @property
    def name(self) -> str:
        return self.rule.name

    @property
    def is_global(self) -> bool:
        return self.rule.is_global

    @property
    def is_private(self) -> bool:
        return self.rule.is_private

    @property
    def author(self) -> str:
        author_meta = self.rule.get_meta_with_name("author")
        if author_meta:
            return author_meta.value.pure_text
        else:
            return ""


def ursify_hex(hex_str: str) -> UrsaExpression:
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
    return UrsaExpression(f"{{{core}}}")


def ursify_string(string) -> Optional[UrsaExpression]:
    if string.is_xor or string.is_nocase:
        return None

    if string.is_plain:
        text = string.pure_text
        if string.is_wide:
            text = bytes(x for y in text for x in [y, 0])
        value_safe = text.hex()
        return UrsaExpression(f"{{{value_safe}}}")
    elif string.is_hex:
        value_safe = string.pure_text.decode()
        return ursify_hex(value_safe)
    elif string.is_regexp:
        # Not supported at this moment
        return None

    return None


class RuleParseEngine:
    def __init__(
        self, strings: Dict[str, str], rules: Dict[str, YaraRuleData]
    ) -> None:
        self.strings = strings
        self.rules = rules

    def and_expr(self, condition: AndExpression) -> Optional[UrsaExpression]:
        left = self.traverse(condition.left_operand)
        right = self.traverse(condition.right_operand)

        if left and right:
            return UrsaExpression.and_(left, right)
        elif not left and not right:
            return None
        else:
            return left or right

    def or_expr(self, condition: OrExpression) -> Optional[UrsaExpression]:
        left = self.traverse(condition.left_operand)
        right = self.traverse(condition.right_operand)

        if left and right:
            return UrsaExpression.or_(left, right)
        elif not left and not right:
            return None
        else:
            return left or right

    def pare_expr(
        self, condition: ParenthesesExpression
    ) -> Optional[UrsaExpression]:
        return self.traverse(condition.enclosed_expr)

    def str_expr(
        self, condition: StringExpression
    ) -> Optional[UrsaExpression]:
        return ursify_string(self.strings[condition.id])

    def expand_string_wildcard(
        self, condition: StringWildcardExpression
    ) -> List[UrsaExpression]:
        condition_regex = re.escape(condition.text)
        condition_regex = condition_regex.replace("\\*", ".*")
        filtered_strings = [
            v for k, v in self.strings.items() if re.match(condition_regex, k)
        ]

        ursa_strings = [ursify_string(x) for x in filtered_strings]
        return [s for s in ursa_strings if s is not None]

    def expand_set_expression(
        self, children: SetExpression
    ) -> List[Optional[UrsaExpression]]:
        parsed_elements: List[Optional[UrsaExpression]] = []
        for e in children.elements:
            if type(e) is StringWildcardExpression:
                parsed_elements += self.expand_string_wildcard(e)
            elif type(e) is StringExpression:
                parsed_elements.append(self.str_expr(e))
            else:
                raise RuntimeError(f"Unknown set expression: {type(e)}")

        return parsed_elements

    def of_expr(self, condition: OfExpression) -> Optional[UrsaExpression]:
        how_many = condition.text[: condition.text.find("of")].strip()

        children = condition.iterated_set

        if type(children) is SetExpression:
            all_elements = self.expand_set_expression(children)
        elif type(children) is ThemExpression:
            all_elements = [ursify_string(k) for k in self.strings.values()]
        else:
            raise YaraParseError(f"Unsupported of_expr type: {type(children)}")

        parsed_elements = [e for e in all_elements if e is not None]
        unknown_count = len(all_elements) - len(parsed_elements)

        if how_many == "all":
            raw_counter = len(all_elements)
        elif how_many == "any":
            raw_counter = 1
        else:
            raw_counter = int(how_many)

        counter = raw_counter - unknown_count

        if counter > 0:
            return UrsaExpression.min_of(counter, *parsed_elements)
        else:
            return None

    def gt_expr(self, condition: GtExpression) -> Optional[UrsaExpression]:
        left = self.traverse(condition.left_operand)
        right = self.traverse(condition.right_operand)
        return left or right

    def eq_expr(self, condition: EqExpression) -> Optional[UrsaExpression]:
        left = self.traverse(condition.left_operand)
        right = self.traverse(condition.right_operand)
        return left or right

    def str_count_expr(
        self, condition: StringCountExpression
    ) -> Optional[UrsaExpression]:
        fixed_id = "$" + condition.id[1:]
        return ursify_string(self.strings[fixed_id])

    def int_lit_expr(
        self, condition: IntLiteralExpression
    ) -> Optional[UrsaExpression]:
        # nothing to be done here
        return None

    def str_at_expr(
        self, condition: StringAtExpression
    ) -> Optional[UrsaExpression]:
        return ursify_string(self.strings[condition.id])

    def id_expr(self, condition: IdExpression) -> Optional[UrsaExpression]:
        return self.rules[condition.symbol.name].parse()

    def str_in_expr(
        self, condition: StringInRangeExpression
    ) -> Optional[UrsaExpression]:
        return ursify_string(self.strings[condition.id])

    CONDITION_HANDLERS = {
        AndExpression: and_expr,
        OrExpression: or_expr,
        ParenthesesExpression: pare_expr,
        StringExpression: str_expr,
        OfExpression: of_expr,
        GtExpression: gt_expr,
        EqExpression: eq_expr,
        StringCountExpression: str_count_expr,
        IntLiteralExpression: int_lit_expr,
        StringAtExpression: str_at_expr,
        IdExpression: id_expr,
        StringInRangeExpression: str_in_expr,
    }

    def traverse(self, condition) -> Optional[UrsaExpression]:
        if type(condition) in self.CONDITION_HANDLERS:
            return self.CONDITION_HANDLERS[type(condition)](self, condition)
        else:
            print(f"unsupported expression: {type(condition)}")
            return None


def parse_yara(yara_rule: str) -> List[YaraRuleData]:
    yar = Yaramod()
    raw_rules = yar.parse_string(yara_rule)

    rules: Dict[str, YaraRuleData] = {}

    for raw_rule in raw_rules.rules:
        rule = YaraRuleData(raw_rule, rules)
        rules[rule.name] = rule

    return list(rules.values())


def combine_rules(rules: List[YaraRuleData]) -> UrsaExpression:
    global_expressions: List[UrsaExpression] = []
    public_expressions: List[UrsaExpression] = []

    for rule in rules:
        if rule.is_global:
            global_expressions.append(rule.parse())
        elif not rule.is_private:
            public_expressions.append(rule.parse())

    print("public", public_expressions)
    print("global", global_expressions)
    return UrsaExpression.and_(
        UrsaExpression.or_(*public_expressions), *global_expressions
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Debug the yara parser.")
    parser.add_argument("filename", help=".yar file to parse")
    parser.add_argument(
        "--combine",
        action="store_true",
        help="Combine rules into one expression",
    )

    args = parser.parse_args()

    with open(args.filename, "r") as f:
        data = f.read()

    rules = parse_yara(data)
    if args.combine:
        print(combine_rules(rules).query)
    else:
        for rule in rules:
            print(rule.name, rule.parse().query)


if __name__ == "__main__":
    main()
