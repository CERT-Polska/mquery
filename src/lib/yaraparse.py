import argparse
import itertools
import re
from typing import Any, Dict, List, Match, Optional, cast, Callable

from yaramod import (  # type: ignore
    AllExpression,
    AndExpression,
    AnyExpression,
    EqExpression,
    GtExpression,
    GeExpression,
    LtExpression,
    LeExpression,
    IdExpression,
    IntLiteralExpression,
    OfExpression,
    OrExpression,
    ParenthesesExpression,
    Regexp,
    RegexpConcat,
    RegexpGroup,
    RegexpOr,
    RegexpText,
    SetExpression,
    String,
    StringAtExpression,
    StringCountExpression,
    StringExpression,
    StringInRangeExpression,
    StringWildcardExpression,
    ThemExpression,
    Yaramod,
)


def xor(data: bytes, key: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(data, itertools.cycle(key)))


class YaraParseError(Exception):
    pass


class UrsaExpression:
    """Represents a single Ursadb SELECT expression body. In the future
    this may be represented as an expression tree, for example.

    Examples of valid expressions are:

    "xyz"
    "xyz" & "www"
    ({112233} | "xxx") & "hmm"

    Some UrsaExpressions are "degenerate" expressions - this means that
    they have no useful checks and UrsaDb can't do anything with them.
    Some examples are "", ("" | "abc") or min 2 of ("", "", "abc").
    """

    def __init__(self, query: str, is_degenerate: bool) -> None:
        self.query = query
        self.is_degenerate = is_degenerate

    @classmethod
    def literal(cls, some_string: bytes) -> "UrsaExpression":
        is_degenerate = len(some_string) < 3
        return cls(f"{{{some_string.hex()}}}", is_degenerate)

    @classmethod
    def and_(cls, *args: "UrsaExpression") -> "UrsaExpression":
        is_degenerate = all(x.is_degenerate for x in args)
        return cls(f"({' & '.join(x.query for x in args)})", is_degenerate)

    @classmethod
    def or_(cls, *args: "UrsaExpression") -> "UrsaExpression":
        is_degenerate = any(x.is_degenerate for x in args)
        return cls(f"({' | '.join(x.query for x in args)})", is_degenerate)

    @classmethod
    def min_of(cls, howmany: int, *of: "UrsaExpression") -> "UrsaExpression":
        is_degenerate = sum(x.is_degenerate for x in of) >= howmany
        return cls(
            f"(min {howmany} of ({', '.join(x.query for x in of)}))",
            is_degenerate,
        )


class YaraRuleData:
    def __init__(self, rule, context: Dict[str, "YaraRuleData"]) -> None:
        self.rule = rule
        self.context = context
        self.__parsed: Optional[UrsaExpression] = None

    def __parse_internal(self) -> UrsaExpression:
        strings = {}
        anonymous_no = 0

        for string in self.rule.strings:
            if string.identifier == "$":
                strings[f"anonymous_{anonymous_no}"] = string
                anonymous_no += 1
            else:
                strings[string.identifier] = string

        parser = RuleParseEngine(strings, self.context)
        result = parser.traverse(self.rule.condition)
        if result is not None:
            return result
        return UrsaExpression.literal(b"")

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


def ursify_hex(hex_str: str) -> UrsaExpression:
    # easier to manage
    hex_str = hex_str.replace(" ", "")

    # alternatives, are nested alternatives a thing?
    hex_parts = re.split(r"\(.*\)", hex_str)
    hex_parts = [x for y in hex_parts for x in re.split(r"\[[\d-]+\]", y)]

    output: List[bytes] = []

    for part in hex_parts:
        last_end = None

        # iterate over nibbles
        for i in range(0, len(part), 2):

            if part[i] == "?" or part[i + 1] == "?":
                if last_end is not None:
                    output.append(bytes.fromhex(part[last_end:i]))
                last_end = None
            elif last_end is None:
                last_end = i

        if last_end is not None:
            output.append(bytes.fromhex(part[last_end:]))

    return UrsaExpression.and_(*[UrsaExpression.literal(f) for f in output])


def ursify_nocase_bytes(raw: bytes) -> UrsaExpression:
    out = []
    for c in raw:
        lower = chr(c).lower()
        upper = chr(c).upper()
        if lower == upper:
            out.append(bytes([c]).hex())
        else:
            out.append(f"({lower.encode().hex()}|{upper.encode().hex()})")
    return UrsaExpression(f"{{{ ' '.join(out) }}}", True)


def encode_wide_bytes(raw: bytes) -> bytes:
    return bytes(x for y in raw for x in [y, 0])


def replace_escape(matchobj: Match) -> bytes:
    escapes = {
        b"n": b"\n",
        b"t": b"\t",
        b"r": b"\r",
        b"f": b"\f",
        b"a": b"\a",
        b"b": b"",
        b"B": b"",
    }

    if matchobj.group(2) is not None:
        # hex byte escape
        return bytes.fromhex(matchobj.group(2).decode())
    elif matchobj.group(1) in escapes:
        return escapes[matchobj.group(1)]
    else:
        return matchobj.group(1)


def unescape_regex_text(raw_text: bytes) -> bytes:
    return re.sub(rb"\\([^x]|x([0-9a-fA-F]{2}))", replace_escape, raw_text)


def ursify_regex_text(
    text: bytes,
    is_ascii: bool,
    is_wide: bool,
    is_nocase: bool,
) -> Optional[UrsaExpression]:
    ursa_strings: List[UrsaExpression] = []
    for s in re.split(rb"(?<!\\)\\[wWsSdD]", text):
        unescaped = unescape_regex_text(s)
        if unescaped:
            ursa_strings.append(
                ursify_plain_string(
                    unescaped,
                    is_ascii=is_ascii,
                    is_wide=is_wide,
                    is_nocase=is_nocase,
                )
            )

    if ursa_strings:
        if len(ursa_strings) == 1:
            return ursa_strings[0]
        else:
            return UrsaExpression.and_(*ursa_strings)
    else:
        return None


def flatten_regex_or_tree(unit: Any) -> Optional[List[bytes]]:
    if type(unit) is RegexpText:
        return [unit.text.encode()]
    elif type(unit) is RegexpOr:
        left = flatten_regex_or_tree(unit.left)
        right = flatten_regex_or_tree(unit.right)
        if not left or not right:
            return None
        return left + right
    elif type(unit) is RegexpConcat:
        chars = [flatten_regex_or_tree(u) for u in unit.units]
        string = b""
        for c in chars:
            if c is None:
                return None
            string += c[0]
        return [string]
    else:
        return None


def urisfy_regex_or_tree(
    unit: Any,
    is_ascii: bool,
    is_wide: bool,
    is_nocase: bool,
) -> Optional[UrsaExpression]:
    or_strings = flatten_regex_or_tree(unit)
    if or_strings and all(or_strings):
        or_ursa_strings: List[UrsaExpression] = []
        for s in or_strings:
            ursified_s = ursify_regex_text(
                s, is_ascii=is_ascii, is_wide=is_wide, is_nocase=is_nocase
            )
            if ursified_s:
                or_ursa_strings.append(ursified_s)
            else:
                return None

        if or_ursa_strings:
            return UrsaExpression.or_(*or_ursa_strings)
        else:
            return None
    else:
        return None


def urisfy_regex(
    regex: Any,
    is_ascii: bool = False,
    is_wide: bool = False,
    is_nocase: bool = False,
) -> Optional[UrsaExpression]:
    strings: List[UrsaExpression] = []

    if type(regex) is RegexpConcat:
        units = regex.units
        joined_string = b""
        for i, unit in enumerate(units):
            if type(unit) is RegexpText:
                joined_string += unit.text.encode()
            elif type(unit) is RegexpGroup:
                expression = urisfy_regex_or_tree(
                    unit.unit, is_ascii, is_wide, is_nocase
                )
                if expression:
                    strings.append(expression)

            if joined_string and (
                type(unit) is not RegexpText or i == len(units) - 1
            ):
                ursified_string = ursify_regex_text(
                    joined_string,
                    is_ascii=is_ascii,
                    is_wide=is_wide,
                    is_nocase=is_nocase,
                )
                if ursified_string:
                    strings.append(ursified_string)
                joined_string = b""
    else:
        expression = urisfy_regex_or_tree(regex, is_ascii, is_wide, is_nocase)
        if expression:
            strings.append(expression)

    if strings:
        return UrsaExpression.and_(*strings)
    else:
        return None


def ursify_regex_string(string: Regexp) -> Optional[UrsaExpression]:
    regex_ascii = urisfy_regex(
        string.unit, is_ascii=True, is_nocase=string.is_nocase
    )
    regex_wide = urisfy_regex(
        string.unit, is_wide=True, is_nocase=string.is_nocase
    )

    if not regex_ascii or not regex_wide:
        return None

    if string.is_wide and not string.is_ascii:
        return regex_wide
    elif string.is_wide and string.is_ascii:
        return UrsaExpression.or_(regex_ascii, regex_wide)
    else:
        return regex_ascii


def ursify_plain_string(
    pure_text: bytes,
    is_ascii: bool = False,
    is_wide: bool = False,
    is_nocase: bool = False,
) -> UrsaExpression:
    text_ascii = pure_text
    text_wide = encode_wide_bytes(pure_text)

    if is_nocase:
        ursa_ascii = ursify_nocase_bytes(text_ascii)
        ursa_wide = ursify_nocase_bytes(text_wide)
    else:
        ursa_ascii = UrsaExpression.literal(text_ascii)
        ursa_wide = UrsaExpression.literal(text_wide)

    if is_wide and not is_ascii:
        return ursa_wide
    elif is_wide and is_ascii:
        return UrsaExpression.or_(ursa_ascii, ursa_wide)
    else:
        return ursa_ascii


def ursify_xor_string(string: String) -> UrsaExpression:
    text_ascii = string.pure_text
    xored_strings: List[UrsaExpression] = []

    # TODO implement modifier ranges - https://github.com/CERT-Polska/mquery/issues/100
    for xor_key in range(256):
        xored_ascii = xor(text_ascii, bytes([xor_key]))
        xored_wide = bytes(x ^ xor_key for y in text_ascii for x in [y, 0])

        if string.is_ascii:
            xored_strings.append(UrsaExpression.literal(xored_ascii))
        if string.is_wide:
            xored_strings.append(UrsaExpression.literal(xored_wide))

    return UrsaExpression.or_(*xored_strings)


def ursify_string(string: String) -> Optional[UrsaExpression]:
    if string.is_xor:
        return ursify_xor_string(string)
    elif string.is_plain:
        return ursify_plain_string(
            string.pure_text,
            is_ascii=string.is_ascii,
            is_wide=string.is_wide,
            is_nocase=string.is_nocase,
        )
    elif string.is_hex:
        value_safe = string.pure_text.decode()
        return ursify_hex(value_safe)
    elif string.is_regexp:
        return ursify_regex_string(cast(Regexp, string))

    return None


class RuleParseEngine:
    def __init__(
        self, strings: Dict[str, String], rules: Dict[str, YaraRuleData]
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
        else:
            return None

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
        children = condition.iterable

        if type(children) is SetExpression:
            all_elements = self.expand_set_expression(children)
        elif type(children) is ThemExpression:
            all_elements = [ursify_string(k) for k in self.strings.values()]
        else:
            raise YaraParseError(f"Unsupported of_expr type: {type(children)}")

        parsed_elements = [e for e in all_elements if e is not None]
        unknown_count = len(all_elements) - len(parsed_elements)

        if type(condition.variable) is AllExpression:
            raw_counter = len(all_elements)
        elif type(condition.variable) is AnyExpression:
            raw_counter = 1
        elif type(condition.variable) is IntLiteralExpression:
            raw_counter = condition.variable.value
        else:
            raise RuntimeError(
                f"Unknown of expression type: {type(condition.variable)}"
            )

        counter = raw_counter - unknown_count

        if counter > 0:
            return UrsaExpression.min_of(counter, *parsed_elements)
        else:
            return None

    def gt_expr(self, condition: GtExpression) -> Optional[UrsaExpression]:
        """From `#a > 3` we can deduce, that #a must occur at least once."""
        return self.traverse(condition.left_operand)

    def lt_expr(self, condition: LtExpression) -> Optional[UrsaExpression]:
        """From `3 < #a` we can deduce, that #a must occur at least once."""
        return self.traverse(condition.right_operand)

    def ge_expr(self, condition: GeExpression) -> Optional[UrsaExpression]:
        """From `#a >= y` we can deduce, that #a must occur at least once if y>0."""
        if isinstance(condition.right_operand, IntLiteralExpression):
            if condition.right_operand.value > 0:
                return self.traverse(condition.left_operand)
        return None

    def le_expr(self, condition: LeExpression) -> Optional[UrsaExpression]:
        """From `y <= #a` we can deduce, that #a must occur at least once if y>0."""
        if isinstance(condition.left_operand, IntLiteralExpression):
            if condition.left_operand.value > 0:
                return self.traverse(condition.right_operand)
        return None

    def eq_expr(self, condition: EqExpression) -> Optional[UrsaExpression]:
        """From `x == literal` and literal > 0 we can deduce that x must occur."""
        if isinstance(condition.left_operand, IntLiteralExpression):
            if condition.left_operand.value > 0:
                return self.traverse(condition.right_operand)
        if isinstance(condition.right_operand, IntLiteralExpression):
            if condition.right_operand.value > 0:
                return self.traverse(condition.left_operand)
        return None

    def str_count_expr(
        self, condition: StringCountExpression
    ) -> Optional[UrsaExpression]:
        fixed_id = "$" + condition.id[1:]
        return ursify_string(self.strings[fixed_id])

    def int_lit_expr(
        self, condition: IntLiteralExpression
    ) -> Optional[UrsaExpression]:
        # nothing to do here
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

    CONDITION_HANDLERS: Dict[type, Callable] = {
        AndExpression: and_expr,
        OrExpression: or_expr,
        ParenthesesExpression: pare_expr,
        StringExpression: str_expr,
        OfExpression: of_expr,
        GtExpression: gt_expr,
        GeExpression: ge_expr,
        LtExpression: lt_expr,
        LeExpression: le_expr,
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
