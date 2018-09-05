from pyparsing import *
import re
import itertools
import string


class YaraParser(object):
    def __init__(self, parsed_yara):
        self.strings = parsed_yara['strings']
        self.condition = ' '.join(parsed_yara['condition_terms'])

    def get_string_names(self):
        return [s['name'] for s in self.strings]

    def string_to_query(self, value):
        value = value.strip()
        if value[0] == '{' and value[-1] == '}':
            consecutive = ['']
            value = value[1:-1].strip()
            hexdigs = 'ABCDEFabcdef0123456789'
            for c in value.split(' '):
                if len(c) == 2 and c != '??' and (c[0] == '?' or c[1] == '?'):
                    consecutive[-1] += c
                elif len(c) == 2 and c[0] in hexdigs and c[1] in hexdigs:
                    consecutive[-1] += c
                else:
                    consecutive.append('')
            return '(' + ' & '.join('{' + c + '}' for c in consecutive if len(c) >= 6) + ')'
        elif value[0] == '"' and value[-1] == '"':
            return "\"" + value[1:-1] + "\""
        elif value[0] == "\"" and value[-1] == "\"":
            return value
        else:
            assert False

    def act_expression(self, a, d, am):
        if len(am) == 3:
            op = am[1]

            if op == 'and':
                op = '&'
            elif op == 'or':
                op = '|'

            return '({} {} {})'.format(am[0], op, am[2])
        return am

    def act_multiselector(self, a, d, am):
        if am[0] == 'any':
            return '(' + ' | '.join(am[2]) + ')'
        elif am[0] == 'all':
            return '(' + ' & '.join(am[2]) + ')'
        elif am[0].isdigit():
            return '(' + ' | '.join(
                '(' + ' & '.join(opt) + ')' for opt in itertools.combinations(am[2], int(am[0]))) + ')'
        else:
            raise Exception('what')

    def act_list(self, a, d, am):
        l = am[0]
        out = []
        for i in range(len(l)):
            reg = re.escape(l[i])
            reg = reg.replace('\\*', '.*')
            for s in self.get_string_names():
                if re.search(reg, s):
                    out.append(s)
        return [out]

    def act_them(self, a, d, am):
        return [self.get_string_names()]

    def act_ignore(self, a, d, am):
        return []

    def act_variable(self, a, d, am):
        if not am[0].startswith('$'):
            return "()"

    def get_grammar(self):
        atom = Forward()
        expression = Forward()

        variable = Word(string.ascii_lowercase + string.ascii_uppercase + string.digits + "[]._#*$").setParseAction(
            self.act_variable)
        variable_list = Or([
            Literal('(').suppress()
            + Group(variable + ZeroOrMore(Literal(',').suppress() + variable)).setParseAction(self.act_list)
            + Literal(")").suppress(),
            Literal('them').setParseAction(self.act_them)
        ])
        count_specifier = Or([
            Literal('any'),
            Literal('all'),
            Word('0123456789'),
        ])
        bracketed_atom = (Literal('(').suppress() + expression + Literal(')').suppress())
        ignoreme_expr = (variable + '==' + Word(string.digits)).setParseAction(self.act_ignore)
        atom << Or([
            variable,
            ignoreme_expr,
            bracketed_atom,
            (count_specifier + 'of' + variable_list).setParseAction(self.act_multiselector),
        ])
        expression << (atom + Optional(
            Or([
                'and' + expression,
                'or' + expression,
            ]),
        )).setParseAction(self.act_expression)

        return expression + Literal(';').suppress()

    def pre_parse(self):
        grammar = self.get_grammar()
        result = grammar.parseString(self.condition + ';')
        return result.asList()[0]

    def replace_strings(self, cond):
        for string in self.strings:
            name = '(?<=[() ])' + re.escape(string['name']) + '(?=[() ])'

            value = string['value']

            str_q = self.string_to_query(value)

            if 'modifiers' in string and 'wide' in string['modifiers']:
                str_q = 'w' + str_q

            cond = re.sub(name, str_q, cond)
            cond = cond.replace('()', '""')  # "always true"

        return cond

    def parse(self):
        pre_parsed = self.pre_parse()
        return self.replace_strings(pre_parsed)
