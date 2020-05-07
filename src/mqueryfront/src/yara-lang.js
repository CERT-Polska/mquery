const YARA = {
    TOKEN_PROVIDER: {
        defaultToken: "invalid",

        keywords: [
            "import",
            "include",
            "rule",
            "meta",
            "strings",
            "condition",
            "global",
            "private",
            "ascii",
            "nocase",
            "wide",
            "xor",
            "fullword",
            "all",
            "any",
            "at",
            "contains",
            "entrypoint",
            "false",
            "filesize",
            "for",
            "in",
            "matches",
            "of",
            "them",
            "true",
            "and",
            "or",
            "not",
        ],

        typeKeywords: [
            "int8",
            "int16",
            "int32",
            "int8be",
            "int16be",
            "int32be",
            "uint16",
            "uint32",
            "uint8be",
            "uint16be",
            "uint32be",
        ],

        operators: [
            "=",
            ">",
            "<",
            "!",
            "~",
            "?",
            ":",
            "==",
            "<=",
            ">=",
            "!=",
            "&&",
            "||",
            "++",
            "--",
            "+",
            "-",
            "*",
            "/",
            "&",
            "|",
            "^",
            "%",
            "<<",
            ">>",
            ">>>",
            "+=",
            "-=",
            "*=",
            "/=",
            "&=",
            "|=",
            "^=",
            "%=",
            "<<=",
            ">>=",
            ">>>=",
        ],

        symbols: /[=><!~?:&|+\-*\/^%]+/,
        escapes: /\\(?:[abfnrtv\\""]|x[0-9A-Fa-f]{1,4}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})/,

        // The main tokenizer for our languages
        tokenizer: {
            root: [
                // identifiers and keywords
                [
                    /[a-z_$][\w$]*/,
                    {
                        cases: {
                            "@keywords": "keyword",
                            "@typeKeywords": "keyword.type",
                            "@default": "identifier",
                        },
                    },
                ],
                [/[A-Z][\w$]*/, "type.identifier"], // to show class names nicely

                // whitespace
                { include: "@whitespace" },

                // delimiters and operators
                [/[{}()\[\]]/, "@brackets"],
                [/[<>](?!@symbols)/, "@brackets"],

                [
                    /@symbols/,
                    {
                        cases: {
                            "@operators": "operator",
                            "@default": "",
                        },
                    },
                ],

                [/#!?\[[^]*\]/, "annotation"],
                [/#!?.*$/, "annotation.invalid"],

                // numbers
                [/\d*\.\d+([eE][\-+]?\d+)?[fFdD]?/, "number.float"],
                [/0[xX][0-9a-fA-F_]*[0-9a-fA-F][Ll]?/, "number.hex"],
                [/0[0-7_]*[0-7][Ll]?/, "number.octal"],
                [/0[bB][0-1_]*[0-1][Ll]?/, "number.binary"],
                [/\d+[lL]?/, "number"],

                // delimiter: after number because of .\d floats
                [/[;,.]/, "delimiter"],

                // strings
                [/"([^"\\]|\\.)*$/, "string.invalid"], // non-teminated string
                [/"/, "string", "@string"],

                // characters
                [/"[^\\"]"/, "string"],
                [/(")(@escapes)(")/, ["string", "string.escape", "string"]],
                [/"/, "string.invalid"],
            ],

            whitespace: [
                [/[ \t\r\n]+/, "white"],
                [/\/\*/, "comment", "@comment"],
                [/\/\/.*$/, "comment"],
            ],

            comment: [
                [/[^\/*]+/, "comment"],
                [/\/\*/, "comment", "@push"],
                [/\/\*/, "comment.invalid"],
                ["\\*/", "comment", "@pop"],
                [/[\/*]/, "comment"],
            ],

            string: [
                [/[^\\"]+/, "string"],
                [/@escapes/, "string.escape"],
                [/\\./, "string.escape.invalid"],
                [/"/, "string", "@pop"],
            ],
        },
    },
    COMPLETION_RULE: [
        "rule ${1:rule_name}",
        "{",
        "\tmeta:",
        '\t\tdescription = "${2:description}"',
        '\t\tauthor = "${3:author}"',
        '\t\tdate = "${CURRENT_YEAR}-${CURRENT_MONTH}-${CURRENT_DATE}"',
        '\t\treference = "${4:reference}"',
        '\t\thash = "${5:hash}"',
        "\tstrings:",
        '\t\t$${6:name} = "${7:string}"',
        "\tcondition:",
        "\t\t${8:all of them}",
        "}",
    ].join("\n"),
};

export default YARA;
