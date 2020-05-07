import React, { Component } from "react";
import Editor, { monaco } from "@monaco-editor/react";
import YARA from "./yara-lang";

class QueryMonaco extends Component {
    constructor(props) {
        super(props);
        this.state = {
            rawYara: props.rawYara,
            editor: null,
            readOnly: false,
            decorations: [],
        };
        this.handleEditorDidMount = this.handleEditorDidMount.bind(this);
        this.decorations = null;
    }

    getValue() {
        if (this.state.editor) {
            return this.state.editor.getValue();
        }
    }

    setValue(newValue) {
        if (this.state.editor) {
            this.state.editor.setValue(newValue);
        }
    }

    setReadOnly(readOnly) {
        if (this.state.editor) {
            this.setState({ readOnly });
        }
    }

    setError(error, startLine, startColumn, endColumn, errorMessage) {
        if (!this.state.editor || !error) {
            return;
        }

        monaco.init().then((monaco) => {
            this.decorations = this.state.editor
                .getModel()
                .deltaDecorations(
                    [],
                    [
                        {
                            range: new monaco.Range(
                                startLine,
                                startColumn,
                                startLine,
                                Number(endColumn) + 1 // Increase by one because it excludes end column
                            ),
                            options: {
                                isWholeLine: endColumn == undefined,
                                className: "contentError",
                                glyphMarginClassName: "glyphMargin",
                            },
                        },
                    ]
                );
        });
    }

    handleEditorDidMount(_, editor) {
        this.setState({ editor });

        monaco
            .init()
            .then((monaco) => {
                // Register a new yara language
                monaco.languages.register({ id: "yara" });

                // Register a tokens provider for yara
                monaco.languages.setMonarchTokensProvider(
                    "yara",
                    YARA.TOKEN_PROVIDER
                );

                // Register a completion item provider for yara
                monaco.languages.registerCompletionItemProvider("yara", {
                    provideCompletionItems: () => {
                        var suggestions = [
                            {
                                label: "rule",
                                kind:
                                    monaco.languages.CompletionItemKind.Snippet,
                                insertText: YARA.COMPLETION_RULE,
                                insertTextRules:
                                    monaco.languages
                                        .CompletionItemInsertTextRule
                                        .InsertAsSnippet,
                                documentation: "Generate a rule skeleton",
                            },
                        ];
                        return { suggestions: suggestions };
                    },
                });

                // We want to have a way to indicate the user that the
                // Editor object is currently in read-only mode
                monaco.editor.defineTheme("readOnlyTheme", {
                    base: "vs",
                    inherit: true,

                    rules: [
                        {
                            token: "",
                            foreground: "565656",
                            background: "ededed",
                        },
                    ],
                    colors: {
                        "editor.background": "#ededed",
                        "editor.foreground": "#121212",
                    },
                });

                // A dirty hack to clear all decorations when the user
                // started typing after the error has showed
                editor.onDidChangeModelContent((ev) => {
                    if (this.state.decorations) {
                        editor.deltaDecorations(this.state.decorations, [
                            {
                                range: new monaco.Range(1, 1, 1, 1),
                                options: {},
                            },
                        ]);
                    }
                });
            })
            .catch((error) =>
                console.error(
                    "An error occurred during initialization of Monaco: ",
                    error
                )
            );
    }

    render() {
        return (
            <Editor
                name="rawYara"
                height="70vh"
                language="yara"
                theme={this.state.readOnly ? "readOnlyTheme" : "light"}
                value={this.state.rawYara}
                editorDidMount={this.handleEditorDidMount}
                options={{
                    selectOnLineNumber: true,
                    lineNumbersMinChars: 0,
                    glyphMargin: true,
                    readOnly: this.state.readOnly,
                    automaticLayout: true,
                    hover: {
                        enabled: true,
                    },
                }}
            />
        );
    }
}

export default QueryMonaco;
