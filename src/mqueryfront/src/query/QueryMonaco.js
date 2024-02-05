import React, { Component } from "react";
import * as monaco from "monaco-editor/esm/vs/editor/edcore.main";
import Editor, { loader } from "@monaco-editor/react";
import YARA from "./yara-lang";

loader.config({ monaco });

class QueryMonaco extends Component {
    constructor(props) {
        super(props);
        this.editor = null;
        this.handleEditorDidMount = this.handleEditorDidMount.bind(this);
        this.handleEditorChange = this.handleEditorChange.bind(this);
        this.decorations = null;
    }

    setError(error, startLine, startColumn, endColumn, errorMessage) {
        if (!this.editor || !error) {
            return;
        }

        this.decorations = this.monacoEditor.deltaDecorations(
            [],
            [
                {
                    range: new monaco.Range(
                        Number(startLine),
                        Number(startColumn),
                        Number(startLine),
                        Number(endColumn) + 1 // Increase by one because it excludes end column
                    ),
                    options: {
                        isWholeLine: endColumn === undefined,
                        className: "contentError",
                        glyphMarginClassName: "glyphMargin",
                    },
                },
            ]
        );
    }

    handleEditorChange(value, event) {
        this.props.onValueChanged(value);

        // A dirty hack to clear all decorations when the user
        // started typing after the error has showed
        if (this.decorations) {
            this.monacoEditor.deltaDecorations(this.decorations, []);
        }
    }

    handleEditorDidMount(editor, monaco) {
        this.monacoEditor = editor;
        this.editor = monaco.editor;

        this.editor.addEditorAction({
            id: "submit",
            label: "Submit",
            keybindings: [monaco.KeyMod.CtrlCmd | monaco.KeyCode.Enter],
            run: () => {
                this.props.onSubmitQuery("medium");
            },
        });
    }

    componentWillUnmount() {
        this.editor = null;
    }

    componentDidUpdate(prevProps) {
        if (this.props.error !== prevProps.error) {
            this.setError(...this.props.error);
        }

        //workaround for clearing editor content
        if (
            prevProps.rawYara !== "" &&
            this.props.rawYara === "" &&
            prevProps.readOnly &&
            !this.props.readOnly
        ) {
            this.editor.setValue("");
        }
    }

    render() {
        return (
            <Editor
                name="rawYara"
                height="70vh"
                language="yara"
                theme={this.props.readOnly ? "readOnlyTheme" : "light"}
                value={this.props.rawYara}
                onMount={this.handleEditorDidMount}
                onChange={this.handleEditorChange}
                options={{
                    selectOnLineNumber: true,
                    lineNumbersMinChars: 0,
                    glyphMargin: true,
                    readOnly: this.props.readOnly,
                    automaticLayout: true,
                    hover: {
                        enabled: true,
                    },
                }}
            />
        );
    }
}

/**
 * Monaco editor initialization
 */

loader.init().then((monaco) => {
    // Register a new yara language
    monaco.languages.register({ id: "yara" });

    // Register a tokens provider for yara
    monaco.languages.setMonarchTokensProvider("yara", YARA.TOKEN_PROVIDER);

    // Register a completion item provider for yara
    monaco.languages.registerCompletionItemProvider("yara", {
        provideCompletionItems: () => {
            var suggestions = [
                {
                    label: "rule",
                    kind: monaco.languages.CompletionItemKind.Snippet,
                    insertText: YARA.COMPLETION_RULE,
                    insertTextRules:
                        monaco.languages.CompletionItemInsertTextRule
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
});

export default QueryMonaco;
