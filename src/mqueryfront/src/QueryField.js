import React, { Component } from "react";
import axios from "axios";
import { API_URL } from "./config";
import QueryMonaco from "./QueryMonaco";

class QueryField extends Component {
    constructor(props) {
        super(props);
        this.editor = React.createRef();

        this.state = {
            rawYara: props.rawYara,
            selectedTaint: null,
        };

        this.handleInputChange = this.handleInputChange.bind(this);
        this.handleQuery = this.handleQuery.bind(this);
        this.handleEdit = this.handleEdit.bind(this);
    }

    componentDidMount() {}

    selectTaint(newTaint) {
        this.setState({
            selectedTaint: newTaint,
        });
    }

    describeTaint() {
        if (this.state.selectedTaint == null) {
            return "everywhere";
        }
        return this.state.selectedTaint;
    }

    static getDerivedStateFromProps(nextProps, prevState) {
        if (
            nextProps.rawYara !== prevState.rawYara ||
            nextProps.readOnly !== prevState.readOnly
        ) {
            return { rawYara: nextProps.rawYara, readOnly: nextProps.readOnly };
        }
    }

    componentDidUpdate(prevProps, prevState) {
        if (
            prevProps.rawYara !== this.state.rawYara ||
            prevProps.readOnly !== this.state.readOnly
        ) {
            this.setState({
                rawYara: this.state.rawYara,
                readOnly: this.state.readOnly,
            });
            this.editor.current.setValue(this.state.rawYara);
            this.editor.current.setReadOnly(this.state.readOnly);
        }
    }

    handleQuery(event, method, priority) {
        axios
            .create()
            .post(API_URL + "/query", {
                raw_yara: this.editor.current.getValue(),
                method: method,
                priority: priority,
                taint: this.state.selectedTaint,
            })
            .then((response) => {
                if (method === "query") {
                    this.props.updateQhash(
                        response.data.query_hash,
                        this.state.rawYara
                    );
                } else if (method === "parse") {
                    this.props.updateQueryPlan(
                        response.data,
                        this.state.rawYara
                    );
                }
            })
            .catch((error) => {
                console.log(error);
                let err = error.toString();

                if (error.response) {
                    err = error.response.data.detail;
                    // Dirty hack to parse error lines from the error message
                    // Error format: "Error at 4.2-7:" or  "Error at 5.1:"
                    this.editor.current.setError(
                        ...err.match(/Error at (\d+).(\d+)-?(\d+)?: (.*)/)
                    );
                }

                this.props.updateQueryError(err, this.state.rawYara);
            });

        event.preventDefault();
    }

    handleInputChange(event) {
        const target = event.target;
        const value =
            target.type === "checkbox" ? target.checked : target.value;
        const name = target.name;

        this.setState({
            [name]: value,
        });
    }

    handleEdit(event) {
        this.props.updateQhash(null);
    }

    render() {
        return (
            <div>
                <div className="btn-group mb-1" role="group">
                    <button
                        type="button"
                        className="btn btn-success btn-sm"
                        onClick={(event) =>
                            this.handleQuery(event, "query", "medium")
                        }
                    >
                        Query
                    </button>
                    <div className="btn-group" role="group">
                        <button
                            type="button"
                            className="btn btn-success dropdown-toggle"
                            data-toggle="dropdown"
                            aria-haspopup="true"
                            aria-expanded="false"
                        />
                        <div className="dropdown-menu">
                            <a
                                className="dropdown-item"
                                href="#"
                                onClick={(event) =>
                                    this.handleQuery(event, "query", "low")
                                }
                            >
                                Low Priority Query
                            </a>
                            <a
                                className="dropdown-item"
                                href="#"
                                onClick={(event) =>
                                    this.handleQuery(event, "query", "medium")
                                }
                            >
                                Standard Priority Query
                            </a>
                            <a
                                className="dropdown-item"
                                href="#"
                                onClick={(event) =>
                                    this.handleQuery(event, "query", "high")
                                }
                            >
                                High Priority Query
                            </a>
                        </div>
                    </div>
                    {this.state.readOnly ? (
                        <button
                            className="btn btn-secondary btn-sm"
                            name="clone"
                            type="submit"
                            onClick={this.handleEdit}
                        >
                            <span className="fa fa-clone" /> Edit
                        </button>
                    ) : (
                        <button
                            className="btn btn-secondary btn-sm"
                            name="parse"
                            type="submit"
                            onClick={(event) =>
                                this.handleQuery(event, "parse", null)
                            }
                        >
                            <span className="fa fa-code" /> Parse
                        </button>
                    )}
                    <div className="btn-group" role="group">
                        <button
                            type="button"
                            className="btn btn-info dropdown-toggle"
                            data-toggle="dropdown"
                            aria-haspopup="true"
                            aria-expanded="false"
                        >
                            Search: {this.describeTaint()}
                        </button>
                        <div className="dropdown-menu">
                            <a
                                className="dropdown-item"
                                href="#"
                                onClick={(event) => this.selectTaint(null)}
                            >
                                everywhere
                            </a>
                            {this.props.availableTaints.map((taint) => {
                                return (
                                    <a
                                        className="dropdown-item"
                                        href="#"
                                        onClick={(event) =>
                                            this.selectTaint(taint)
                                        }
                                    >
                                        {taint}
                                    </a>
                                );
                            })}
                        </div>
                    </div>
                </div>
                <div className="mt-1 monaco-container">
                    <QueryMonaco ref={this.editor} />
                </div>
            </div>
        );
    }
}

export default QueryField;
