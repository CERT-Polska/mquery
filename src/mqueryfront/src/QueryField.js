import React, { Component } from "react";
import axios from "axios";
import { API_URL } from "./config";
import QueryMonaco from "./QueryMonaco";

class QueryField extends Component {
    constructor(props) {
        super(props);

        this.state = {
            selectedTaint: null,
            error: null,
        };

        this.handleInputChange = this.handleInputChange.bind(this);
        this.handleYaraChanged = this.handleYaraChanged.bind(this);
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

    handleYaraChanged(value) {
        this.props.updateYara(value);
    }

    handleQuery(event, method, priority) {
        const yara = this.props.rawYara;
        axios
            .create()
            .post(API_URL + "/query", {
                raw_yara: yara,
                method: method,
                priority: priority,
                taint: this.state.selectedTaint,
            })
            .then((response) => {
                if (method === "query") {
                    this.props.updateQhash(response.data.query_hash, yara);
                } else if (method === "parse") {
                    this.props.updateQueryPlan(response.data, yara);
                }
            })
            .catch((error) => {
                let err = error.toString();

                if (error.response) {
                    err = error.response.data.detail;
                    // Dirty hack to parse error lines from the error message
                    // Error format: "Error at 4.2-7:" or  "Error at 5.1:"
                    let parsedError = err.match(
                        /Error at (\d+).(\d+)-?(\d+)?: (.*)/
                    );
                    if (parsedError) {
                        this.setState({ error: parsedError });
                    }
                }

                this.props.updateQueryError(err, this.props.rawYara);
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
                            <button
                                className="dropdown-item"
                                onClick={(event) =>
                                    this.handleQuery(event, "query", "low")
                                }
                            >
                                Low Priority Query
                            </button>
                            <button
                                className="dropdown-item"
                                onClick={(event) =>
                                    this.handleQuery(event, "query", "medium")
                                }
                            >
                                Standard Priority Query
                            </button>
                            <button
                                className="dropdown-item"
                                onClick={(event) =>
                                    this.handleQuery(event, "query", "high")
                                }
                            >
                                High Priority Query
                            </button>
                        </div>
                    </div>
                    {this.props.readOnly ? (
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
                            <button
                                className="dropdown-item"
                                onClick={(event) => this.selectTaint(null)}
                            >
                                everywhere
                            </button>
                            {this.props.availableTaints.map((taint) => {
                                return (
                                    <button
                                        className="dropdown-item"
                                        onClick={(event) =>
                                            this.selectTaint(taint)
                                        }
                                    >
                                        {taint}
                                    </button>
                                );
                            })}
                        </div>
                    </div>
                </div>
                <div className="mt-1 monaco-container">
                    <QueryMonaco
                        readOnly={this.props.readOnly}
                        onValueChanged={this.handleYaraChanged}
                        rawYara={this.props.rawYara}
                        error={this.state.error}
                    />
                </div>
            </div>
        );
    }
}

export default QueryField;
