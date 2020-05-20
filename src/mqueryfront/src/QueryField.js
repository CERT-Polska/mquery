import React, { Component } from "react";
import QueryMonaco from "./QueryMonaco";

class QueryField extends Component {
    describeTaint() {
        if (this.props.selectedTaint == null) {
            return "everywhere";
        }
        return this.props.selectedTaint;
    }

    render() {
        return (
            <div>
                <div className="btn-group mb-1" role="group">
                    <button
                        type="button"
                        className="btn btn-success btn-sm"
                        onClick={(event) => {
                            event.preventDefault();
                            this.props.submitQuery("query", "medium");
                        }}
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
                                onClick={(event) => {
                                    event.preventDefault();
                                    this.props.submitQuery("query", "low");
                                }}
                            >
                                Low Priority Query
                            </button>
                            <button
                                className="dropdown-item"
                                onClick={(event) => {
                                    event.preventDefault();
                                    this.props.submitQuery("query", "medium");
                                }}
                            >
                                Standard Priority Query
                            </button>
                            <button
                                className="dropdown-item"
                                onClick={(event) => {
                                    event.preventDefault();
                                    this.props.submitQuery("query", "high");
                                }}
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
                            onClick={this.props.editQuery}
                        >
                            <span className="fa fa-clone" /> Edit
                        </button>
                    ) : (
                        <button
                            className="btn btn-secondary btn-sm"
                            name="parse"
                            type="submit"
                            onClick={(event) => {
                                event.preventDefault();
                                this.props.submitQuery("parse");
                            }}
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
                                onClick={(event) =>
                                    this.props.selectTaint(null)
                                }
                            >
                                everywhere
                            </button>
                            {this.props.availableTaints.map((taint) => {
                                return (
                                    <button
                                        className="dropdown-item"
                                        onClick={(event) =>
                                            this.props.selectTaint(taint)
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
                        onValueChanged={this.props.updateYara}
                        rawYara={this.props.rawYara}
                        error={this.props.error}
                    />
                </div>
            </div>
        );
    }
}

export default QueryField;
