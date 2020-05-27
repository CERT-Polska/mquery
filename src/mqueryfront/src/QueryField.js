import React, { Component } from "react";
import QueryMonaco from "./QueryMonaco";
import ReactMultiSelectCheckboxes from "react-multiselect-checkboxes";

class QueryField extends Component {
    render() {
        const options = this.props.availableTaints.map((obj) => ({
            label: obj,
            value: obj,
        }));

        let multiselect = null;
        let placeholder = "everywhere";
        if (this.props.selectedTaints.length) {
            placeholder = this.props.selectedTaints
                .map((obj) => obj.value)
                .toString();
            placeholder = placeholder.toString();
        }

        if (this.props.availableTaints.length) {
            multiselect = (
                <ReactMultiSelectCheckboxes
                    onChange={this.props.handleChange}
                    options={options}
                    value={this.props.selectedTaints}
                    placeholderButtonLabel={placeholder}
                />
            );
        }

        return (
            <div>
                <div className="btn-group mb-1" role="group">
                    <button
                        type="button"
                        className="btn btn-success btn-sm"
                        onClick={() => {
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
                                onClick={() => {
                                    this.props.submitQuery("query", "low");
                                }}
                            >
                                Low Priority Query
                            </button>
                            <button
                                className="dropdown-item"
                                onClick={() => {
                                    this.props.submitQuery("query", "medium");
                                }}
                            >
                                Standard Priority Query
                            </button>
                            <button
                                className="dropdown-item"
                                onClick={() => {
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
                            onClick={() => {
                                this.props.submitQuery("parse");
                            }}
                        >
                            <span className="fa fa-code" /> Parse
                        </button>
                    )}
                    {multiselect}
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
