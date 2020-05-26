import React, { Component } from "react";
import QueryMonaco from "./QueryMonaco";
import ReactMultiSelectCheckboxes from "react-multiselect-checkboxes";

class QueryField extends Component {
    render() {
        var options = this.props.availableTaints.map(function (obj) {
            return {
                label: obj,
                value: obj,
            };
        });

        var multiselect = null;
        var placeHolder = "everywhere";

        if (this.props.selectedTaints.length) {
            placeHolder = this.props.selectedTaints.map(function (obj) {
                return obj.value;
            });
            placeHolder = placeHolder.toString();
        }

        if (this.props.availableTaints.length) {
            multiselect = (
                <ReactMultiSelectCheckboxes
                    onChange={this.props.handleChange}
                    options={options}
                    defaultValue={this.props.selectedTaints}
                    placeholderButtonLabel={placeHolder}
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
