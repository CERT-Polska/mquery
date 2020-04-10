import React, { Component } from "react";


class QueryParseStatus extends Component {
    constructor(props) {
        super(props);
    }

    render() {
        if (this.props.queryError) {
            return (
                <div className="alert alert-danger">
                    <h2>Error occurred</h2>
                    {this.props.queryError}
                </div>
            );
        } else if (this.props.queryPlan) {
            return (
                <div>
                    <h4>Parse result</h4>
                    {this.props.queryPlan.map((rule) => (
                        <div key={rule.rule_name} style={{ marginTop: "55px" }}>
                            <div className="form-group">
                                <label>
                                    <b>{rule.rule_name}</b>
                                    {rule.is_private ? (
                                        <span className="badge badge-info">
                                            private
                                        </span>
                                    ) : null}
                                    {rule.is_global ? (
                                        <span className="badge badge-info">
                                            global
                                        </span>
                                    ) : null}
                                </label>
                                <textarea
                                    rows="4"
                                    className="form-control"
                                    value={rule.parsed}
                                    readOnly
                                />
                            </div>
                        </div>
                    ))}
                </div>
            );
        } else {
            return <div />;
        }
    }
}

export default QueryParseStatus;
