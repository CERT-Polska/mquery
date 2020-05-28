import React from "react";
import { PT_QUERYPLAN } from "../queryUtils";

const QueryParseStatus = (props) => {
    const { queryPlan } = props;

    if (!queryPlan) return null;

    const parseResult = queryPlan.map((rule) => {
        const { is_private, is_global, rule_name, parsed } = rule;

        const badge =
            is_private || is_global ? (
                <span className="badge badge-info">
                    {is_private ? "private" : "global"}
                </span>
            ) : null;

        return (
            <div key={rule_name} className="mt-3">
                <div className="form-group">
                    <label>
                        <span className="mr-2 font-weight-bold">
                            {rule_name}
                        </span>
                        {badge}
                    </label>
                    <div className="jumbotron text-monospace text-break p-2">
                        {parsed}
                    </div>
                </div>
            </div>
        );
    });

    return (
        <div>
            <h4>Parse result</h4>
            {parseResult}
        </div>
    );
};

QueryParseStatus.propTypes = {
    queryPlan: PT_QUERYPLAN.isRequired,
};

export default QueryParseStatus;
