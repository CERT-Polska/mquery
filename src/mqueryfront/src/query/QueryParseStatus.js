import React from "react";

const QueryParseStatus = (props) => {
    const { queryPlan } = props;

    if (!queryPlan) return null;

    const parseResult = queryPlan.map((rule) => {
        const { is_private, is_global, is_degenerate, rule_name, parsed } = rule;

        const private_badge =is_private ?(
                <span className="badge bg-info">private</span>
            ) : null;
        const global_badge =is_global?(
                <span className="badge bg-info">private</span>
            ) : null;
        const degenerate_badge =is_degenerate?(
                <span className="badge bg-danger">degenerate</span>
            ) : null;
        const badges = <>{private_badge} {global_badge} {degenerate_badge}</>;

        return (
            <div key={rule_name} className="mt-3">
                <div className="form-group">
                    <label>
                        <span className="me-2 font-weight-bold">
                            {rule_name}
                        </span>
                        {badges}
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

export default QueryParseStatus;
