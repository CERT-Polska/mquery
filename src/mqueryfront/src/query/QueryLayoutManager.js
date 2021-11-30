import React from "react";
import QueryField from "./QueryField";
import QueryResultsStatus from "./QueryResultsStatus";
import QueryParseStatus from "./QueryParseStatus";
import ToggleLayoutButton from "../components/ToggleLayoutButton";
import ErrorPage from "../components/ErrorPage";
import LoadingPage from "../components/LoadingPage";
import PropTypes from "prop-types";
import { PT_JOB, PT_MATCHES, PT_QUERYPLAN, PT_PAGINATION } from "../queryUtils";

const QueryLayoutManager = (props) => {
    const {
        isCollapsed,
        onCollapsePane,
        job,
        matches,
        pagination,
        onCancel,
        qhash,
        queryPlan,
        queryError,
        onSubmitQuery,
        onEditQuery,
        onParseQuery,
        onTaintSelect,
        availableTaints,
        rawYara,
        onYaraUpdate,
        parsedError,
        selectedTaints,
    } = props;

    const queryParse = queryError ? (
        <ErrorPage error={queryError} />
    ) : queryPlan ? (
        <QueryParseStatus queryPlan={queryPlan} />
    ) : null;

    const queryResults = job ? (
        <div>
            <ToggleLayoutButton
                buttonClass="btn btn-primary btn-sm pull-left mr-4"
                onClick={onCollapsePane}
                label={isCollapsed ? "Show query" : "Hide query"}
            />
            <QueryResultsStatus
                qhash={qhash}
                job={job}
                matches={matches}
                pagination={pagination}
                onCancel={onCancel}
            />
        </div>
    ) : (
        <LoadingPage />
    );

    const queryFieldPane = isCollapsed ? null : (
        <div className="col-md-5">
            <QueryField
                readOnly={!!qhash}
                onSubmitQuery={onSubmitQuery}
                onEditQuery={onEditQuery}
                onParseQuery={onParseQuery}
                onTaintSelect={onTaintSelect}
                availableTaints={availableTaints}
                rawYara={rawYara}
                onYaraUpdate={onYaraUpdate}
                parsedError={parsedError}
                selectedTaints={selectedTaints}
            />
        </div>
    );

    const queryResultOrParse = qhash ? queryResults : queryParse;

    return (
        <div className="container-fluid">
            <div className="row wrapper">
                {queryFieldPane}
                <div
                    className={
                        isCollapsed
                            ? "col-md-12"
                            : "col-md-7 order-first order-md-last"
                    }
                >
                    {queryResultOrParse}
                </div>
            </div>
        </div>
    );
};

QueryLayoutManager.propTypes = {
    isCollapsed: PropTypes.bool.isRequired,
    onCollapsePane: PropTypes.func.isRequired,
    job: PT_JOB,
    matches: PT_MATCHES,
    pagination: PT_PAGINATION,
    onCancel: PropTypes.func.isRequired,
    qhash: PropTypes.string,
    queryPlan: PT_QUERYPLAN,
    queryError: PropTypes.string,
    onSubmitQuery: PropTypes.func.isRequired,
    onEditQuery: PropTypes.func.isRequired,
    onParseQuery: PropTypes.func.isRequired,
    onTaintSelect: PropTypes.func.isRequired,
    availableTaints: PropTypes.arrayOf(PropTypes.string).isRequired,
    rawYara: PropTypes.string.isRequired,
    onYaraUpdate: PropTypes.func.isRequired,
    parsedError: PropTypes.arrayOf(PropTypes.string).isRequired,
    selectedTaints: PropTypes.arrayOf(PropTypes.string).isRequired,
};

export default QueryLayoutManager;
