import React from "react";
import QueryField from "./QueryField";
import QueryResultsStatus from "./QueryResultsStatus";
import QueryParseStatus from "./QueryParseStatus";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faAlignLeft } from "@fortawesome/free-solid-svg-icons";
import ErrorPage from "../components/ErrorPage";
import LoadingPage from "../components/LoadingPage";

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
            <button
                type="button"
                className="btn btn-primary btn-sm pull-left me-4"
                onClick={onCollapsePane}
            >
                <FontAwesomeIcon icon={faAlignLeft} />
                {isCollapsed ? "Show query" : "Hide query"}
            </button>
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

    const queryResultOrParse = qhash ? queryResults : queryParse;

    const queryFieldPane = isCollapsed ? null : (
        <div className={queryResultOrParse ? "col-md-6" : "col-md-12"}>
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

    return (
        <div className="container-fluid">
            <div className="row wrapper">
                {queryFieldPane}
                <div
                    className={
                        isCollapsed
                            ? "col-md-12"
                            : "col-md-6 order-first order-md-last"
                    }
                >
                    {queryResultOrParse}
                </div>
            </div>
        </div>
    );
};

export default QueryLayoutManager;
