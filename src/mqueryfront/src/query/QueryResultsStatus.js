import React from "react";
import QueryProgressBar from "../components/QueryProgressBar";
import ErrorPage from "../components/ErrorPage";
import QueryMatches from "./QueryMatches";
import PropTypes from "prop-types";
import { PT_JOB, PT_MATCHES, PT_PAGINATION } from "../queryUtils";

const QueryResultsStatus = (props) => {
    const { job, matches, qhash, pagination, onCancel } = props;
    const { status, files_matched } = job;

    if (job.error) {
        return <ErrorPage error={job.error} />;
    }

    if (status === "expired") {
        return (
            <div className="mquery-scroll-matches">
                Search results expired. Please run the query once again.
            </div>
        );
    }

    const results =
        files_matched === 0 ? (
            status === "done" ? (
                <div className="alert alert-info">No matches found.</div>
            ) : null
        ) : (
            <QueryMatches
                matches={matches}
                qhash={qhash}
                pagination={pagination}
            />
        );

    return (
        <div>
            <QueryProgressBar job={job} onCancel={onCancel} />
            {results}
        </div>
    );
};

QueryResultsStatus.propTypes = {
    matches: PT_MATCHES.isRequired,
    job: PT_JOB.isRequired,
    qhash: PropTypes.string,
    pagination: PT_PAGINATION.isRequired,
    onCancel: PropTypes.func.isRequired,
};

export default QueryResultsStatus;
