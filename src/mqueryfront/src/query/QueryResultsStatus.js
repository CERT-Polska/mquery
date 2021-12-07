import React from "react";
import QueryProgressBar from "../components/QueryProgressBar";
import ErrorPage from "../components/ErrorPage";
import QueryMatches from "./QueryMatches";
import PropTypes from "prop-types";
import { PT_JOB, PT_MATCHES, PT_PAGINATION } from "../queryUtils";

const QueryResultsStatus = (props) => {
    const { job, matches, qhash, pagination, onCancel } = props;
    const { status, files_matched } = job;

    if (status === "expired") {
        return (
            <div className="mquery-scroll-matches">
                Search results expired. Please run the query once again.
            </div>
        );
    }

    let results = null;

    if (job.error) {
        results = (
            <div className="alert alert-danger">
                <b>Job error occured</b>: {job.error}
            </div>
        );
    } else if (files_matched > 0) {
        results = (
            <QueryMatches
                matches={matches}
                qhash={qhash}
                pagination={pagination}
            />
        );
    } else if (status === "done") {
        results = <div className="alert alert-info">No matches found.</div>;
    }

    return (
        <div>
            <QueryProgressBar job={job} onCancel={onCancel} compact={false} />
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
