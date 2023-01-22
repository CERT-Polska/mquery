import React from "react";
import QueryProgressBar from "../components/QueryProgressBar";
import QueryMatches from "./QueryMatches";

const QueryResultsStatus = (props) => {
    const { job, matches, qhash, pagination, onCancel } = props;
    const { status, files_matched } = job;
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

export default QueryResultsStatus;
