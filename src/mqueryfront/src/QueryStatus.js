import React, { Component } from "react";
import axios from "axios/index";
import { API_URL } from "./config";

function MatchItem(props) {
    const metadata = Object.values(props.meta).map((v) => (
        <a href={v.url}>
            {" "}
            <span className="badge badge-pill badge-warning">
                {v.display_text}
            </span>
        </a>
    ));

    const matches = Object.values(props.matches).map((v) => (
        <span>
            {" "}
            <span className="badge badge-pill badge-primary">{v}</span>
        </span>
    ));

    const download_url =
        API_URL +
        "/download?job_id=" +
        encodeURIComponent(props.qhash) +
        "&ordinal=" +
        encodeURIComponent(props.ordinal) +
        "&file_path=" +
        encodeURIComponent(props.file);

    return (
        <tr>
            <a href={download_url}>{props.file}</a>
            {matches}
            {metadata}
        </tr>
    );
}

function ReturnExpiredJob(job_error) {
    return (
        <div className="mquery-scroll-matches">
            {job_error ? (
                <div className="alert alert-danger">{job_error}</div>
            ) : (
                <div />
            )}
            <div style={{ marginTop: "55px" }}>
                Search results expired. Please run the query once again.
            </div>
        </div>
    );
}

class QueryStatus extends Component {
    constructor(props) {
        super(props);

        this.state = {
            qhash: props.qhash,
            job: null,
            matches: [],
            queryPlan: null,
            queryError: null,
            shouldRequest: false,
        };

        this.timeout = null;

        this.reloadStatus = this.reloadStatus.bind(this);
        this.handleCancelJob = this.handleCancelJob.bind(this);
    }

    componentWillMount() {
        this.reloadStatus();
    }

    componentWillUnmount() {
        if (this.timeout !== null) {
            clearTimeout(this.timeout);
        }
    }

    componentWillReceiveProps(newProps) {
        if (this.state.qhash !== newProps.qhash) {
            this.setState({
                job: null,
            });
        }

        this.setState({
            qhash: newProps.qhash,
            queryPlan: newProps.queryPlan,
            queryError: newProps.queryError,
            matches: [],
            shouldRequest: !!newProps.qhash,
        });
    }

    reloadStatus() {
        const LIMIT = 50;

        if (this.state.shouldRequest) {
            axios
                .get(
                    API_URL +
                        "/matches/" +
                        this.state.qhash +
                        "?offset=" +
                        this.state.matches.length +
                        "&limit=" +
                        LIMIT
                )
                .then((response) => {
                    let newShouldRequest = true;

                    if (
                        ["done", "cancelled", "failed", "expired"].indexOf(
                            response.data.job.status
                        ) !== -1
                    ) {
                        if (!response.data.matches.length) {
                            newShouldRequest = false;
                        }
                    }

                    this.setState({
                        matches: [
                            ...this.state.matches,
                            ...response.data.matches,
                        ],
                        job: response.data.job,
                        shouldRequest: newShouldRequest,
                    });

                    let nextTimeout =
                        response.data.matches.length >= LIMIT ? 50 : 1000;
                    this.timeout = setTimeout(
                        () => this.reloadStatus(),
                        nextTimeout
                    );
                });
        } else {
            this.timeout = setTimeout(() => this.reloadStatus(), 100);
        }
    }

    handleCancelJob() {
        axios.delete(API_URL + "/job/" + this.state.qhash);
    }

    render() {
        let error = null;

        if (this.state.queryError) {
            error = this.state.queryError;
        } else if (
            this.state.status &&
            this.state.job &&
            this.state.job.error
        ) {
            error = this.state.job.error;
        }

        if (error) {
            return (
                <div className="alert alert-danger">
                    <h2>Error occurred</h2>
                    {error}
                </div>
            );
        }

        if (this.state.queryPlan) {
            return (
                <div>
                    <h4>Parse result</h4>
                    {this.state.queryPlan.map((rule) => (
                        <div key={rule.rule_name} style={{ marginTop: "55px" }}>
                            <div className="form-group">
                                <label>
                                    <b>{rule.rule_name}</b>
                                    {rule.is_private ? (
                                        <span class="badge badge-info">
                                            private
                                        </span>
                                    ) : null}
                                    {rule.is_global ? (
                                        <span class="badge badge-info">
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
        }

        if (!this.state.qhash) {
            return <div />;
        }

        if (!this.state.job) {
            return (
                <div>
                    <h2>
                        <i className="fa fa-spinner fa-spin spin-big" />{" "}
                        Loading...
                    </h2>
                </div>
            );
        }

        let progress = Math.floor(
            (this.state.job.files_processed * 100) / this.state.job.total_files
        );
        let processed =
            this.state.job.files_processed + " / " + this.state.job.total_files;
        let cancel = (
            <button
                className="btn btn-danger btn-sm"
                onClick={this.handleCancelJob}
            >
                cancel
            </button>
        );

        if (isNaN(progress)) {
            progress = 100
            processed = "-"
        }

        const matches = this.state.matches.map((match, index) => (
            <MatchItem
                {...match}
                qhash={this.state.qhash}
                key={match.file}
                ordinal={index}
            />
        ));

        let progressBg = "bg-info";

        if (this.state.job.status === "done") {
            progressBg = "bg-success";
            cancel = <span />;
        } else if (this.state.job.status === "cancelled") {
            progressBg = "bg-danger";
            cancel = <span />;
        } else if (this.state.job.status === "expired") {
            progressBg = "bg-secondary";
            cancel = <span />;
        }

        const lenMatches = this.state.matches.length;

        if (this.state.job.status === "expired") {
            return ReturnExpiredJob(this.state.job.error);
        }
        
        let results;

        if (lenMatches === 0) {
            results = (
                <div className="alert alert-info">
                    No matches found.
                </div>
            )
        } else {
            results = (
                <table className={"table table-striped table-bordered"}>
                    <thead>
                        <tr>
                            <th>Matches</th>
                        </tr>
                    </thead>
                    <tbody>{matches}</tbody>
                </table>
            )
        }

        return (
            <div className="mquery-scroll-matches">
                <div className="progress" style={{ marginTop: "55px" }}>
                    <div
                        className={"progress-bar " + progressBg}
                        role="progressbar"
                        style={{ width: progress + "%" }}
                    >
                        {progress}%
                    </div>
                </div>
                <div className="row m-0 pt-3">
                    <div className="col-md-2">
                        <p>
                            Matches: <span>{lenMatches}</span>
                        </p>
                    </div>
                    <div className="col-md-3">
                        Status:{" "}
                        <span className="badge badge-dark">
                            {this.state.job.status}
                        </span>
                    </div>
                    <div className="col-md-5">
                        Processed: <span>{processed}</span>
                    </div>
                    <div className="col-md-2">{cancel}</div>
                </div>
                {this.state.job.error ? (
                    <div className="alert alert-danger">
                        {this.state.job.error}
                    </div>
                ) : (
                    <div />
                )}
                {results}
            </div>
        );
    }
}

export default QueryStatus;