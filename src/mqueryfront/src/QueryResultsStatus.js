import React, { Component } from "react";
import axios from "axios/index";
import { API_URL } from "./config";
import Pagination from "react-js-pagination";
import QueryTimer from "./QueryTimer";
import { finishedStatuses } from "./QueryUtils";
import { CopyToClipboard } from "react-copy-to-clipboard";

function MatchItem(props) {
    const metadata = Object.values(props.meta)
        .filter((v) => !v.hidden)
        .map((v) => (
            <a href={v.url} key={v}>
                {" "}
                <span className="badge badge-pill badge-warning">
                    {v.display_text}
                </span>
            </a>
        ));

    let hashes = Object.values(props.meta)
        .filter((v) => v.hidden)
        .map((v) => (
            <CopyToClipboard text={v.display_text} key={v}>
                <div
                    style={{ fontFamily: "monospace" }}
                    data-toggle="tooltip"
                    title="Click to copy"
                >
                    {v.display_text}
                </div>
            </CopyToClipboard>
        ));

    let matches = <span></span>;
    if (props.matches) {
        matches = Object.values(props.matches).map((v) => (
            <span key={v}>
                <div className="badge badge-pill badge-primary ml-1 mt-1">
                    {v}
                </div>
            </span>
        ));
    }

    const download_url =
        API_URL +
        "/download?job_id=" +
        encodeURIComponent(props.qhash) +
        "&ordinal=" +
        encodeURIComponent(props.ordinal) +
        "&file_path=" +
        encodeURIComponent(props.file);

    const path = require("path");

    return (
        <tr>
            <td>
                <div className="row m-0 text-truncate">
                    <div className="text-truncate" style={{ minWidth: 50 }}>
                        <a
                            href={download_url}
                            data-toggle="tooltip"
                            title={props.file}
                        >
                            {path.basename(props.file)}
                        </a>
                    </div>
                    {matches}
                    {metadata}
                </div>
            </td>
            {props.collapsed ? <td>{hashes}</td> : null}
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

class QueryResultsStatus extends Component {
    constructor(props) {
        super(props);

        this.state = {
            activePage: 1,
            itemsPerPage: 20,
        };

        this.handleCancelJob = this.handleCancelJob.bind(this);
    }

    handleCancelJob() {
        axios.delete(API_URL + "/job/" + this.props.qhash);
    }

    sendResultsActivePage = (pageNumber) => {
        this.props.parentCallback(pageNumber);
    };

    handlePageChange(pageNumber) {
        this.setState({ activePage: pageNumber });
        this.sendResultsActivePage(pageNumber);
    }

    renderSwitchStatus(status) {
        switch (status) {
            case "done":
                return "success";
            case "cancelled":
                return "danger";
            case "expired":
                return "warning";
            case "processing":
            case "querying":
                return "info";
            default:
                return "info";
        }
    }

    componentDidUpdate(prevProps) {
        if (prevProps.qhash !== this.props.qhash) {
            this.setState({ activePage: 1 });
        }
    }

    render() {
        if (this.props.job && this.props.job.error) {
            return (
                <div className="alert alert-danger">
                    <h2>Error occurred</h2>
                    {this.props.job.error}
                </div>
            );
        }

        if (!this.props.job) {
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
            (this.props.job.files_processed * 100) / this.props.job.total_files
        );
        let processing = Math.round(
            (this.props.job.files_in_progress * 100) /
                this.props.job.total_files
        );
        let processed =
            this.props.job.files_processed + " / " + this.props.job.total_files;
        let errored = Math.round(
            (this.props.job.files_errored / this.props.job.total_files) * 100
        );
        let errorTooltip = `${this.props.job.files_errored} errors during processing`;
        let cancel = (
            <button
                className="btn btn-danger btn-sm"
                onClick={this.handleCancelJob}
            >
                cancel
            </button>
        );

        if (!this.props.job.total_files && this.props.job.status !== "done") {
            progress = 0;
            processed = "-";
        }

        const matches = this.props.matches.map((match, index) => (
            <MatchItem
                {...match}
                qhash={this.props.qhash}
                key={match.file}
                ordinal={index}
                collapsed={this.props.collapsed}
            />
        ));

        let progressBg = "bg-" + this.renderSwitchStatus(this.props.job.status);

        if (finishedStatuses.includes(this.props.job.status)) {
            cancel = <span />;
        }

        const lenMatches = this.props.job.files_matched;

        if (this.props.job.status === "expired") {
            return ReturnExpiredJob(this.props.job.error);
        }
        let results = <div />;

        if (lenMatches === 0 && this.props.job.status === "done") {
            progress = 100;
            results = <div className="alert alert-info">No matches found.</div>;
        } else if (lenMatches !== 0) {
            const styleFixed = {
                tableLayout: "fixed",
            };
            results = (
                <div className="mquery-scroll-matches">
                    <table
                        className={"table table-striped table-bordered"}
                        style={styleFixed}
                    >
                        <thead>
                            <tr>
                                <th className="col-md-8">Matches</th>
                                {this.props.collapsed && (
                                    <th className="col-md-4 d-none d-sm-table-cell">
                                        SHA256
                                    </th>
                                )}
                            </tr>
                        </thead>
                        <tbody>{matches}</tbody>
                    </table>
                    {lenMatches > 0 && (
                        <Pagination
                            activePage={this.state.activePage}
                            itemsCountPerPage={this.state.itemsPerPage}
                            totalItemsCount={lenMatches}
                            pageRangeDisplayed={5}
                            onChange={this.handlePageChange.bind(this)}
                            itemClass="page-item"
                            linkClass="page-link"
                        />
                    )}
                </div>
            );
        }
        return (
            <div>
                <div className="progress" style={{ marginTop: "55px" }}>
                    <div
                        className={"progress-bar " + progressBg}
                        role="progressbar"
                        style={{ width: progress + "%" }}
                    >
                        {progress}%
                    </div>
                    {this.props.job.total_files > 0 && processing > 0 && (
                        <div
                            className={"progress-bar bg-warning"}
                            role="progressbar"
                            style={{ width: Math.max(3, processing) + "%" }}
                        >
                            {processing}%
                        </div>
                    )}
                    {this.props.job.files_errored > 0 && (
                        <div
                            className={"progress-bar bg-danger"}
                            role="progressbar"
                            style={{ width: Math.max(3, errored) + "%" }}
                            data-toggle="tooltip"
                            title={errorTooltip}
                        />
                    )}
                </div>
                <div className="row m-0 pt-3">
                    <div className="col-md-3">
                        <p>
                            Matches: <span>{lenMatches}</span>
                        </p>
                    </div>
                    <div className="col-md-3">
                        Status:{" "}
                        <span
                            className={
                                "badge badge-" +
                                this.renderSwitchStatus(this.props.job.status)
                            }
                        >
                            {this.props.job.status}
                        </span>
                    </div>
                    <div className="col-md-3">
                        Processed: <span>{processed}</span>
                    </div>
                    <div className="col-md-3" style={{ textAlign: "right" }}>
                        <QueryTimer
                            job={this.props.job}
                            finishStatus={finishedStatuses}
                            duration={true}
                            countDown={true}
                        />{" "}
                        {cancel}
                    </div>
                </div>
                {this.props.job.error ? (
                    <div className="alert alert-danger">
                        {this.props.job.error}
                    </div>
                ) : (
                    <div />
                )}
                {results}
            </div>
        );
    }
}

export default QueryResultsStatus;
