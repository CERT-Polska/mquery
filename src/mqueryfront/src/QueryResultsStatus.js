import React, { Component } from "react";
import axios from "axios/index";
import { API_URL } from "./config";
import Pagination from "react-js-pagination";
import QueryTimer from "./QueryTimer";
import {
    isStatusFinished,
    getProgressBarClass,
    getBadgeClass,
} from "./queryUtils";
import { CopyToClipboard } from "react-copy-to-clipboard";
import ActionCancel from "./components/ActionCancel";
import { faFileAlt, faArchive } from "@fortawesome/free-solid-svg-icons";

function MatchItem(props) {
    const download_url =
        API_URL +
        "/download?job_id=" +
        encodeURIComponent(props.qhash) +
        "&ordinal=" +
        encodeURIComponent(props.ordinal) +
        "&file_path=" +
        encodeURIComponent(props.file);

    const path = require("path");

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

    return (
        <tr>
            <td>
                <div className="row m-0 text-truncate">
                    <div className="text-truncate" style={{ minWidth: 50 }}>
                        <div>
                            {props.meta.sha256.display_text}
                            <small>
                                <a
                                    href={download_url}
                                    data-toggle="tooltip"
                                    title={props.file}
                                    className="text-secondary"
                                >
                                    <i className="fa fa-download fa-xm ml-2" />
                                </a>
                                <CopyToClipboard
                                    text={props.meta.sha256.display_text}
                                    className="copyable-item"
                                >
                                    <span
                                        data-toggle="tooltip"
                                        title="Copy sha256 to clipboard"
                                    >
                                        <i className="fa fa-copy fa-xm ml-2" />
                                    </span>
                                </CopyToClipboard>
                            </small>
                        </div>
                        <small className="text-secondary">
                            {path.basename(props.file)}
                            <CopyToClipboard
                                text={path.basename(props.file)}
                                className="copyable-item"
                            >
                                <span
                                    data-toggle="tooltip"
                                    title="Copy file name to clipboard"
                                >
                                    <i className="fa fa-copy fa-xm ml-2" />
                                </span>
                            </CopyToClipboard>
                        </small>
                        {matches}
                        {metadata}
                    </div>
                </div>
            </td>
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

    componentDidUpdate(prevProps) {
        if (prevProps.qhash !== this.props.qhash) {
            this.setState({ activePage: 1 });
        }
    }

    render() {
        const { job } = this.props;
        const {
            status,
            files_processed,
            total_files,
            files_in_progress,
            files_errored,
            files_matched,
        } = job;

        if (job && job.error) {
            return (
                <div className="alert alert-danger">
                    <h2>Error occurred</h2>
                    {job.error}
                </div>
            );
        }

        if (!job) {
            return (
                <div>
                    <h2>
                        <i className="fa fa-spinner fa-spin spin-big" />{" "}
                        Loading...
                    </h2>
                </div>
            );
        }

        let progress = Math.floor((files_processed * 100) / total_files);
        let processing = Math.round((files_in_progress * 100) / total_files);
        let processed = files_processed + " / " + total_files;

        let errored = Math.round((files_errored / total_files) * 100);
        const errorString = files_errored === 1 ? "error" : "errors";
        const errorTooltip = `${files_errored} ${errorString} during processing`;
        let cancel = <ActionCancel onClick={this.handleCancelJob} size="lg" />;

        if (!total_files && status !== "done") {
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

        const isFinished = isStatusFinished(status);
        if (isFinished) {
            cancel = <span />;
        }

        if (status === "expired") {
            return ReturnExpiredJob(job.error);
        }
        let results = <div />;

        if (files_matched === 0 && status === "done") {
            progress = 100;
            results = <div className="alert alert-info">No matches found.</div>;
        } else if (files_matched !== 0) {
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
                                <th className="col-md-8">
                                    <span className="d-inline-block mr-4">
                                        Matches
                                    </span>
                                    <div className="dropdown d-inline">
                                        <i
                                            className="dropdown-toggle fa fa-download text-secondary"
                                            id="dropdown-download"
                                            data-toggle="dropdown"
                                            aria-haspopup="true"
                                            aria-expanded="false"
                                        ></i>
                                        <div
                                            className="dropdown-menu"
                                            aria-labelledby="dropdown-download"
                                        >
                                            <a
                                                className="dropdown-item"
                                                download={
                                                    this.props.qhash + ".zip"
                                                }
                                                href={
                                                    API_URL +
                                                    "/download/files/" +
                                                    this.props.qhash
                                                }
                                            >
                                                Download files (.zip)
                                            </a>
                                            <a
                                                className="dropdown-item"
                                                download={
                                                    this.props.qhash +
                                                    "_sha256.txt"
                                                }
                                                href={
                                                    API_URL +
                                                    "/download/hashes/" +
                                                    this.props.qhash
                                                }
                                            >
                                                Download sha256 hashes (.txt)
                                            </a>
                                        </div>
                                    </div>
                                </th>
                            </tr>
                        </thead>
                        <tbody>{matches}</tbody>
                    </table>
                    {files_matched > 0 && (
                        <Pagination
                            activePage={this.state.activePage}
                            itemsCountPerPage={this.state.itemsPerPage}
                            totalItemsCount={files_matched}
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
                        className={getProgressBarClass(status)}
                        role="progressbar"
                        style={{ width: progress + "%" }}
                    >
                        {progress}%
                    </div>
                    {total_files > 0 && processing > 0 && (
                        <div
                            className={"progress-bar bg-warning"}
                            role="progressbar"
                            style={{ width: Math.max(3, processing) + "%" }}
                        >
                            {processing}%
                        </div>
                    )}
                    {files_errored > 0 && (
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
                            Matches: <span>{files_matched}</span>
                        </p>
                    </div>
                    <div className="col-md-3">
                        Status:{" "}
                        <span className={getBadgeClass(status)}>{status}</span>
                    </div>
                    <div className="col-md-3">
                        Processed: <span>{processed}</span>
                    </div>
                    <div className="col-md-3" style={{ textAlign: "right" }}>
                        <QueryTimer
                            job={job}
                            isFinished={isFinished}
                            duration={true}
                            countDown={true}
                        />{" "}
                        {cancel}
                    </div>
                </div>
                {job.error ? (
                    <div className="alert alert-danger">{job.error}</div>
                ) : (
                    <div />
                )}
                {results}
            </div>
        );
    }
}

export default QueryResultsStatus;
