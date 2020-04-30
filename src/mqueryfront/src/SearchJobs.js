import React, { Component } from "react";
import { Link } from "react-router-dom";
import ErrorBoundary from "./ErrorBoundary";
import axios from "axios";
import { API_URL } from "./config";
import PriorityIcon from "./components/PriorityIcon";
import ActionClose from "./components/ActionClose";
import ActionCancel from "./components/ActionCancel";
import StatusProgress from "./components/StatusProgress";

class SearchJobRow extends Component {
    constructor(props) {
        super(props);

        this.state = {
            cancelled: false,
        };

        this.handleCancelJob = this.handleCancelJob.bind(this);
    }

    handleCancelJob() {
        axios.delete(API_URL + "/job/" + this.props.id).then((response) => {
            this.setState({ cancelled: true });
        });
    }

    render() {
        const submittedDate = new Date(
            this.props.submitted * 1000
        ).toISOString();

        let status;
        if (this.state.cancelled) {
            status = "cancelled";
        } else {
            status = this.props.status;
        }

        let actionBtn;
        if (
            status === "cancelled" ||
            status === "expired" ||
            status === "done"
        ) {
            actionBtn = <ActionClose onClick={this.props.onClose} />;
        } else {
            actionBtn = <ActionCancel onClick={this.handleCancelJob} />;
        }

        let rule_author = this.props.rule_author
            ? this.props.rule_author
            : "(no author)";

        return (
            <tr>
                <td>
                    <div className="d-flex">
                        <div
                            className="text-truncate"
                            style={{ minWidth: 50, maxWidth: "20vw" }}
                        >
                            <Link
                                to={"/query/" + this.props.id}
                                style={{ fontFamily: "monospace" }}
                            >
                                {this.props.rule_name}
                            </Link>
                        </div>
                        <span className="ml-2">
                            <PriorityIcon priority={this.props.priority} />
                        </span>
                    </div>
                    <p style={{ fontSize: 11 }}>
                        [{rule_author}] {submittedDate}
                    </p>
                </td>
                <td className="align-middle text-center">
                    {this.props.files_matched}
                </td>
                <td className="text-center align-middle">
                    <StatusProgress
                        status={status}
                        total_files={this.props.total_files}
                        files_processed={this.props.files_processed}
                    />
                </td>
                <td className="text-center align-middle">{actionBtn}</td>
            </tr>
        );
    }
}

class SearchJobs extends Component {
    constructor(props) {
        super(props);

        this.state = {
            jobs: [],
            error: null,
        };

        this.handleClose = this.handleClose.bind(this);
    }

    handleClose(id) {
        const jobs = Object.assign([], this.state.jobs).filter(
            (job) => job.id !== id
        );

        this.setState({ jobs: jobs });
    }

    componentDidMount() {
        axios
            .get(API_URL + "/job")
            .then((response) => {
                this.setState({ jobs: response.data.jobs });
            })
            .catch((error) => {
                this.setState({ error: error });
            });
    }

    render() {
        const backendJobRows = this.state.jobs.map((job) => (
            <SearchJobRow
                {...job}
                key={job.id}
                onClose={() => this.handleClose(job.id)}
            />
        ));

        return (
            <ErrorBoundary error={this.state.error}>
                <div className="table-responsive">
                    <table className="table table-striped table-bordered">
                        <thead>
                            <tr>
                                <th>Job name</th>
                                <th className="text-center">Matches</th>
                                <th className="text-center">Status/Progress</th>
                                <th className="text-center">Actions</th>
                            </tr>
                        </thead>
                        <tbody>{backendJobRows}</tbody>
                    </table>
                </div>
            </ErrorBoundary>
        );
    }
}

export default SearchJobs;
