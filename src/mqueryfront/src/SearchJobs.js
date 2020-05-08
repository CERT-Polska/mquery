import React, { Component } from "react";
import { Link } from "react-router-dom";
import ErrorBoundary from "./ErrorBoundary";
import axios from "axios";
import { API_URL } from "./config";

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
        const shortId = this.props.id.substr(0, 6);
        const submittedDate = new Date(
            this.props.submitted * 1000
        ).toISOString();
        let rowClass;

        switch (this.props.status) {
            case "done":
                rowClass = "table-success";
                break;
            case "processing":
                rowClass = "table-info";
                break;
            case "querying":
                rowClass = "table-info";
                break;
            case "cancelled":
                rowClass = "table-danger";
                break;
            case "expired":
                rowClass = "table-warning";
                break;
            default:
                rowClass = "";
                break;
        }

        let status = this.props.status;
        let cancelBtn = (
            <button
                className="btn btn-sm btn-danger"
                onClick={this.handleCancelJob}
            >
                cancel
            </button>
        );

        if (this.props.status === "cancelled" || this.state.cancelled) {
            status = "cancelled";
            cancelBtn = <span />;
        }

        if (this.props.status === "expired") {
            cancelBtn = "";
        }

        if (this.props.status === "done") {
            cancelBtn = "";
        }

        let rule_author = this.props.rule_author
            ? this.props.rule_author
            : "(no author)";

        return (
            <tr className={rowClass}>
                <td>
                    <Link
                        to={"/query/" + this.props.id}
                        style={{ fontFamily: "monospace" }}
                    >
                        {this.props.rule_name} ({shortId})
                    </Link>
                    <p style={{ fontSize: "11px" }}>
                        [{rule_author}] {submittedDate}
                    </p>
                </td>
                <td>{this.props.priority}</td>
                <td>{this.props.taint}</td>
                <td>{status}</td>
                <td>
                    {this.props.files_processed} / {this.props.total_files}
                </td>
                <td>{cancelBtn}</td>
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
            <SearchJobRow {...job} key={job.id} />
        ));

        return (
            <ErrorBoundary error={this.state.error}>
                <div className="table-responsive">
                    <table className="table table-striped table-bordered">
                        <thead>
                            <tr>
                                <th>Job name</th>
                                <th>Priority</th>
                                <th>Taints</th>
                                <th>Status</th>
                                <th>Progress</th>
                                <th>Actions</th>
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
