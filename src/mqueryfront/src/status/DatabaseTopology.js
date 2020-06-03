import React, { Component } from "react";
import filesize from "filesize";

import ErrorBoundary from "../components/ErrorBoundary";
import axios from "axios";
import { API_URL } from "../config";

class DatasetRow extends Component {
    render() {
        return [
            <tr
                data-toggle="collapse"
                data-target={"#collapsed_" + this.props.id}
                className="accordion-toggle"
            >
                <td>
                    <code>{this.props.id}</code>
                    {this.props.taints.map((taint) => (
                        <span>
                            {" "}
                            <span className="badge badge-secondary">
                                {taint}
                            </span>
                        </span>
                    ))}
                </td>
                <td>
                    {this.props.file_count} files (
                    {filesize(this.props.size, { standard: "iec" })})
                </td>
            </tr>,
            <tr>
                <td colspan="2" className="hiddentablerow p-0">
                    <div
                        className="accordian-body collapse"
                        id={"collapsed_" + this.props.id}
                    >
                        <div className="p-3">
                            {this.props.indexes.map((x) => {
                                return (
                                    <div key={x.type}>
                                        <code>{x.type}</code> (
                                        {filesize(x.size, { standard: "iec" })})
                                    </div>
                                );
                            })}
                        </div>
                    </div>
                </td>
            </tr>,
        ];
    }
}

class DatabaseTopology extends Component {
    constructor(props) {
        super(props);

        this.state = {
            datasets: [],
            error: null,
            startedWork: false,
        };

        this.index = this.index.bind(this);
        this.compact = this.compact.bind(this);
    }

    componentDidMount() {
        axios
            .get(API_URL + "/backend/datasets")
            .then((response) => {
                this.setState({ datasets: response.data.datasets });
            })
            .catch((error) => {
                this.setState({ error: error });
            });
    }

    index() {
        this.setState({ startedWork: true });
        axios.post(API_URL + "/index", {});
    }

    compact() {
        this.setState({ startedWork: true });
        axios.post(API_URL + "/compact", {});
    }

    render() {
        const datasetRows = Object.keys(
            this.state.datasets
        ).map((dataset_id) => (
            <DatasetRow
                {...this.state.datasets[dataset_id]}
                id={dataset_id}
                key={dataset_id}
            />
        ));

        const datasets = Object.values(this.state.datasets);
        const datasetTooltip = `Number of datasets: ${datasets.length}`;
        const totalCount = datasets
            .map((x) => x.file_count)
            .reduce((a, b) => a + b, 0);
        const totalBytes = datasets
            .map((x) => x.size)
            .reduce((a, b) => a + b, 0);
        const totalSize = filesize(totalBytes, { standard: "iec" });
        const filesTooltip = `Total files: ${totalCount} (${totalSize})`;

        const isLocked = this.props.working || this.state.startedWork;
        const workingMsg = "Another operation is in progress";
        const compactMsg = isLocked
            ? workingMsg
            : "Merge datasets with each other (if there are any candidates)";
        const compactButton = (
            <button
                type="button"
                className="btn btn-success"
                data-toggle="tooltip"
                title={compactMsg}
                onClick={this.compact}
                disabled={isLocked}
            >
                compact
            </button>
        );
        const reindexMsg = isLocked
            ? workingMsg
            : "Scan samples directory for new files and index them";
        const reindexButton = (
            <button
                type="button"
                className="btn btn-success"
                data-toggle="tooltip"
                title={reindexMsg}
                onClick={this.index}
                disabled={isLocked}
            >
                reindex
            </button>
        );

        return (
            <ErrorBoundary error={this.state.error}>
                <h2 className="text-center mq-bottom">
                    Topology
                    <div className="btn-group pull-right">
                        {compactButton}
                        {reindexButton}
                    </div>
                </h2>
                <div className="table-responsive">
                    <table className="table table-bordered table-topology">
                        <thead>
                            <tr>
                                <th
                                    data-toggle="tooltip"
                                    title={datasetTooltip}
                                >
                                    Dataset ID
                                </th>
                                <th data-toggle="tooltip" title={filesTooltip}>
                                    # Files (size)
                                </th>
                            </tr>
                        </thead>
                        <tbody>{datasetRows}</tbody>
                    </table>
                </div>
            </ErrorBoundary>
        );
    }
}

export default DatabaseTopology;
