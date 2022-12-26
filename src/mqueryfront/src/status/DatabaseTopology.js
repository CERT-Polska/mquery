import React, { Component } from "react";
import filesize from "filesize";

import ErrorBoundary from "../components/ErrorBoundary";
import api from "../api";

class DatasetRow extends Component {
    render() {
        return [
            <tr
                data-bs-toggle="collapse"
                data-bs-target={"#collapsed_" + this.props.id}
                className="accordion-toggle"
                key={`hdr_${this.props.id}`}
            >
                <td>
                    <code>{this.props.id}</code>
                    {this.props.taints.map((taint) => (
                        <span key={taint}>
                            {" "}
                            <span className="badge bg-secondary">{taint}</span>
                        </span>
                    ))}
                </td>
                <td>
                    {this.props.file_count} files (
                    {filesize(this.props.size, { standard: "iec" })})
                </td>
            </tr>,
            <tr key={`child_${this.props.id}`}>
                <td colSpan="2" className="hiddentablerow p-0">
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
    }

    componentDidMount() {
        api.get("/backend/datasets")
            .then((response) => {
                this.setState({ datasets: response.data.datasets });
            })
            .catch((error) => {
                this.setState({ error: error });
            });
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

        return (
            <ErrorBoundary error={this.state.error}>
                <h2 className="text-center mq-bottom">
                    Topology
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
