import React, { Component } from "react";
import filesize from "filesize";

import ErrorBoundary from "./ErrorBoundary";
import axios from "axios";
import { API_URL } from "./config";

class DatasetRow extends Component {
    render() {
        return [
            <tr
                data-toggle="collapse"
                data-target={"#collapsed_" + this.props.id}
                class="accordion-toggle"
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
                <td colspan="2" class="hiddentablerow p-0">
                    <div
                        class="accordian-body collapse"
                        id={"collapsed_" + this.props.id}
                    >
                        <div class="p-3">
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
            compacting: false,
            error: null,
        };
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

        let datasets = Object.values(this.state.datasets);
        let datasetTooltip = `Number of datasets: ${datasets.length}`;
        let totalCount = datasets
            .map((x) => x.file_count)
            .reduce((a, b) => a + b, 0);
        let totalBytes = datasets.map((x) => x.size).reduce((a, b) => a + b, 0);
        let totalSize = filesize(totalBytes, { standard: "iec" });
        let filesTooltip = `Total files: ${totalCount} (${totalSize})`;

        return (
            <ErrorBoundary error={this.state.error}>
                <h2 className="text-center mq-bottom">Topology</h2>
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
                                    {" "}
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
