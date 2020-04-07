import React, { Component } from "react";
import filesize from "filesize";

import ErrorBoundary from "./ErrorBoundary";
import axios from "axios";
import { API_URL } from "./config";

class DatasetRow extends Component {
    render() {
        return (
            <tr>
                <td>
                    <code>{this.props.id}</code>
                    {this.props.taints.map((taint) => (
                        <span>
                            {" "}
                            <span class="badge badge-secondary">{taint}</span>
                        </span>
                    ))}
                </td>
                <td>
                    {this.props.indexes.map((x) => {
                        return (
                            <div class="h6">
                                <code>{x.type}</code> (
                                {filesize(x.size, { standard: "iec" })})
                            </div>
                        );
                    })}
                </td>
                <td>{filesize(this.props.size, { standard: "iec" })}</td>
            </tr>
        );
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

    runCompactAll = () => {
        axios.get(API_URL + "/compactall").catch((error) => {
            this.setState({ error: error });
        });
        this.setState({ compacting: true });
    };

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

        return (
            <ErrorBoundary error={this.state.error}>
                <h2 className="text-center mq-bottom">
                    topology
                    <button
                        className="btn btn-danger btn-sm float-right"
                        name="query"
                        type="submit"
                        disabled={this.state.compacting}
                        onClick={this.runCompactAll}
                        title="Compact the db. Warning: this may take a long time"
                    >
                        db compact
                    </button>
                </h2>
                <div className="table-responsive">
                    <table className="table table-striped table-bordered">
                        <thead>
                            <tr>
                                <th>dataset id</th>
                                <th>index types</th>
                                <th>size</th>
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
