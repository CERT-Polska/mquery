import React, {Component} from 'react';
import filesize from 'filesize';

import ErrorBoundary from './ErrorBoundary';
import axios from 'axios';
import {API_URL} from "./config";


class DatasetRows extends Component {
    render() {
        return <tr>
            <td><code>{this.props.id}</code></td>
            <td>{this.props.indexes.map((x) => {return (
                    <div class="h6">
                        <code>{x.type}</code> ({filesize(x.size, {standard: "iec"})})
                    </div>
                    )
                })}
            </td>
            <td>{filesize(this.props.size, {standard: "iec"})}</td>
        </tr>;
    }
}

class DatabaseTopology extends Component {
    constructor(props) {
        super(props);

        this.state = {
            datasets: [],
            error: null
        }
    }

    componentDidMount() {
        axios
            .get(API_URL + "/backend/datasets")
            .then(response => {
                this.setState({"datasets": response.data.datasets});
            })
            .catch(error => {
                this.setState({"error": error});
            });
    }

    render() {
        const datasetRows = Object.keys(this.state.datasets)
            .map((dataset_id) =>
                <DatasetRows {...this.state.datasets[dataset_id]} id={dataset_id} key={dataset_id} />
            );

        return (
            <ErrorBoundary error={this.state.error}>
                <div className="table-responsive">
                    <table className="table table-striped table-bordered">
                        <thead>
                        <tr>
                            <th>dataset id</th>
                            <th>index types</th>
                            <th>size</th>
                        </tr>
                        </thead>
                        <tbody>
                            {datasetRows}
                        </tbody>
                    </table>
                </div>
            </ErrorBoundary>
        );
    }
}

export default DatabaseTopology;