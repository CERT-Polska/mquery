import React, {Component} from 'react';
import ErrorBoundary from './ErrorBoundary';
import axios from 'axios';
import {API_URL} from "./config";


class BackendJobRow extends Component {
    render() {
        return <tr>
            <td>{this.props.id}</td>
            <td>{this.props.connection_id}</td>
            <td><code>{this.props.request}</code></td>
            <td>
                {this.props.work_done} / {this.props.work_estimated}
            </td>
        </tr>;
    }
}

class BackendStatus extends Component {
    constructor(props) {
        super(props);

        this.state = {
            jobs: [],
            error: null
        }
    }

    componentDidMount() {
        axios
            .get(API_URL + "/backend")
            .then(response => {
                this.setState({"jobs": response.data.tasks});
            })
            .catch(error => {
                this.setState({"error": error});
            });
    }

    render() {
        const backendJobRows = this.state.jobs
            .map((job) =>
                <BackendJobRow {...job} key={job.id}/>
            );

        return (
            <ErrorBoundary error={this.state.error}>
                <div className="table-responsive">
                    <table className="table table-striped table-bordered">
                        <thead>
                        <tr>
                            <th>id</th>
                            <th>conn</th>
                            <th>request</th>
                            <th>progress</th>
                        </tr>
                        </thead>
                        <tbody>
                            {backendJobRows}
                        </tbody>
                    </table>
                </div>
            </ErrorBoundary>
        );
    }
}

export default BackendStatus;
