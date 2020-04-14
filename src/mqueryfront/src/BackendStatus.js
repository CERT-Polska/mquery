import React, { Component } from "react";

class BackendJobRow extends Component {
    render() {
        return (
            <tr>
                <td>{this.props.id}</td>
                <td>{this.props.connection_id}</td>
                <td>
                    <code>{this.props.request}</code>
                </td>
                <td>
                    {this.props.work_done} / {this.props.work_estimated}
                </td>
            </tr>
        );
    }
}

class BackendStatus extends Component {
    render() {
        const backendJobRows = this.props.jobs.map((job) => (
            <BackendJobRow {...job} key={job.id} />
        ));

        return (
            <div>
                <h2 className="text-center mq-bottom">Current Connections</h2>
                <div className="table-responsive">
                    <table className="table table-striped table-bordered">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Connection</th>
                                <th>Request</th>
                                <th>Progress</th>
                            </tr>
                        </thead>
                        <tbody>{backendJobRows}</tbody>
                    </table>
                </div>
            </div>
        );
    }
}

export default BackendStatus;
