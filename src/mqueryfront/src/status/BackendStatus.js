import React, { Component } from "react";

import ErrorBoundary from "../components/ErrorBoundary";


class BackendJobRow extends Component {
    render() {
        let shortRequest = this.props.request;
        if (shortRequest.length > 200) {
            let prefix = shortRequest.substring(0, 140);
            let suffix = shortRequest.substring(shortRequest.length - 60, 60);
            shortRequest = prefix + " (...) " + suffix;
        }
        return (
            <tr>
                <td>{this.props.id}</td>
                <td>{this.props.connection_id}</td>
                <td>
                    <code>{shortRequest}</code>
                </td>
                <td>
                    {this.props.work_done} / {this.props.work_estimated}
                </td>
            </tr>
        );
    }
}

class AgentStatus extends Component {
    render() {
        const backendJobRows = this.props.tasks.map((task) => (
            <BackendJobRow {...task} key={task.id} />
        ));

        let badge = null;
        if (!this.props.alive) {
            badge = (
                <span className="badge badge-secondary badge-sm">offline</span>
            );
        }

        return (
            <div>
                <h2
                    className="text-center mq-bottom"
                    data-toggle="tooltip"
                    title={this.props.url}
                >
                    Agent: {this.props.name} {badge}
                </h2>
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

class BackendStatus extends Component {
    render() {
        const agentRows = this.props.agents.map((agent) => (
            <AgentStatus
                name={agent.name}
                alive={agent.alive}
                tasks={agent.tasks}
                url={agent.url}
                key={agent.name}
            />
        ));

        return (
            <ErrorBoundary error={!agentRows.length && "No agents found."}>
                <div>{agentRows}</div>
            </ErrorBoundary>
        );
    }
}

export default BackendStatus;
