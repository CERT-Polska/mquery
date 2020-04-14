import React, { Component } from "react";
import ErrorBoundary from "./ErrorBoundary";

class StorageRow extends Component {
    getWatchedBadge() {
        if (this.props.enabled) {
            return (
                <span
                className="badge badge-success"
                    data-toggle="tooltip"
                    title="This location is watched and indexed automatically"
                >
                    watched
                </span>
            );
        }
        return (
            <span
            className="badge badge-secondary"
                data-toggle="tooltip"
                title="This location is not indexed automatically"
            >
                disabled
            </span>
        );
    }

    render() {
        let taintTags = this.props.taints.map((taint) => (
            <span>
                {" "}
                <span
                    className="badge badge-primary"
                    data-toggle="tooltip"
                    title={`New indexed files are tagged with "${taint}"`}
                >
                    {taint}
                </span>
            </span>
        ));

        let actionButtons = (
            <div>
                <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    data-toggle="tooltip"
                    title="Reindex this dataset now"
                >
                    Reindex
                </button>{" "}
                <button
                    type="button"
                    className="btn btn-danger btn-sm"
                    data-toggle="tooltip"
                    title="Stop watching the dataset (keep indexed files)"
                >
                    Delete
                </button>
            </div>
        );

        return (
            <tr>
                <td>
                    <code>{this.props.name}</code>
                    {taintTags}
                </td>
                <td>
                    <code>{this.props.path}</code>
                </td>
                <td>
                    {new Date(this.props.lastUpdate).toLocaleDateString()}{" "}
                    {this.getWatchedBadge()}
                </td>
                <td>{actionButtons}</td>
            </tr>
        );
    }
}

class StorageList extends Component {
    render() {
        const storageRows = this.props.storage.map((storage) => (
            <StorageRow
                name={storage.name}
                path={storage.path}
                taints={storage.taints}
                lastUpdate={storage.last_update}
                enabled={storage.enabled}
                key={storage.id}
            />
        ));

        return (
            <ErrorBoundary error={this.props.error}>
                <div className="table-responsive">
                    <table className="table table-striped table-bordered">
                        <thead>
                            <tr>
                                <th>name</th>
                                <th>path</th>
                                <th>last update</th>
                                <th>actions</th>
                            </tr>
                        </thead>
                        <tbody>{storageRows}</tbody>
                    </table>
                </div>
            </ErrorBoundary>
        );
    }
}

export default StorageList;
