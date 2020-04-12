import React, { Component } from "react";
import ErrorBoundary from "./ErrorBoundary";

class StorageRow extends Component {
    getWatchedBadge() {
        if (this.props.enabled) {
            return (
                <span
                    class="badge badge-success"
                    data-toggle="tooltip"
                    title="This location is watched and indexed automatically"
                >
                    watched
                </span>
            );
        }
        return (
            <span
                class="badge badge-secondary"
                data-toggle="tooltip"
                title="This location is not indexed automatically"
            >
                disabled
            </span>
        );
    }

    render() {
        return (
            <tr>
                <td>
                    <code>{this.props.name}</code>
                    {this.props.taints.map((taint) => (
                        <span>
                            {" "}
                            <span
                                class="badge badge-primary"
                                data-toggle="tooltip"
                                title={`New indexed files are tagged with "${taint}"`}
                            >
                                {taint}
                            </span>
                        </span>
                    ))}
                </td>
                <td>
                    <code>{this.props.path}</code>
                </td>
                <td>
                    {new Date(this.props.lastUpdate).toLocaleDateString()}{" "}
                    {this.getWatchedBadge()}
                </td>
                <td>
                    <button
                        type="button"
                        class="btn btn-secondary btn-sm"
                        data-toggle="tooltip"
                        title="Reindex this dataset now"
                    >
                        Reindex
                    </button>
                    <button
                        type="button"
                        class="btn btn-danger btn-sm"
                        data-toggle="tooltip"
                        title="Stop watching the dataset (keep indexed files)"
                    >
                        Delete
                    </button>
                </td>
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
