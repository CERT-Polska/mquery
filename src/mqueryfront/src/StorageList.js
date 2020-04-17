import React, { Component } from "react";
import axios from "axios";
import { API_URL } from "./config";
import ErrorBoundary from "./ErrorBoundary";

class StorageRow extends Component {
    constructor(props) {
        super(props);

        this.state = {
            storageName: "",
            storagePath: "",
            error: null,
        };

        this.handleEnable = this.handleEnable.bind(this);
        this.handleDisable = this.handleDisable.bind(this);
        this.handleDelete = this.handleDelete.bind(this);
    }

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

    handleEnable() {
        axios
            .create()
            .post(API_URL + "/storage/enable", {
                id: this.props.id,
            })
            .then(() => this.props.reload());
    }

    handleDisable() {
        axios
            .create()
            .post(API_URL + "/storage/disable", {
                id: this.props.id,
            })
            .then(() => this.props.reload());
    }

    handleDelete() {
        axios
            .create()
            .post(API_URL + "/storage/delete", {
                id: this.props.id,
            })
            .then(() => this.props.reload());
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

        let toggleButton;
        if (this.props.enabled) {
            toggleButton = (
                <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    data-toggle="tooltip"
                    title="Disable reindexing"
                    onClick={this.handleDisable}
                >
                    Disable
                </button>
            );
        } else {
            toggleButton = (
                <button
                    type="button"
                    className="btn btn-success btn-sm"
                    data-toggle="tooltip"
                    title="Enable reindexing"
                    onClick={this.handleEnable}
                >
                    Enable
                </button>
            );
        }

        let actionButtons = (
            <div>
                {toggleButton}{" "}
                <button
                    type="button"
                    className="btn btn-danger btn-sm"
                    data-toggle="tooltip"
                    title="Stop watching the dataset (keep indexed files)"
                    onClick={this.handleDelete}
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
                id={storage.id}
                name={storage.name}
                path={storage.path}
                taints={storage.taints}
                lastUpdate={storage.last_update}
                enabled={storage.enabled}
                key={storage.id}
                reload={this.props.reload}
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
