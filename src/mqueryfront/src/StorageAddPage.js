import React, { Component } from "react";
import axios from "axios";
import { API_URL } from "./config";
import ErrorBoundary from "./ErrorBoundary";

class StorageAddForm extends Component {
    constructor(props) {
        super(props);

        this.state = {
            storageName: "",
            storagePath: "",
            error: null,
        };

        this.handleInputChange = this.handleInputChange.bind(this);
    }

    handleInputChange(event) {
        const target = event.target;
        this.setState({
            [target.name]: target.value,
        });
    }

    handleAdd(event) {
        axios
            .create()
            .post(API_URL + "/storage", {
                name: this.state.storageName,
                path: this.state.storagePath,
            })
            .then(() => {
                this.props.history.push("/storage");
            })
            .catch((error) => {
                this.setState({ error: error });
            });
    }

    render() {
        return (
            <div>
                <ErrorBoundary error={this.state.error}>{null}</ErrorBoundary>
                <div className="form-group row">
                    <label
                        for="storageName"
                        className="col-sm-2 col-form-label col-form-label"
                    >
                        Name
                    </label>
                    <div className="col-sm-10">
                        <input
                            type="text"
                            className="form-control form-control"
                            name="storageName"
                            placeholder="Name for your new storage"
                            onChange={this.handleInputChange}
                            value={this.state.storageName}
                        />
                    </div>
                </div>
                <div className="form-group row">
                    <label
                        for="storagePath"
                        className="col-sm-2 col-form-label col-form-label"
                    >
                        Path
                    </label>
                    <div className="col-sm-10">
                        <input
                            type="text"
                            className="form-control form-control"
                            name="storagePath"
                            placeholder="Root local filesystem path for storage"
                            onChange={this.handleInputChange}
                            value={this.state.storagePath}
                        />
                    </div>
                </div>
                <button
                    className="btn btn-primary"
                    onClick={() => this.handleAdd()}
                >
                    Submit
                </button>
            </div>
        );
    }
}

class StorageAddPage extends Component {
    render() {
        return (
            <div className="container-fluid">
                <h1 className="text-center mq-bottom">Configure Storage </h1>
                <StorageAddForm history={this.props.history} />
            </div>
        );
    }
}

export default StorageAddPage;
