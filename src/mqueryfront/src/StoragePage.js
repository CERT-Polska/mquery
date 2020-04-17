import React, { Component } from "react";
import ErrorBoundary from "./ErrorBoundary";
import StorageList from "./StorageList";
import axios from "axios";
import { API_URL } from "./config";
import { Link } from "react-router-dom";

class StoragePage extends Component {
    constructor(props) {
        super(props);

        this.state = {
            storage: [],
            error: null,
        };

        this.reloadStorage = this.reloadStorage.bind(this);
    }

    componentDidMount() {
        this.reloadStorage();
    }

    reloadStorage() {
        axios
            .get(API_URL + "/storage")
            .then((response) => {
                this.setState({ storage: response.data });
            })
            .catch((error) => {
                this.setState({ error: error });
            });
    }

    render() {
        return (
            <ErrorBoundary error={this.state.error}>
                <div className="container-fluid">
                    <h1 className="text-center mq-bottom">
                        Storage{" "}
                        <Link
                            className="nav-link"
                            to={"/storage/add"}
                            type="button"
                            className="btn btn-success btn-sm"
                            data-toggle="tooltip"
                            title="Configure a new storage location"
                        >
                            +
                        </Link>
                    </h1>
                    <StorageList
                        reload={this.reloadStorage}
                        storage={this.state.storage}
                    />
                </div>
            </ErrorBoundary>
        );
    }
}

export default StoragePage;
