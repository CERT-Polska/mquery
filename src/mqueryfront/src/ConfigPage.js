import React, { Component } from "react";
import ErrorBoundary from "./ErrorBoundary";
import ConfigEntryList from "./ConfigEntries";
import axios from "axios";
import { API_URL } from "./config";
import { Link } from "react-router-dom";

class ConfigPage extends Component {
    constructor(props) {
        super(props);

        this.state = {
            config: [],
            error: null,
        };
    }

    componentDidMount() {
        axios
            .get(API_URL + "/config")
            .then((response) => {
                this.setState({ config: response.data });
            })
            .catch((error) => {
                this.setState({ error: error });
            });
    }

    render() {
        return (
            <ErrorBoundary error={this.state.error}>
                <div className="container-fluid">
                    <h1 className="text-center mq-bottom">Config</h1>
                    <ConfigEntryList config={this.state.config} />
                </div>
            </ErrorBoundary>
        );
    }
}

export default ConfigPage;
