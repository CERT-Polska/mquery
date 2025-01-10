import React, { Component } from "react";
import ErrorBoundary from "../components/ErrorBoundary";
import ConfigEntryList from "./ConfigEntries";
import api from "../api";

class ConfigPage extends Component {
    constructor(props) {
        super(props);

        this.state = {
            config: [],
            error: null,
        };
    }

    componentDidMount() {
        localStorage.setItem("currentLocation", window.location.href)
        api.get("/config")
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
