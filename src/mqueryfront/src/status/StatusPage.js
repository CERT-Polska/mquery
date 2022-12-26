import React, { Component } from "react";
import ErrorBoundary from "../components/ErrorBoundary";
import BackendStatus from "./BackendStatus";
import DatabaseTopology from "./DatabaseTopology";
import VersionStatus from "./VersionStatus";
import api from "../api";

class StatusPage extends Component {
    constructor(props) {
        super(props);

        this.state = {
            backend: {
                agents: [],
                components: [],
            },
            error: null,
        };
    }

    componentDidMount() {
        api.get("/backend")
            .then((response) => {
                this.setState({ backend: response.data });
            })
            .catch((error) => {
                this.setState({ error: error });
            });
    }

    render() {
        return (
            <ErrorBoundary error={this.state.error}>
                <div className="container-fluid">
                    <h1 className="text-center mq-bottom">Status</h1>
                    <div className="row">
                        <div className="col-md-6">
                            <VersionStatus
                                components={this.state.backend.components}
                            />
                            <BackendStatus agents={this.state.backend.agents} />
                        </div>
                        <div className="col-md-6">
                            <DatabaseTopology />
                        </div>
                    </div>
                </div>
            </ErrorBoundary>
        );
    }
}

export default StatusPage;
