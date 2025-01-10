import React, { Component } from "react";
import ErrorBoundary from "../components/ErrorBoundary";
import BackendStatus from "./BackendStatus";
import DatabaseTopology from "./DatabaseTopology";
import VersionStatus from "./VersionStatus";
import api from "../api";
import WarningPage from "../components/WarningPage";

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
        localStorage.setItem("currentLocation", window.location.href);
        api.get("/backend")
            .then((response) => {
                this.setState({ backend: response.data });
            })
            .catch((error) => {
                this.setState({ error: error });
            });
        this._ismounted = true;
    }

    getAgentsUrsaURLDuplicatesWarning(agentgroups) {
        var ursaURLS = agentgroups.map((agent) => agent.spec.ursadb_url);
        var duplicateURLS = ursaURLS.filter(
            (url, index) => ursaURLS.indexOf(url) !== index
        );
        if (!duplicateURLS.length) {
            return null;
        }
        return `At least two agents share the same UrsaDB URL(s): \
        ${duplicateURLS.join(
            ", "
        )}. Something might be wrong with backend configuration.`;
    }

    getNoAgentsWarning(agentgroups) {
        if (agentgroups.length) {
            return null;
        }
        return "There are no connected agents! Check your backend configuration.";
    }

    render() {
        const ursaURLWarning = this.getAgentsUrsaURLDuplicatesWarning(
            this.state.backend.agents
        );
        const noAgentsWarning = this.getNoAgentsWarning(
            this.state.backend.agents
        );
        return (
            <ErrorBoundary error={this.state.error}>
                <div className="container-fluid">
                    {this._ismounted && ursaURLWarning && (
                        <WarningPage msg={ursaURLWarning} dismissable />
                    )}
                    <h1 className="text-center mq-bottom">Status</h1>
                    <div className="row">
                        <div className="col-md-6">
                            <VersionStatus
                                components={this.state.backend.components}
                            />
                            {this._ismounted && noAgentsWarning ? (
                                <WarningPage msg={noAgentsWarning} />
                            ) : (
                                <BackendStatus
                                    agents={this.state.backend.agents}
                                />
                            )}
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
