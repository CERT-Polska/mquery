import React, { Component } from "react";
import ErrorBoundary from "../components/ErrorBoundary";
import axios from "axios";

class AuthPage extends Component {
    constructor(props) {
        super(props);

        this.state = {
            error: null,
        };
    }

    componentDidUpdate(prevProps) {
        if (this.props.config == prevProps.config || !this.props.config) {
            return;
        }
        if (!this.props.config["openid_auth_url"]) {
            this.setState({ error: "OIDC not configured" });
        }
        const queryString = window.location.search;
        const urlParams = new URLSearchParams(queryString);
        const code = urlParams.get("code");

        const params = new URLSearchParams();
        params.append("grant_type", "authorization_code");
        params.append("code", code);
        params.append("client_id", "app");
        axios
            .post(this.props.config["openid_auth_url"], params)
            .then((response) => {
                this.props.login(response.data["access_token"]);
            })
            .catch((error) => {
                this.setState({ error: error });
            });
    }

    render() {
        const message = this.state.username
            ? `Logged in as ${JSON.stringify(this.state.username)}`
            : "Logging in...";
        return (
            <ErrorBoundary error={this.state.error}>
                <div className="container-fluid">
                    <h1 className="text-center mq-bottom">{message}</h1>
                </div>
            </ErrorBoundary>
        );
    }
}

export default AuthPage;
