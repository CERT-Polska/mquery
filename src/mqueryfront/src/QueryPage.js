import React, { Component } from "react";
import QueryField from "./QueryField";
import QueryStatus from "./QueryStatus";
import axios from "axios";
import { API_URL } from "./config";

class QueryPage extends Component {
    constructor(props) {
        super(props);

        let qhash = null;

        if (this.props.match.params.hash) {
            qhash = this.props.match.params.hash;
        }

        this.state = {
            qhash: qhash,
            rawYara: "",
            queryPlan: null,
            queryError: null,
        };

        this.updateQhash = this.updateQhash.bind(this);
        this.updateQueryError = this.updateQueryError.bind(this);
        this.updateQueryPlan = this.updateQueryPlan.bind(this);
    }

    componentDidMount() {
        if (this.state.qhash) {
            axios.get(API_URL + "/job/" + this.state.qhash).then((response) => {
                this.setState({ rawYara: response.data.raw_yara });
            });
        }
    }

    componentWillReceiveProps(newProps) {
        console.log(newProps);
    }

    updateQhash(newQhash, rawYara) {
        console.log("update qhash called", newQhash);

        if (typeof rawYara !== "undefined") {
            this.setState({ rawYara: rawYara });
        }

        if (!newQhash) {
            this.props.history.push("/");
        } else {
            this.props.history.push("/query/" + newQhash);
        }

        this.setState({
            queryError: null,
            queryPlan: null,
            qhash: newQhash,
        });
    }

    updateQueryError(newError, rawYara) {
        this.setState({
            queryError: newError,
            queryPlan: null,
            rawYara: rawYara,
        });
    }

    updateQueryPlan(parsedQuery, rawYara) {
        this.setState({
            queryError: null,
            queryPlan: parsedQuery,
            rawYara: rawYara,
        });
    }

    render() {
        return (
            <div className="container-fluid">
                <div className="row">
                    <div className="col-md-6">
                        <QueryField
                            rawYara={this.state.rawYara}
                            isLoading={this.state.qhash && !this.state.rawYara}
                            isLocked={!!this.state.qhash}
                            updateQhash={this.updateQhash}
                            updateQueryPlan={this.updateQueryPlan}
                            updateQueryError={this.updateQueryError}
                        />
                    </div>
                    <div className="col-md-6" id="status-col">
                        <QueryStatus
                            qhash={this.state.qhash}
                            queryPlan={this.state.queryPlan}
                            queryError={this.state.queryError}
                        />
                    </div>
                </div>
            </div>
        );
    }
}

export default QueryPage;
