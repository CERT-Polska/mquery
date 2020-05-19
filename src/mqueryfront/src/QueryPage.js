import React, { Component } from "react";
import QueryField from "./QueryField";
import QueryResultsStatus from "./QueryResultsStatus";
import QueryParseStatus from "./QueryParseStatus";
import axios from "axios";
import { API_URL } from "./config";
import { isStatusFinished } from "./queryUtils";
import ToggleLayoutButton from "./components/ToggleLayoutButton";

const INITIAL_STATE = {
    mode: "query",
    collapsed: false,
    qhash: null,
    rawYara: "",
    queryPlan: null,
    queryError: null,
    datasets: {},
    matches: null,
    job: null,
    activePage: 1,
};

class QueryPage extends Component {
    constructor(props) {
        super(props);

        let initialState = { ...INITIAL_STATE };
        if (this.props.match.params.hash) {
            initialState.qhash = this.props.match.params.hash;
        }
        this.state = initialState;

        this.updateQhash = this.updateQhash.bind(this);
        this.updateQueryError = this.updateQueryError.bind(this);
        this.updateQueryPlan = this.updateQueryPlan.bind(this);
        this.collapsePane = this.collapsePane.bind(this);
        this.updateYara = this.updateYara.bind(this);
    }

    componentDidMount() {
        if (this.state.qhash) {
            axios.get(API_URL + "/job/" + this.state.qhash).then((response) => {
                this.updateQhash(this.state.qhash, response.data.raw_yara);
            });
        }
        axios.get(API_URL + "/backend/datasets").then((response) => {
            this.setState({ datasets: response.data.datasets });
        });
    }

    componentWillUnmount() {
        if (this.timeout !== null) {
            clearTimeout(this.timeout);
        }

        this.setState({
            qhash: null,
        });
    }

    componentDidUpdate(prevProps, prevState) {
        if (
            this.props.match.path === "/" &&
            this.props.location.key !== prevProps.location.key
        ) {
            this.setState(INITIAL_STATE);
        }
    }

    availableTaints() {
        var taintList = Object.values(this.state.datasets)
            .map((ds) => ds.taints)
            .flat();
        return [...new Set(taintList)];
    }

    updateQhash(newQhash, rawYara) {
        if (typeof rawYara !== "undefined") {
            this.setState({ rawYara: rawYara });
        }

        if (!newQhash) {
            this.props.history.push("/");
        } else {
            this.props.history.push("/query/" + newQhash);
            this.collapsePane();
        }

        this.setState({
            mode: "job",
            queryError: null,
            queryPlan: null,
            qhash: newQhash,
            matches: null,
            job: null,
            activePage: 1,
        });
        this.loadJob();
    }

    updateYara(value) {
        this.setState({ rawYara: value });
    }

    loadJob() {
        const LIMIT = 20;
        let OFFSET = (this.state.activePage - 1) * 20;

        if (!this.state.qhash) {
            return;
        }

        axios
            .get(
                API_URL +
                    "/matches/" +
                    this.state.qhash +
                    "?offset=" +
                    OFFSET +
                    "&limit=" +
                    LIMIT
            )
            .then((response) => {
                const { job, matches } = response.data;

                this.setState({
                    job: job,
                    matches: matches,
                });
                const isDone = isStatusFinished(job.status);
                if (isDone) {
                    return;
                }
                this.timeout = setTimeout(() => this.loadJob(), 1000);
            });
    }

    callbackResultsActivePage = (pageNumber) => {
        this.setState({ activePage: pageNumber }, () => {
            this.loadMatches();
        });
    };

    loadMatches() {
        const LIMIT = 20;
        let OFFSET = (this.state.activePage - 1) * 20;
        axios
            .get(
                API_URL +
                    "/matches/" +
                    this.state.qhash +
                    "?offset=" +
                    OFFSET +
                    "&limit=" +
                    LIMIT
            )
            .then((response) => {
                this.setState({
                    matches: response.data.matches,
                });
            });
    }

    updateQueryError(newError, rawYara) {
        this.setState({
            mode: "query",
            queryError: newError,
            queryPlan: null,
            rawYara: rawYara,
            job: null,
            matches: null,
        });
    }

    updateQueryPlan(parsedQuery, rawYara) {
        this.setState({
            mode: "query",
            queryPlan: parsedQuery,
            queryError: null,
            rawYara: rawYara,
            job: null,
            matches: null,
        });
    }

    collapsePane() {
        this.setState((prevState) => ({
            collapsed: !prevState.collapsed,
        }));
    }

    render() {
        const queryParse = (
            <QueryParseStatus
                qhash={this.state.qhash}
                queryPlan={this.state.queryPlan}
                queryError={this.state.queryError}
            />
        );

        const queryResults = (
            <div>
                <ToggleLayoutButton
                    buttonClass="btn btn-primary btn-sm pull-left mr-4"
                    onClick={this.collapsePane}
                    label={this.state.collapsed ? "Show query" : "Hide query"}
                />
                <QueryResultsStatus
                    qhash={this.state.qhash}
                    job={this.state.job}
                    matches={this.state.matches}
                    parentCallback={this.callbackResultsActivePage}
                    collapsed={this.state.collapsed}
                />
            </div>
        );
        return (
            <div className="container-fluid">
                <div className="row wrapper">
                    {!this.state.collapsed ? (
                        <div className="col-md-5">
                            <QueryField
                                rawYara={this.state.rawYara}
                                readOnly={!!this.state.qhash}
                                updateQhash={this.updateQhash}
                                availableTaints={this.availableTaints()}
                                updateQueryPlan={this.updateQueryPlan}
                                updateQueryError={this.updateQueryError}
                                updateYara={this.updateYara}
                            />
                        </div>
                    ) : (
                        []
                    )}
                    <div
                        className={
                            this.state.collapsed ? "col-md-12" : "col-md-7"
                        }
                    >
                        {this.state.mode === "query"
                            ? queryParse
                            : this.state.job
                            ? queryResults
                            : null}
                    </div>
                </div>
            </div>
        );
    }
}

export default QueryPage;
