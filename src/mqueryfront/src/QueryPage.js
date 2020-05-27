import React, { Component } from "react";
import QueryField from "./QueryField";
import QueryResultsStatus from "./QueryResultsStatus";
import QueryParseStatus from "./QueryParseStatus";
import axios from "axios";
import { API_URL } from "./config";
import { isStatusFinished } from "./queryUtils";
import ToggleLayoutButton from "./components/ToggleLayoutButton";

const INITIAL_STATE = {
    collapsed: false,
    rawYara: "",
    queryPlan: null,
    queryError: null,
    datasets: {},
    matches: [],
    selectedTaints: [],
    job: null,
    activePage: 1,
};

class QueryPage extends Component {
    constructor(props) {
        super(props);

        this.state = { ...INITIAL_STATE };
        this.trackJobTimeout = null;

        this.collapsePane = this.collapsePane.bind(this);
        this.updateYara = this.updateYara.bind(this);
        this.setActivePage = this.setActivePage.bind(this);
        this.submitQuery = this.submitQuery.bind(this);
        this.editQuery = this.editQuery.bind(this);
        this.handleChange = this.handleChange.bind(this);
    }

    get queryHash() {
        return this.props.match.params.hash;
    }

    componentDidMount() {
        if (this.queryHash) {
            this.fetchJob();
        }
        axios.get(API_URL + "/backend/datasets").then((response) => {
            this.setState({ datasets: response.data.datasets });
        });
    }

    async fetchJob() {
        // Go to the job mode
        // Load initial job information and start tracking results
        let response = await axios.get(API_URL + "/job/" + this.queryHash);
        this.setState(
            {
                ...INITIAL_STATE,
                rawYara: response.data.raw_yara,
                collapsed: true,
                job: response.data,
                datasets: this.state.datasets,
            },
            () => {
                this.trackJob();
            }
        );
    }

    componentWillUnmount() {
        this.cancelJob();
    }

    componentDidUpdate(prevProps, prevState) {
        const prevQueryHash = prevProps.match.params.hash;
        if (this.queryHash) {
            if (prevQueryHash !== this.queryHash) {
                // Went to the job mode or switched to another job
                this.cancelJob();
                this.fetchJob();
            }
        } else if (this.props.location.key !== prevProps.location.key) {
            let editMode =
                this.props.location.state &&
                this.props.location.state.editQuery;
            // Refresh view into query mode
            this.cancelJob();
            this.setState({
                ...INITIAL_STATE,
                datasets: this.state.datasets,
                rawYara: editMode ? this.state.rawYara : "",
            });
        }
    }

    availableTaints() {
        var taintList = Object.values(this.state.datasets)
            .map((ds) => ds.taints)
            .flat();
        return [...new Set(taintList)];
    }

    handleChange = (selectedTaintsParam) => {
        this.setState({ selectedTaints: selectedTaintsParam });
    };

    updateYara(value) {
        this.setState({ rawYara: value });
    }

    async trackJob() {
        // Periodically reloads job status until job is finished
        let { job, matches } = await this.loadMatches();

        this.setState({ job, matches });
        if (!isStatusFinished(job.status)) {
            this.trackJobTimeout = setTimeout(() => this.trackJob(), 1000);
        } else {
            this.trackJobTimeout = null;
        }
    }

    cancelJob() {
        // Cancels perodic job status reload
        if (this.trackJobTimeout !== null) {
            clearTimeout(this.trackJobTimeout);
            this.trackJobTimeout = null;
        }
    }

    setActivePage(pageNumber) {
        this.setState({ activePage: pageNumber }, async () => {
            this.setState(await this.loadMatches());
        });
    }

    async loadMatches() {
        // Loads matches from the current page
        const LIMIT = 20;
        const OFFSET = (this.state.activePage - 1) * LIMIT;
        const response = await axios.get(
            API_URL +
                "/matches/" +
                this.queryHash +
                "?offset=" +
                OFFSET +
                "&limit=" +
                LIMIT
        );
        return response ? response.data : {};
    }

    collapsePane() {
        this.setState((prevState) => ({
            collapsed: !prevState.collapsed,
        }));
    }

    async submitQuery(method, priority) {
        try {
            var taints =
                this.state.selectedTaints.map((obj) => obj.value) || [];

            let response = await axios.post(API_URL + "/query", {
                raw_yara: this.state.rawYara,
                method: method,
                priority: priority,
                taints: taints,
            });
            if (method === "query") {
                this.props.history.push("/query/" + response.data.query_hash);
            } else if (method === "parse") {
                this.setState({
                    queryPlan: response.data,
                    queryError: null,
                });
            }
        } catch (error) {
            this.setState({
                queryError: error.response
                    ? error.response.data.detail
                    : error.toString(),
                queryPlan: null,
            });
        }
    }

    get parsedError() {
        if (this.state.queryError) {
            // Dirty hack to parse error lines from the error message
            // Error format: "Error at 4.2-7:" or  "Error at 5.1:"
            let parsedError = this.state.queryError.match(
                /Error at (\d+).(\d+)-?(\d+)?: (.*)/
            );
            if (parsedError) return parsedError;
        }
        return [];
    }

    editQuery() {
        // Goes to the query mode keeping the original query
        this.props.history.push("/", { editQuery: this.queryHash });
    }

    render() {
        const queryParse = (
            <QueryParseStatus
                qhash={this.queryHash}
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
                    qhash={this.queryHash}
                    job={this.state.job}
                    matches={this.state.matches}
                    parentCallback={this.setActivePage}
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
                                error={this.parsedError}
                                readOnly={!!this.queryHash}
                                availableTaints={this.availableTaints()}
                                updateYara={this.updateYara}
                                submitQuery={this.submitQuery}
                                editQuery={this.editQuery}
                                handleChange={this.handleChange}
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
                        {!this.queryHash
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
