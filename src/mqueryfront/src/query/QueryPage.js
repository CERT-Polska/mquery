import React, { Component } from "react";
import axios from "axios";
import { API_URL } from "../config";
import { isStatusFinished } from "../queryUtils";
import QueryLayoutManager from "./QueryLayoutManager";

const INITIAL_STATE = {
    isCollapsed: false,
    rawYara: "",
    queryPlan: null,
    queryError: null,
    datasets: {},
    matches: [],
    selectedTaints: [],
    job: null,
    activePage: 1,
};

const PAGE_SIZE = 20;

class QueryPage extends Component {
    constructor(props) {
        super(props);

        this.state = INITIAL_STATE;
        this.trackJobTimeout = null;

        this.handleCollapsePane = this.handleCollapsePane.bind(this);
        this.handleYaraUpdate = this.handleYaraUpdate.bind(this);
        this.handlePageChange = this.handlePageChange.bind(this);
        this.handleSubmitQuery = this.handleSubmitQuery.bind(this);
        this.handleEditQuery = this.handleEditQuery.bind(this);
        this.handleParseQuery = this.handleParseQuery.bind(this);
        this.handleTaintsSelection = this.handleTaintsSelection.bind(this);
        this.handleCancelJob = this.handleCancelJob.bind(this);
    }

    async componentDidMount() {
        if (this.queryHash) {
            this.fetchJob();
        }
        const response = await axios.get(API_URL + "/backend/datasets");
        const datasets = response.data.datasets;

        this.setState({ datasets: datasets });
    }

    componentWillUnmount() {
        this.cancelJobReload();
    }

    componentDidUpdate(prevProps, prevState) {
        const prevQueryHash = prevProps.match.params.hash;
        if (this.queryHash) {
            if (prevQueryHash !== this.queryHash) {
                // Went to the job mode or switched to another job
                this.cancelJobReload();
                this.fetchJob();
            }
        } else if (this.props.location.key !== prevProps.location.key) {
            const editMode =
                this.props.location.state &&
                this.props.location.state.editQuery;
            // Refresh view into query mode
            this.cancelJobReload();
            this.setState({
                ...INITIAL_STATE,
                datasets: this.state.datasets,
                rawYara: editMode ? this.state.rawYara : "",
            });
        }
    }

    handleSubmitQuery(priority) {
        this.submitJob("query", priority);
    }

    handleParseQuery() {
        this.submitJob("parse", null);
    }

    handleEditQuery() {
        // Goes to the query mode keeping the original query
        this.props.history.push("/", { editQuery: this.queryHash });
    }

    handleTaintsSelection = (selectedTaintsParam) => {
        this.setState({ selectedTaints: selectedTaintsParam });
    };

    handleYaraUpdate(value) {
        this.setState({ rawYara: value });
    }

    async handleCancelJob() {
        await axios.delete(API_URL + "/job/" + this.queryHash);
    }

    handlePageChange(pageNumber) {
        this.setState({ activePage: pageNumber }, async () => {
            this.setState(await this.loadMatches());
        });
    }

    handleCollapsePane() {
        this.setState((prevState) => ({
            isCollapsed: !prevState.isCollapsed,
        }));
    }

    async fetchJob() {
        // Go to the job mode
        // Load initial job information and start tracking results
        const response = await axios.get(API_URL + "/job/" + this.queryHash);
        this.setState(
            {
                ...INITIAL_STATE,
                rawYara: response.data.raw_yara,
                isCollapsed: true,
                job: response.data,
                datasets: this.state.datasets,
            },
            () => {
                this.trackJob();
            }
        );
    }

    async trackJob() {
        // Periodically reloads job status until job is finished
        const { job, matches } = await this.loadMatches();

        this.setState({ job, matches });
        if (!isStatusFinished(job.status)) {
            this.trackJobTimeout = setTimeout(() => this.trackJob(), 1000);
        } else {
            this.trackJobTimeout = null;
        }
    }

    async loadMatches() {
        // Loads matches from the current page
        const OFFSET = (this.state.activePage - 1) * PAGE_SIZE;
        const response = await axios.get(
            API_URL +
                "/matches/" +
                this.queryHash +
                "?offset=" +
                OFFSET +
                "&limit=" +
                PAGE_SIZE
        );
        return response ? response.data : {};
    }

    async submitJob(method, priority) {
        try {
            const taints =
                this.state.selectedTaints.map((obj) => obj.value) || [];

            const response = await axios.post(API_URL + "/query", {
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

    cancelJobReload() {
        // Cancels perodic job status reload
        if (this.trackJobTimeout !== null) {
            clearTimeout(this.trackJobTimeout);
            this.trackJobTimeout = null;
        }
    }

    get availableTaints() {
        var taintList = Object.values(this.state.datasets)
            .map((ds) => ds.taints)
            .flat();
        return [...new Set(taintList)];
    }

    get queryHash() {
        return this.props.match.params.hash;
    }

    get parsedError() {
        if (this.state.queryError) {
            // Dirty hack to parse error lines from the error message
            // Error format: "Error at 4.2-7:" or  "Error at 5.1:"
            const parsedError = this.state.queryError.match(
                /Error at (\d+).(\d+)-?(\d+)?: (.*)/
            );
            if (parsedError) return parsedError;
        }
        return [];
    }

    render() {
        const pagination = this.state.job
            ? {
                  activePage: this.state.activePage,
                  itemsCountPerPage: PAGE_SIZE,
                  totalItemsCount: this.state.job.files_matched,
                  pageRangeDisplayed: 5,
                  onChange: this.handlePageChange,
              }
            : null;

        return (
            <QueryLayoutManager
                isCollapsed={this.state.isCollapsed}
                onCollapsePane={this.handleCollapsePane}
                qhash={this.queryHash}
                queryPlan={this.state.queryPlan}
                queryError={this.state.queryError}
                job={this.state.job}
                matches={this.state.matches}
                pagination={pagination}
                onCancel={this.handleCancelJob}
                onSubmitQuery={this.handleSubmitQuery}
                onEditQuery={this.handleEditQuery}
                onParseQuery={this.handleParseQuery}
                onTaintSelect={this.handleTaintsSelection}
                availableTaints={this.availableTaints}
                rawYara={this.state.rawYara}
                onYaraUpdate={this.handleYaraUpdate}
                parsedError={this.parsedError}
            />
        );
    }
}

export default QueryPage;
