import React, { Component } from "react";
import SearchJobs from "./SearchJobs";
import ErrorBoundary from "./ErrorBoundary";
import axios from "axios";
import { API_URL } from "./config";

class RecentPage extends Component {
    constructor(props) {
        super(props);

        this.state = {
            jobs: [],
            head: [],
            filter: null,
            error: null,
        };

        this.handleCancelJob = this.handleCancelJob.bind(this);
        this.handleClose = this.handleClose.bind(this);
        this.handleFilter = this.handleFilter.bind(this);
        this._getHead = this._getHead.bind(this);
        this._getDistinctList = this._getDistinctList.bind(this);
    }

    handleCancelJob(id) {
        const { jobs } = this.state;
        const index = jobs.findIndex((obj) => obj.id === id);

        if (index >= 0) {
            const newJobs = [...jobs];
            newJobs[index].status = "cancelled";

            axios.delete(API_URL + "/job/" + id).then((response) => {
                this.setState({ jobs: newJobs, head: this._getHead(newJobs) });
            });
        }
    }

    handleClose(id) {
        const { jobs } = this.state;
        const index = jobs.findIndex((obj) => obj.id === id);

        if (index >= 0) {
            const newJobs = [...jobs.slice(0, index), ...jobs.slice(index + 1)];

            this.setState({ jobs: newJobs, head: this._getHead(newJobs) });
        }
    }

    handleFilter(name, value, index) {
        const { filter } = this.state;

        if (index > 0) {
            this.setState({ filter: { name: name, value: value } });
        } else {
            if (filter && filter.name === name) this.setState({ filter: null });
        }
    }

    _getHead(jobs) {
        const head = [
            {
                title: "Job name",
                attrubuteName: "rule_name",
                valueList: this._getDistinctList(jobs, "rule_name", "All"),
            },
            {
                title: "Author",
                attrubuteName: "rule_author",
                valueList: this._getDistinctList(jobs, "rule_author", "All"),
            },
            {
                title: "Matches",
                attrubuteName: "files_matched",
                valueList: this._getDistinctList(jobs, "files_matched", "All"),
            },
            {
                title: "Status/Progress",
                attrubuteName: "status",
                valueList: this._getDistinctList(jobs, "status", "All"),
            },
            {
                title: "Actions",
                attrubuteName: "",
                valueList: null,
            },
        ];

        return head;
    }

    _getDistinctList(arrayOfObjects, attributeName, allElement) {
        let returnList = null;    

        if (arrayOfObjects)
            returnList = arrayOfObjects
                .map((item) => item[attributeName])
                .filter((value, index, self) => self.indexOf(value) === index)
                .sort();

        if (returnList) returnList.unshift(allElement);

        return returnList;
    }

    componentDidMount() {
        axios
            .get(API_URL + "/job")
            .then((response) => {
                const { jobs } = response.data;

                this.setState({ jobs: jobs, head: this._getHead(jobs) });
            })
            .catch((error) => {
                this.setState({ error: error });
            });
    }

    render() {
        const { jobs, head, filter } = this.state;

        return (
            <ErrorBoundary error={this.state.error}>
                <SearchJobs
                    jobs={jobs}
                    head={head}
                    filter={filter}
                    onFilter={this.handleFilter}
                    onClose={this.handleClose}
                    onCancel={this.handleCancelJob}
                />
            </ErrorBoundary>
        );
    }
}

export default RecentPage;
