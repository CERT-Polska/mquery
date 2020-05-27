import React, { Component } from "react";
import SearchJobs from "./SearchJobs";
import ErrorBoundary from "../components/ErrorBoundary";
import axios from "axios";
import { API_URL } from "../config";

class RecentPage extends Component {
    constructor(props) {
        super(props);

        this.state = {
            jobs: [],
            filter: null,
            head: [],
            activePage: 1,
            itemsPerPage: 10,
            error: null,
        };

        this.handleCancelJob = this.handleCancelJob.bind(this);
        this.handleRemove = this.handleRemove.bind(this);
        this.handleFilter = this.handleFilter.bind(this);
        this.handlePageChange = this.handlePageChange.bind(this);
    }

    componentDidMount() {
        axios
            .get(API_URL + "/job")
            .then((response) => {
                const { jobs } = response.data;

                this.setState({ jobs: jobs, head: this.getHead(jobs) });
            })
            .catch((error) => {
                this.setState({ error: error });
            });
    }

    handlePageChange(pageNumber) {
        this.setState({ activePage: pageNumber });
    }

    handleCancelJob(id) {
        const { jobs } = this.state;
        const index = jobs.findIndex((obj) => obj.id === id);

        if (index >= 0) {
            const newJobs = [...jobs];
            newJobs[index].status = "cancelled";

            axios.delete(API_URL + "/job/" + id).then((response) => {
                this.setState({ jobs: newJobs, head: this.getHead(newJobs) });
            });
        }
    }

    handleRemove(id) {
        const { jobs } = this.state;
        const index = jobs.findIndex((obj) => obj.id === id);

        if (index >= 0) {
            const newJobs = [...jobs.slice(0, index), ...jobs.slice(index + 1)];

            axios.delete(API_URL + "/query/" + id).then((response) => {
                this.setState({ jobs: newJobs, head: this.getHead(newJobs) });
            });
        }
    }

    handleFilter(name, value, index) {
        const { filter } = this.state;

        if (index > 0) {
            this.setState({
                filter: { name: name, value: value },
                activePage: 1,
            });
        } else {
            if (filter && filter.name === name)
                this.setState({ filter: null, activePage: 1 });
        }
    }

    getHead(jobs) {
        const head = [
            {
                title: "Job name",
                attrubuteName: "rule_name",
                valueList: this.getDistinctList(jobs, "rule_name"),
            },
            {
                title: "Author",
                attrubuteName: "rule_author",
                valueList: this.getDistinctList(jobs, "rule_author"),
            },
            {
                title: "Matches",
                attrubuteName: "files_matched",
                valueList: this.getDistinctList(jobs, "files_matched", true),
            },
            {
                title: "Status/Progress",
                attrubuteName: "status",
                valueList: this.getDistinctList(jobs, "status"),
            },
            {
                title: "Actions",
                attrubuteName: "",
                valueList: null,
            },
        ];

        return head;
    }

    getDistinctList(
        arrayOfObjects,
        attributeName,
        sortNumerically = false,
        allElement = "All"
    ) {
        let returnList = null;

        if (arrayOfObjects) {
            returnList = arrayOfObjects
                .map((item) => item[attributeName])
                .filter((value, index, self) => self.indexOf(value) === index);

            if (sortNumerically) returnList.sort((a, b) => a - b);
            else returnList.sort();

            returnList.unshift(allElement);
        }

        return returnList;
    }

    getJobsPage(jobs, activePage, itemsPerPage) {
        const indexOfLastJob = activePage * itemsPerPage;
        const indexOfFistJob = indexOfLastJob - itemsPerPage;
        return jobs.slice(indexOfFistJob, indexOfLastJob);
    }

    render() {
        const { jobs, head, filter, itemsPerPage } = this.state;
        let { activePage } = this.state;

        let jobsFiltered = jobs;
        if (filter) {
            const { name, value } = filter;
            jobsFiltered = jobs.filter((el) => el[name] === value);
        }
        const jobCount = jobsFiltered.length;

        let jobsPage = this.getJobsPage(jobsFiltered, activePage, itemsPerPage);

        // prevent from displaying empty table
        if (jobsPage.length === 0 && activePage > 1) {
            activePage--;
            jobsPage = this.getJobsPage(jobsFiltered, activePage, itemsPerPage);
        }

        const pagination = {
            activePage: activePage,
            itemsCountPerPage: itemsPerPage,
            totalItemsCount: jobCount,
            pageRangeDisplayed: 5,
            onChange: this.handlePageChange,
        };

        return (
            <ErrorBoundary error={this.state.error}>
                <SearchJobs
                    jobs={jobsPage}
                    filter={filter}
                    head={head}
                    onFilter={this.handleFilter}
                    onRemove={this.handleRemove}
                    onCancel={this.handleCancelJob}
                    pagination={pagination}
                />
            </ErrorBoundary>
        );
    }
}

export default RecentPage;
