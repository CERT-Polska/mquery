import React from "react";
import FilteringTableHeader from "../components/FilteringTableHeader";
import FilteringTitle from "../components/FilteringTitle";
import Pagination from "react-js-pagination";
import PropTypes from "prop-types";
import { PT_JOBS, PT_PAGINATION } from "../queryUtils";
import SearchJobItem, { SearchJobItemEmpty } from "./SearchJobItem";

const SearchJobs = (props) => {
    const {
        jobs,
        head,
        filter,
        onCancel,
        onRemove,
        onFilter,
        pagination,
    } = props;

    const filterValue = filter ? filter.value : null;

    const backendJobRows = jobs.map((job) => (
        <SearchJobItem
            key={job.id}
            job={job}
            onRemove={() => onRemove(job.id)}
            onCancel={() => onCancel(job.id)}
        />
    ));

    // make table itemsCountPerPage size
    while (backendJobRows.length < pagination.itemsCountPerPage) {
        backendJobRows.push(<SearchJobItemEmpty key={backendJobRows.length} />);
    }

    return (
        <div className="row">
            <div className="col-md-8 offset-md-2">
                <FilteringTitle title="Recent jobs" filterValue={filterValue} />
                <div className="table-responsive">
                    <table className="table table-striped table-bordered">
                        <FilteringTableHeader
                            head={head}
                            currentFilter={filter}
                            onClick={onFilter}
                        />
                        <tbody>{backendJobRows}</tbody>
                    </table>
                </div>
                <div className="d-flex justify-content-center">
                    <Pagination
                        activePage={pagination.activePage}
                        itemsCountPerPage={pagination.itemsCountPerPage}
                        totalItemsCount={pagination.totalItemsCount}
                        pageRangeDisplayed={pagination.pageRangeDisplayed}
                        onChange={pagination.onChange}
                        itemClass="page-item"
                        linkClass="page-link"
                    />
                </div>
            </div>
        </div>
    );
};

SearchJobs.propTypes = {
    jobs: PT_JOBS.isRequired,
    head: PropTypes.arrayOf(
        PropTypes.shape({
            title: PropTypes.string.isRequired,
            attrubuteName: PropTypes.string,
            valueList: PropTypes.arrayOf(
                PropTypes.oneOfType([PropTypes.string, PropTypes.number])
            ),
        })
    ).isRequired,
    filterValue: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
    onFilter: PropTypes.func.isRequired,
    onRemove: PropTypes.func.isRequired,
    onCancel: PropTypes.func.isRequired,
    pagination: PT_PAGINATION.isRequired,
};

export default SearchJobs;
