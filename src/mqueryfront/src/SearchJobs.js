import React from "react";
import { Link } from "react-router-dom";
import PriorityIcon from "./components/PriorityIcon";
import ActionClose from "./components/ActionClose";
import ActionCancel from "./components/ActionCancel";
import StatusProgress from "./components/StatusProgress";
import FilteringTableHeader from "./components/FilteringTableHeader";
import FilteringTitle from "./components/FilteringTitle";
import Pagination from "react-js-pagination";
import PropTypes from "prop-types";
import { finishedStatuses } from "./QueryUtils";

const SearchJobRowEmpty = () => {
    return (
        <tr>
            <td>
                <div className="d-flex">
                    <span className="invisible">sth</span>
                </div>
                <p className="mb-0 invisible" style={{ fontSize: 11 }}>
                    sth
                </p>
            </td>
            <td></td>
            <td></td>
            <td></td>
            <td></td>
        </tr>
    );
};

const SearchJobRow = (props) => {
    const {
        id,
        status,
        submitted,
        rule_name,
        priority,
        files_matched,
        total_files,
        files_processed,
        files_in_progress,
    } = props.job;
    const rule_author = props.job.rule_author
        ? props.job.rule_author
        : "(no author)";
    const { onClose, onCancel } = props;

    const submittedDate = new Date(submitted * 1000).toISOString();

    const actionBtn = finishedStatuses.includes(status) ? (
        <ActionClose onClick={onClose} />
    ) : (
        <ActionCancel onClick={onCancel} />
    );

    return (
        <tr>
            <td>
                <div className="d-flex">
                    <div
                        className="text-truncate"
                        style={{ minWidth: 50, maxWidth: "20vw" }}
                    >
                        <Link
                            to={"/query/" + id}
                            style={{ fontFamily: "monospace" }}
                        >
                            {rule_name}
                        </Link>
                    </div>
                    <span className="ml-2">
                        <PriorityIcon priority={priority} />
                    </span>
                </div>
                <p className="mb-0" style={{ fontSize: 11 }}>
                    {submittedDate}
                </p>
            </td>
            <td className="align-middle text-center">{rule_author}</td>
            <td className="align-middle text-center">{files_matched}</td>
            <td className="text-center align-middle w-50">
                <StatusProgress
                    status={status}
                    total_files={total_files}
                    files_processed={files_processed}
                    files_in_progress={files_in_progress}
                />
            </td>
            <td className="text-center align-middle">{actionBtn}</td>
        </tr>
    );
};

const SearchJobs = (props) => {
    const {
        jobs,
        head,
        filter,
        onCancel,
        onClose,
        onFilter,
        activePage,
        itemsPerPage,
        jobCount,
        onPageChange,
    } = props;

    const filterValue = filter ? filter.value : null;

    const backendJobRows = jobs.map((job) => (
        <SearchJobRow
            key={job.id}
            job={job}
            onClose={() => onClose(job.id)}
            onCancel={() => onCancel(job.id)}
        />
    ));

    // make table itemsPerPage size
    let i = backendJobRows.length;
    while (i < itemsPerPage) {
        backendJobRows.push(<SearchJobRowEmpty key={i} />);
        i++;
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
                        activePage={activePage}
                        itemsCountPerPage={itemsPerPage}
                        totalItemsCount={jobCount}
                        pageRangeDisplayed={5}
                        onChange={onPageChange}
                        itemClass="page-item"
                        linkClass="page-link"
                    />
                </div>
            </div>
        </div>
    );
};

SearchJobs.propTypes = {
    jobs: PropTypes.array.isRequired,
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
    onClose: PropTypes.func.isRequired,
    onCancel: PropTypes.func.isRequired,
};

export default SearchJobs;
