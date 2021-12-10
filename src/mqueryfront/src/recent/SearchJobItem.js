import React from "react";
import { Link } from "react-router-dom";
import PriorityIcon from "../components/PriorityIcon";
import ActionRemove from "../components/ActionRemove";
import ActionCancel from "../components/ActionCancel";
import QueryProgressBar from "../components/QueryProgressBar";
import PropTypes from "prop-types";
import { PT_JOB, isStatusFinished } from "../queryUtils";

export const SearchJobItemEmpty = () => {
    return (
        <tr>
            <td>
                <div className="d-flex">
                    <span className="invisible">&nbsp;</span>
                </div>
                <p className="mb-0 invisible" style={{ fontSize: 11 }}>
                    &nbsp;
                </p>
            </td>
            <td></td>
            <td></td>
            <td></td>
        </tr>
    );
};

const SearchJobItem = (props) => {
    const { job, onRemove, onCancel } = props;
    const { id, status, submitted, rule_name, priority, files_matched } = job;
    const rule_author = props.job.rule_author
        ? props.job.rule_author
        : "(no author)";
    const isFinished = isStatusFinished(status);
    const submittedDate = new Date(submitted * 1000).toISOString();
    const actionBtn = isFinished ? (
        <ActionRemove onClick={onRemove} size="lx" />
    ) : (
        <ActionCancel onClick={onCancel} size="lx" />
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
            <td className="text-center align-middle w-50">
                <QueryProgressBar job={job} compact={true} />
            </td>
            <td className="text-center align-middle">{actionBtn}</td>
        </tr>
    );
};

SearchJobItem.propTypes = {
    job: PT_JOB.isRequired,
    onRemove: PropTypes.func.isRequired,
    onCancel: PropTypes.func.isRequired,
};

export default SearchJobItem;
