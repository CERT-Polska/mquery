import React from "react";
import PropTypes from "prop-types";
import { getProgressBarClass } from "../queryUtils";

const StatusProgress = (props) => {
    const { status, isFinished, total_files, files_processed } = props;

    const progressClass = getProgressBarClass(status);

    const percentage = Math.round(
        total_files
            ? (files_processed * 100) / total_files
            : isFinished
            ? 100
            : 0
    );

    return (
        <div
            className="progress position-relative"
            style={{ minWidth: 160, height: 18, fontSize: 12 }}
        >
            <div
                className={progressClass}
                role="progressbar"
                style={{ width: percentage + "%" }}
                aria-valuenow={percentage}
                aria-valuemin="0"
                aria-valuemax="100"
            ></div>
            <span
                className="justify-content-center d-flex position-absolute w-100"
                data-toggle="tooltip"
                data-placement="right"
                title={props.status}
            >
                {`${props.files_processed} / ${props.total_files} (${percentage}%)`}
            </span>
        </div>
    );
};

StatusProgress.propTypes = {
    status: PropTypes.string.isRequired,
    isFinished: PropTypes.bool.isRequired,
    total_files: PropTypes.number.isRequired,
    files_processed: PropTypes.number.isRequired,
};

export default StatusProgress;
