import React from "react";
import PropTypes from "prop-types";

const StatusProgress = (props) => {
    let rowClass;
    switch (props.status) {
        case "done":
            rowClass = "success";
            break;
        case "processing":
            rowClass = "info";
            break;
        case "querying":
            rowClass = "info";
            break;
        case "cancelled":
            rowClass = "danger";
            break;
        case "expired":
            rowClass = "warning";
            break;
        default:
            rowClass = "";
            break;
    }

    const progressClass = "progress-bar bg-" + rowClass;

    const percentage = Math.round(
        props.total_files
            ? (props.files_processed * 100) / props.total_files
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
    total_files: PropTypes.number.isRequired,
    files_processed: PropTypes.number.isRequired,
};

export default StatusProgress;
