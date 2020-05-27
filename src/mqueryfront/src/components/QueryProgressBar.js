import React from "react";
import ActionCancel from "./ActionCancel";
import QueryTimer from "./QueryTimer";
import PropTypes from "prop-types";
import {
    isStatusFinished,
    getProgressBarClass,
    getBadgeClass,
    PT_JOB,
} from "../queryUtils";

const getPercentage = (partial, total) =>
    total ? Math.round((partial * 100) / total) : 0;

const QueryProgressBar = (props) => {
    const { job, displayBarOnly, onCancel } = props;
    const {
        status,
        files_processed,
        total_files,
        files_in_progress,
        files_errored,
        files_matched,
    } = job;

    const isFinished = isStatusFinished(status);
    const inProgeressPc = getPercentage(files_in_progress, total_files);
    const erroredPct = getPercentage(files_errored, total_files);
    const processedPct =
        total_files === 0 && isFinished
            ? 100
            : getPercentage(files_processed, total_files);

    const errorString = files_errored === 1 ? "error" : "errors";
    const errorTooltip = `${files_errored} ${errorString} during processing`;

    const cancelButton = isFinished ? null : (
        <ActionCancel onClick={onCancel} size="lg" />
    );

    const statusTooltip = displayBarOnly ? status : "";

    return (
        <div>
            <div className="progress">
                <div
                    className={getProgressBarClass(status)}
                    role="progressbar"
                    style={{ width: processedPct + "%" }}
                    data-toggle="tooltip"
                    title={statusTooltip}
                >
                    {`${files_processed} / ${total_files} (${processedPct}%)`}
                </div>
                {total_files > 0 && inProgeressPc > 0 && (
                    <div
                        className={"progress-bar bg-warning"}
                        role="progressbar"
                        style={{ width: Math.max(3, inProgeressPc) + "%" }}
                    >
                        {inProgeressPc}%
                    </div>
                )}
                {files_errored > 0 && (
                    <div
                        className={"progress-bar bg-danger"}
                        role="progressbar"
                        style={{ width: Math.max(3, erroredPct) + "%" }}
                        data-toggle="tooltip"
                        title={errorTooltip}
                    />
                )}
            </div>
            {!displayBarOnly && (
                <div className="d-flex justify-content-between m-0 pt-2">
                    <div>
                        <p>
                            Matches: <span>{files_matched}</span>
                        </p>
                    </div>
                    <div>
                        Status:
                        <span className={getBadgeClass(status) + " ml-2"}>
                            {status}
                        </span>
                    </div>
                    <div>
                        <QueryTimer
                            job={job}
                            isFinished={isFinished}
                            duration={true}
                            countDown={true}
                        />
                        <span className="ml-2">{cancelButton}</span>
                    </div>
                </div>
            )}
        </div>
    );
};

QueryProgressBar.defaultProps = {
    displayBarOnly: false,
};

QueryProgressBar.propTypes = {
    job: PT_JOB.isRequired,
    displayBarOnly: PropTypes.bool,
    onCancel: PropTypes.func,
};

export default QueryProgressBar;
