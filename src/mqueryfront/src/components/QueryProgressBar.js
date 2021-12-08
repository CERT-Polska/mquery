import React from "react";
import ActionCancel from "./ActionCancel";
import QueryTimer from "./QueryTimer";
import { isStatusFinished, getProgressBarClass } from "../queryUtils";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faSpinner } from "@fortawesome/free-solid-svg-icons";

const getPercentage = (partial, total) =>
    total ? Math.round((partial * 100) / total) : 0;

const QueryProgressBar = (props) => {
    const { job, compact, onCancel } = props;
    const {
        status,
        files_processed,
        total_files,
        files_in_progress,
        files_errored,
        files_matched,
        total_datasets,
        datasets_left,
    } = job;

    const datasetsDone = total_datasets - datasets_left;
    const datasetFrac = total_datasets > 0 ? datasetsDone / total_datasets : 0;
    const datasetPct = Math.round(datasetFrac * 100);

    const isFinished = isStatusFinished(status);
    const inProgeressPct = getPercentage(
        files_in_progress * datasetFrac,
        total_files
    );
    const erroredPct = getPercentage(files_errored * datasetFrac, total_files);
    const processedPct =
        total_files === 0 && isFinished
            ? 100
            : getPercentage(files_processed * datasetFrac, total_files);

    const errorString = files_errored === 1 ? "error" : "errors";
    const errorTooltip = `${files_errored} ${errorString} during processing`;

    const cancelButton = isFinished ? null : (
        <ActionCancel onClick={onCancel} size="sm" />
    );

    const matches = `${files_matched} matches`;
    let statusInfo = null;
    if (total_datasets === 0 && status === "new") {
        statusInfo = "Collecting datasets...";
    } else if (datasets_left > 0) {
        statusInfo = `Searching for candidates: ${datasetsDone}/${total_datasets} (${datasetPct}%)...`;
    } else if (status === "processing") {
        statusInfo = `Matching Yara: ${files_processed} / ${total_files} (${processedPct}%), ${matches}`;
    }

    return (
        <div>
            <div className="progress">
                <div
                    className={getProgressBarClass(status)}
                    role="progressbar"
                    style={{ width: processedPct + "%" }}
                    data-toggle="tooltip"
                    title={status}
                >
                    {Math.round(processedPct)}%
                </div>
                {total_files > 0 && inProgeressPct > 0 && (
                    <div
                        className={"progress-bar bg-warning"}
                        role="progressbar"
                        style={{ width: inProgeressPct + "%" }}
                    ></div>
                )}
                {files_errored > 0 && (
                    <div
                        className={"progress-bar bg-danger"}
                        role="progressbar"
                        style={{ width: erroredPct + "%" }}
                        data-toggle="tooltip"
                        title={errorTooltip}
                    />
                )}
            </div>
            {
                <div className={compact ? "small" : ""}>
                    <div class="float-left">
                        {statusInfo && (
                            <FontAwesomeIcon
                                icon={faSpinner}
                                spin
                                size={props.size}
                                className="mr-1"
                            />
                        )}
                        {statusInfo || matches}
                    </div>
                    <div class="float-right">
                        <QueryTimer
                            job={job}
                            isFinished={isFinished}
                            duration={true}
                            countDown={true}
                        />
                        {compact || isFinished ? null : (
                            <ActionCancel
                                onClick={onCancel}
                                size="sm"
                                className="ml2"
                            />
                        )}
                    </div>
                    <div class="clearfix"></div>
                </div>
            }
        </div>
    );
};

export default QueryProgressBar;
