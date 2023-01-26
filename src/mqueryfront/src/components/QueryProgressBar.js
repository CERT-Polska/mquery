import React from "react";
import ActionCancel from "./ActionCancel";
import QueryTimer from "./QueryTimer";
import { isStatusFinished } from "../utils";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faSpinner } from "@fortawesome/free-solid-svg-icons";

const finalProgressBar = (job, text, cssBg, progress = 100) => (
    <div>
        <div className="progress">
            <div
                className={"progress-bar " + cssBg}
                role="progressbar"
                style={{ width: `${progress}%` }}
                data-toggle="tooltip"
                title={text}
            >
                {text}
            </div>
        </div>
        <div>
            <div className="float-right">
                <QueryTimer
                    job={job}
                    isFinished={true}
                    duration={true}
                    countDown={true}
                />
            </div>
            <div className="clearfix"></div>
        </div>
    </div>
);

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
        agents_left,
    } = job;

    const getPercentage = (files) =>
        total_files ? Math.round((files * datasetFrac * 100) / total_files) : 0;

    const datasetsDone = total_datasets - datasets_left;
    const datasetFrac = total_datasets > 0 ? datasetsDone / total_datasets : 0;
    const datasetPct = Math.round(datasetFrac * 100);

    const isFinished = isStatusFinished(status);
    const inProgeressPct = getPercentage(files_in_progress);
    const erroredPct = getPercentage(files_errored);
    const filesSuccess = files_processed - files_errored;
    const processedPct =
        total_files === 0 && isFinished ? 100 : getPercentage(filesSuccess);

    if (status == "cancelled") {
        const percent = processedPct;
        return finalProgressBar(job, "query cancelled", "bg-danger", percent);
    }

    let statusInfo = "";
    const matches = `${files_matched} matches`;
    const matches_long = `${matches} (out of ${total_files} candidates)`;
    if (agents_left > 0) {
        statusInfo += `Backends working: ${agents_left}. `;
    }
    if (total_datasets === 0 && status === "new") {
        statusInfo += "Collecting datasets. ";
    }
    if (datasets_left > 0) {
        statusInfo += `Querying datasets: ${datasetsDone}/${total_datasets} (${datasetPct}%). `;
    }
    if (status === "processing" && files_processed < total_files) {
        statusInfo += `Matching Yara: ${files_processed} / ${total_files} (${processedPct}%), ${matches}. `;
    }
    return (
        <div>
            <div className="progress">
                <div
                    className={"progress-bar bg-success"}
                    role="progressbar"
                    style={{ width: processedPct + "%" }}
                    data-toggle="tooltip"
                    title={`${filesSuccess} files checked`}
                >
                    {Math.round(processedPct)}%
                </div>
                <div
                    className={"progress-bar bg-warning"}
                    role="progressbar"
                    style={{ width: inProgeressPct + "%" }}
                    title={`${files_in_progress} files in progress`}
                ></div>
                <div
                    className={"progress-bar bg-danger"}
                    role="progressbar"
                    style={{ width: erroredPct + "%" }}
                    data-toggle="tooltip"
                    title={`${files_errored} files errored when checking`}
                />
            </div>
            <div className={compact ? "small" : ""}>
                <div className="float-left">
                    {!isFinished && (
                        <FontAwesomeIcon
                            icon={faSpinner}
                            spin
                            size={props.size}
                            className="me-1"
                        />
                    )}
                    {statusInfo || (compact ? matches : matches_long)}
                </div>
                <div className="float-right">
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
                <div className="clearfix"></div>
            </div>
        </div>
    );
};

export default QueryProgressBar;
