import PropTypes from "prop-types";

export const VALID_STATUSES = [
    "done",
    "new",
    "processing",
    "expired",
    "cancelled",
    "failed",
    "removed",
];

export const VALID_PRIORITIES = ["low", "medium", "high"];

export const PT_JOB = PropTypes.shape({
    datasets_left: PropTypes.number,
    files_errored: PropTypes.number.isRequired,
    files_in_progress: PropTypes.number.isRequired,
    files_matched: PropTypes.number.isRequired,
    files_processed: PropTypes.number.isRequired,
    finished: PropTypes.number,
    id: PropTypes.string.isRequired,
    iterator: PropTypes.any,
    priority: PropTypes.oneOf(VALID_PRIORITIES).isRequired,
    raw_yara: PropTypes.string.isRequired,
    rule_author: PropTypes.string.isRequired,
    rule_name: PropTypes.string.isRequired,
    status: PropTypes.oneOf(VALID_STATUSES).isRequired,
    submitted: PropTypes.number.isRequired,
    taints: PropTypes.arrayOf(PropTypes.string).isRequired,
    total_datasets: PropTypes.number.isRequired,
    total_files: PropTypes.number.isRequired,
});

export const PT_JOBS = PropTypes.arrayOf(PT_JOB.isRequired);

export const PT_MATCH = PropTypes.shape({
    file: PropTypes.string.isRequired,
    meta: PropTypes.shape({
        sha256: PropTypes.shape({
            display_text: PropTypes.string.isRequired,
            hidden: PropTypes.bool.isRequired,
        }),
    }).isRequired,
    matches: PropTypes.arrayOf(PropTypes.string).isRequired,
});

export const PT_MATCHES = PropTypes.arrayOf(PT_MATCH.isRequired);

export const PT_QUERYPLAN = PropTypes.arrayOf(
    PropTypes.shape({
        is_global: PropTypes.bool.isRequired,
        is_private: PropTypes.bool.isRequired,
        parsed: PropTypes.string.isRequired,
        rule_author: PropTypes.string.isRequired,
        rule_name: PropTypes.string.isRequired,
    })
);

export const PT_PAGINATION = PropTypes.shape({
    activePage: PropTypes.number.isRequired,
    itemsCountPerPage: PropTypes.number.isRequired,
    totalItemsCount: PropTypes.number.isRequired,
    pageRangeDisplayed: PropTypes.number.isRequired,
    onChange: PropTypes.func.isRequired,
});

export const isStatusFinished = (status) =>
    ["done", "cancelled", "failed", "expired", "removed"].includes(status);

export const getClassForStatus = (status) => {
    let classSufix = null;

    switch (status) {
        case "done":
            classSufix = "success";
            break;
        case "new":
        case "processing":
            classSufix = "info";
            break;
        case "expired":
            classSufix = "warning";
            break;
        case "cancelled":
        case "failed":
            classSufix = "danger";
            break;
        case "removed":
            classSufix = "dark";
            break;
        default:
            console.log(`getClassForStatus: unknown status="${status}"`);
            break;
    }

    return classSufix;
};

export const getProgressBarClass = (status) => {
    const classSufix = getClassForStatus(status);

    return "progress-bar" + (classSufix ? " bg-" + classSufix : "");
};

export const getBadgeClass = (status) => {
    const classSufix = getClassForStatus(status);

    return "badge" + (classSufix ? " badge-" + classSufix : "");
};
