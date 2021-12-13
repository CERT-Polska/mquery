export const isStatusFinished = (status) =>
    ["done", "cancelled", "failed", "expired", "removed"].includes(status);

const statusClassMap = {
    done: "success",
    new: "info",
    processing: "info",
    expired: "warning",
    cancelled: "danger",
    failed: "danger",
    removed: "dark",
};

export const getProgressBarClass = (status) => {
    const classSufix = statusClassMap[status];
    return "progress-bar" + (classSufix ? " bg-" + classSufix : "");
};
