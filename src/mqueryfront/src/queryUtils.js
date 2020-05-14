export const isStatusFinished = (status) =>
    ["done", "cancelled", "failed", "expired", "removed"].includes(status);

export const getClassForStatus = (status) => {
    let classSufix = null;

    switch (status) {
        case "done":
            classSufix = "success";
            break;
        case "processing":
        case "querying":
            classSufix = "info";
            break;
        case "expired":
            classSufix = "warning";
            break;
        case "cancelled":
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
