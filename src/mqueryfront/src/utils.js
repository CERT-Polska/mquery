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

export const isAuthEnabled = (config) =>
    config && config["auth_enabled"] && config["auth_enabled"] !== "false";

export const openidLoginUrl = (config) => {
    const login_url = new URL(config["openid_url"] + "/auth");
    login_url.searchParams.append(
        "client_id",
        config["openid_client_id"]
    );
    login_url.searchParams.append("response_type", "code");
    login_url.searchParams.append(
        "redirect_uri",
        window.location.origin + "/auth"
    );
    return login_url;
}
