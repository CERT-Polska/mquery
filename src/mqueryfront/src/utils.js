export const isStatusFinished = (status) =>
    ["done", "cancelled"].includes(status);

const statusClassMap = {
    done: "success",
    new: "info",
    processing: "info",
    cancelled: "danger",
};

export const isAuthEnabled = (config) =>
    config && config["auth_enabled"] && config["auth_enabled"] !== "false";

export const openidLoginUrl = (config) => {
    if (config["openid_url"] === null || config["openid_client_id"] === null) {
        // Defensive programming - config keys can be null.
        return "#";
        gi;
    }
    const login_url = new URL(config["openid_url"] + "/auth");
    login_url.searchParams.append("client_id", config["openid_client_id"]);
    login_url.searchParams.append("response_type", "code");
    login_url.searchParams.append(
        "redirect_uri",
        window.location.origin + "/auth"
    );
    return login_url;
};
