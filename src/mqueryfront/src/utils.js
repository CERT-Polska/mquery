import axios from "axios";
import api, { parseJWT } from "./api";
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

export const storeTokenData = (token) => {
    localStorage.setItem("rawToken", token);
    const decodedToken = parseJWT(token);
    localStorage.setItem("expiresAt", decodedToken.exp * 1000);
};

export const refreshAccesToken = async () => {
    const rawToken = localStorage.getItem("rawToken");
    const expiresAt = localStorage.getItem("expiresAt");
    if (rawToken) {
        const headers = rawToken ? { Authorization: `Bearer ${rawToken}` } : {};
        const response = await axios.request("/api/token/refresh", {
            method: "POST",
            headers: headers,
            withCredentials: true,
        });
        if (response.data["token"]) {
            storeTokenData(response.data["token"]);
        } else {
            return;
        }
    }
};

export const clearTokenData = (tokenInterval) => {
    clearInterval(tokenInterval);
    localStorage.removeItem("expiresAt");
    localStorage.removeItem("rawToken");
};

export const tokenExpired = () => {
    const rawToken = localStorage.getItem("rawToken");
    if (rawToken) {
        const expiresAt = localStorage.getItem("expiresAt");
        if (Date.now() > expiresAt) {
            return true;
        }
        return false;
    }
    return false;
};
