import axios from "axios";
import { refreshAccesToken, tokenExpired } from "./utils";

export const api_url = "/api";

export function parseJWT(token) {
    const base64Url = token.split(".")[1];
    const base64 = base64Url.replace("-", "+").replace("_", "/");
    return JSON.parse(atob(base64));
}

async function request(method, path, payload, params) {
    if (tokenExpired()) {
        await refreshAccesToken();
    }
    const rawToken = localStorage.getItem("rawToken");
    const headers = rawToken ? { Authorization: `Bearer ${rawToken}` } : {};
    return axios
        .request(path, {
            method: method,
            data: payload,
            params: params,
            headers: headers,
        })
        .catch((error) => {
            if (error.response.status === 401) {
                window.location = "/auth";
            }
            throw error;
        });
}

function post(path, payload) {
    return request("post", `${api_url}${path}`, payload);
}

function get(path, params) {
    return request("get", `${api_url}${path}`, {}, params);
}

function delete_(path) {
    return request("delete", `${api_url}${path}`, {});
}

export default {
    post: post,
    get: get,
    delete: delete_,
};
