import axios from "axios";

export const api_url = "/api";

export function parseJWT(token) {
    const base64Url = token.split(".")[1];
    const base64 = base64Url.replace("-", "+").replace("_", "/");
    return JSON.parse(Buffer.from(base64, "base64").toString("binary"));
}

function request(method, path, payload) {
    const rawToken = localStorage.getItem("token");
    const headers = rawToken ? { Authorization: `Bearer ${rawToken}` } : {};
    return axios.request(path, {
        method: method,
        data: payload,
        headers: headers,
    });
}

function post(path, payload) {
    return request("post", `${api_url}${path}`, payload);
}

function get(path) {
    return request("get", `${api_url}${path}`, {});
}

function delete_(path) {
    return request("delete", `${api_url}${path}`, {});
}

export default {
    post: post,
    get: get,
    delete: delete_,
};
