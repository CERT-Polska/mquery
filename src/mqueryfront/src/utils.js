import axios from "axios";

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

export const storeTokenData = (token_data) => {
    localStorage.setItem("rawToken", token_data['access_token']);
    localStorage.setItem("expiresAt", Date.now() + token_data['expires_in'] *1000)
    localStorage.setItem("refreshToken", token_data['refresh_token'])
}

export const refreshAccesToken = (config) => {
    // console.log("CONFIG: ", config)
    if(config && 'openid_client_id' in config) {
        const expiresAt = localStorage.getItem("expiresAt")
        if(expiresAt && Date.now() > Number(expiresAt) - 60*1000){
            let openid_client_id = config["openid_client_id"]

            let refreshToken = localStorage.getItem("refreshToken")
            const params = new URLSearchParams();
            params.append("grant_type", "refresh_token");
            params.append("refresh_token", refreshToken);
            params.append("client_id", openid_client_id);
            params.append("redirect_uri", window.location.origin + "/auth");
            axios
                    .post(config["openid_url"] + "/token", params)
                    .then((response) => {
                        storeTokenData(response.data)
                    })
                    .catch((error) => {
                        console.error(error)
                        const currentLocation = localStorage.getItem("currentLocation")
                        if(currentLocation) {
                            window.location.href = currentLocation
                        }
                        else {
                            window.location.href = "/"
                        } 
                    });
        }

    }

}

export const clearTokenData = (tokenInterval) => {
    clearInterval(tokenInterval)
    localStorage.removeItem("expiresAt");
    localStorage.removeItem("refreshToken");
    localStorage.removeItem("rawToken");

}
