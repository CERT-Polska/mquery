import React, { useState, useRef, useEffect } from "react";
import { Routes, Route } from "react-router-dom";
import Navigation from "./Navigation";
import QueryPage from "./query/QueryPage";
import RecentPage from "./recent/RecentPage";
import StatusPage from "./status/StatusPage";
import ConfigPage from "./config/ConfigPage";
import AboutPage from "./about/AboutPage";
import AuthPage from "./auth/AuthPage";
import api, { parseJWT } from "./api";
import "./App.css";
import { refreshAccesToken, storeTokenData, clearTokenData } from "./utils";

function getCurrentTokenOrNull() {
    // This function handles missing and corrupted token in the same way.
    try {
        return parseJWT(localStorage.getItem("rawToken"));
    } catch {
        return null;
    }
}

function App() {
    const [config, setConfig] = useState(null);
    const configRef = useRef(config);
    const tokenIntervalRef = useRef(null);

    useEffect(() => {
        configRef.current = config;
    }, [config]);

    useEffect(() => {
        api.get("/server").then((response) => {
            setConfig(response.data);
        });
        tokenIntervalRef.current = setInterval(() => {
            if (configRef.current && "openid_client_id" in configRef.current) {
                refreshAccesToken(configRef.current);
            }
        }, 60000);
        return () => clearInterval(tokenIntervalRef.current);
    }, []);

    const login = (token_data) => {
        storeTokenData(token_data);
        let location_href = localStorage.getItem("currentLocation");
        if (location_href) {
            window.location.href = location_href;
        } else {
            window.location.href = "/";
        }
    };

    const logout = () => {
        clearTokenData(tokenIntervalRef.curr);
        if (config !== null) {
            const logout_url = new URL(config["openid_url"] + "/logout");
            logout_url.searchParams.append(
                "redirect_uri",
                window.location.origin
            );
            window.location.href = logout_url;
        } else {
            // Shouldn't happen, but reload just in case.
            window.location.href = "/";
        }
    };

    const token = getCurrentTokenOrNull();

    return (
        <div className="App">
            <Navigation session={token} config={config} logout={logout} />
            <Routes>
                <Route exact path="/" element={<QueryPage />} />
                <Route path="/query/:hash" element={<QueryPage />} />
                <Route exact path="/recent" element={<RecentPage />} />
                <Route exact path="/config" element={<ConfigPage />} />
                <Route exact path="/status" element={<StatusPage />} />
                <Route
                    exact
                    path="/about"
                    element={<AboutPage config={config} />}
                />
                <Route
                    exact
                    path="/auth"
                    element={<AuthPage config={config} login={login} />}
                />
            </Routes>
        </div>
    );
}

export default App;
