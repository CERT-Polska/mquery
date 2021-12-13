import React, { useState, useEffect } from "react";
import { Routes, Route } from "react-router-dom";
import Navigation from "./Navigation";
import QueryPage from "./query/QueryPage";
import RecentPage from "./recent/RecentPage";
import StatusPage from "./status/StatusPage";
import ConfigPage from "./config/ConfigPage";
import AuthPage from "./auth/AuthPage";
import axios from "axios";
import { API_URL } from "./config";
import "./App.css";

function parseJWT(token) {
    const base64Url = token.split(".")[1];
    const base64 = base64Url.replace("-", "+").replace("_", "/");
    return JSON.parse(Buffer.from(base64, "base64").toString("binary"));
}

function App() {
    const [config, setConfig] = useState(null);
    const rawToken = localStorage.getItem("rawToken");
    const token = rawToken ? parseJWT(rawToken) : null;

    useEffect(() => {
        axios.get(`${API_URL}/server`).then((response) => {
            setConfig(response.data);
        });
    }, []);

    const login = (rawToken) => {
        localStorage.setItem("rawToken", rawToken);
        window.location.href = "/";
    };

    const logout = () => {
        localStorage.removeItem("rawToken");
        window.location.href = "/";
    };

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
                    path="/auth"
                    element={<AuthPage config={config} login={login} />}
                />
            </Routes>
        </div>
    );
}

export default App;
