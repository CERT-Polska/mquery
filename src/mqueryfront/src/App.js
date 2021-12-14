import React, { useState, useEffect } from "react";
import { Routes, Route } from "react-router-dom";
import Navigation from "./Navigation";
import QueryPage from "./query/QueryPage";
import RecentPage from "./recent/RecentPage";
import StatusPage from "./status/StatusPage";
import ConfigPage from "./config/ConfigPage";
import LoadingPage from "./components/LoadingPage";
import axios from "axios";
import { API_URL } from "./config";
import "./App.css";

function getRoutes(config) {
    if (!config) {
        return <LoadingPage />;
    }

    return (
        <Routes>
            <Route exact path="/" element={<QueryPage config={config} />} />
            <Route
                path="/query/:hash"
                element={<QueryPage config={config} />}
            />
            <Route
                exact
                path="/recent"
                element={<RecentPage config={config} />}
            />
            <Route
                exact
                path="/config"
                element={<ConfigPage config={config} />}
            />
            <Route
                exact
                path="/status"
                element={<StatusPage config={config} />}
            />
        </Routes>
    );
}

function App() {
    const [config, setConfig] = useState(null);

    useEffect(() => {
        axios.get(`${API_URL}/server`).then((response) => {
            setConfig(response.data);
        });
    }, []);

    return (
        <div className="App">
            <Navigation />
            {getRoutes(config)}
        </div>
    );
}

export default App;
