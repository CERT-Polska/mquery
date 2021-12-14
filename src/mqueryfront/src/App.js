import React, { useState, useEffect } from "react";
import { Routes, Route } from "react-router-dom";
import Navigation from "./Navigation";
import QueryPage from "./query/QueryPage";
import RecentPage from "./recent/RecentPage";
import StatusPage from "./status/StatusPage";
import ConfigPage from "./config/ConfigPage";
import axios from "axios";
import { API_URL } from "./config";
import "./App.css";

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
        </div>
    );
}

export default App;
