import React, { Component } from "react";
import { Switch, Route } from "react-router-dom";
import Navigation from "./Navigation";
import QueryPage from "./QueryPage";
import RecentPage from "./RecentPage";
import StatusPage from "./StatusPage";
import StoragePage from "./StoragePage";
import StorageAddPage from "./StorageAddPage";
import "./App.css";

class App extends Component {
    render() {
        return (
            <div className="App">
                <Navigation />

                <Switch>
                    <Route exact path="/" component={QueryPage} />
                    <Route path="/query/:hash" component={QueryPage} />
                    <Route exact path="/recent" component={RecentPage} />
                    <Route exact path="/storage" component={StoragePage} />
                    <Route
                        exact
                        path="/storage/add"
                        component={StorageAddPage}
                    />
                    <Route exact path="/status" component={StatusPage} />
                </Switch>
            </div>
        );
    }
}

export default App;
