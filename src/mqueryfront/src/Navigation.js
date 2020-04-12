import React, { Component } from "react";
import { Link } from "react-router-dom";
import { withRouter } from "react-router-dom";
import logo from "./logo.svg";

class Navigation extends Component {
    constructor(props) {
        super(props);
        this.state = {};
    }

    render() {
        return (
            <nav className="navbar navbar-expand-lg navbar-dark bg-dark mb-3">
                <Link className="navbar-brand" to={"/"}>
                    <img src={logo} width="150" alt="" />
                </Link>
                <button
                    className="navbar-toggler"
                    type="button"
                    data-toggle="collapse"
                    data-target="#navbarSupportedContent"
                    aria-controls="navbarSupportedContent"
                    aria-expanded="false"
                    aria-label="Toggle navigation"
                >
                    <span className="navbar-toggler-icon" />
                </button>

                <div
                    className="collapse navbar-collapse"
                    id="navbarSupportedContent"
                >
                    <ul className="navbar-nav mr-auto">
                        <li className="nav-item">
                            <Link className="nav-link" to={"/"}>
                                Query
                            </Link>
                        </li>
                        <li className="nav-item">
                            <Link className="nav-link" to={"/recent"}>
                                Recent jobs
                            </Link>
                        </li>
                        {process.env.NODE_ENV == "development" ? (
                            <li className="nav-item">
                                <Link className="nav-link" to={"/storage"}>
                                    Storage
                                </Link>
                            </li>
                        ) : undefined}
                        <li className="nav-item">
                            <Link className="nav-link" to={"/status"}>
                                Status
                            </Link>
                        </li>
                    </ul>
                    <ul className="navbar-nav mr-auto navbar-right">
                        <li className="nav-item nav-right">
                            <a className="nav-link" href="/docs">
                                API Docs
                            </a>
                        </li>
                    </ul>
                </div>
            </nav>
        );
    }
}

export default withRouter(Navigation);
