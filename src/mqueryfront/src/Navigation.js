import React from "react";
import { Link } from "react-router-dom";
import { ReactComponent as Logo } from "./logo.svg";
import { isAuthEnabled } from "./utils";

function Navigation(props) {
    let loginElm = null;
    let authEnabled = isAuthEnabled(props.config);
    if (!authEnabled) {
        loginElm = null;
    } else if (props.session != null) {
        loginElm = (
            <li className="nav-item nav-right">
                <a className="nav-link" href="/" onClick={props.logout}>
                    Logout ({props.session.preferred_username})
                </a>
            </li>
        );
    } else {
        loginElm = (
            <li className="nav-item nav-right">
                <a className="nav-link" href="/auth">
                    Login
                </a>
            </li>
        );
    }

    return (
        <nav className="navbar navbar-expand-lg navbar-dark bg-dark mb-3">
            <Link className="navbar-brand" to={"/"}>
                <Logo width="150" height="100%" />
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
                    <li className="nav-item">
                        <Link className="nav-link" to={"/config"}>
                            Config
                        </Link>
                    </li>
                    <li className="nav-item">
                        <Link className="nav-link" to={"/status"}>
                            Status
                        </Link>
                    </li>
                </ul>
                <ul className="navbar-nav navbar-right">
                    <li className="nav-item nav-right">
                        <a className="nav-link" href="/docs">
                            API Docs
                        </a>
                    </li>
                    {loginElm}
                </ul>
            </div>
        </nav>
    );
}

export default Navigation;
