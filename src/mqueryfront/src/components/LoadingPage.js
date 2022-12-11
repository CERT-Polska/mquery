import React from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faSpinner } from "@fortawesome/free-solid-svg-icons";

const LoadingPage = () => (
    <h2>
        <FontAwesomeIcon icon={faSpinner} spin size="lg" className="me-2" />
        Loading...
    </h2>
);

export default LoadingPage;
