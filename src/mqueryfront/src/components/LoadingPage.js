import React from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faSpinner } from "@fortawesome/free-solid-svg-icons";

const LoadingPage = () => (
    <div>
        <h2>
            <FontAwesomeIcon icon={faSpinner} spin size="lg" className="mr-2" />
            Loading...
        </h2>
    </div>
);

export default LoadingPage;
