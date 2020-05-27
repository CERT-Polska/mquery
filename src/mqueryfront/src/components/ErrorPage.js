import React from "react";
import PropTypes from "prop-types";

const ErrorPage = (props) => {
    return (
        <div className="alert alert-danger">
            <h2>Error occurred</h2>
            {props.error}
        </div>
    );
};

ErrorPage.propTypes = {
    error: PropTypes.string.isRequired,
};

export default ErrorPage;
