import React from "react";

const ErrorPage = (props) => (
    <div className="alert alert-danger">
        <h2>Error occurred</h2>
        {props.error}
    </div>
);

export default ErrorPage;
