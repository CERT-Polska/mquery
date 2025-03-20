import React from "react";

const IndexSuccessPage = (props) => (
    <div className="alert alert-primary alert-dismissible fade show">
        <h2>Success!</h2>
        {props.msg}
        <button
            type="button"
            className="btn-close"
            data-bs-dismiss="alert"
            aria-label="Close"
            onClick={() => props.onClick()}
        />
    </div>
);

export default IndexSuccessPage;
