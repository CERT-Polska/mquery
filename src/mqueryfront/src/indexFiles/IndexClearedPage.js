import React from "react";

const IndexClearedPage = (props) => (
    <div className="alert alert-danger alert-dismissible fade show">
        <h2>Cleared!</h2>
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

export default IndexClearedPage;
