import React from "react";

const WarningPage = (props) => (
    <div className="alert alert-warning alert-dismissible fade show">
        <h2>Warning</h2>
        {props.msg}
        {props.dismissable && (
            <button
                type="button"
                class="btn-close"
                data-bs-dismiss="alert"
                aria-label="Close"
            />
        )}
    </div>
);

export default WarningPage;
