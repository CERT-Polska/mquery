import React from "react";

const QuerySubmitNav = (props) => {
    const { onClick, forceMode } = props;

    const label = forceMode ? "Force query (may be very slow!)" : "Query";
    const style = forceMode ? "btn-danger" : "btn-success";

    return (
        <button
            type="button"
            className={"btn btn-sm " + style}
            onClick={onClick}
        >
            {label}
        </button>
    );
};

export default QuerySubmitNav;
