import React from "react";

const QuerySubmitNav = (props) => {
    const { onClick, forceMode } = props;

    const label = forceMode ? "Force query (may be very slow!)" : "Query";
    const style = forceMode ? "btn-danger" : "btn-success";

    return (
        <React.Fragment>
            <button
                type="button"
                className={"btn btn-sm " + style}
                onClick={() => onClick("medium")}
            >
                {label}
            </button>
            <div className="btn-group">
                <button
                    type="button"
                    className={"btn dropdown-toggle " + style}
                    data-bs-toggle="dropdown"
                    aria-expanded="false"
                />
                <div className="dropdown-menu">
                    <button
                        className="dropdown-item"
                        onClick={() => onClick("low")}
                    >
                        Low Priority Query
                    </button>
                    <button
                        className="dropdown-item"
                        onClick={() => onClick("medium")}
                    >
                        Standard Priority Query
                    </button>
                    <button
                        className="dropdown-item"
                        onClick={() => onClick("high")}
                    >
                        High Priority Query
                    </button>
                </div>
            </div>
        </React.Fragment>
    );
};

export default QuerySubmitNav;
