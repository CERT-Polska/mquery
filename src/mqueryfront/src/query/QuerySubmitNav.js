import React from "react";
import PropTypes from "prop-types";

const QuerySubmitNav = (props) => {
    const { onClick } = props;

    return (
        <React.Fragment>
            <button
                type="button"
                className="btn btn-success btn-sm"
                onClick={() => onClick("medium")}
            >
                Query
            </button>
            <div className="btn-group" role="group">
                <button
                    type="button"
                    className="btn btn-success dropdown-toggle"
                    data-toggle="dropdown"
                    aria-haspopup="true"
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

QuerySubmitNav.propTypes = {
    onClick: PropTypes.func.isRequired,
};

export default QuerySubmitNav;
