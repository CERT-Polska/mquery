import React from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faTimes } from "@fortawesome/free-solid-svg-icons";
import PropTypes from "prop-types";

const ActionClose = (props) => {
    return (
        <button className="btn shadow-none" onClick={props.onClick}>
            <span data-toggle="tooltip" title={props.tooltipMessage}>
                <FontAwesomeIcon icon={faTimes} size={props.size} />
            </span>
        </button>
    );
};

ActionClose.defaultProps = {
    size: "1x",
    tooltipMessage: "close",
};

ActionClose.propTypes = {
    onClick: PropTypes.func.isRequired,
    size: PropTypes.oneOf([
        "lg",
        "xs",
        "sm",
        "1x",
        "2x",
        "3x",
        "4x",
        "5x",
        "6x",
        "7x",
        "8x",
        "9x",
        "10x",
    ]),
};

export default ActionClose;
