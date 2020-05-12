import React from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faTrashAlt } from "@fortawesome/free-solid-svg-icons";
import PropTypes from "prop-types";

const ActionRemove = (props) => {
    return (
        <button className="btn shadow-none" onClick={props.onClick}>
            <span data-toggle="tooltip" title={props.tooltipMessage}>
                <FontAwesomeIcon
                    icon={faTrashAlt}
                    size={props.size}
                    color={props.color}
                />
            </span>
        </button>
    );
};

ActionRemove.defaultProps = {
    size: "1x",
    tooltipMessage: "remove",
    color: "black",
};

ActionRemove.propTypes = {
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
    tooltipMessage: PropTypes.string,
    color: PropTypes.string,
};

export default ActionRemove;
