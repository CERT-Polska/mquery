import React from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faMinusCircle } from "@fortawesome/free-solid-svg-icons";
import PropTypes from "prop-types";

const ActionCancel = (props) => {
    return (
        <button className="btn shadow-none" onClick={props.onClick}>
            <span data-toggle="tooltip" title="cancel">
                <FontAwesomeIcon
                    icon={faMinusCircle}
                    size={props.size}
                    color="red"
                />
            </span>
        </button>
    );
};

ActionCancel.defaultProps = {
    size: "1x",
};

ActionCancel.propTypes = {
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

export default ActionCancel;
