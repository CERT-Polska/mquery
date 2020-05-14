import React from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faMinusCircle } from "@fortawesome/free-solid-svg-icons";
import { FONTAWESOMESIZES } from "./bootstrapUtils";
import PropTypes from "prop-types";

const ActionCancel = (props) => {
    return (
        <button className="btn shadow-none" onClick={props.onClick}>
            <span data-toggle="tooltip" title={props.tooltipMessage}>
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
    tooltipMessage: "cancel",
};

ActionCancel.propTypes = {
    onClick: PropTypes.func.isRequired,
    size: PropTypes.oneOf(FONTAWESOMESIZES),
};

export default ActionCancel;
