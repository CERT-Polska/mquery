import React from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faTimes } from "@fortawesome/free-solid-svg-icons";
import { FONTAWESOMESIZES } from "./bootstrapUtils";
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
    size: PropTypes.oneOf(FONTAWESOMESIZES),
    tooltipMessage: PropTypes.string,
};

export default ActionClose;
