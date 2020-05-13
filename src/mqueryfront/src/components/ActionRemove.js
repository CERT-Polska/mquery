import React from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faTrashAlt } from "@fortawesome/free-solid-svg-icons";
import { FONTAWESOMESIZES } from "./bootstrapUtils";
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
    size: PropTypes.oneOf(FONTAWESOMESIZES),
    tooltipMessage: PropTypes.string,
    color: PropTypes.string,
};

export default ActionRemove;
