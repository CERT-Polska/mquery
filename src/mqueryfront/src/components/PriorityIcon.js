import React from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
    faAngleDown,
    faAngleUp,
    faAngleDoubleUp,
} from "@fortawesome/free-solid-svg-icons";
import PropTypes from "prop-types";

const PriorityIcon = (props) => {
    let icon;
    if (props.priority === "low") icon = faAngleDown;
    else if (props.priority === "medium") icon = faAngleUp;
    else if (props.priority === "high") icon = faAngleDoubleUp;
    else return null;

    return (
        <span data-toggle="tooltip" title={props.priority}>
            <FontAwesomeIcon icon={icon} size="1x" color="red" />
        </span>
    );
};

PriorityIcon.propTypes = {
    priority: PropTypes.oneOf(["low", "medium", "high"]).isRequired,
};

export default PriorityIcon;
