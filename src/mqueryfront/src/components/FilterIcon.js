import React from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faFilter } from "@fortawesome/free-solid-svg-icons";
import PropTypes from "prop-types";

const FilterIcon = (props) => {
    return (
        <span data-toggle="tooltip" title={props.tooltipMessage}>
            <FontAwesomeIcon
                icon={faFilter}
                size={props.size}
                color={props.color}
            />
        </span>
    );
};

FilterIcon.defaultProps = {
    size: "xs",
    color: undefined,
    tooltipMessage: "filter",
};

FilterIcon.propTypes = {
    color: PropTypes.string,
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
};

export default FilterIcon;
