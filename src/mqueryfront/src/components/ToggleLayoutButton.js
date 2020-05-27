import React from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faAlignLeft } from "@fortawesome/free-solid-svg-icons";
import PropTypes from "prop-types";

const ToggleLayoutButton = (props) => {
    const { buttonClass, onClick } = props;
    const icon = faAlignLeft;
    let { label } = props;
    if (props.label !== "") label = " " + label;

    return (
        <button type="button" className={buttonClass} onClick={onClick}>
            <span data-toggle="tooltip" title={props.tooltipMessage}>
                <FontAwesomeIcon icon={icon} />
                {label}
            </span>
        </button>
    );
};

ToggleLayoutButton.defaultProps = {
    buttonClass: "btn btn-primary",
    tooltipMessage: "",
    label: "",
};

ToggleLayoutButton.propTypes = {
    onClick: PropTypes.func.isRequired,
    buttonClass: PropTypes.string,
    label: PropTypes.string,
    tooltipMessage: PropTypes.string,
};

export default ToggleLayoutButton;
