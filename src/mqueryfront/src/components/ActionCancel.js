import React from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faMinusCircle } from "@fortawesome/free-solid-svg-icons";

const ActionCancel = (props) => (
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

export default ActionCancel;
