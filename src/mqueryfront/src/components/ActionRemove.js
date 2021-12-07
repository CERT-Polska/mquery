import React from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faTrashAlt } from "@fortawesome/free-solid-svg-icons";

const ActionRemove = (props) => (
    <button className="btn shadow-none" onClick={props.onClick}>
        <span data-toggle="tooltip" title="remove">
            <FontAwesomeIcon
                icon={faTrashAlt}
                size={props.size}
                color="black"
            />
        </span>
    </button>
);

export default ActionRemove;
