import React from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faClone, faCode } from "@fortawesome/free-solid-svg-icons";

const QueryEditParseNav = (props) => {
    const { onEditQuery, onParseQuery, isEditActive } = props;
    let label, onClick, icon, name;

    if (isEditActive) {
        label = "Edit";
        onClick = onEditQuery;
        icon = faClone;
        name = "clone";
    } else {
        label = "Parse";
        onClick = onParseQuery;
        icon = faCode;
        name = "parse";
    }
    return (
        <button
            className="btn btn-secondary btn-sm"
            name={name}
            type="submit"
            onClick={onClick}
        >
            <FontAwesomeIcon icon={icon} /> {label}
        </button>
    );
};

export default QueryEditParseNav;
