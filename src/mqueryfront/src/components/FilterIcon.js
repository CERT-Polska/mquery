import React from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faFilter } from "@fortawesome/free-solid-svg-icons";

const FilterIcon = (props) => (
    <span data-toggle="tooltip" title={props.tooltipMessage}>
        <FontAwesomeIcon icon={faFilter} size="xs" />
    </span>
);

export default FilterIcon;
