import React from "react";
import ReactMultiSelectCheckboxes from "react-multiselect-checkboxes";

const QuerySearchNav = (props) => {
    const { onClick, availableTaints } = props;

    if (availableTaints.length === 0) return null;

    const options = availableTaints.map((obj) => ({
        label: obj,
        value: obj,
    }));

    return (
        <ReactMultiSelectCheckboxes
            onChange={onClick}
            options={options}
            placeholderButtonLabel="everywhere"
        />
    );
};

export default QuerySearchNav;
