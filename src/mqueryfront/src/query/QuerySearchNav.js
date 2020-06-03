import React from "react";
import ReactMultiSelectCheckboxes from "react-multiselect-checkboxes";
import PropTypes from "prop-types";

const QuerySearchNav = (props) => {
    const { onChange, availableTaints } = props;

    if (availableTaints.length === 0) return null;

    const options = availableTaints.map((obj) => ({
        label: obj,
        value: obj,
    }));

    let placeholder = "everywhere";
    if (props.selectedTaints.length) {
        placeholder = props.selectedTaints.map((obj) => obj.value).toString();
    }

    return (
        <ReactMultiSelectCheckboxes
            onChange={onChange}
            options={options}
            value={props.selectedTaints}
            placeholderButtonLabel={placeholder}
        />
    );
};

QuerySearchNav.propTypes = {
    availableTaints: PropTypes.arrayOf(PropTypes.string).isRequired,
    selectedTaints: PropTypes.arrayOf(PropTypes.string).isRequired,
    onChange: PropTypes.func.isRequired,
};
export default QuerySearchNav;
