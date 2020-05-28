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

    return (
        <ReactMultiSelectCheckboxes
            onChange={onChange}
            options={options}
            placeholderButtonLabel="everywhere"
        />
    );
};

QuerySearchNav.propTypes = {
    availableTaints: PropTypes.arrayOf(PropTypes.string).isRequired,
    onChange: PropTypes.func.isRequired,
};
export default QuerySearchNav;
