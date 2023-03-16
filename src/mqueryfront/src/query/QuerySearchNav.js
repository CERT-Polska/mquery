import React from "react";
import Select from "react-select";

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
        <Select
            onChange={onChange}
            options={options}
            value={props.selectedTaints}
            placeholder={placeholder}
            isMulti
            isSearchable
        />
    );
};

export default QuerySearchNav;
