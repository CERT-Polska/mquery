import React from "react";
import FilterIcon from "./FilterIcon";

const FilteringTitle = (props) => {
    const { title, filterValue } = props;

    const filter = filterValue && <FilterIcon tooltipMessage="filtered by:" />;
    return (
        <div class="d-flex justify-content-between">
            <div class="col"></div>
            <h1 className="">{title}</h1>
            <div class="col text-right">
                {filter}
                {filterValue}
            </div>
        </div>
    );
};

export default FilteringTitle;
