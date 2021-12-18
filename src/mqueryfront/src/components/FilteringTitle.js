import React from "react";
import FilterIcon from "./FilterIcon";

const FilteringTitle = (props) => {
    const { title, filterValue } = props;

    const filter = filterValue && <FilterIcon tooltipMessage="filtered by:" />;
    return (
        <div className="d-flex justify-content-between">
            <div className="col"></div>
            <h1 className="">{title}</h1>
            <div className="col text-right">
                {filter}
                {filterValue}
            </div>
        </div>
    );
};

export default FilteringTitle;
