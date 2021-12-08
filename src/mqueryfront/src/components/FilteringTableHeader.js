import React from "react";
import FilteringThead from "./FilteringThead";

const FilteringTableHeader = (props) => {
    const head = props.head.map((el, index) => {
        const filterData = {
            attributeName: el.attributeName,
            valueList: el.valueList,
            onClick: props.onClick,
        };

        return (
            <FilteringThead
                title={el.title}
                filterData={filterData}
                currentFilter={props.currentFilter}
                key={index}
            />
        );
    });

    return (
        <thead>
            <tr>{head}</tr>
        </thead>
    );
};

export default FilteringTableHeader;
