import React from "react";
import FilterIcon from "./FilterIcon";

const FilteringThead = (props) => {
    let activeColumn = false;
    let icon = null;

    if (
        props.currentFilter &&
        props.currentFilter.name === props.filterData.attributeName
    ) {
        activeColumn = true;
        icon = (
            <span className="mr-1">
                <FilterIcon tooltipMessage="active filter" />
            </span>
        );
    }

    let thContent;
    if (props.filterData && props.filterData.valueList) {
        const list = props.filterData.valueList.map((el, index) => {
            let activeItem = false;
            if (activeColumn && props.currentFilter.value === el)
                activeItem = true;

            const itemStyle = "font-weight-" + (activeItem ? "bold" : "normal");

            return (
                <button
                    className="dropdown-item"
                    onClick={() =>
                        props.filterData.onClick(
                            props.filterData.attributeName,
                            el,
                            index
                        )
                    }
                    key={index}
                >
                    <span className={itemStyle}>{el}</span>
                </button>
            );
        });

        thContent = (
            <div className="dropdown">
                <button
                    type="button"
                    className="btn btn-block dropdown-toggle shadow-none"
                    data-toggle="dropdown"
                >
                    {icon}
                    <span className="font-weight-bold">{props.title}</span>
                </button>
                <div className="dropdown-menu">{list}</div>
            </div>
        );
    } else thContent = props.title;

    return (
        <th className="align-middle text-center text-nowrap">{thContent}</th>
    );
};

export default FilteringThead;
