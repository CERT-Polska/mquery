import React from "react";
import FilterIcon from "./FilterIcon";

const FilteringTitle = (props) => {
    const { title, filterValue } = props;

    const icon = (
        <span className="mr-1">
            <FilterIcon tooltipMessage="filtered by:" />
        </span>
    );

    if (filterValue)
        return (
            <div className="d-flex justify-content-between align-items-center">
                <div className="flex-fill">
                    <div
                        className="text-truncate invisible"
                        style={{
                            minWidth: 50,
                            maxWidth: "20vw",
                        }}
                    >
                        {icon}
                        {filterValue}
                    </div>
                </div>
                <div className="flex-fill">
                    <h1 className="text-center">{title}</h1>
                </div>

                <div className="flex-fill">
                    <div
                        className="text-truncate text-right"
                        style={{
                            minWidth: 50,
                            maxWidth: "20vw",
                        }}
                    >
                        {icon}
                        {filterValue}
                    </div>
                </div>
            </div>
        );
    else return <h1 className="text-center mq-bottom">{title}</h1>;
};

export default FilteringTitle;
