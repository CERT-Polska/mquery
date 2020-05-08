import React from "react";
import FilteringThead from "./FilteringThead";
import PropTypes from "prop-types";

const FilteringTableHeader = (props) => {
    const head = props.head.map((el, index) => {
        const filterData = {
            attrubuteName: el.attrubuteName,
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

FilteringTableHeader.propTypes = {
    head: PropTypes.arrayOf(
        PropTypes.shape({
            title: PropTypes.string.isRequired,
            attrubuteName: PropTypes.string,
            valueList: PropTypes.arrayOf(
                PropTypes.oneOfType([PropTypes.string, PropTypes.number])
            ),
        })
    ).isRequired,
    currentFilter: PropTypes.shape({
        name: PropTypes.string,
        value: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
    }),
    onClick: PropTypes.func,
};

export default FilteringTableHeader;
