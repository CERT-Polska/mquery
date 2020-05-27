import React from "react";
import QuerySubmitNav from "./QuerySubmitNav";
import QueryEditParseNav from "./QueryEditParseNav";
import QuerySearchNav from "./QuerySearchNav";
import PropTypes from "prop-types";

const QueryNavigation = (props) => {
    const {
        onSubmitQuery,
        onEditQuery,
        onParseQuery,
        onTaintSelect,
        isEditActive,
        availableTaints,
    } = props;

    return (
        <div className="btn-group" role="group">
            <QuerySubmitNav onClick={onSubmitQuery} />
            <QueryEditParseNav
                isEditActive={isEditActive}
                onEditQuery={onEditQuery}
                onParseQuery={onParseQuery}
            />
            <QuerySearchNav
                onClick={onTaintSelect}
                availableTaints={availableTaints}
            />
        </div>
    );
};

QueryNavigation.propTypes = {
    onSubmitQuery: PropTypes.func.isRequired,
    onEditQuery: PropTypes.func.isRequired,
    onParseQuery: PropTypes.func.isRequired,
    onTaintSelect: PropTypes.func.isRequired,
    isEditActive: PropTypes.bool.isRequired,
    availableTaints: PropTypes.arrayOf(PropTypes.string).isRequired,
};

export default QueryNavigation;
