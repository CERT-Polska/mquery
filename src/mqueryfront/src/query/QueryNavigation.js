import React from "react";
import QuerySubmitNav from "./QuerySubmitNav";
import QueryEditParseNav from "./QueryEditParseNav";
import QuerySearchNav from "./QuerySearchNav";

const QueryNavigation = (props) => {
    const {
        onSubmitQuery,
        onEditQuery,
        onParseQuery,
        onTaintSelect,
        isEditActive,
        availableTaints,
        selectedTaints,
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
                onChange={onTaintSelect}
                availableTaints={availableTaints}
                selectedTaints={selectedTaints}
            />
        </div>
    );
};

export default QueryNavigation;
