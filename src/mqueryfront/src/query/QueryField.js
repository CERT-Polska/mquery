import React from "react";
import QueryNavigation from "./QueryNavigation";
import QueryMonaco from "./QueryMonaco";
import PropTypes from "prop-types";

const QueryField = (props) => {
    return (
        <div>
            <QueryNavigation
                isEditActive={props.readOnly}
                onSubmitQuery={props.onSubmitQuery}
                onEditQuery={props.onEditQuery}
                onParseQuery={props.onParseQuery}
                onTaintSelect={props.onTaintSelect}
                availableTaints={props.availableTaints}
            />
            <div className="mt-2 monaco-container">
                <QueryMonaco
                    readOnly={props.readOnly}
                    rawYara={props.rawYara}
                    onValueChanged={props.onYaraUpdate}
                    error={props.parsedError}
                />
            </div>
        </div>
    );
};

QueryField.propTypes = {
    rawYara: PropTypes.string.isRequired,
    parsedError: PropTypes.arrayOf(PropTypes.string).isRequired,
    readOnly: PropTypes.bool.isRequired,
    availableTaints: PropTypes.arrayOf(PropTypes.string).isRequired,
    onYaraUpdate: PropTypes.func.isRequired,
    onSubmitQuery: PropTypes.func.isRequired,
    onEditQuery: PropTypes.func.isRequired,
    onParseQuery: PropTypes.func.isRequired,
    onTaintSelect: PropTypes.func.isRequired,
};

export default QueryField;
