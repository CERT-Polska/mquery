import React from "react";
import QueryNavigation from "./QueryNavigation";
import QueryMonaco from "./QueryMonaco";

const QueryField = (props) => (
    <div>
        <QueryNavigation
            isEditActive={props.readOnly}
            onSubmitQuery={props.onSubmitQuery}
            onEditQuery={props.onEditQuery}
            onParseQuery={props.onParseQuery}
            onTaintSelect={props.onTaintSelect}
            availableTaints={props.availableTaints}
            selectedTaints={props.selectedTaints}
            forceSlowQueries={props.forceSlowQueries}
        />
        <div className="mt-2 monaco-container">
            <QueryMonaco
                readOnly={props.readOnly}
                rawYara={props.rawYara}
                onValueChanged={props.onYaraUpdate}
                error={props.parsedError}
                onSubmitQuery={props.onSubmitQuery}
            />
        </div>
    </div>
);

export default QueryField;
