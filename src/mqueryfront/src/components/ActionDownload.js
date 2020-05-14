import React from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";

const ActionDownload = (props) => {
    return (
        <a href={props.downloadUrl} download={props.downloadName}>
            <button
                className="btn shadow-none"
                data-toggle="tooltip"
                title={props.title}
            >
                <FontAwesomeIcon icon={props.icon} size="sm" />
            </button>
        </a>
    );
};

export default ActionDownload;
