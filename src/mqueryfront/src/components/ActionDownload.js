import React from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faDownload } from "@fortawesome/free-solid-svg-icons";

const ActionDownload = (props) => {
    return (
        <a href={props.downloadUrl} download={props.downloadName}>
            <button
                className="btn shadow-none"
                data-toggle="tooltip"
                title="Download"
            >
                <FontAwesomeIcon icon={faDownload} size="sm" />
            </button>
        </a>
    );
};

export default ActionDownload;
