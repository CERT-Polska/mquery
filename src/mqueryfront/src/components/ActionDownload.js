import React from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faFileDownload } from "@fortawesome/free-solid-svg-icons";

const ActionDownload = (props) => (
    <a
        href={props.href}
        data-toggle="tooltip"
        title="Download"
        className="text-secondary"
    >
        <FontAwesomeIcon icon={faFileDownload} size="sm" />
    </a>
);

export default ActionDownload;
