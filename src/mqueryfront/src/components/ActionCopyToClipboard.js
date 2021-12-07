import React from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faCopy } from "@fortawesome/free-solid-svg-icons";
import { CopyToClipboard } from "react-copy-to-clipboard";

const ActionCopyToClipboard = (props) => (
    <CopyToClipboard text={props.text} className="copyable-item">
        <span data-toggle="tooltip" title={props.tooltipMessage}>
            <FontAwesomeIcon icon={faCopy} size="sm" />
        </span>
    </CopyToClipboard>
);

export default ActionCopyToClipboard;
