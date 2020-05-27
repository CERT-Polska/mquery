import React from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faCopy } from "@fortawesome/free-solid-svg-icons";
import { FONTAWESOMESIZES } from "./bootstrapUtils";
import { CopyToClipboard } from "react-copy-to-clipboard";
import PropTypes from "prop-types";

const ActionCopyToClipboard = (props) => {
    const { text, tooltipMessage, size } = props;

    return (
        <CopyToClipboard text={text} className="copyable-item">
            <span data-toggle="tooltip" title={tooltipMessage}>
                <i>
                    <FontAwesomeIcon icon={faCopy} size={size} />
                </i>
            </span>
        </CopyToClipboard>
    );
};

ActionCopyToClipboard.defaultProps = {
    size: "sm",
    tooltipMessage: "",
};

ActionCopyToClipboard.propTypes = {
    text: PropTypes.string.isRequired,
    tooltipMessage: PropTypes.string,
    size: PropTypes.oneOf(FONTAWESOMESIZES),
};

export default ActionCopyToClipboard;
