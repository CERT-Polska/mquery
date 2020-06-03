import React from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faFileDownload } from "@fortawesome/free-solid-svg-icons";
import { FONTAWESOMESIZES } from "./bootstrapUtils";
import PropTypes from "prop-types";

const ActionDownload = (props) => {
    const { href, tooltipMessage, size } = props;

    return (
        <a
            href={href}
            data-toggle="tooltip"
            title={tooltipMessage}
            className="text-secondary"
        >
            <i>
                <FontAwesomeIcon icon={faFileDownload} size={size} />
            </i>
        </a>
    );
};

ActionDownload.defaultProps = {
    size: "sm",
    tooltipMessage: "Download",
};

ActionDownload.propTypes = {
    href: PropTypes.string.isRequired,
    tooltipMessage: PropTypes.string,
    size: PropTypes.oneOf(FONTAWESOMESIZES),
};

export default ActionDownload;
