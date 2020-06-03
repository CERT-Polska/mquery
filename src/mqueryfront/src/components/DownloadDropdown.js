import React from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
    faDownload,
    faFileArchive,
    faFileDownload,
} from "@fortawesome/free-solid-svg-icons";
import { FONTAWESOMESIZES } from "./bootstrapUtils";
import PropTypes from "prop-types";

const DownloadDropdown = (props) => {
    const { itemList, size } = props;
    const dropdownItems = itemList.map((item, index) => {
        const iconName = item.icon;

        const icon =
            iconName === "archive"
                ? faFileArchive
                : iconName === "file"
                ? faFileDownload
                : faDownload;

        return (
            <a
                key={index}
                className="dropdown-item"
                download={item.file}
                href={item.href}
            >
                <FontAwesomeIcon icon={icon} />
                <span className="ml-3">{item.text}</span>
            </a>
        );
    });

    return (
        <div className="dropdown">
            <button
                type="button"
                className="btn shadow-none text-secondary dropdown-toggle"
                data-toggle="dropdown"
            >
                <FontAwesomeIcon icon={faDownload} size={size} />
            </button>
            <div className="dropdown-menu">{dropdownItems}</div>
        </div>
    );
};

DownloadDropdown.defaultProps = {
    size: "sm",
};

DownloadDropdown.propTypes = {
    itemList: PropTypes.arrayOf(
        PropTypes.shape({
            text: PropTypes.string.isRequired,
            file: PropTypes.string.isRequired,
            href: PropTypes.string.isRequired,
            icon: PropTypes.string,
        })
    ).isRequired,
    size: PropTypes.oneOf(FONTAWESOMESIZES),
};

export default DownloadDropdown;
