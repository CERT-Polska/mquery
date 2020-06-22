import React from "react";
import ActionDownload from "../components/ActionDownload";
import ActionCopyToClipboard from "../components/ActionCopyToClipboard";
import PropTypes from "prop-types";
import { PT_MATCH } from "../queryUtils";

const QueryMatchesItem = (props) => {
    const { match, download_url } = props;
    const { matches, meta, file } = match;

    const addFilter = (event) => {
        props.changeFilter(event);
    };

    const path = require("path");
    const fileBasename = path.basename(file);

    const metadataBadges = Object.values(meta)
        .filter((v) => !v.hidden)
        .map((v) => (
            <a href={v.url} key={v}>
                <span className="badge badge-pill badge-warning ml-1 mt-1">
                    {v.display_text}
                </span>
            </a>
        ));

    const matchBadges = Object.values(matches).map((v) => (
        <span
            key={v}
            className="badge badge-pill badge-primary ml-1 mt-1 cursor-pointer"
            onClick={() => props.changeFilter(v)}
        >
            {v}
        </span>
    ));

    return (
        <tr>
            <td>
                <div className="d-flex">
                    <div className="text-truncate" style={{ minWidth: 50 }}>
                        {meta.sha256.display_text}
                    </div>
                    <small className="text-secondary">
                        <div className="btn-group " role="group">
                            <span className="mx-2">
                                <ActionDownload href={download_url} />
                            </span>
                            <ActionCopyToClipboard
                                text={meta.sha256.display_text}
                                tooltipMessage="Copy sha256 to clipboard"
                            />
                        </div>
                    </small>
                </div>
                <div className="d-flex">
                    <div className="text-truncate" style={{ minWidth: 50 }}>
                        <small
                            className="text-secondary"
                            data-toggle="tooltip"
                            title={file}
                        >
                            {fileBasename}
                        </small>
                    </div>
                    <small className="text-secondary ml-2 mr-1 mt-1">
                        <ActionCopyToClipboard
                            text={fileBasename}
                            tooltipMessage="Copy file name to clipboard"
                        />
                    </small>
                    {matchBadges}
                    {metadataBadges}
                </div>
            </td>
        </tr>
    );
};

QueryMatchesItem.propTypes = {
    match: PT_MATCH.isRequired,
    download_url: PropTypes.string.isRequired,
};

export default QueryMatchesItem;
