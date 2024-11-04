import React from "react";
import path from "path-browserify";
import ActionDownload from "../components/ActionDownload";
import ActionCopyToClipboard from "../components/ActionCopyToClipboard";
import ActionShowMatchContext from "../components/ActionShowMatchContext";

const QueryMatchesItem = (props) => {
    const { match, download_url } = props;
    const { matches, meta, file, context } = match; // NOTE: presuming new field in Match schema context which would be dict with 'matches' as keys

    const stubContext = context
        ? context
        : {
              key1:
                  "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.",
              key2:
                  "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.",
              key3:
                  "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.",
          };

    const fileBasename = path.basename(file);

    const metadataBadges = Object.values(meta)
        .filter((v) => !v.hidden)
        .map((v) => (
            <a href={v.url} key={v}>
                <span className="badge rounded-pill bg-warning ms-1 mt-1">
                    {v.display_text}
                </span>
            </a>
        ));

    const matchBadges = (
        <div>
            {Object.values(matches).map((v) => (
                <span
                    key={v}
                    className="badge rounded-pill bg-primary ms-1 mt-1 cursor-pointer text-wrap"
                    onClick={() => props.changeFilter(v)}
                >
                    {v}
                </span>
            ))}
        </div>
    );

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
                    <small className="text-secondary ms-2 me-1 mt-1">
                        <ActionCopyToClipboard
                            text={fileBasename}
                            tooltipMessage="Copy file name to clipboard"
                        />
                    </small>
                    <small className="text-secondary ms-2 me-1 mt-1">
                        <ActionShowMatchContext
                            filename={fileBasename}
                            context={stubContext}
                        />
                    </small>
                    {matchBadges}
                    {metadataBadges}
                </div>
            </td>
        </tr>
    );
};

export default QueryMatchesItem;
