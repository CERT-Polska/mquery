import React, { useState } from "react";
import Pagination from "react-js-pagination";
import FilterIcon from "../components/FilterIcon";
import QueryMatchesItem from "./QueryMatchesItem";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import api, { api_url } from "../api";
import {
    faCopy,
    faDownload,
    faFileArchive,
    faFileDownload,
} from "@fortawesome/free-solid-svg-icons";

const copyHashesToClipboard = async (qhash) => {
    api.get(`/download/hashes/${qhash}`).then((response) => {
        navigator.clipboard.writeText(response.data);
    });
};

const DownloadDropdown = (props) => {
    const [show, setShow] = useState(false);

    return (
        <div className="dropdown">
            <button
                type="button"
                className="btn shadow-none text-secondary dropdown-toggle"
                data-toggle="dropdown"
                onClick={() => setShow(!show)}
            >
                <FontAwesomeIcon icon={faDownload} size="sm" />
            </button>
            <div className={"dropdown-menu " + (show ? "show" : "")}>
                <a
                    className="dropdown-item"
                    download={`${props.qhash}.zip`}
                    href={`${api_url}/download/files/${props.qhash}`}
                >
                    <FontAwesomeIcon icon={faFileDownload} />
                    <span className="ms-3">Download files (.zip)</span>
                </a>
                <a
                    className="dropdown-item"
                    download={`${props.qhash}_sha256.txt`}
                    href={`${api_url}/download/hashes/${props.qhash}`}
                >
                    <FontAwesomeIcon icon={faFileArchive} />
                    <span className="ms-3">Download sha256 hashes (.txt)</span>
                </a>
                <button
                    className="dropdown-item btn"
                    onClick={() => {
                        copyHashesToClipboard(props.qhash);
                    }}
                >
                    <FontAwesomeIcon icon={faCopy} />
                    <span className="ms-3">
                        Copy sha256 hashes to clipboard
                    </span>
                </button>
            </div>
        </div>
    );
};

const QueryMatches = (props) => {
    const { matches, qhash, pagination } = props;

    const [filters, setFilter] = useState([]);

    const updateFilter = (name) => {
        if (!filters.includes(name)) {
            setFilter([...filters, name]);
        } else {
            setFilter(filters.filter((e) => e !== name));
        }
    };

    const matchesList = matches
        .filter((match) => {
            if (filters.length > 0) {
                if (match.matches.some((v) => filters.includes(v))) {
                    return match;
                }
            } else {
                return match;
            }
            return null;
        })
        .map((match, index) => {
            const downloadUrl = new URL(
                `${api_url}/download`,
                document.baseURI
            );
            downloadUrl.search = new URLSearchParams({
                job_id: qhash,
                ordinal: index,
                file_path: match.file,
            });

            return (
                <QueryMatchesItem
                    key={match.file}
                    match={match}
                    download_url={downloadUrl.href}
                    filters={filters}
                    setFilter={setFilter}
                    changeFilter={updateFilter}
                />
            );
        });

    const filtersHead = filters.map((v) => (
        <span
            key={v}
            className="badge rounded-pill bg-secondary ms-1 mt-1 cursor-pointer"
            onClick={() => updateFilter(v)}
        >
            {v}
        </span>
    ));

    return (
        <div className="mquery-scroll-matches">
            <table
                className="table table-striped table-bordered"
                style={{ tableLayout: "fixed" }}
            >
                <thead>
                    <tr>
                        <th className="col-md-8">
                            Matches
                            <span className="d-inline-block ms-4">
                                <DownloadDropdown qhash={qhash} />
                            </span>
                            {filters.length > 0 && (
                                <span className="border rounded p-1 pull-right text-secondary">
                                    <FilterIcon tooltipMessage="filter" />
                                    {filtersHead}
                                </span>
                            )}
                        </th>
                    </tr>
                </thead>
                <tbody>{matchesList}</tbody>
            </table>
            <Pagination
                activePage={pagination.activePage}
                itemsCountPerPage={pagination.itemsCountPerPage}
                totalItemsCount={pagination.totalItemsCount}
                pageRangeDisplayed={pagination.pageRangeDisplayed}
                onChange={pagination.onChange}
                itemClass="page-item"
                linkClass="page-link"
            />
        </div>
    );
};

export default QueryMatches;
