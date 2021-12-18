import React, { useState } from "react";
import { API_URL } from "../config";
import Pagination from "react-js-pagination";
import FilterIcon from "../components/FilterIcon";
import QueryMatchesItem from "./QueryMatchesItem";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import axios from "axios";
import {
    faCopy,
    faDownload,
    faFileArchive,
    faFileDownload,
} from "@fortawesome/free-solid-svg-icons";

const copyHashesToClipboard = async (qhash) => {
    axios.get(`${API_URL}/download/hashes/${qhash}`).then((response) => {
        navigator.clipboard.writeText(response.data);
    });
};

const DownloadDropdown = (props) => (
    <div className="dropdown">
        <button
            type="button"
            className="btn shadow-none text-secondary dropdown-toggle"
            data-toggle="dropdown"
        >
            <FontAwesomeIcon icon={faDownload} size="sm" />
        </button>
        <div className="dropdown-menu">
            <a
                className="dropdown-item"
                download={`${props.qhash}.zip`}
                href={`${API_URL}/download/files/${props.qhash}`}
            >
                <FontAwesomeIcon icon={faFileDownload} />
                <span className="ml-3">Download files (.zip)</span>
            </a>
            <a
                className="dropdown-item"
                download={`${props.qhash}_sha256.txt`}
                href={`${API_URL}/download/hashes/${props.qhash}`}
            >
                <FontAwesomeIcon icon={faFileArchive} />
                <span className="ml-3">Download sha256 hashes (.txt)</span>
            </a>
            <a
                className="dropdown-item btn"
                onClick={() => {
                    copyHashesToClipboard(props.qhash);
                }}
            >
                <FontAwesomeIcon icon={faCopy} />
                <span className="ml-3">Copy sha256 hashes to clipboard</span>
            </a>
        </div>
    </div>
);

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
            const qhashElm = encodeURIComponent(qhash);
            const indexElm = encodeURIComponent(index);
            const fileElm = encodeURIComponent(match.file);
            const downloadUrl = `${API_URL}/download?job_id=${qhashElm}&ordinal=${indexElm}&file_path=${fileElm}`;

            return (
                <QueryMatchesItem
                    key={match.file}
                    match={match}
                    download_url={downloadUrl}
                    filters={filters}
                    setFilter={setFilter}
                    changeFilter={updateFilter}
                />
            );
        });

    const filtersHead = filters.map((v) => (
        <span
            key={v}
            className="badge badge-pill badge-secondary ml-1 mt-1 cursor-pointer"
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
                            <span className="d-inline-block ml-4">
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
