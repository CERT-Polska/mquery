import React, { useState } from "react";
import { API_URL } from "../config";
import Pagination from "react-js-pagination";
import DownloadDropdown from "../components/DownloadDropdown";
import QueryMatchesItem from "./QueryMatchesItem";
import PropTypes from "prop-types";
import { PT_MATCHES, PT_PAGINATION } from "../queryUtils";

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
            if (
                filters.length > 0 &&
                match.matches.some((v) => filters.includes(v))
            ) {
                return match;
            } else {
                return match;
            }
        })
        .map((match, index) => {
            const download_url =
                API_URL +
                "/download?job_id=" +
                encodeURIComponent(qhash) +
                "&ordinal=" +
                encodeURIComponent(index) +
                "&file_path=" +
                encodeURIComponent(match.file);

            return (
                <QueryMatchesItem
                    key={match.file}
                    match={match}
                    download_url={download_url}
                    filters={filters}
                    setFilter={setFilter}
                    changeFilter={updateFilter}
                />
            );
        });

    const downloadDropdownList = [
        {
            text: "Download files (.zip)",
            file: qhash + ".zip",
            href: API_URL + "/download/files/" + qhash,
            icon: "archive",
        },
        {
            text: "Download sha256 hashes (.txt)",
            file: qhash + "_sha256.txt",
            href: API_URL + "/download/hashes/" + qhash,
            icon: "file",
        },
    ];

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
                                <DownloadDropdown
                                    itemList={downloadDropdownList}
                                />
                            </span>
                            {filters.map((v) => (
                                <span
                                    key={v}
                                    className="badge badge-pill badge-primary ml-1 mt-1"
                                    onClick={() => updateFilter(v)}
                                >
                                    {v}
                                </span>
                            ))}
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
            )
        </div>
    );
};

QueryMatches.propTypes = {
    matches: PT_MATCHES.isRequired,
    qhash: PropTypes.string.isRequired,
    pagination: PT_PAGINATION.isRequired,
};

export default QueryMatches;
