import React, { useState, useRef, useEffect } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faLightbulb } from "@fortawesome/free-solid-svg-icons";
import Draggable from "react-draggable";
import ReactHtmlParser from "react-html-parser";

const useClickOutsideModal = (ref, callback) => {
    const handleClick = (event) => {
        if (ref.current && !ref.current.contains(event.target)) {
            // lose focus (higher z-index) only if other modal was clicked
            const modals = document.querySelectorAll(".modal");
            const wasClicked = (modal) => modal.contains(event.target);
            if (Array.from(modals).some(wasClicked)) {
                callback();
            }
        }
    };

    useEffect(() => {
        document.addEventListener("click", handleClick);

        return () => {
            document.removeEventListener("click", handleClick);
        };
    });
};

function base64ToHex(str64) {
    return atob(str64)
        .split("")
        .map(function (aChar) {
            return ("0" + aChar.charCodeAt(0).toString(16)).slice(-2);
        })
        .join("")
        .toUpperCase();
}

function base64ToSanitizedUtf8(str64) {
    return atob(str64)
        .split("")
        .map(function (aChar) {
            if (32 <= aChar.charCodeAt(0) && aChar.charCodeAt(0) < 127) {
                return aChar;
            }
            return ".";
        })
        .join("");
}

function insertEveryNChars(str, insert, n) {
    return str
        .split(new RegExp(`(.{${n}})`))
        .filter((x) => x)
        .join(insert);
}

function cellHTML(foundSample, lineLength, transformFunc) {
    const hexBefore = transformFunc(foundSample["before"]);
    const hexMatching = transformFunc(foundSample["matching"]);
    const hexAfter = transformFunc(foundSample["after"]);
    const basicStr = hexBefore + hexMatching + hexAfter;
    const strWithBreakLines = insertEveryNChars(basicStr, "<br>", lineLength);
    const breaksInBefore = Math.floor(hexBefore.length / lineLength);
    const breaksInBeforeAndMatching = Math.floor(
        (hexBefore.length + hexMatching.length) / lineLength
    );
    const BoldOpeningTagIndex = hexBefore.length + 4 * breaksInBefore;
    const BoldClosingTagIndex =
        hexBefore.length + hexMatching.length + 4 * breaksInBeforeAndMatching;
    let boldedStr =
        strWithBreakLines.slice(0, BoldClosingTagIndex) +
        "</b>" +
        strWithBreakLines.slice(BoldClosingTagIndex);
    boldedStr =
        boldedStr.slice(0, BoldOpeningTagIndex) +
        "<b>" +
        boldedStr.slice(BoldOpeningTagIndex);
    return boldedStr;
}

const ActionShowMatchContext = (props) => {
    const ref = useRef(null);
    const [showModal, setShowModal] = useState(false);
    const [focus, setFocus] = useState(true);
    useClickOutsideModal(ref, () => setFocus(false));

    const modalHeader = (
        <div className="modal-header d-flex justify-content-between">
            <h6 className="modal-title">{`Match context for ${props.filename}`}</h6>
            <button
                type="button"
                className="btn-close"
                onClick={() => setShowModal(false)}
            />
        </div>
    );

    const tableRows = Object.keys(props.context).map((rulename, index) => {
        const rulenameRows = Object.keys(props.context[rulename]).map(
            (identifier) => {
                const foundSample = props.context[rulename][identifier];
                return (
                    <>
                        <td scope="row" style={{ width: "10%" }}>
                            <span className="badge rounded-pill bg-info ms-1 mt-1">
                                {identifier}
                            </span>
                        </td>
                        <td scope="row" className="text-monospace">
                            {ReactHtmlParser(
                                cellHTML(foundSample, 20, base64ToHex)
                            )}
                        </td>
                        <td scope="row" className="text-monospace">
                            {ReactHtmlParser(
                                cellHTML(foundSample, 10, base64ToSanitizedUtf8)
                            )}
                        </td>
                    </>
                );
            }
        );

        return (
            <>
                <tr key={index}>
                    <td
                        scope="row fit-content"
                        rowSpan={Object.keys(props.context[rulename]).length}
                        style={{ width: "15%" }}
                    >
                        <span className="badge rounded-pill bg-primary ms-1 mt-1">
                            {rulename}
                        </span>
                    </td>
                    {rulenameRows[0]}
                </tr>
                {rulenameRows.slice(1).map((row) => (
                    <tr>{row}</tr>
                ))}
            </>
        );
    });

    const modalBody = (
        <div className="modal-body modal-table">
            {!Object.keys(props.context).length ? (
                "No context available"
            ) : (
                <table className="table table-bordered">
                    <tbody>{tableRows}</tbody>
                </table>
            )}
        </div>
    );

    return (
        <div className="d-flex flex-row">
            <button
                title="Show match context"
                className="text-secondary"
                style={{ border: 0, background: 0 }}
                onClick={() => setShowModal(!showModal)}
            >
                <FontAwesomeIcon icon={faLightbulb} size="sm" />
            </button>
            {showModal && (
                <Draggable handle=".modal-header">
                    <div
                        className="modal-container"
                        style={{ zIndex: focus ? 100 : 10 }}
                        ref={ref}
                        onClick={() => setFocus(true)}
                    >
                        <div
                            className="modal modal-block"
                            style={{ display: showModal ? "block" : "none" }}
                        >
                            <div className="modal-dialog modal-lg">
                                <div className="modal-content">
                                    {modalHeader}
                                    {modalBody}
                                </div>
                            </div>
                        </div>
                    </div>
                </Draggable>
            )}
        </div>
    );
};

export default ActionShowMatchContext;
