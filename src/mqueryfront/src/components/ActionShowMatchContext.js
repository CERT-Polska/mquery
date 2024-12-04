import React, { useState, useRef, useEffect } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faLightbulb } from "@fortawesome/free-solid-svg-icons";
import Draggable from "react-draggable";

const useClickOutside = (ref, callback) => {
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
        .toUpperCase(); // Per your example output
}

const ActionShowMatchContext = (props) => {
    const ref = useRef(null);
    const [showModal, setShowModal] = useState(false);
    const [focus, setFocus] = useState(true);
    useClickOutside(ref, () => setFocus(false));

    const modalHeader = (
        <div className="modal-header d-flex justify-content-between">
            <h6 className="modal-title">{`Match context for ${props.filename}`}</h6>
            <button
                type="button"
                className="close "
                onClick={() => setShowModal(false)}
            >
                <span aria-hidden="true">&times;</span>
            </button>
        </div>
    );
    // Buffer.from(rawData, 'base64');

    const tableRows = Object.keys(props.context).map((rulename, index) => {
        const rulenameRows = props.context[rulename].map((foundSample) => {
            return (
                <>
                    <td scope="row">
                        {atob(foundSample["before"])}
                        {<b>{atob(foundSample["matching"])}</b>}
                        {atob(foundSample["after"])}
                    </td>
                    <td scope="row">
                        {base64ToHex(foundSample["before"])}
                        {<b>{base64ToHex(foundSample["matching"])}</b>}
                        {base64ToHex(foundSample["after"])}
                    </td>
                </>
            );
        });

        return (
            <>
                <tr key={index}>
                    <td
                        scope="row fit-content"
                        rowSpan={props.context[rulename].length}
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
                <table className="table">
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
