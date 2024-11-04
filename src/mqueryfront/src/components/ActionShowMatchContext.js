import React, { useState } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faLightbulb } from "@fortawesome/free-solid-svg-icons";

const ActionShowMatchContext = (props) => {
    const [showModal, setShowModal] = useState(false);

    const modalHeader = (
        <div className="modal-header d-flex justify-content-between">
            <h6 className="modal-title">Match context</h6>
            <button
                type="button"
                className="close "
                onClick={() => setShowModal(false)}
            >
                <span aria-hidden="true">&times;</span>
            </button>
        </div>
    );

    const tableRows = Object.entries(props.context).map(
        (contextItem, index) => (
            <tr key={index}>
                <th scope="row fit-content">
                    <span className="badge rounded-pill bg-primary ms-1 mt-1">
                        {contextItem[0]}
                    </span>
                </th>
                <th scope="row">{contextItem[1]}</th>
            </tr>
        )
    );

    const modalBody = (
        <div className="modal-body modal-table">
            {!props.context ? (
                "No context available"
            ) : (
                <table className="table">
                    <tbody>{tableRows}</tbody>
                </table>
            )}
        </div>
    );

    return (
        <>
            <button
                title="Show match context"
                className="text-secondary"
                style={{ border: 0, background: 0 }}
                onClick={() => setShowModal(!showModal)}
            >
                <FontAwesomeIcon icon={faLightbulb} size="sm" />
            </button>
            <div className="modal-container">
                <div
                    className="modal modal-block"
                    style={{
                        display: showModal ? "block" : "none",
                        blockSize: "fit-content",
                        width: "fit-content",
                        position: "center",
                    }}
                >
                    <div className="modal-dialog">
                        <div className="modal-content">
                            {modalHeader}
                            {modalBody}
                        </div>
                    </div>
                </div>
            </div>
        </>
    );
};

export default ActionShowMatchContext;
