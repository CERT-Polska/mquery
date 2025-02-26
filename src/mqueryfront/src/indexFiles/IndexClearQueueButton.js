import React, { Component } from "react";
import api from "../api";

class IndexClearQueueButton extends Component {
    onClick() {
        api.delete(`/queue/${this.props.ursa_id}`);
    }

    render() {
        return (
            <span
                data-toggle="tooltip"
                title={
                    "This action will remove all files from this queue"
                }
            >
                <button
                    className="btn btn-secondary btn-sm btn-danger my-2"
                    onClick={() => this.onClick()}
                >
                    Clear queue
                </button>
            </span>
        );
    }
}

export default IndexClearQueueButton;
