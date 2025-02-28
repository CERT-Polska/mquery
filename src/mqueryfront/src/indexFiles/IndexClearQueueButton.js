import React, { Component } from "react";
import api from "../api";

class IndexClearQueueButton extends Component {
    render() {
        return (
            <span
                data-toggle="tooltip"
                title={"This action will remove all files from this queue"}
            >
                <button
                    className="btn btn-secondary btn-sm btn-danger my-2"
                    onClick={() => this.props.onClick()}
                >
                    {this.props.msg}
                </button>
            </span>
        );
    }
}

export default IndexClearQueueButton;
