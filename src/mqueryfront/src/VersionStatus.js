import React, { Component } from "react";

class VersionStatus extends Component {
    render() {
        const VersionRows = Object(this.props.components);

        return (
            <div>
                <h2 className="text-center mq-bottom">system version</h2>
                <div className="table-responsive">
                    <table className="table table-striped table-bordered">
                        <thead>
                            <tr>
                                <th>component</th>
                                <th>version</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td>mquery-web</td>
                                <td>{VersionRows.mquery}</td>
                            </tr>
                            <tr>
                                <td>ursadb</td>
                                <td>{VersionRows.ursadb}</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        );
    }
}

export default VersionStatus;
