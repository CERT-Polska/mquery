import React, {Component} from 'react';

class VersionStatus extends Component {
    constructor(props) {
        super(props);
    }

    render() {
        const VersionRows = Object(this.props.components)

        return (
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
        );
    }
}

export default VersionStatus;