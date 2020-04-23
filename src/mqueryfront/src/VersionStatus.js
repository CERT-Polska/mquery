import React, { Component } from "react";

class VersionStatus extends Component {
    render() {
        console.log(this.props.components);
        console.log(Object.entries(this.props.components));
        let rows = Object.keys(this.props.components).map((component) => (
            <tr key={component}>
                <td>{component}</td>
                <td>{this.props.components[component]}</td>
            </tr>
        ));

        return (
            <div>
                <h2 className="text-center mq-bottom">System Version</h2>
                <div className="table-responsive">
                    <table className="table table-striped table-bordered">
                        <thead>
                            <tr>
                                <th>Component</th>
                                <th>Version</th>
                            </tr>
                        </thead>
                        <tbody>{rows}</tbody>
                    </table>
                </div>
            </div>
        );
    }
}

export default VersionStatus;
