import React, { Component } from "react";
import { Link } from "react-router-dom";

class VersionStatus extends Component {
    render() {
        function makeButton(component) {
            const match = component.match(/^ursadb \(([^)]+)\)$/);
            if (!match) {
                return component;
            }
            const ursadb_id = match[1];
            return (
                <Link exact="true" to={`/ursadb/${ursadb_id}`}>
                    {component}
                </Link>
            );
        }

        let rows = Object.keys(this.props.components).map((component) => (
            <tr key={component}>
                <td>{makeButton(component)}</td>
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
