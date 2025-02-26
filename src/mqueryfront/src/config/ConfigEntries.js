import React, { Component } from "react";
import ErrorBoundary from "../components/ErrorBoundary";
import api from "../api";

const R_BOOL = /^(|true|false)$/;
const R_URL = /^(https?:\/\/.*)$/;
const R_ROLES = /^((admin|user|nobody)(,(admin|user|nobody))*)?$/;

const KNOWN_RULES = {
    openid_url: R_URL,
    auth_enabled: R_BOOL,
    auth_default_roles: R_ROLES,
    query_allow_slow: R_BOOL,
};

class ConfigRow extends Component {
    constructor(props) {
        super(props);

        this.state = {
            edit: false,
            value: this.props.value,
        };

        this.save = this.save.bind(this);
        this.cancel = this.cancel.bind(this);
        this.edit = this.edit.bind(this);
        this.handleEdit = this.handleEdit.bind(this);
    }

    save() {
        this.setState({
            edit: false,
        });
        api.post("/config/edit", {
            plugin: this.props.plugin,
            key: this.props.keyName,
            value: this.state.value,
        });
    }

    cancel() {
        this.setState({
            edit: false,
            value: this.props.value,
        });
    }

    edit() {
        this.setState({
            edit: true,
        });
    }

    handleEdit(event) {
        this.setState({
            value: event.target.value,
        });
    }

    validate() {
        if (this.props.keyName in KNOWN_RULES) {
            const rule = KNOWN_RULES[this.props.keyName];
            return rule.test(this.state.value);
        }
        return true;
    }

    render() {
        let valueControl;
        let editToggle;
        if (this.state.edit) {
            const isValid = this.validate();
            valueControl = (
                <input
                    type="text"
                    className="form-control"
                    defaultValue={this.state.value}
                    onChange={this.handleEdit}
                    placeholder="Enter new value"
                />
            );
            editToggle = (
                <div>
                    <button
                        type="button"
                        className="btn btn-success"
                        data-toggle="tooltip"
                        title="Save your changes"
                        onClick={this.save}
                        disabled={!isValid}
                    >
                        save
                    </button>
                    <button
                        type="button"
                        className="btn btn-danger"
                        data-toggle="tooltip"
                        title="Discard changes"
                        onClick={this.cancel}
                    >
                        cancel
                    </button>
                </div>
            );
        } else {
            valueControl = <span>{this.state.value}</span>;
            editToggle = (
                <button
                    type="button"
                    className="btn btn-info"
                    data-toggle="tooltip"
                    title="Change value of this parameter"
                    onClick={this.edit}
                >
                    edit
                </button>
            );
        }

        return (
            <tr>
                <td>
                    <code
                        data-toggle="tooltip"
                        title="Name of the plugin using this field"
                    >
                        {this.props.plugin}
                    </code>
                </td>
                <td>
                    <code data-toggle="tooltip" title="Configuration key">
                        {this.props.keyName}
                    </code>
                </td>
                <td className="w-25">
                    <div className="d-flex">
                        <div
                            className="flex-grow-1"
                            style={{
                                wordWrap: "break-word",
                                maxWidth: "800px",
                            }}
                        >
                            {valueControl}
                        </div>
                        <div className="flex-shrink-1">{editToggle}</div>
                    </div>
                </td>
                <td>
                    <span>{this.props.description}</span>
                </td>
            </tr>
        );
    }
}

class ConfigEntryList extends Component {
    render() {
        const configRows = this.props.config.map((config) => (
            <ConfigRow
                key={config.plugin + ":" + config.key}
                plugin={config.plugin}
                keyName={config.key}
                value={config.value}
                description={config.description}
            />
        ));

        return (
            <ErrorBoundary error={this.props.error}>
                <div className="table-responsive">
                    <table className="table table-striped table-bordered">
                        <thead>
                            <tr>
                                <th>plugin</th>
                                <th>key</th>
                                <th>value</th>
                                <th>description</th>
                            </tr>
                        </thead>
                        <tbody>{configRows}</tbody>
                    </table>
                </div>
            </ErrorBoundary>
        );
    }
}

export default ConfigEntryList;
