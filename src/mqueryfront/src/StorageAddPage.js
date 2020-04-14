import React, { Component } from "react";

class StorageAddForm extends Component {
    render() {
        return (
            <form>
                <div className="form-group row">
                    <label
                        for="storageName"
                        className="col-sm-2 col-form-label col-form-label"
                    >
                        Name
                    </label>
                    <div className="col-sm-10">
                        <input
                            type="text"
                            className="form-control form-control"
                            id="storageName"
                            placeholder="Name for your new storage"
                        />
                    </div>
                </div>
                <div className="form-group row">
                    <label
                        for="storagePath"
                        className="col-sm-2 col-form-label col-form-label"
                    >
                        Path
                    </label>
                    <div className="col-sm-10">
                        <input
                            type="text"
                            className="form-control form-control"
                            id="storagePath"
                            placeholder="Root local filesystem path for storage"
                        />
                    </div>
                </div>
                <button className="btn btn-primary" type="submit">
                    Submit
                </button>
            </form>
        );
    }
}

class StorageAddPage extends Component {
    render() {
        return (
            <div className="container-fluid">
                <h1 className="text-center mq-bottom">Configure Storage </h1>
                <StorageAddForm />
            </div>
        );
    }
}

export default StorageAddPage;
