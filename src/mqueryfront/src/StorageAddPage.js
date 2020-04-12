import React, { Component } from "react";

class StorageAddForm extends Component {
    render() {
        return (
            <form>
                <div class="form-group row">
                    <label
                        for="storageName"
                        class="col-sm-2 col-form-label col-form-label"
                    >
                        Name
                    </label>
                    <div class="col-sm-10">
                        <input
                            type="text"
                            class="form-control form-control"
                            id="storageName"
                            placeholder="Name for your new storage"
                        />
                    </div>
                </div>
                <div class="form-group row">
                    <label
                        for="storagePath"
                        class="col-sm-2 col-form-label col-form-label"
                    >
                        Path
                    </label>
                    <div class="col-sm-10">
                        <input
                            type="text"
                            class="form-control form-control"
                            id="storagePath"
                            placeholder="Root local filesystem path for storage"
                        />
                    </div>
                </div>
                <button class="btn btn-primary" type="submit">
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
