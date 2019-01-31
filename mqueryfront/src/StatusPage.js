import React, {Component} from 'react';
import BackendStatus from './BackendStatus';
import DatabaseTopology from './DatabaseTopology';
import axios from 'axios';
import {API_URL} from "./config";


class StatusPage extends Component {
    constructor(props) {
        super(props);

        this.state = {
            "paths": []
        };

        this.handleIndex = this.handleIndex.bind(this);
    }

    handleIndex(path) {
        return () => {
            axios.post(API_URL + '/admin/index', {path: path})
                .then(response => {
                    alert('Re-index operation was queued.');
                }, error => {
                    alert('Error: ' + error.response.data.error);
                })
        };
    }

    componentDidMount() {
        axios.get(API_URL + '/indexable_paths')
            .then(response => {
                this.setState({"paths": response.data.indexable_paths});
            });
    }

    render() {
        const indexButtons = this.state.paths.map(
        (path) => <button key={path} type="submit" className="btn btn-primary"
                          onClick={this.handleIndex(path)}>Index {path}</button>);

        return (
            <div className="container-fluid">
                <h1 className="text-center mq-bottom">Status</h1>
                <div className="row">
                    <div className="col-md-6">
                        <h2 className="text-center mq-bottom">connections</h2>
                        <BackendStatus />
                    </div>
                    <div className="col-md-6">
                        <h2 className="text-center mq-bottom">topology</h2>
                        <DatabaseTopology />

                        {indexButtons}
                    </div>
                </div>
            </div>
        );
    }
}

export default StatusPage;
