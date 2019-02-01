import React, {Component} from 'react';
import BackendStatus from './BackendStatus';
import DatabaseTopology from './DatabaseTopology';

class StatusPage extends Component {
    render() {
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
                    </div>
                </div>
            </div>
        );
    }
}

export default StatusPage;
