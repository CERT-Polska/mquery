import React, {Component} from 'react';
import SearchJobs from './SearchJobs';


class RecentPage extends Component {
    render() {
        return (
            <div className="container-fluid">
                <h1 className="text-center mq-bottom">Recent jobs</h1>
                <div className="row">
                    <div className="col-md-6 offset-md-3">
                        <SearchJobs />
                    </div>
                </div>
            </div>
        );
    }
}

export default RecentPage;
