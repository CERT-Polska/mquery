import React, { Component } from "react";
import SearchJobs from "./SearchJobs";

class RecentPage extends Component {
    render() {
        return (
            <div>
                <h1 className="text-center mq-bottom">Recent jobs</h1>
                <div className="row">
                    <div className="col-md-8 offset-md-2">
                        <SearchJobs />
                    </div>
                </div>
            </div>
        );
    }
}

export default RecentPage;
