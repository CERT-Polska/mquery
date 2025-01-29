import { Component } from "react";

class IndexProgressBar extends Component {
    render() {
        return (
            <div className="row my-2">
                <h4 className="text-center mq-bottom">Indexing progress</h4>
                <div className="progress my-2">
                    <div
                        className="progress-bar progress-bar-striped progress-bar-animated"
                        role="progressbar"
                        aria-valuenow={this.props.percentage}
                        aria-valuemin="0"
                        aria-valuemax="100"
                        style={{ width: `${this.props.percentage}%` }}
                    >
                        {`${this.props.percentage}%`}
                    </div>
                </div>
            </div>
        );
    }
}

export default IndexProgressBar;
