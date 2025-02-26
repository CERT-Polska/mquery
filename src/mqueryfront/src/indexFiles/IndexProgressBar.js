import { Component } from "react";

// NOTE: this module is currently not used, but might prove useful in future
// when status might be applied to QueuedFile objects
// (only required param is "percentage" as float value from 0 to 100)
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
