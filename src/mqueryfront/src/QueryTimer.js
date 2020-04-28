import React, { Component } from "react";

class QueryTimer extends Component {
    constructor(props) {
        super(props);
        this.state = { currentTime: 0 };
    }

    tick() {
        this.setState({
            currentTime: Math.floor(Date.now() / 1000),
        });
    }

    componentDidMount() {
        this.interval = setInterval(() => this.tick(), 1000);
    }

    componentWillUnmount() {
        clearInterval(this.interval);
    }

    render() {
        if (
            !this.props.job.submitted ||
            ["done", "cancelled", "failed", "expired"].includes(
                this.props.job.status
            )
        ) {
            return <span />;
        }
        let durationTime;
        if (this.props.duration) {
            durationTime = this.state.currentTime - this.props.job.submitted;
        }
        let countDownTime;
        if (this.props.job.files_processed > 0 && this.props.eta) {
            let processedFiles =
                this.props.job.total_files / this.props.job.files_processed;
            let processedTime =
                this.state.currentTime - this.props.job.submitted;
            countDownTime = Math.round(
                processedFiles * processedTime - processedTime
            );
        }
        let clock;
        if (this.props.duration && this.props.eta) {
            clock = (
                <i>
                    {durationTime}s (~{countDownTime}s left)
                </i>
            );
        } else if (this.props.duration && !this.props.eta) {
            clock = <i>{durationTime}s</i>;
        } else if (!this.props.duration && this.props.eta) {
            clock = <i>~{countDownTime}s</i>;
        }

        return <span>{clock}</span>;
    }
}
export default QueryTimer;
