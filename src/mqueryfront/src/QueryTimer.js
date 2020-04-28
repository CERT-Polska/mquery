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
            this.props.finishStatus.includes(this.props.job.status)
        ) {
            return null;
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

        if (this.props.duration && this.props.eta) {
            return (
                <i>
                    {durationTime}s (~{countDownTime}s left)
                </i>
            );
        } else if (this.props.duration && !this.props.eta) {
            return <i>{durationTime}s</i>;
        } else if (!this.props.duration && this.props.eta) {
            return <i>~{countDownTime}s</i>;
        }
    }
}
export default QueryTimer;
