import React, { Component } from "react";
import { finishedStatuses } from "./QueryUtils";

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
            finishedStatuses.includes(this.props.job.status)
        ) {
            return null;
        }

        let durationSec;
        if (this.props.duration) {
            durationSec = this.state.currentTime - this.props.job.submitted;
        }
        let durationMin;
        if (durationSec >= 60) {
            durationMin = Math.floor(durationSec / 60);
            durationSec = durationSec % 60;
        }

        let countDownSec;
        if (this.props.job.files_processed > 0 && this.props.countDown) {
            let processedFiles =
                this.props.job.total_files / this.props.job.files_processed;
            let processedTime =
                this.state.currentTime - this.props.job.submitted;
            countDownSec = Math.round(
                processedFiles * processedTime - processedTime
            );
        }
        let countdowmMin;
        if (countDownSec >= 60) {
            countdowmMin = Math.floor(countDownSec / 60);
            countDownSec = countDownSec % 60;
        }

        let durationTime = durationMin ? (
            <span>
                {durationMin}m {durationSec}s
            </span>
        ) : (
            <span>{durationSec}s</span>
        );

        let countDownTime = countdowmMin ? (
            <span>
                {countdowmMin}m {countDownSec}s
            </span>
        ) : (
            countDownSec >= 0 && <span>{countDownSec}s</span>
        );

        if (this.props.duration && this.props.countDown) {
            return (
                <i>
                    {durationTime} (~
                    {countDownTime} left)
                </i>
            );
        } else if (this.props.duration) {
            return <i>{durationTime}</i>;
        } else if (this.props.countDown) {
            return <i>{countDownTime}</i>;
        }
    }
}
export default QueryTimer;
