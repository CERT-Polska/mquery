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

        let durationTime;
        if (this.props.duration) {
            durationTime = this.state.currentTime - this.props.job.submitted;
        }
        let durationMin;
        if (durationTime >= 60) {
            durationMin = Math.floor(durationTime / 60);
            durationTime = durationTime % 60;
        }

        let countDownTime;
        if (this.props.job.files_processed > 0 && this.props.countDown) {
            let processedFiles =
                this.props.job.total_files / this.props.job.files_processed;
            let processedTime =
                this.state.currentTime - this.props.job.submitted;
            countDownTime = Math.round(
                processedFiles * processedTime - processedTime
            );
        }
        let countdowmMin;
        if (countDownTime >= 60) {
            countdowmMin = Math.floor(countDownTime / 60);
            countDownTime = countDownTime % 60;
        }

        if (this.props.duration && this.props.countDown) {
            return (
                <i>
                    {durationMin ? (
                        <span>
                            {durationMin}m {durationTime}s
                        </span>
                    ) : (
                        <span>{durationTime}s</span>
                    )}{" "}
                    (~
                    {countdowmMin ? (
                        <span>
                            {countdowmMin}m {countDownTime}s
                        </span>
                    ) : (
                        countDownTime >= 0 && <span>{countDownTime}s</span>
                    )}{" "}
                    left)
                </i>
            );
        } else if (this.props.duration && !this.props.countDown) {
            return (
                <i>
                    {durationMin ? (
                        <span>
                            {durationMin}m {durationTime}s
                        </span>
                    ) : (
                        <span>{durationTime}s</span>
                    )}
                </i>
            );
        } else if (!this.props.duration && this.props.countDown) {
            return (
                <i>
                    {countdowmMin ? (
                        <span>
                            {countdowmMin}m {countDownTime}s
                        </span>
                    ) : (
                        countDownTime >= 0 && <span>{countDownTime}s</span>
                    )}
                </i>
            );
        }
    }
}
export default QueryTimer;
