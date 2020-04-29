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

    getRenderTime(seconds){
        let minutes;
        if (seconds >= 60) {
            minutes = Math.floor(seconds / 60);
            seconds = seconds % 60;
        }

        return( minutes ? (
            <span>
                {minutes}m {seconds}s
            </span>
        ) : (
            seconds >= 0 && <span>{seconds}s</span>
        ));
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

        if (this.props.duration && this.props.countDown) {
            return (
                <i>
                    {this.getRenderTime(durationSec)} (~
                    {this.getRenderTime(countDownSec)} left)
                </i>
            );
        } else if (this.props.duration) {
            return <i>{this.getRenderTime(durationSec)}</i>;
        } else if (this.props.countDown) {
            return <i>{this.getRenderTime(countDownSec)}</i>;
        }
    }
}
export default QueryTimer;
