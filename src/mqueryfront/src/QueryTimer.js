import React, { Component } from "react";

class QueryTimer extends Component {
    constructor(props) {
        super(props);
        this.state = { currentTime: 0, countDownTime: undefined, firstCountDown: true };
    }

    tick() {
        this.setState({
            currentTime: Math.floor(Date.now() / 1000),
        });
    }

    componentDidMount() {
        this.interval = setInterval(() => this.tick(), 1000);

        if (this.props.eta) {
            this.interwalCountDown = setInterval(
                () => this.setCountDownTime(),
                1000
            );
        }
    }
    componentWillUnmount() {
        clearInterval(this.interval);
    }

    componentDidUpdate(prevProps) {
        if (prevProps.qhash !== this.props.qhash) {
            this.setState({
                currentTime: 0,
                countDownTime: undefined,
                firstCountDown: true,
            });
        }
    }

    setCountDownTime() {
        let finishedStatuses = ["done", "cancelled", "failed", "expired"];
        if (
            this.props.job.submitted &&
            !finishedStatuses.includes(this.props.job.status)
        ) {
            if (this.props.job.files_processed > 0 && this.props.eta) {
                let processedFiles =
                    this.props.job.total_files / this.props.job.files_processed;
                let processedTime =
                    this.state.currentTime - this.props.job.submitted;
                let countDown = Math.round(
                    processedFiles * processedTime - processedTime
                );
                if (this.state.firstCountDown) {
                    this.setState({
                        countDownTime: countDown,
                        firstCountDown: false,
                    });
                } else if (
                    this.state.countDownTime > countDown &&
                    ["processing", "querying"].includes(this.props.job.status)
                ) {
                    this.setState({ countDownTime: countDown });
                }
            }
        }
    }

    render() {
        let durationTime;
        let clock = <span />;
        let finishedStatuses = ["done", "cancelled", "failed", "expired"];
        if (
            this.props.job.submitted &&
            !finishedStatuses.includes(this.props.job.status)
        ) {
            if (this.props.duration) {
                durationTime =
                    this.state.currentTime - this.props.job.submitted;
            }

            if (this.props.duration && this.props.eta) {
                clock = (
                    <i>
                        {durationTime}s (~{this.state.countDownTime}s left)
                    </i>
                );
            } else if (this.props.duration && !this.props.eta) {
                clock = <i>{durationTime}s</i>;
            } else if (!this.props.duration && this.props.eta) {
                clock = <i>~{this.state.countDownTime}s</i>;
            }
        } else {
            clock = <span />;
        }

        return <span>{clock}</span>;
    }
}
export default QueryTimer;
