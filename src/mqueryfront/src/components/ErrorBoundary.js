import React, { Component } from "react";

class ErrorBoundary extends Component {
    constructor(props) {
        super(props);

        let error = props.error ? props.error : null;
        this.state = { error: error };
    }

    componentDidUpdate(prevProps, prevState, snapshot) {
        if (this.props.error !== this.state.error) {
            this.setState({ error: this.props.error });
        }
    }

    componentDidCatch(error, info) {
        this.setState({ error: error });
    }

    render() {
        return (
            <>
            {this.state.error && (
                <div className="container-fluid">
                    <div className="alert alert-danger">
                        {this.state.error.toString()}
                    </div>
                </div>
            )}
            {this.props.children}
            </>
        );
    }
}

export default ErrorBoundary;
