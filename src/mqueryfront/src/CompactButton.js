import React, {Component} from 'react';
import ErrorBoundary from './ErrorBoundary';
import axios from "axios/index";
import {API_URL} from "./config";

class CompactButton extends Component {
    constructor(props) {
        super(props);
        this.state = {
            error: ''
        }
    }

    runCompactAll = ()=>{
        axios.get(API_URL + "/compactall")
        .catch(error => {
            this.setState({"error": error});
        });
    }

    render(){
        return(
            <ErrorBoundary error={this.state.error}>
                <div>
                    <button className="btn btn-success btn-lg" name="query" type="submit" onClick={this.runCompactAll}>
                        Compact All
                    </button>
                </div>
            </ErrorBoundary>
        );
    }
}

export default CompactButton;