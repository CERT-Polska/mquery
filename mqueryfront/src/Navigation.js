import React, {Component} from 'react';
import {Link} from 'react-router-dom';
import { withRouter } from 'react-router-dom';
import logo from './logo.svg';

class Navigation extends Component {
    constructor(props){
        super(props);
        this.state = {};
    }

    render() {
        return (
            <nav className="navbar navbar-expand-lg navbar-dark bg-dark mb-3">
                <Link className="navbar-brand" to={'/'}><img src={logo} width="150" alt=""/></Link>
                <button className="navbar-toggler" type="button" data-toggle="collapse"
                        data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent"
                        aria-expanded="false" aria-label="Toggle navigation">
                    <span className="navbar-toggler-icon"></span>
                </button>

                <div className="collapse navbar-collapse" id="navbarSupportedContent">
                    <ul className="navbar-nav mr-auto">
                        <li className="nav-item">
                            <Link className="nav-link" to={'/'}>Query</Link>
                        </li>
                        <li className="nav-item">
                            <Link className="nav-link" to={'/admin'}>Admin</Link>
                        </li>
                        <li className="nav-item">
                            <Link className="nav-link" to={'/help'}>Help</Link>
                        </li>
                    </ul>
                </div>
            </nav>
        )
    }
}

export default withRouter(Navigation);
