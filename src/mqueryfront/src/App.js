import React, {Component} from 'react';
import { Switch, Route } from 'react-router-dom';
import Navigation from './Navigation';
import QueryPage from './QueryPage';
import RecentPage from './RecentPage';
import StatusPage from './StatusPage';
import HelpPage from './HelpPage';
import './App.css';

class App extends Component {
    render() {
        return (
            <div className="App">
                <Navigation/>

                <Switch>
                    <Route exact path='/' component={QueryPage} />
                    <Route path='/query/:hash' component={QueryPage} />
                    <Route exact path='/recent' component={RecentPage} />
                    <Route exact path='/status' component={StatusPage} />
                    <Route exact path='/help' component={HelpPage} />
                </Switch>
            </div>
        );
    }
}

export default App;
