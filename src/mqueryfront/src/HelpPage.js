import React, {Component} from 'react';


class HelpPage extends Component {
    render() {
        return (
            <div className="container" style={{width: "80%"}}>
                <h1 className="text-center" style={{marginBottom: "40px"}}>Help me?</h1>
                <h2>General information</h2>
                <p>
                    The mquery system is used to efficiently search for malware samples among our collections.
                    The input information is the YARA rule, which should match the desired samples.
                    As a result of the system's operation user receives a list of matching files.
                </p>

                <div className="alert alert-warning">
                    When using the system, it is worth to
                    know <a href="http://yara.readthedocs.io/en/v3.4.0/writingrules.html">YARA</a> syntax.
                </div>

                <p>
                    The process of result generation is divided into two stages.
                    First, the YARA rules are parsed, and then the corresponding queries to UrsaDB are generated.
                    The database is used for preliminary screening of samples - it is a fast process, but it
                    generates false-positives. Finally, the results returned by the database are verified by
                    the YARA tool.
                </p>

                <p>
                    Such filtering helps reduce the set of samples to be checked with the YARA tool by several
                    orders of magnitude. This additional step is necessary due to the naive search of the
                    entire set of samples, i.e. the launch of YARA on all files, due to their number
                    could take a few weeks to complete.
                </p>

                <h2>Usage</h2>
                <p>
                    The YARA rule may be entered in a large text field which is on the "Query" page. After doing that,
                    one should press "Query" in order to start the search. The "Parse" button is there to present
                    what UrsaDB queries will be generated out of YARA and thus allow for some debugging and fine tuning.
                </p>

                <p>
                    Po zleceniu wyszukiwania po prawej stronie powinna pojawić sie tabelka wraz z listą dopasowań oraz
                    pasek postępu. Wyniki wyszukiwania można pobierać pojedynczo przez interfejs webowy, albo pobrać
                    listę
                    wszystkich dopasowań w celu późniejszego obrobienia jej za pomocą zewnętrznych narzedzi (curl, wget
                    etc).
                </p>

                <div className="alert alert-danger">
                    <strong>Warning!</strong> Depending on the internal optimizer and the quality of the provided YARA
                    rules, some search jobs may take very long time to complete. If the job execution time is
                    unacceptable (e.g. the number of preliminary matches exceeds several hundred thousand), one should
                    cancel the task and try again with a different rule.
                </div>

                <p>
                    The entered rule together with the search results is saved in "Recent jobs" tab. Due to that,
                    it is possible to refer to the historical searches.
                </p>

                <h2>Contact</h2>
                <p>
                    The originator of the project and the author of the first proof-of-concept is <a href="https://tailcall.net/">msm</a>.
                    At the moment, the system is being developed and maintained at CERT.PL by <a
                    href="mailto:monk@cert.pl">monk</a>.
                </p>
            </div>
        );
    }
}

export default HelpPage;
