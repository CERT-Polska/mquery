import { Component } from "react";
import IndexMultiSelect from "./IndexMultiSelect";
import { useParams } from "react-router-dom";
import api from "../api";
import ErrorBoundary from "../components/ErrorBoundary";
import IndexProgressBar from "./IndexProgressBar";
import IndexClearQueueButton from "./IndexClearQueueButton";

// function getAvailableTaintsListFromDatasets(datasets) {
//     var taintList = Object.values(datasets)
//         .map((ds) => ds.taints)
//         .flat();
//     return [...new Set(taintList)];
// }

class IndexPageInner extends Component {
    constructor(props) {
        super(props);
        this.state = {
            filenames: [],
            availableNGrams: ["gram3", "text4", "wide8", "hash4"],
            selectedNGrams: [],
            availableTaints: [],
            selectedTaints: [],
            allQueuedFilesLength: 0,
            finishedQueuedFilesLength: 0,
        };
        this.handleSubmit = this.handleSubmit.bind(this);
        this.handleTextareaInput = this.handleTextareaInput.bind(this);
        this.handleNGramSelect = this.handleNGramSelect.bind(this);
        this.handleTaintSelect = this.handleTaintSelect.bind(this);
    }

    ursa_id = this.props.params.ursa_id;

    componentDidMount() {
        api.get(`/queue/${this.props.params.ursa_id}`)
            // .then((response) => {
            //     this.setState({
            //         allQueuedFilesLength: response.data.all_files, // NOTE: dunno whether these params will be provided at all
            //         finishedQueuedFilesLength: response.data.finished_files
            //     })
            // })
            // .catch((error) => {
            //     this.setState({ error: error });
            // });
            .catch((_e) => {
                this.setState({
                    allQueuedFilesLength: 10000,
                    finishedQueuedFilesLength: 2137,
                });
            }); // TODO: uncomment prev then-catch clause after API implementation

        api.get("/backend/datasets")
            .then((_response) => {
                // this.setState({
                //     availableTaints: getAvailableTaintsListFromDatasets(response.data.datasets),
                // });
                this.setState({
                    availableTaints: ["test_taint", "some other taint"],
                }); // TODO: uncomment prev set state after API implementation
            })
            .catch((error) => {
                this.setState({ error: error });
            });
    }

    handleTextareaInput(e) {
        const splitFiles = e.target.value.split("\n").filter((file) => !!file);
        this.setState({ filenames: splitFiles });
    }

    handleNGramSelect(selection) {
        this.setState({ selectedNGrams: selection });
    }

    handleTaintSelect(selection) {
        this.setState({ selectedTaints: selection });
    }

    handleSubmit() {
        // TODO: process following data accordingly to new endpoint
        // c_onsole.log(this.state.filenames); // list of strings
        // c_onsole.log(this.state.selectedNGrams); // list of {value: nGram, label: nGram} objects
        // c_onsole.log(this.state.selectedTaints); // list of {value: taint, label: taint} objects
        api.post(`/queue/${this.ursa_id}`, {})
            .then((_r) => {})
            .catch((_e) => {});
    }

    render() {
        const fileLen = this.state.filenames.length;
        const percentage = this.state.allQueuedFilesLength
            ? (this.state.finishedQueuedFilesLength * 100.0) /
              this.state.allQueuedFilesLength
            : 0;
        return (
            <ErrorBoundary error={this.state.error}>
                <div className="container-fluid">
                    <h1 className="text-center mq-bottom">{`Index ${this.props.params.ursa_id}`}</h1>
                    <div className="index-form-wrapper">
                        <textarea
                            id="filenames-textarea"
                            className="form-control"
                            name="rows"
                            placeholder="Input filenames here (each line representing one filename)"
                            onChange={this.handleTextareaInput}
                        />
                        <IndexMultiSelect
                            placeholder="Select nGrams"
                            options={this.state.availableNGrams}
                            onChange={this.handleNGramSelect}
                        />
                        {this.state.availableTaints.length > 0 && (
                            <IndexMultiSelect
                                placeholder="Select taints"
                                options={this.state.availableTaints}
                                onChange={this.handleTaintSelect}
                            />
                        )}
                        <button
                            className="btn btn-secondary btn-sm btn-success"
                            onClick={this.handleSubmit}
                        >
                            {`Add to queue${
                                fileLen > 0
                                    ? ` (${fileLen} file${
                                          fileLen > 1 ? "s" : ""
                                      })`
                                    : ""
                            }`}
                        </button>
                    </div>
                    {percentage ? (
                        <>
                            <IndexProgressBar percentage={percentage} />
                            <IndexClearQueueButton
                                ursa_id={this.props.params.ursa_id}
                            />
                        </>
                    ) : (
                        <></>
                    )}
                </div>
            </ErrorBoundary>
        );
    }
}

function IndexPage() {
    return <IndexPageInner params={useParams()} />;
}

export default IndexPage;
