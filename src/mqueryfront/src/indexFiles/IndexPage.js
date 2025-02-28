import { Component } from "react";
import IndexMultiSelect from "./IndexMultiSelect";
import { useParams } from "react-router-dom";
import api from "../api";
import ErrorBoundary from "../components/ErrorBoundary";
import IndexClearQueueButton from "./IndexClearQueueButton";
import IndexSuccessPage from "./IndexSuccessPage";
import IndexClearedPage from "./IndexClearedPage";
import Draggable from "react-draggable";

function getAvailableTaintsListFromDatasets(datasets) {
    var taintList = Object.values(datasets)
        .map((ds) => ds.taints)
        .flat();
    return [...new Set(taintList)];
}

class IndexPageInner extends Component {
    constructor(props) {
        super(props);
        this.state = {
            filenames: [],
            availableNGrams: ["gram3", "text4", "wide8", "hash4"],
            selectedNGrams: [],
            availableTaints: [],
            selectedTaints: [],
            size: 0,
            oldestFile: null,
            newestFile: null,
            alertShowFileLen: false,
            alertShowCleared: false,
            modalShowClearQueue: false,
        };
        this.handleSubmit = this.handleSubmit.bind(this);
        this.handleClearQueue = this.handleClearQueue.bind(this);
        this.handleTextareaInput = this.handleTextareaInput.bind(this);
        this.handleNGramSelect = this.handleNGramSelect.bind(this);
        this.handleTaintSelect = this.handleTaintSelect.bind(this);
        this.handleModalOpen = this.handleModalOpen.bind(this);
        this.handleAlertClose = this.handleAlertClose.bind(this);
        this.handleAlertClearedClose = this.handleAlertClearedClose.bind(this);
        this.fileOrFiles = this.fileOrFiles.bind(this);
    }

    ursa_id = this.props.params.ursa_id;

    componentDidMount() {
        api.get(`/queue/${this.props.params.ursa_id}`)
            .then((response) => {
                this.setState({
                    size: response.data.size, // NOTE: I don't know whether these params will be provided at all
                    oldestFile: response.data.oldest_file,
                    newestFile: response.data.newest_file,
                });
            })
            .catch((error) => {
                this.setState({ error: error });
            });

        api.get("/backend/datasets")
            .then((response) => {
                this.setState({
                    availableTaints: getAvailableTaintsListFromDatasets(
                        response.data.datasets
                    ),
                });
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

    fileOrFiles(length) {
        return `file${length > 1 ? "s" : ""}`;
    }

    handleSubmit() {
        const indexList = this.state.selectedNGrams.map((nG) => nG.value);
        const tagsList = this.state.selectedTaints.map((taint) => taint.value);
        const data = this.state.filenames.map((filename) => ({
            path: filename,
            index_types: indexList,
            tags: tagsList,
        }));

        api.post(`/queue/${this.ursa_id}`, data)
            .catch((error) => {
                this.setState({ error: error });
            })
            .then((_r) => {
                this.setState({
                    alertShowFileLen: this.state.filenames.length,
                });
            })
            .then((_w) => {
                this.setState({
                    filenames: [],
                    selectedNGrams: [],
                    selectedTaints: [],
                });
                document.getElementById("filenames-textarea").value = "";
            })
            .catch((error) => {
                this.setState({ error: error });
            });
    }

    handleClearQueue() {
        // TODO: include modal before handling closing
        api.delete(`/queue/${this.ursa_id}`)
            .then((response) => {
                this.setState({
                    modalShowClearQueue: false,
                });
                if (response.data.status == "ok") {
                    this.setState({
                        alertShowCleared: true,
                    });
                } // NOTE: this will not throw error on 'ursa_id not found' status
            })
            .catch((error) => this.setState({ error: error }));
    }

    handleAlertClose() {
        this.setState({ alertShowFileLen: false });
    }

    handleModalOpen() {
        this.setState({ modalShowClearQueue: true });
    }

    handleAlertClearedClose() {
        this.setState({ alertShowCleared: false });
    }

    render() {
        const fileLen = this.state.filenames.length;

        const clearQueueModal = (
            <Draggable handle=".modal-header">
                <div className="modal-container-index-page">
                    <div
                        className="modal modal-block"
                        style={{
                            display: this.state.modalShowClearQueue
                                ? "block"
                                : "none",
                        }}
                    >
                        <div className="modal-dialog modal-xl">
                            <div className="modal-content">
                                <div className="modal-header d-flex justify-content-between">
                                    <h6 className="modal-title">{`Clear queue alert`}</h6>
                                    <button
                                        type="button"
                                        className="btn-close"
                                        onClick={() =>
                                            this.setState({
                                                modalShowClearQueue: false,
                                            })
                                        }
                                    />
                                </div>
                                <div className="modal-body">
                                    <div>
                                        Are you sure you want to clear queue at
                                        UrsaDB: {this.ursa_id}?
                                    </div>
                                    <div className="d-flex justify-content-evenly">
                                        <IndexClearQueueButton
                                            msg="Yes, clear queue"
                                            ursa_id={this.props.params.ursa_id}
                                            onClick={this.handleClearQueue}
                                        />
                                        <button
                                            className="btn btn-secondary btn-sm my-2"
                                            onClick={() =>
                                                this.setState({
                                                    modalShowClearQueue: false,
                                                })
                                            }
                                        >
                                            Cancel
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </Draggable>
        );

        return (
            <ErrorBoundary error={this.state.error}>
                <div className="container-fluid">
                    <h1 className="text-center mq-bottom">{`Ursadb: ${this.props.params.ursa_id}`}</h1>
                    {this.state.alertShowFileLen && (
                        <IndexSuccessPage
                            msg={`Successfully added ${
                                this.state.alertShowFileLen
                            } ${this.fileOrFiles(
                                this.state.alertShowFileLen
                            )}!`}
                            onClick={this.handleAlertClose}
                        />
                    )}
                    {this.state.alertShowCleared && (
                        <IndexClearedPage
                            msg={`Successfully cleared ${
                                this.state.alertShowFileLen
                            } ${this.fileOrFiles(
                                this.state.alertShowFileLen
                            )} from queue ${this.ursa_id}!`}
                            onClick={this.handleAlertClearedClose}
                        />
                    )}
                    <div className="index-form-wrapper">
                        <textarea
                            id="filenames-textarea"
                            className="form-control"
                            name="rows"
                            placeholder="Input filenames here (one per line)"
                            onChange={this.handleTextareaInput}
                        />
                        <IndexMultiSelect
                            placeholder="Select nGrams"
                            options={this.state.availableNGrams}
                            onChange={this.handleNGramSelect}
                            value={this.state.selectedNGrams}
                        />
                        {this.state.availableTaints.length > 0 && (
                            <IndexMultiSelect
                                placeholder="Select taints"
                                options={this.state.availableTaints}
                                onChange={this.handleTaintSelect}
                                value={this.state.selectedTaints}
                            />
                        )}
                        <button
                            className="btn btn-secondary btn-sm btn-success"
                            disabled={fileLen === 0}
                            onClick={this.handleSubmit}
                        >
                            {`Add to queue${
                                fileLen > 0
                                    ? ` (${fileLen} ${this.fileOrFiles(
                                          fileLen
                                      )})`
                                    : ""
                            }`}
                        </button>
                    </div>
                    <div className="my-2">{`Files in queue (regardless of status): ${this.state.size}`}</div>
                    {this.state.newestFile && (
                        <div className="my-2">{`Newest file in the queue: ${this.state.newestFile}`}</div>
                    )}
                    {this.state.oldestFile && (
                        <div className="my-2">{`Oldest file in the queue: ${this.state.oldestFile}`}</div>
                    )}
                    <IndexClearQueueButton
                        msg="Clear queue"
                        ursa_id={this.props.params.ursa_id}
                        onClick={this.handleModalOpen}
                    />
                    {this.state.modalShowClearQueue && clearQueueModal}
                </div>
            </ErrorBoundary>
        );
    }
}

function IndexPage() {
    return <IndexPageInner params={useParams()} />;
}

export default IndexPage;
