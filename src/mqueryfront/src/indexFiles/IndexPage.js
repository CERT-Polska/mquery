import { Component } from "react";
import IndexMultiSelect from "./IndexMultiSelect";
import { useParams } from "react-router-dom";
import api from "../api";
import ErrorBoundary from "../components/ErrorBoundary";
import IndexClearQueueButton from "./IndexClearQueueButton";

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
        };
        this.handleSubmit = this.handleSubmit.bind(this);
        this.handleTextareaInput = this.handleTextareaInput.bind(this);
        this.handleNGramSelect = this.handleNGramSelect.bind(this);
        this.handleTaintSelect = this.handleTaintSelect.bind(this);
    }

    ursa_id = this.props.params.ursa_id;

    componentDidMount() {
        api.get(`/queue/${this.props.params.ursa_id}`)
            .then((response) => {
                this.setState({
                    size: response.data.size, // NOTE: dunno whether these params will be provided at all
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

    handleSubmit() {
        const indexList = this.state.selectedNGrams.map((nG) => nG.value);
        const tagsList = this.state.selectedTaints.map((taint) => taint.value);
        const data = this.state.filenames.map((filename) => ({
            path: filename,
            index_types: indexList,
            tags: tagsList,
        }));

        api.post(`/queue/${this.ursa_id}`, data).catch((error) => {
            this.setState({ error: error });
        });
    }

    render() {
        const fileLen = this.state.filenames.length;
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
                    <div className="my-2">{`Files in queue (regardless of status): ${this.state.size}`}</div>
                    {this.state.newestFile && (
                        <div className="my-2">{`Newest file date of adding to queue (regardless of status): ${this.state.newestFile}`}</div>
                    )}
                    {this.state.oldestFile && (
                        <div className="my-2">{`Oldest file date of adding to queue (regardless of status): ${this.state.oldestFile}`}</div>
                    )}
                    <IndexClearQueueButton
                        ursa_id={this.props.params.ursa_id}
                    />
                </div>
            </ErrorBoundary>
        );
    }
}

function IndexPage() {
    return <IndexPageInner params={useParams()} />;
}

export default IndexPage;
