import { Component } from "react";
import Select from "react-select";

class IndexMultiselect extends Component {
    get optionsList() {
        return this.props.options.map((obj) => ({
            label: obj,
            value: obj,
        }));
    }

    render() {
        return (
            <Select
                name={this.props.name}
                options={this.optionsList}
                placeholder={this.props.placeholder}
                value={this.props.value}
                isMulti
                isSearchable
                onChange={this.props.onChange}
            />
        );
    }
}

export default IndexMultiselect;
