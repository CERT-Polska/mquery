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
                form="formName"
                name={this.props.name}
                options={this.optionsList}
                placeholder={this.props.placeholder}
                isMulti
                isSearchable
                onChange={this.props.onChange}
            />
        );
    }
}

export default IndexMultiselect;
