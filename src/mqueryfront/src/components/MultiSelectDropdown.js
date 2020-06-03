import React, { Component } from "react";
import PropTypes from "prop-types";

class MulitSelectDropdown extends Component {
    constructor(props) {
        super(props);

        this.state = {
            options: this.props.optionList.map((item) => {
                return { name: item, isChecked: false };
            }),
        };
        this.handleItem = this.handleItem.bind(this);
    }

    handleItem(event, isItem) {
        const { name, checked } = event.target;
        let options = this.state.options.map((item) => {
            let isChecked = item.isChecked;
            if (!isItem) isChecked = checked;
            else if (item.name === name) isChecked = !item.isChecked;

            return { name: item.name, isChecked: isChecked };
        });

        this.setState({
            options: options,
        });

        const checkedList = options
            .filter((item) => item.isChecked)
            .map((item) => item.name);
        this.props.onChange(checkedList);
    }

    render() {
        const { itemsname, prefixSelectionMsg, noSelectionMsg } = this.props;

        const checkedList = this.state.options.filter((item) => item.isChecked);
        const selectedCount = checkedList.length;

        let selectionTxt;
        if (selectedCount === 0) {
            selectionTxt = noSelectionMsg;
        } else if (selectedCount === 1) {
            selectionTxt = checkedList[0].name;
        } else if (selectedCount === this.state.options.length) {
            selectionTxt = `All ${itemsname}`;
        } else selectionTxt = `${selectedCount} ${itemsname}`;
        selectionTxt = prefixSelectionMsg + selectionTxt;

        const optionsCount = this.state.options.length;
        if (optionsCount === 0)
            return (
                <button type="button" className="btn btn-info ">
                    {selectionTxt}
                </button>
            );

        const optionElements = this.state.options.map((item) => {
            return (
                <div
                    className="dropdown-item list-group-item-action"
                    key={item.name}
                >
                    &nbsp;
                    <label className="form-check-label">
                        <input
                            type="checkbox"
                            className="form-check-input"
                            name={item.name}
                            checked={item.isChecked}
                            onChange={(event) => this.handleItem(event, true)}
                        />
                        &nbsp;{item.name}
                    </label>
                </div>
            );
        });

        return (
            <div className="btn-group" role="group">
                <button
                    type="button"
                    className="btn btn-info dropdown-toggle"
                    data-toggle="dropdown"
                >
                    {selectionTxt}
                </button>
                <div className="dropdown-menu">
                    <div className="dropdown-item list-group-item-action">
                        &nbsp;
                        <label className="form-check-label">
                            <input
                                type="checkbox"
                                className="form-check-input"
                                name="all"
                                checked={selectedCount === optionsCount}
                                onChange={this.handleItem}
                            />
                            &nbsp;All {itemsname}
                        </label>
                    </div>
                    <div className="dropdown-divider"></div>
                    {optionElements}
                </div>
            </div>
        );
    }
}

MulitSelectDropdown.defaultProps = {
    prefixSelectionMsg: "",
    noSelectionMsg: "nothing selected",
    itemsname: "items",
};

MulitSelectDropdown.propTypes = {
    optionList: PropTypes.arrayOf(PropTypes.string).isRequired,
    onChange: PropTypes.func.isRequired,
    prefixSelectionMsg: PropTypes.string,
    noSelectionMsg: PropTypes.string,
    itemsname: PropTypes.string,
};
export default MulitSelectDropdown;
