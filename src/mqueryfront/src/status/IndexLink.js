import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faArrowRight } from "@fortawesome/free-solid-svg-icons";
import { Link } from "react-router-dom";

const IndexLink = (props) => {
    return (
        <div className="index-navlink">
            <Link exact to={`/index-files/${props.ursaID}`}>
                Index using UrsaDB id.:{props.ursaID}
                <FontAwesomeIcon
                    className="mx-2"
                    icon={faArrowRight}
                    size="xl"
                    color="black"
                />
            </Link>
        </div>
    );
};

export default IndexLink;
