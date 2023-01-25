import React from "react";

const AboutPage = (props) => {
    const aboutHtml = props.config ? props.config.about : null;
    return (
        <div className="container-fluid">
            <div className="p-5 mb-4 bg-light rounded-3">
                <div className="container-fluid py-5">
                    <h1 className="display-5 fw-bold">About this instance</h1>
                    <p
                        className="col-md-8 fs-4"
                        dangerouslySetInnerHTML={{ __html: aboutHtml }}
                    />
                </div>
            </div>
        </div>
    );
};

export default AboutPage;
