const { createProxyMiddleware } = require("http-proxy-middleware");

module.exports = function (app) {
    app.use(createProxyMiddleware("/api", { target: "http://dev-web:5000/" }));
    app.use(createProxyMiddleware("/docs", { target: "http://dev-web:5000/" }));
    app.use(
        createProxyMiddleware("/openapi.json", {
            target: "http://dev-web:5000/",
        })
    );
};
