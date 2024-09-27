import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import svgr from "vite-plugin-svgr";
const fs = require("fs").promises;

export default defineConfig({
    base: "/",
    plugins: [react(), svgr({ svgrOptions: {} })],
    server: {
        port: 80,
        proxy: {
            "/api": { target: "http://dev-web:5000/" },
            "/docs": { target: "http://dev-web:5000/" },
            "/openapi.json": { target: "http://dev-web:5000/" },
        },
    },
    esbuild: {
        loader: "jsx",
        include: /src\/.*\.jsx?$/,
        exclude: [],
    },
    optimizeDeps: {
        esbuildOptions: {
            loader: {
                ".js": "jsx",
            },
            plugins: [
                {
                    name: "load-js-files-as-jsx",
                    setup(build) {
                        build.onLoad(
                            { filter: /src\/.*\.js$/ },
                            async (args) => {
                                return {
                                    loader: "jsx",
                                    contents: await fs.readFile(
                                        args.path,
                                        "utf8"
                                    ),
                                };
                            }
                        );
                    },
                },
            ],
        },
    },
});
