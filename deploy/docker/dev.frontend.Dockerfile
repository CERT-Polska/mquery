FROM node:16 AS build

RUN npm install -g serve
COPY src/mqueryfront /app
WORKDIR /app
RUN npm install --legacy-peer-deps && \
    mkdir ./public/monaco-vs && \
    cp -r ./node_modules/monaco-editor/min/vs/. ./public/monaco-vs
CMD ["npm", "start"]
