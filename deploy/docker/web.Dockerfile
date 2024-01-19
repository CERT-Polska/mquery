FROM node:16 AS build

RUN npm install -g serve
COPY src/mqueryfront /app
WORKDIR /app
RUN npm install --legacy-peer-deps && \
    mkdir ./public/monaco-vs && \
    cp -r ./node_modules/monaco-editor/min/vs/. ./public/monaco-vs && \
    npm run build

FROM python:3.10

WORKDIR /usr/src/app/src

RUN apt update; apt install -y cmake

# mquery and plugin requirements
COPY requirements.txt src/plugins/requirements-*.txt /tmp/
RUN ls /tmp/requirements*.txt | xargs -i,, pip --no-cache-dir install -r ,,

COPY "src/." "."
COPY --from=build "/app/build" "./mqueryfront/build"
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5000"]
