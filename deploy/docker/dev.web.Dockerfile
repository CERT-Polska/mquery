FROM node:18 AS build

RUN npm install -g serve
COPY src/mqueryfront /app
WORKDIR /app
RUN npm install --legacy-peer-deps && npm run build

FROM python:3.10

RUN apt update; apt install -y cmake

# mquery and plugin requirements
COPY requirements.txt src/plugins/requirements-*.txt /tmp/
RUN ls /tmp/requirements*.txt | xargs -i,, pip --no-cache-dir install -r ,,

COPY requirements.txt setup.py MANIFEST.in /usr/src/app/
COPY src /usr/src/app/src/
COPY --from=build "/app/dist" "/usr/src/app/src/mqueryfront/dist"
RUN pip3 install /usr/src/app
CMD uvicorn mquery.app:app --host 0.0.0.0 --port 5000 --reload
