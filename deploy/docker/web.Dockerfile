FROM node:8 AS build

RUN npm install -g serve
COPY mqueryfront /app
COPY mqueryfront/src/config.dist.js /app/src/config.js
WORKDIR /app
RUN npm install && npm run build

FROM python:3.7

WORKDIR /usr/src/app/src

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r /requirements.txt
COPY . .
COPY --from=build /app/build ./mqueryfront/build
COPY config.docker.py /app/config.py
COPY uwsgi-docker.ini /app/uwsgi.ini
