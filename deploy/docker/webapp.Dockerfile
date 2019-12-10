FROM node:8 AS build

RUN npm install -g serve
COPY mqueryfront /app
COPY mqueryfront/src/config.dist.js /app/src/config.js
WORKDIR /app
RUN npm install && npm run build

FROM tiangolo/uwsgi-nginx-flask:python3.6

ENV STATIC_PATH /app/mqueryfront/build/static
COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt
COPY . /app
COPY --from=build /app/build /app/mqueryfront/build
COPY config.docker.py /app/config.py
COPY uwsgi-docker.ini /app/uwsgi.ini
