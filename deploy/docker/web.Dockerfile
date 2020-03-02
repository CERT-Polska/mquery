FROM node:8 AS build

RUN npm install -g serve
COPY src/mqueryfront /app
COPY src/mqueryfront/src/config.dist.js /app/src/config.js
WORKDIR /app
RUN npm install && npm run build

FROM python:3.7

WORKDIR /usr/src/app/src

RUN apt update; apt install -y cmake
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY "src/." "."
COPY --from=build "/app/build" "./mqueryfront/build"
COPY "src/config.docker.py" "config.py"
CMD ["flask", "run", "--host", "0.0.0.0"]
