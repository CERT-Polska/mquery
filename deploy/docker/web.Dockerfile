FROM node:16 AS build

RUN npm install -g serve
COPY src/mqueryfront /app
WORKDIR /app
RUN npm install --legacy-peer-deps && npm run build

FROM python:3.10

WORKDIR /usr/src/app/src

RUN apt update; apt install -y cmake

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# plugin requirements
# requirements.txt is added because at least one file must exist
COPY requirements.txt src/plugins/requirements-*.txt /tmp/
RUN ls /tmp/requirements-*.txt | xargs -i,, pip --no-cache-dir install -r ,,

COPY "src/." "."
COPY --from=build "/app/build" "./mqueryfront/build"
COPY "src/config.docker.py" "config.py"
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "5000"]
