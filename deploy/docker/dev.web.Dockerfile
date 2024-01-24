FROM python:3.10

WORKDIR /usr/src/app/src

RUN apt update; apt install -y cmake

# mquery and plugin requirements
COPY requirements.txt src/plugins/requirements-*.txt /tmp/
RUN ls /tmp/requirements*.txt | xargs -i,, pip --no-cache-dir install -r ,,

CMD mkdir ./mqueryfront/build && pip install -e /usr/src/app && uvicorn mquery.app:app --host 0.0.0.0 --port 5000 --reload
