FROM python:3.10

RUN apt update; apt install -y cmake

# mquery and plugin requirements
COPY requirements.txt src/plugins/requirements-*.txt /tmp/
RUN ls /tmp/requirements*.txt | xargs -i,, pip --no-cache-dir install -r ,,

COPY "." "/app"
RUN pip install /app

ENTRYPOINT ["mquery-daemon"]
