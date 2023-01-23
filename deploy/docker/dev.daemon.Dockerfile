FROM python:3.10

WORKDIR /usr/src/app/src

RUN apt update; apt install -y cmake

# mquery and plugin requirements
COPY requirements.txt src/plugins/requirements-*.txt /tmp/
RUN ls /tmp/requirements*.txt | xargs -i,, pip --no-cache-dir install -r ,,

# ./src is expected to be mounted with a docker volume
CMD ["./autoreload", "python3", "daemon.py"]
