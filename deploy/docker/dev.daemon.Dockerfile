FROM python:3.10

WORKDIR /usr/src/app/src

RUN apt update; apt install -y cmake
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
# requirements.txt is added because at least one file must exist
COPY requirements.txt src/plugins/requirements-*.txt /tmp/
RUN ls /tmp/requirements-*.txt | xargs -i,, pip --no-cache-dir install -r ,,
# ./src is expected to be mounted with a docker volume
CMD ["./autoreload", "python3", "daemon.py"]
