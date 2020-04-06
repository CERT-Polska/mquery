FROM python:3.7

WORKDIR /usr/src/app/src

RUN apt update; apt install -y cmake
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
# ./src is expected to be mounted with a docker volume
CMD ["./autoreload", "python3 daemon.py"]
