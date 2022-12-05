FROM python:3.10

RUN apt update; apt install -y cmake
COPY "requirements.txt" "/tmp/requirements.txt"
RUN pip install -r /tmp/requirements.txt
# requirements.txt is added because at least one file must exist
COPY requirements.txt src/plugins/requirements-*.txt /tmp/
RUN ls /tmp/requirements-*.txt | xargs -i,, pip --no-cache-dir install -r ,,

COPY "src/" "/app"
RUN chmod +x "/app/daemon.py"
COPY "src/config.docker.py" "/app/config.py"

ENTRYPOINT ["/app/daemon.py"]
