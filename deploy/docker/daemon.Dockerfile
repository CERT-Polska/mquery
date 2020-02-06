FROM python:3.7

COPY "src/requirements.txt" "/tmp/requirements.txt"
RUN pip install -r /tmp/requirements.txt
COPY "src/" "/app"
RUN chmod +x "/app/daemon.py"
COPY "src/config.docker.py" "/app/config.py"

ENTRYPOINT ["/app/daemon.py"]
