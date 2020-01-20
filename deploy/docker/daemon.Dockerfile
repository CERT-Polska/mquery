FROM python:3.6

COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt
COPY . /app
RUN chmod +x /app/daemon.py
COPY config.docker.py /app/config.py

ENTRYPOINT ["/app/daemon.py"]
