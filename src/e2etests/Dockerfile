FROM python:3.10
RUN apt update; apt install -y cmake
RUN pip3 install pytest==7.1.2
COPY requirements.txt /app/requirements.txt
RUN pip3 install -r /app/requirements.txt
COPY . /app/
RUN pip3 install /app/
WORKDIR /app
CMD ["python", "-m", "pytest", "--log-cli-level=INFO", "/app/src/e2etests/"]
