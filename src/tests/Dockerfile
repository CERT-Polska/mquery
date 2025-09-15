FROM python:3.10
RUN apt update; apt install -y cmake
RUN pip install pytest pytest-timeout
COPY requirements.txt /app/requirements.txt
RUN pip3 install -r /app/requirements.txt
COPY src/ /app/
WORKDIR /app
CMD ["python", "-m", "pytest", "--log-cli-level=INFO", "tests/"]
