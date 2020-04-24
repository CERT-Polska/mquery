FROM python:3.6
RUN apt update; apt install -y cmake
COPY src/tests/requirements.txt /app/requirements.txt
RUN pip3 install -r /app/requirements.txt
COPY src/ /app/
WORKDIR /app
#CMD ["python", "-m", "pytest", "--log-cli-level=INFO", "tests/"]
CMD ["python", "-m", "pytest", "-s", "tests/"]
