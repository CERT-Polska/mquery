FROM python:3.6
RUN apt update; apt install -y cmake
COPY requirements.txt /app/requirements.txt
RUN pip3 install -r /app/requirements.txt
RUN pip3 install pytest
COPY src/ /app/
WORKDIR /app
CMD ["python", "-m", "pytest", "--log-cli-level=INFO", "."]
