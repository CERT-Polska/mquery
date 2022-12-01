FROM python:3.10
RUN apt update; apt install -y cmake
RUN pip3 install pytest==5.4.1
COPY requirements.txt /app/requirements.txt
RUN pip3 install -r /app/requirements.txt
COPY src/ /app/
WORKDIR /app
CMD ["python", "-m", "pytest", "--log-cli-level=INFO", "e2etests/"]
