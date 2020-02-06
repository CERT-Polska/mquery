FROM python:3.6
COPY requirements.txt /app/requirements.txt
RUN pip3 install -r /app/requirements.txt
COPY *.py /app
WORKDIR /app
CMD ["pytest"]
