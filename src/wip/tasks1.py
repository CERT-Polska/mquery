from datetime import datetime, timedelta
import time

from redis import Redis
from rq import Queue

queue = Queue(connection=Redis())

def print_task(data):
    print(data, ". Hello World!")
    if data[-1] != "0":
        queue.enqueue(print_task, data + str(int(data[-1]) - 1))
