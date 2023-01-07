from datetime import datetime, timedelta
import time
from redis import Redis
from rq import Queue
import tasks1

queue = Queue(connection=Redis())

def queue_tasks():
    for i in range(5):
        queue.enqueue(tasks1.print_task, str(i))

def main():
    queue_tasks()

if __name__ == "__main__":
    main()
