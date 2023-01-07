from redis import Redis
from rq import Queue
import wip.tasks as tasks
import config
from db import Database

queue = Queue(connection=Redis(config.REDIS_HOST, config.REDIS_PORT))

def main():
    # queue.enqueue(tasks.ursadb_command, "topology;")

    db = Database(config.REDIS_HOST, config.REDIS_PORT)
    job = db.create_search_object(
        "kot",
        "kot",
        "rule kot{ strings: $kot = {61 61 61} condition: all of them }",
        "medium",
        0,
        "nop",
        [],
        ["default"]
    )
    queue.enqueue(tasks.start_search, job)

if __name__ == "__main__":
    main()
