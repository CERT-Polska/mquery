#!/usr/bin/env python
import os
import random
import string


def random_secret():
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(32))


with open('/app/config.py', 'w') as f:
    repo = os.environ.get('MQUERY_REPO_URL', 'https://database/analysis?hash={hash}')

    f.write("BACKEND = 'tcp://ursadb:9281'\n")
    f.write("REDIS_HOST = 'redis'\n")
    f.write("REDIS_PORT = 6379\n")
    f.write("SECRET_KEY = '{}'\n".format(random_secret()))
    f.write("REPO_URL = '{}'\n".format(repo))
    f.write("INDEXABLE_PATHS = ['/mnt/samples']\n")
