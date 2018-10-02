#!/usr/bin/python3
import random
import string

import yaml
import base64


def gen_secret():
    charset = string.ascii_letters + string.digits
    return ''.join(random.SystemRandom().choice(charset) for _ in range(32))


def gen_kube_secret():
    secret = gen_secret()

    kube_def = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": "mquery-secret"
        },
        "type": "Opaque",
        "data": {
            "SECRET_KEY": base64.b64encode(secret.encode("utf-8")).decode("utf-8")
        }
    }

    return yaml.dump(kube_def, default_flow_style=False)


print(gen_kube_secret())
