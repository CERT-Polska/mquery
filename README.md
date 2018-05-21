mquery: Yara malware queries accelerator
=========================================

mquery is a malware query accelerator developed at CERT Polska. This project provides full instrumentation around
UrsaDB suitable for performing fast YARA queries.


Installation (Docker)
---------------------

Recommended way of installing things is to use `docker-compose`:

```
docker-compose up --scale daemon=3
```

where `--scale daemon=...` refers to the number of workers which will execute select/index tasks.


Installation (manual)
---------------------

1. Run `ursadb` database (see `ursadb` project for further instructions on that topic).
2. Install `redis-server` and `python2`.
3. Install requirements: `pip install -r requirements.txt`
4. Setup a flask application originating from `webapp.py` in your favourite web server.
5. Run `daemon.py` - a standalone script which should work constantly, consider putting it in systemd.
