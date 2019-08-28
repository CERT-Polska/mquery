mquery: Blazingly fast Yara queries for malware analysts
========================================================

Ever had trouble searching for particular malware samples? Our project is an analyst-friendly web GUI to look through your digital warehouse.

mquery can be used to search through terabytes of malware in a blink of an eye:

![mquery web GUI](docs/mquery-web-ui.gif?raw=1)

Thanks to the [UrsaDB database](https://github.com/CERT-Polska/ursadb), queries on large datasets can be extremely fast.


Demo
-----------------

Take a look at [https://mquery.tailcall.net](https://mquery.tailcall.net) for a quick demo.

Unfortunately, you won't find any actual malware there. For demo purposes we
have indexed the sources of this project - so you can try to find all exceptions
in our source code by using this yara rule:

```
rule find_exceptions: trojan
{
    meta:
        author = "mquery_demo"
    strings:
        $exception_string = "Exception"
    condition:
        all of them
}
```


How does it work?
-----------------

YARA is pretty fast, but searching through large dataset for given signature can take a lot of time. To countermeasure this, we have implemented a custom database called UrsaDB. It is able to pre-filter the results, so it is only necessary to run YARA against a small fraction of binaries:

![mquery flowchart](docs/mquery-flowchart.png?raw=1)


Quick start
-----------

1. Start up the whole system (see `Installation (Docker)`).
2. Web interface (by default) should be available on `http://localhost:80/`
3. Upload files to be indexed to the `samples` directory, which is bind-mounted to all containers at `/mnt/samples`.
4. Execute `sudo docker-compose run ursadb-cli tcp://ursadb:9281 --cmd 'index "/mnt/samples";'`. This will tell the database to index all the files in `/mnt/samples` (change the path depending on your system).
5. The command should output the progress. Wait until the task is finished.
6. After successful indexing, your files should be searchable. Open the web interface and upload some YARA rule, e.g.:

```
rule emotet4_basic: trojan
{
    meta:
        author = "cert.pl"
    strings:
        $emotet4_rsa_public = { 8d ?? ?? 5? 8d ?? ?? 5? 6a 00 68 00 80 00 00 ff 35 [4] ff 35 [4] 6a 13 68 01 00 01 00 ff 15 [4] 85 }
        $emotet4_cnc_list = { 39 ?? ?5 [4] 0f 44 ?? (FF | A3)}
    condition:
        all of them
}
```

Note: Any administrative tasks can be performed using ursacb-cli.
See [CERT-Polska/ursadb](https://github.com/CERT-Polska/ursadb#queries) for a complete list of supported commands.


Installation (Docker)
---------------------

Easy way to install the software is to build it from sources using `docker-compose`:

```
git clone --recurse-submodules https://github.com/CERT-Polska/mquery.git
cd mquery
docker-compose up --scale daemon=3
```

where `--scale daemon=...` refers to the number of workers which will simultaneously process select/index jobs.

Hint: Your `docker-compose` must support v3 syntax of `docker-compose.yml`. Update your software if you have any problems.

For a production environment consider using kubernetes (take a look at `kuebrnetes` directory to get you started)
or a manual installation (see below).


Installation (Manual)
---------------------

There are three separate components:

- ursadb (backend) - Run `db.ursa tcp://0.0.0.0:9281` after compilation. (will listen on tcp port 9281).
  Needs persistent storage at cwd (for docker deployments use a volume. You don't need to do anything special for bare metal installations)
- mquery (web ui) - After creating a valid `config.py` run `python3 webapp.py` or expose it via uwsgi.
- daemon - daemon to pick up yara queries. Uses the same `config.py` file. You can use more than one daemon.

You need to mount files indexed by ursadb at the same logical path in mquery and daemons.

You also need to have a redis server somewhere (used as a task queue for mquery and daemon)


Maintainers
-----------

Questions/comments/pull requests are welcome.

* Michał Leszczyński (monk@cert.pl)
* Jarosław Jedynak (msm@tailcall.net)
