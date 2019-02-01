mquery: Blazingly fast Yara queries for malware analysts
========================================================

Ever had trouble searching for particular malware samples? Our project is an analyst-friendly web GUI to look through your digital warehouse.

mquery can be used to search through terabytes of malware in a blink of an eye:

![mquery web GUI](docs/mquery-web-ui.gif?raw=1)

Thanks to our [UrsaDB database](https://github.com/CERT-Polska/ursadb), queries on large datasets can be extremely fast.


How does it work?
-----------------

YARA is pretty fast, but searching through large dataset for given signature can take a lot of time. To countermeasure this, we have implemented a custom database called UrsaDB. It is able to pre-filter the results, so it is only necessary to run YARA against a small fraction of binaries:

![mquery flowchart](docs/mquery-flowchart.png?raw=1)


Installation (Docker)
---------------------

Recommended way of installing things is to build from sources using `docker-compose`:

```
git clone --recurse-submodules https://github.com/CERT-Polska/mquery.git
docker-compose up --scale daemon=3
```

where `--scale daemon=...` refers to the number of workers which will simultaneously process select/index jobs.

Hint: Your `docker-compose` must support v3 syntax of `docker-compose.yml`. Update your software if you have any problems.


Quick start
-----------

1. Start up the whole system (see `Installation (Docker)`).
2. Web interface (by default) should be available on `http://localhost:80/`
3. Upload files to be indexed to the `samples` directory, which is bind-mounted to all containers at `/mnt/samples`.
4. Execute `sudo docker-compose run ursadb-cli tcp://ursadb:9281 --cmd 'index "/mnt/samples";'`. This will tell the database to index all the files.
5. The command should output the progress. Wait until the task is finished.
6. After successful indexing, your files should be searchable. Open the web interface and upload some YARA rule, e.g.:

```
rule emotet4_basic: trojan
{
    meta:
        author = "psrok1/mak"
        module = "emotet"
    strings:
        $emotet4_rsa_public = { 8d ?? ?? 5? 8d ?? ?? 5? 6a 00 68 00 80 00 00 ff 35 [4] ff 35 [4] 6a 13 68 01 00 01 00 ff 15 [4] 85 }
        $emotet4_cnc_list = { 39 ?? ?5 [4] 0f 44 ?? (FF | A3)}
    condition:
        all of them
}
```

Note: Any administrative tasks are to be performed as in the step #4. See [CERT-Polska/ursadb](https://github.com/CERT-Polska/ursadb#queries) for a complete list of supported commands.


Maintainers
-----------

Questions/comments/pull requests are welcome.

* Michał Leszczyński (monk@cert.pl)
* Jarosław Jedynak (msm@tailcall.net)
