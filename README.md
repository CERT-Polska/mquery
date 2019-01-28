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


Installation (manual)
---------------------

1. Run `ursadb` database (see `ursadb` project for further instructions on that topic).
2. Install `redis-server`, `python3` and `npm`.
3. Install requirements: `pip install -r requirements.txt`.
4. Run `cp mqueryfront/src/config.dist.js mqueryfront/src/config.js`
5. Adjust settings in `mqueryfront/src/config.js` accordingly.
4. Run `cd mqueryfront && npm install && npm run build`
5. Copy `config.example.py` to `config.py`, remember to adjust the settings and set unique `SECRET_KEY`.
6. Setup a flask application originating from `webapp.py` in your favourite web server.
7. Run `daemon.py` - a standalone script which should work constantly, consider putting it in systemd.


How to use this thing
---------------------

1. Start up the whole system (see "Installation").
2. Web interface (by default) should be available on http://localhost:80/
3. Upload files to be indexed to the `mquery_samples` volume. From the host it should be visible at `/var/lib/docker/volumes/mquery_samples/_data`. If in doubt, debug using `docker image inspect mquery_samples` command.
4. Open web interface, choose "admin" tab and click "Index /mnt/samples".
5. While indexing, the current progress will be displayed in the "backend" section of "admin" tab (no auto refresh), ursadb will also periodically report something on the console.
6. After successful indexing, your files should be searchable. Go to the main tab and upload some Yara, e.g.:

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

Maintainers
-----------

Questions/comments/pull requests are welcome.

* Michał Leszczyński (monk@cert.pl)
* Jarosław Jedynak (msm@tailcall.net)
