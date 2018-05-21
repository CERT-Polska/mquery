mquery: Yara malware queries accelerator
=========================================

mquery is a malware query accelerator developed at CERT Polska. This project provides full instrumentation around
UrsaDB suitable for performing fast YARA queries.


Installation (Docker)
---------------------

Recommended way of installing things is to build from sources using `docker-compose`:

```
git clone --recurse-submodules https://github.com/CERT-Polska/mquery.git
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
