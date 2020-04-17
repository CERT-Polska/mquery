# mquery: Blazingly fast Yara queries for malware analysts

Ever had trouble searching for particular malware samples? Our project is an analyst-friendly web GUI to look through your digital warehouse.

mquery can be used to search through terabytes of malware in a blink of an eye:

![mquery web GUI](docs/mquery-web-ui.gif?raw=1)
_(a bit outdated) screencast_

Thanks to the [UrsaDB database](https://github.com/CERT-Polska/ursadb), queries on large datasets can be very fast.

## Demo

Take a look at [https://mquery.tailcall.net](https://mquery.tailcall.net) for a quick demo (unofficial and unmaintained).

Unfortunately, you won't find any actual malware there. For demo purposes we
have indexed the sources of this project - for example, you can find all exceptions
in our source code by using this Yara rule:

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

## Quickstart

The easiest way to start is by using `docker-compose` from the source:

```
git clone --recurse-submodules https://github.com/CERT-Polska/mquery.git
cd mquery
# now set SAMPLES_DIR to a directory with your files, and INDEX_DIR to
# empty directory for database files to live in. By default database will
# expect files in ./samples directory, and keep index in ./index.
vim .env  
docker-compose up --scale daemon=3  # building the images will take a while
```

The web interface should be available at `http://localhost`.

For more options see our [installation manual](./INSTALL.md).


After you start the system, you should index some files. Use `ursacli`:

```
$ sudo docker-compose exec ursadb ursacli
[2020-04-13 23:25:49.597] [info] Connected to UrsaDB v1.3.0 (connection id: 006B8B4569)
ursadb> index "/mnt/samples";
```

In a default docker-compose deployment, `/mnt/samples` point to the configured
`SAMPLES_DIR` from the `.env` file.

The command will track the progress.
Wait until it's finished (this can take a while).

Now your files should be searchable - try with the following Yara rule (or any other):

```
rule emotet4_basic
{
    meta:
        author = "cert.pl"
    strings:
        $emotet4_rsa_public = {
            8d ?? ?? 5? 8d ?? ?? 5? 6a 00 68 00 80 00 00 ff 35 [4] ff
            35 [4] 6a 13 68 01 00 01 00 ff 15 [4] 85
        }
        $emotet4_cnc_list = { 39 ?? ?5 [4] 0f 44 ?? (FF | A3)}
    condition:
        all of them
}
```

## Learn more

Read [mquery internals](./docs/internals.md) to learn about:

 - How mquery works on a high level.
 - Known limitations and design decisions.
 - How to create efficient yara rules.

## Contributing

If you want to contribute, see our dedicated [documentation for contributors](./CONTRIBUTING.md).

## Contact

If you have any problems, bugs or feature requests related to mquery, you're
encouraged to create a GitHub issue. If you have other questions or want to
contact the developers directly, you can email:

- Michał Leszczyński (monk@cert.pl)
- Jarosław Jedynak (msm@cert.pl)
- CERT.PL (info@cert.pl)
