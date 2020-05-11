# mquery: Blazingly fast Yara queries for malware analysts

Ever had trouble searching for particular malware samples? Mquery is an
analyst-friendly web GUI to look through your digital warehouse.

It can be used to search through terabytes of malware in a blink of an eye:

![mquery web GUI](docs/mquery-web-ui.gif?raw=1)
_(a bit outdated) screencast_

Under the hood we use our [UrsaDB](https://github.com/CERT-Polska/ursadb), to
accelerate yara queries with ngrams.

## Demo

Take a look at [https://mquery.tailcall.net](https://mquery.tailcall.net) for an (unofficial) demo.

## Quickstart

### 1. Start the system

The easiest way to do this is with `docker-compose`:

```
git clone --recurse-submodules https://github.com/CERT-Polska/mquery.git
cd mquery
vim .env  # optional - change samples and index directory locations
docker-compose up --scale daemon=3  # building the images will take a while
```

The web interface should be available at `http://localhost`.

*(For more installation options see the [installation manual](./INSTALL.md) ).*

### 2. Add the files

Put some files in the `SAMPLES_DIR` (by default `./samples` in the repository,
configurable with variable in `.env` file).

### 3. Index your collection

If you use the default configuration, just click "reindex" button on the status
page:

![](./docs/index-button.png)

This will scan samples directory for all new files and index them. You can
monitor the progress in the `tasks` window on the left. You have to
repeat this every time you want to add new files!

This is a good and easy way to start, but if you have a big collection you are
strongly encouraged to read [indexing page](./docs/indexing.md) in the manual. 

### 4. Test it

Now your files should be searchable - try the following Yara rule (or any other):

```
rule yara_rule_test
{
    meta:
        author = "cert.pl"
    strings:
        $emotet4_rsa_public = {
            8d ?? ?? 5? 8d ?? ?? 5? 6a 00 68 00 80 00 00 ff 35 [4] ff
            35 [4] 6a 13 68 01 00 01 00 ff 15 [4] 85
        }
    condition:
        all of them
}
```

## Learn more

See the [documentation](./docs/README.md) to learn more. Probably a good idea
if you plan a bigger deployment.

You can also read the hosted version here:
[cert-polska.github.io/mquery/docs](https://cert-polska.github.io/mquery/docs).

## Contributing

If you want to contribute, see our dedicated
[documentation for contributors](./CONTRIBUTING.md).

## Contact

If you have any problems, bugs or feature requests related to mquery, you're
encouraged to create a GitHub issue.

If you have questions unsuitable for github, you can email CERT.PL
(info@cert.pl) directly.
