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

## How does it work?

YARA is pretty fast, but searching through large dataset for given signature can take a lot of time. To countermeasure this, we have implemented a custom database called UrsaDB. It is able to pre-filter the results, so it is only necessary to run YARA against a small fraction of binaries:

![mquery flowchart](docs/mquery-flowchart.png?raw=1)

## Quick start (docker)

Easiest way start is with `docker-compose`:

```
git clone --recurse-submodules https://github.com/CERT-Polska/mquery.git
cd mquery
# change `./samples` in `./samples:/mnt/samples` to the path where you keep
# your malware samples. You can also keep it as it is, and copy malware samples
# to ./samples directory before indexing.
vim docker-compose.yml
docker-compose up --scale daemon=3  # building the images will take a while
```

Web interface should be available at `http://localhost`.

## Quick start (manual installation)

You can also build the system from source:

```
sudo apt install libzmq3-dev cmake gcc g++ make python3 git npm redis-server

git clone --recurse-submodules https://github.com/CERT-Polska/mquery.git

cd mquery
pip install -r requirements.txt  # this may take a few minutes
cp src/config.example.py src/config.py

cd src/mqueryfront
npm install
cp src/config.dist.js src/config.js
npm run build

cd ../../ursadb
mkdir build; cd build
cmake -D CMAKE_BUILD_TYPE=Release ..  # requires gcc 7+
make
```

Create a new database:

```
./ursadb/build/ursadb_new ~/db.ursa
```

And start everything manually (systemd services recommended here):

```
project_dir/mquery/src$ flask run  # web server
project_dir/mquery/src$ python3 daemon.py  # job daemon (can be scaled horisontally)
project_dir/ursadb/build$ ./ursadb ~/db.ursa  # backend database
```

Web interface should be available at `http://localhost:5000`.

## Quick start (kubernetes)

Dealing with Kubernetes is never quick. If you're up for a challenge, take a look
at the `./deploy/k8s` directory.

## Next steps

After you start the system, you should index some files.

Right now it can only be done with ursadb-cli tool. Start it:

- for bare metal setup: `python3 ursadb-cli/ursaclient.py`
- for docker: `sudo docker-compose run ursadb-cli tcp://ursadb:9281`

Enter the `index` command (for more complicated options, see ursadb docs):

- for bare metal setup `index "/path/to/your/malware/samples";`
- for docker: `index "/mnt/samples";` (remember, this is mount configured in `docker-compose.yml`)

The command should print the progress. Wait until it's finished (this can take a while).

Now your files should be searchable - try with the following yara rule (or any other):

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

## Contributing

If you want to contribute, ensure that your PR passes through the CI pipeline. Ideally:

 - check your code with `flake8`
 - autoformat your python code with `black`
 - autoformat your html/js/jsx with `prettier --tab-width=4`

## Contact

In case of any questions, feel free to contact:

- Michał Leszczyński (monk@cert.pl)
- Jarosław Jedynak (msm@cert.pl)
- CERT.PL (info@cert.pl)
