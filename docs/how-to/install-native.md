# Install mquery natively (without docker)

This document will guide you through the basic native mquery installation.

Native installation is good if you want to have control over everything,
don't like Docker, or need to use advanced plugins (it's possible to use
plugins in Docker, but you may need to build your own images). This method
makes it also easier to understand what's going on, and is easier to tweak.

This guide was tested on Ubuntu 22.10.

## Requirements

* Linux system with at least 4GB RAM and enough disk space for your samples
and index
* Sudo access

## Installation procedure

### 1. Install dependencies

This depends on your package manager. For ubuntu:

```
sudo apt install libzmq3-dev cmake gcc g++ make python3 git npm redis-server python3-dev python3.10-venv
```

### 2. Get the sources

For purposes of this guide, we will install mquery components to `/opt`. Modify
according to your preferences.

```
cd /opt/
git clone https://github.com/CERT-Polska/mquery.git
```

### 3. Install python dependencies

We will install all dependencies to a so-called Python virtual environment.
This means they will not be availbale globally, but to access them you will
have to run `source /opt/mquery/venv/bin/activate`

```
cd /opt/mquery
python3 -m venv venv
source /opt/mquery/venv/bin/activate  # activate the virtual env
pip install -r /opt/mquery/requirements.txt  # this may take a few minutes
```

### 4. Build the frontend 

Mquery's frontend is built in react and we need to build a bundle before
we can start a web server.

```
cd /opt/mquery/src/mqueryfront
npm install --legacy-peer-deps
npm run build
```

### 5. Download (or build) Ursadb

Final component we will need to get is Ursadb. It's written in C++, so we need
to compile it first or download a pre-compiled release.

You can get a compiled release from https://github.com/CERT-Polska/ursadb/releases/.
Just download a tar.gz from the newest release, unpack it, and you're good
to go:

```
cd /opt
wget https://github.com/CERT-Polska/ursadb/releases/download/v1.5.1/ursadb.tar.gz
tar xvf ursadb.tar.gz
```

You can also compile it yourself:

```
cd /opt
git clone --recurse-submodules https://github.com/CERT-Polska/ursadb.git
cd /opt/ursadb
mkdir build; cd build
cmake -D CMAKE_BUILD_TYPE=Release ..  # requires gcc 7+
make -j $(nproc)
```

### Create a new ursadb's database

In this example, we will store our samples in `/var/mquery/samples`,
and our index in `/var/mquery/index`.

Create a new database (change path to `/opt/ursadb/build/ursadb_new` if
you built ursadb from source):

```
mkdir /var/mquery /var/mquery/samples /var/mquery/index
/opt/ursadb/ursadb_new /var/mquery/index/db.ursa
```

### Configure mquery

Default configuration is almost good for us, we just need to change samples dir:

```
cd /opt/mquery/src
cp config.example.py config.py 
vim config.py
```

Edit the config.py and change `INDEX_DIR` to `/var/mquery/samples`. After
editing, save the file and exit by typing `[esc]:x[enter]`

### Start everything

You will need at least three separate terminals to run all the components:

#### Terminal 1: web server

Web server is the only client visible part, and probably most important:

```
cd /opt/mquery/src/
source /opt/mquery/venv/bin/activate  # remember, we need virtualenv
uvicorn app:app --host 0.0.0.0 --port 80
```

#### Terminal 2: mquery worker

To actually do any work, mquery needs workers. You may run as many workers as
you want - you probably want more than one. To make it simpler, you can start
worker with a flag, for example, `--scale 4`, to create 4 workers using a
single command:

```
cd /opt/mquery/src
source /opt/mquery/venv/bin/activate  # remember, we need virtualenv
python3 daemon.py --scale 4
```

#### Terminal 3: ursadb

Last but not least, you need ursadb running. This part is easy:

```
/opt/ursadb/ursadb /var/mquery/index/db.ursa
```

## Next steps

Congratulations, Mquery is now installed and working. You can now...

* Visit the web interface at `http://localhost:80`.
* [Index some files](../indexing.md)
