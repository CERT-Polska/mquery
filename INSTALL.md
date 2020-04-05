# INSTALL.md

Supported installation and deployment methods:

- [docker-compose.yml](#Docker_compose)
- [docker-compose.dev.yml](#Docker_compose_(dev))
- [bare metal](#bare_metal)
- [kubernetes](kubernetes)

## Docker compose

Quick build&run with [docker compose](https://docs.docker.com/compose/).

```
git clone --recurse-submodules https://github.com/CERT-Polska/mquery.git
cd mquery
# Copy your malware samples to ./samples directory in the cloned repository
docker-compose up --scale daemon=3  # this will take a while
```

- Good for testing mquery and production deployments on a single server
- Poor for development

## Docker compose (dev)

Docker compose dedicated for developers.

```
git clone --recurse-submodules https://github.com/CERT-Polska/mquery.git
cd mquery
# Optionally copy test files to ./samples directory
docker-compose -f docker-compose.dev.yml up  # this will take a while
```

- Good for development - all file changes will be picked up automatically.
- Poor for production

## Bare metal

You can also compile and run everything manually.

```
sudo apt install libzmq3-dev cmake gcc g++ make python3 git npm redis-server

git clone --recurse-submodules https://github.com/CERT-Polska/mquery.git

cd mquery
pip install -r requirements.txt  # this may take a few minutes

cd src/mqueryfront
npm install
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

And start everything:

```
project_dir/mquery/src$ flask run  # web server
project_dir/mquery/src$ python3 daemon.py  # job daemon
project_dir/ursadb/build$ ./ursadb ~/db.ursa  # backend database
```

Web interface should be available at `http://localhost:5000`.

- Good for production - the most flexible method.
- Good for development, but setting up a proper environment is tricky.
    Just use docker compose.

## Kubernetes

Not strictly supported, but we use it internally so it's battle-tested.
Take a look at the the `./deploy/k8s` directory for hints.

- Good for production - it's webscale!
- Terrible for development.
