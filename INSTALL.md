# How to install mquery

Supported installation and deployment methods:

- [docker-compose.yml](#docker-compose)
- [docker-compose.dev.yml](#docker-compose-dev)
- [bare metal](#bare-metal)
- [kubernetes](#kubernetes)

## Docker compose

Quick build & run with [docker compose](https://docs.docker.com/compose/).

```
git clone https://github.com/CERT-Polska/mquery.git
cd mquery
mkdir samples
# now set SAMPLES_DIR to a directory with your files, and INDEX_DIR to
# empty directory for database files to live in. By default database will
# expect files in ./samples directory, and keep index in ./index.
vim .env
docker-compose up --scale daemon=3  # this will take a while
docker-compose exec web python3 -m mquery.db
```

- Good for testing mquery and production deployments on a single server
- Poor for development

## Docker compose (dev)

Docker compose dedicated for developers.

```
git clone https://github.com/CERT-Polska/mquery.git
cd mquery
# now set SAMPLES_DIR to a directory with your files, and INDEX_DIR to
# empty directory for database files to live in. By default database will
# expect files in ./samples directory, and keep index in ./index.
vim .env
docker-compose -f docker-compose.dev.yml up  # this will take a while
docker-compose exec dev-web python3 -m mquery.db
```

- Good for development - all file changes will be picked up automatically.
- Poor for production

## Bare metal

- Read [How to: Install mquery natively (without docker)](how-to/install-native.md)

## Kubernetes

Not strictly supported, but production ready - it's used internally in a
few places, including CERT.PL.
