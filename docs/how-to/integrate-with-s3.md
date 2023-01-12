# Integrate mquery with s3

One very common question is "how to use Mquery with s3". S3 is a file storage
API exposed by many open- and closed-source solutions, like Minio or of course
AWS. Mquery does not support S3 natively, but can work with S3 thanks to its
very flexible plugin system. Unfortunately, this is not completely transparent,
and S3 deployment is not easy. In this guide I'll explain how to integrat
Mquery with existing s3 deployment.

## Requirements

* Linux system with at least 4GB RAM and enough disk space for your samples
and index
* Sudo access
* Mquery is installed natively (not from docker-compose). We will have to
install additional dependencies, and it's not trivial with existing images.
To make things simpler, we assume you installed mquery natively (see
[Install mquery natively (without docker)](./install-native.md) if you want to
learn how to do this).
* S3-compatible server with your samples. In this guide we'll deploy minio for
demonstration purposes.

## Integration procedure

### 1. Install additional dependencies

We will need to install `minio` package. This can be done with a simple
`pip install minio`. If you followed [our native install
guide](./install-native.md) you can install it in the virtual environment
like this:

```
cd /opt/mquery/src/
source /opt/mquery/venv/bin/activate
pip install minio
```

If your installation slightly differs, adjust this command to your needs.

### 2. Enable S3 plugin

Open mquery config file (`/opt/mquery/src/config.py` in the example installation):

```
vim /opt/mquery/src/config.py
```

Change `PLUGINS` key to:

```
PLUGINS = ["plugins.s3_plugin:S3Plugin"]
```

And exit vim with `[esc]:x[enter]`.

Restart mquery workers and the web interface.

