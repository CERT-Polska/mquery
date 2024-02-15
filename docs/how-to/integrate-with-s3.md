# Integrate mquery with S3

One very common question is "how to use Mquery with S3". S3 is a file storage
API is exposed by many open- and closed-source solutions, like Minio or of course
AWS. Mquery does not support S3 natively but can work with S3 thanks to its
very flexible plugin system. Unfortunately, this is not completely transparent,
and S3 deployment is not easy. In this guide, I'll explain how to integrate
Mquery with existing S3 deployment.

## Requirements

* Linux system with at least 4GB RAM and enough disk space for your samples
and index
* Sudo access
* Mquery is installed natively (not from docker compose). We will have to
install additional dependencies, and it's not trivial with existing images.
To make things simpler, we assume you installed mquery natively (see
[Install mquery natively (without docker)](./install-native.md) if you want to
learn how to do this).
* S3-compatible server with your samples. In this guide, we'll deploy MinIO for
demonstration purposes.

## Caveats

The integration has some rough edges and assumes some things. Most importantly:

* Malware collection that you want to index cannot have duplicate filenames. This is obvious if your data is already in S3 (S3 buckets cannot have
duplicate filenames), but it's something to keep in mind if you're moving
existing collections from disk to S3. Ideally, you should store your files
using hashes (like sha256) as names.
* Do not mix S3 and non-S3 storage in a single database. Mquery works best if
either all your files are stored in S3, or none are. If you really need to,
it is possible, but you may need to edit the S3 plugin source code.

This integration works in the following way:

* First, you index your S3 samples in any way you want. You just need to
  make sure that the filenames in S3 and ursadb are the same. For example,
  you can download all your bucket to a temporary directory, index it,
  and remove the directory. This is automated with the `s3index.py` script.
* When mquery needs to access raw sample data (for example, to run YARA)
  it runs the S3 plugin.
* Our plugin looks only at the filename. For example, if the file path returned
  from ursadb is `/opt/mquery/samples/9535be65f6d2f315971e53440e4e1`, the plugin
  looks at `9535be65f6d2f315971e53440e4e1` and completely ignores the path.
* Next, the plugin downloads that filename from a configured S3 bucket - in our
  example, the plugin will get a file called `9535be65f6d2f315971e53440e4e1`.
* This file is used for the requested operation, like scanning with YARA,
  and removed when it's no longer necessary.

During the indexing, samples are temporarily downloaded to the ursadb machine, but
don't worry - after indexing, samples can be safely removed - so the ursadb machine
will only contain the index.

## Integration procedure

### 1. Install additional dependencies

We will need to install `minio` package. This can be done with a simple
`pip install minio`. If you followed [our native install
guide](./install-native.md) you can install it in the virtual environment
like this:

```shell
cd /opt/mquery/src/
source /opt/mquery/venv/bin/activate
pip install minio
```

If your installation slightly differs, adjust this command to your needs.

By the way, `minio` is a Python library for S3 communication - it doesn't mean
that you must use `MinIO` server.

### 2. Deploy a minio server for test purposes

(This is optional - if you already have an S3 server, you can use it)

We will use docker to keep things simple. Remember, that this is just for
demonstration - our server will be neither secure nor persistent. Install docker if you don't have it already:

```shell
apt install docker.io
```

And run the minio server (username: `minio`, password: `minio123`)

```shell
docker run --network host -p 9000:9000 -p 9001:9001 -e "MINIO_ROOT_USER=minio" -e "MINIO_ROOT_PASSWORD=minio123" quay.io/minio/minio server /data --console-address ":9001"
```

You should be able to login to minio at `http://localhost:9001`.

Login using username `minio` and password `minio123`. Click "Create Bucket"
and call it `mquery`.

### 3. Enable S3 plugin

Open the mquery config file (`/opt/mquery/src/config.py` in the example installation):

```shell
vim /opt/mquery/src/config.py
```

Change `PLUGINS` key to:

```python
PLUGINS = ["plugins.s3_plugin:S3Plugin"]
```

And exit vim with `[esc]:x[enter]`.

Restart mquery workers and the web interface.

### 4. Configure the plugin

If you did it correctly, workers should print the following message:

```
[12/01/2023 00:23:40][ERROR] Failed to load S3Plugin plugin
Traceback (most recent call last):
  File "/opt/mquery/src/plugins/__init__.py", line 49, in __init__
    active_plugins.append(plugin_class(db, plugin_config))
  File "/opt/mquery/src/plugins/s3_plugin.py", line 24, in __init__
    super().__init__(db, config)
  File "/opt/mquery/src/metadata.py", line 28, in __init__
    raise KeyError(
KeyError: "Required configuration key 's3_url' is not set"
```

Navigate to the mquery config page at http://localhost/config. You should see
the plugin configuration there. Set all the fields:

* `s3_url` to your S3 url - in our example this will be `your_ip:9000` (for
   example `1.2.3.4:9000`, or just `localhost:9000`).
   Remember, do not add `http://`.
* `s3_bucket` to your S3 bucket name - in our example `mquery`.
* `s3_access_key` and `s3_secret_key` to your S3 credentials for mquery.
  Create key pair in minio if you don't have one already.
* `s3_secure` to `false` (in our example - you probably want HTTPs in production).

At this point, workers should be able to load plugins correctly.

### 5. Index your files

Good news - that's everything you need for querying! Bad news - you still
need to index your files.

To do this, you will need to run a dedicated S3 indexing script. If your ursadb
instance is on a different server than your workers, you must run this script on
the UrsaDB server (to be more precise, you need a shared storage with UrsaDB.
The easiest way to obtain this is to run on the same disk).

Go to the mquery directory and execute the following (fix the parameters
depending on your use case):

```shell
cd /opt/mquery/src/
source /opt/mquery/venv/bin/activate
python3 -m utils.s3index \
    --workdir /root/mquery_tmp \
    --s3-url localhost:9000 \
    --s3-secret-key YOUR-SECRET-KEY \
    --s3-access-key YOUR-ACCESS-KEY \
    --s3-bucket mquery \
    --s3-secure 0
```

`--workdir` is used to specify directory where the samples are temporarily downloaded. This is important, because this will be the path that UrsaDB sees
and stores in the index. To make things simple for yourself, you should
always use the same working directory, for example `/var/s3/mquery`.

This may take a while (or A LOT of time)), depending on how many samples you have.
Unfortunately, this script is not parallelised, and it's not safe to run
multiple instances of this script at once. Future versions of this script
will improve the performance.

## Next steps

Congratulations, that's all! You can index files in s3 and query them
using mquery.
