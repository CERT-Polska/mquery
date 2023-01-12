# s3index.py

Can be used to index files from s3.

This script was created to accompany the [S3 integration guide](../how-to/integrate-with-s3.md). It will download files from s3 temporarily and index
them with ursadb. After indexing local copies of samples are deleted.

WARNING: this script is still in the development, and usage may change
in the future.

## Usage

```
$ python3 -m utils.s3index --help
usage: s3index.py [-h] [--mode {prepare,index,prepare-and-index}] [--ursadb URSADB] --s3-url S3_URL --s3-secret-key S3_SECRET_KEY --s3-access-key S3_ACCESS_KEY --s3-bucket S3_BUCKET [--s3-secure S3_SECURE]
                  [--workdir WORKDIR] [--batch BATCH] [--type {gram3,text4,hash4,wide8}] [--tag TAGS] [--workers WORKERS] [--working-datasets WORKING_DATASETS]

Index files from s3.

options:
  -h, --help            show this help message and exit
  --mode {prepare,index,prepare-and-index}
                        Mode of operation. Only prepare batches, index them, or both.
  --ursadb URSADB       URL of the ursadb instance.
  --s3-url S3_URL       S3 server url.
  --s3-secret-key S3_SECRET_KEY
                        Secret key.
  --s3-access-key S3_ACCESS_KEY
                        Access key.
  --s3-bucket S3_BUCKET
                        Bucket name.
  --s3-secure S3_SECURE
                        Use https (1 or 0)?.
  --workdir WORKDIR     Path to a working directory.
  --batch BATCH         Size of indexing batch.
  --type {gram3,text4,hash4,wide8}
                        Index types. By default [gram3, text4, wide8, hash4]
  --tag TAGS            Additional tags for indexed datasets.
  --workers WORKERS     Number of parallel indexing jobs.
  --working-datasets WORKING_DATASETS
                        Numer of working datasets (uses sane value by default).
```

## Example

Only --workdir and s3-related parameters are required:

```
$ python3 -m utils.s3index \
    --workdir /root/mquery_tmp \
    --s3-url localhost:9000 \
    --s3-secret-key YOUR-SECRET-KEY \
    --s3-access-key YOUR-ACCESS-KEY \
    --s3-bucket mquery \
    --s3-secure 0
```
