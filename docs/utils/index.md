# index.py

Can be used to index large amounts of data in a reliable way.

## Usage

```
$ python3 -m utils.index --help
usage: index.py [-h] [--mode {prepare,index,prepare-and-index}]
                [--ursadb URSADB] [--workdir WORKDIR] [--batch BATCH]
                [--path PATH] [--path-mount PATH_MOUNT]
                [--max-file-size-mb MAX_FILE_SIZE_MB]
                [--type {gram3,text4,hash4,wide8}] [--tag TAGS]
                [--workers WORKERS] [--working-datasets WORKING_DATASETS]

Reindex local files.

optional arguments:
  -h, --help            show this help message and exit
  --mode {prepare,index,prepare-and-index}
                        Mode of operation. Only prepare batches, index them,
                        or both.
  --ursadb URSADB       URL of the ursadb instance.
  --workdir WORKDIR     Path to a working directory.
  --batch BATCH         Size of indexing batch.
  --path PATH           Path of samples to be indexed.
  --path-mount PATH_MOUNT
                        Path to the samples to be indexed, as seen by ursadb
                        (if different).
  --max-file-size-mb MAX_FILE_SIZE_MB
                        Maximum file size, in MB, to index. 128 By default.
  --type {gram3,text4,hash4,wide8}
                        Index types. By default [gram3, text4, wide8, hash4]
  --tag TAGS            Additional tags for indexed datasets.
  --workers WORKERS     Number of parallel indexing jobs.
  --working-datasets WORKING_DATASETS
                        Numer of working datasets (uses sane value by
                        default).
```

## Example


Probably the most complex script shipped with mquery. See
[indexing](../indexing.md) guide for complete a tutorial. Basic usage is
relatively simple though. To index files with ursadb running natively, run:

```
$ python3 -m utils.index --workdir /tmp/work --path ../samples --path-mount /mnt/samples
ERROR:root:Can't connect to ursadb instance at tcp://localhost:9281
INFO:root:Prepare.1: load all indexed files into memory.
INFO:root:Prepare.2: find all new files.
INFO:root:Prepare.3: Got 1 files in 1 batches to index.
INFO:root:Index.1: Determine compacting threshold.
INFO:root:Index.1: Compact threshold = 84.
INFO:root:Index.2: Find prepared batches.
INFO:root:Index.2: Got 1 batches to run.
INFO:root:Index.3: Run index commands with 2 workers.
INFO:root:Index.4: Batch /tmp/work/batch_0000000000.txt done [1/1].
INFO:root:Index.5: Unlinking the workdir.
INFO:root:Indexing finished. Consider compacting the database now
```

## Caveats

This script can be stopped with Ctrl+C at any point, but the last started
started indexing batch will continue.

Don't set `--workers` parameter to a number too big! It can cause OOM crashes.
