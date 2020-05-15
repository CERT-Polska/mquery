# Indexing

Indexing is one of the two most important things you can do with mquery
(the other one is searching). So it's pretty useful to understand how it works.
There are many ways to do it, unfortunately not all are equally good.

## Method 1: the magic button

Just click the button and it works:

![](index-button.png)

This will scan and index the preconfigured folder with samples, and will work
out of the box with the docker configuration.

This method is the simplest one and should be enough for small to medium collections.
Unfortunately, it's not very flexible or doesn't scale well. The biggest problem
is failure-resistance - in case of database/server crash, the indexing progress
won't be saved and you'll have to restart it from the beginning. This matters when you
index many millions of files.
If you need something more powerful or robust, continue reading.

## Method 2: ursacli

Go to the mquery directory and run:

```
sudo docker-compose exec ursadb ursacli
[2020-05-10 05:23:27.216] [info] Connecting to tcp://localhost:9281
[2020-05-10 05:23:27.219] [info] Connected to UrsaDB v1.3.2+be20951 (connection id: 006B8B45B4)
ursadb>
```

This will start Ursadb client command prompt. Type:

```
ursadb> index "/mnt/samples";
```

To index `"/mnt/samples"` directory. By default, this will only use `gram3` index.
It's a good idea to use all of them for better results:


```
ursadb> index "/mnt/samples" with [gram3, text4, wide8, hash4];
```

This is exactly what the `reindex` button does under the hood.

There are more variations of this command. For example, you can:
 - Index a list of files, or even read that list from a file. 
 - Tag all indexed samples with arbitrary metadata.
 - Disable safety measures that protect you from indexing the same file twice.

For more ideas and reference, see
[ursadb documentation](https://github.com/CERT-Polska/ursadb).

This method suffers from the same problem as the button - it's all a part
of a single transaction, so database/server crash will delete all progress.


## Method 3: utils.index script

More advanced indexing workflows are supported with a separate script. To use
it, open a terminal in `mquery/src` directory. This method is slower
than the previous ones but can be parallelised easily.

There are two stages: `prepare` and `index`.

### 1. Prepare files to be indexed

First, you need to generate a list of new files to index.

For bare metal deployments:
```
python3 -m utils.index --mode prepare --workdir ~/workdir --path ../samples
```

For docker you also need `--path-mount` argument (`./samples` are visible as
`/mnt/samples` in the container):
```
python3 -m utils.index --mode prepare --workdir ~/workdir --path ../samples --path-mount /mnt/samples
```

After that command, the `./samples` directory will be scanned for new samples,
and `~/workdir` directory will contain a list of batches (by default with
1000 files per batch). You can check them manually to ensure they have the files
you expect:

```
$ python3 -m utils.index --mode prepare --workdir ~/workdir --path ~/mquery/samples/ --path-mount /mnt/samples
INFO:root:Prepare.1: load all indexed files into memory.
INFO:root:Prepare.2: find all new files.
INFO:root:Prepare.3: Got 141 files in 1 batches to index.

$ ls ~/workdir/
batch_0000000000.txt

$ head -n 3 ~/workdir/batch_0000000000.txt
/mnt/samples/ad9c8a455c5453ef9dd37e99c4584a09
/mnt/samples/059f0f0231db41b5734a2b71b9bc12cd
/mnt/samples/dfcf969c31851f8c11d801d54cc0cd8d
```

### 2. Index the files

Now index the files:

```
[nix-shell:~/Projects/mquery2/src]$ python3 -m utils.index --mode index --workdir ~/workdir
INFO:root:Index.1: Determine compacting threshold.
INFO:root:Index.1: Compact threshold = 82.
INFO:root:Index.2: Find prepared batches.
INFO:root:Index.2: Got 1 batches to run.
INFO:root:Index.3: Run index commands with 2 workers.
INFO:root:Index.4: Batch /root/workdir/batch_0000000000.txt done [1/1].
INFO:root:Index.5: Unlinking the workdir.
```

That will take some time. Files that are currently being processed are renamed to `.wip`
and removed later. In case there are any errors, the relevant file
will be renamed from `batch_XYZ.txt` to `batch_XYZ.error`, and error messages will
be saved to `batch_XYZ.message`.

You can increase the number of parallel workers with the `--workers` switch,
but don't overdo it - indexing needs a lot of RAM and by default Ursadb has only
4 workers, so increasing this higher won't help anything.

If the indexing crashes or has to be stopped for some reason, you can resume it
using the same command, with the same working directory.

### 3. Advanced options

1. If you want to save some keystrokes, you can combine these two stages:

```
python3 -m utils.index --workdir ~/workdir --path ../samples
```

2. Mquery works best with small files. You can pre-filter indexed files by size
with `--max-file-size-mb` switch (for example, `--max-file-size-mb 5` to index only
files smaller than 5MB).

3. You can change the default batch size with `--batch` switch

4. By default all index types are used. You can control this with `--type` switch,
for example if you want to save some disk space, use
`--type gram3 --type text4 --type wide8` ([Read this](./indextypes.md) for
more details).

5. You can tag indexed samples with metadata tags. Tags can be used for limiting
future searches. Use `--tag tlp:green --tag virusshare`.

