# Indexing

Indexing is one of the two most important things you can do with mquery
(the other one is searching). So it's pretty useful to understand how it works.
There are many ways to do it, unfortunately not all are equally good.

## Method 1: ursacli

Run the `ursacli` executable. For docker-compose deployment, go to the mquery
directory and run `sudo docker-compose exec ursadb ursacli`:

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
It's usually a good idea to use more index types for better results:


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

This method does all operations as a part of a single transaction.
This means that partial results won't be visible before the indexing ends, and
a server reboot or database termination will delete all progress made so far
(there's no way to pause and resume work). For this reasons, when indexing
a lot of files, it's useful to use auxillary script described below.

## Method 2: utils.index script

More advanced indexing workflows are supported with a separate script. To use
it, open a terminal in `mquery/src` directory. This method is a bit slower
than the previous ones but can be parallelised easily.

The script splits work into two stages: `prepare` and `index`.

### 1. Prepare files to be indexed

First, you need to generate a list of new files to index.

For bare metal deployments:
```
python3 -m utils.index --mode prepare --workdir ~/workdir --path ../samples
```

For docker you may use `--path-mount` argument (`./samples` are visible as
`/mnt/samples` in the container) to map file paths from host to container:
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
but don't overdo it - indexing needs
[a lot of RAM](https://cert-polska.github.io/ursadb/docs/limits.html), and by
default Ursadb has only 4 workers, so increasing this too much won't speed
things up.

If the indexing crashes or has to be stopped for some reason, you can resume it
using the same command, with the same working directory.

### 3. Advanced options

1. If you want to save some keystrokes, you can combine these two stages by
just running:

```
python3 -m utils.index --workdir ~/workdir --path ../samples
```

2. Mquery works best with small files. You can pre-filter indexed files by size
with `--max-file-size-mb` switch (for example, `--max-file-size-mb 5` to index only
files smaller than 5MB). You can later follow that up with `--min-file-size-mb 5`
to index all the other files.

3. You can change the default batch size with `--batch` switch

4. By default all index types are used. You can control this with `--type` switch,
for example if you want to save some disk space and disable hash4 index type, use
`--type gram3 --type text4 --type wide8`
([Read this](https://github.com/CERT-Polska/ursadb/blob/master/docs/indextypes.md) for
more details).

5. You can tag indexed samples with metadata tags. Tags can be used for limiting
future searches. Use `--tag tlp:green --tag virusshare`.

