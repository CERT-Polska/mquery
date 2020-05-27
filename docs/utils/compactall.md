# compactall.py

Will compact datasets in the Ursadb instance as long, as there's anything
left to compact.

## Usage

```
$ python3 -m utils.compactall --help
usage: compactall.py [-h] [--ursadb URSADB] [--mode {smart,all}]

Keep the database lean.

optional arguments:
  -h, --help          show this help message and exit
  --ursadb URSADB     URL of the ursadb instance.
  --mode {smart,all}  Compacting mode. Force (all) or optimise for time
                      (smart).

```

## Example

This script is very easy to use - it only needs an url of the Ursadb instance,
for example `tcp://127.0.0.1:9281` (which is the default).

```
python3 -m utils.compactall --ursadb tcp://127.0.0.1:9281
```

It will start issuing merging compatible datasets with the `compact` command,
and will only stop when:
 - There are no more compatible datasets that can be merged;
 - There are compatible datasets, but they can't be merged because resulting
    dataset would exceed size maximum configured in Ursadb.

Running this script periodically probably can't help (but it may put a lot of
load on the disk, so should be run when the db is not used heavily).

## Caveats

This script can be stopped with Ctrl+C at any point, but the last issued
command will continue running (the database will finish compacting the datasets
that it started).
