# mquery documentation

## User guide

- [Installation](../INSTALL.md): Installation instruction.
- [Indexing](./indexing.md): Indexing files is one of the most important things in
    mquery. In simple cases it can be solved without leaving the web UI, but
    many things will require more advanced approach. Read this if you need to
    index a considerable number of files.
- [Yara support and limitations](./yara.md): Explains how mquery
    accelerates queries, what will, and what won't work.
- [Utility scripts](./utils): Mquery ships with a few useful scripts.
    Here you can find documentation for them.
- [For future contributors](../CONTRIBUTING.md): How to contribute.

## Relevant [ursadb's documentation](https://cert-polska.github.io/ursadb/docs)

Ursadb is the backend doing the heavy lifting for mquery. If you need to work with large
datasets, it's a very useful read. It is also a prerequisite for understanding
many things in mquery.

- [Index types](https://cert-polska.github.io/ursadb/docs/indextypes.md): Picking
    index types you need is an important decision that's hard to change later.
- [Datasets](https://cert-polska.github.io/ursadb/docs/datasets.md): Introduction to
    datasets.
- [Performance and limits](https://cert-polska.github.io/ursadb/docs/ursadb.md):
    Read in case you're not sure if Ursadb can handle your collection.
- [On-disk format](https://cert-polska.github.io/ursadb/docs/ondiskformat.md):
    Ursadb index format is relatively simple - reading this may be useful for
    advanced users.

## Advanced topics 

- [Distributed mquery](./distributed.md): For users that want to run mquery on
    more than one machine.
- [On-disk format](./ondiskformat.md): Read if you want to understand ursadb's on
    disk format (spoiler: many files are just JSON and can be inspected with vim).
- [Plugin system](./plugins.md): For filtering, processing and tagging files.
- [API](./api.md): Mquery exposes a simple API that you may use for your automation.
