# Utilities

Mquery ships with a few scripts to automate common tasks:

 - [mquery.py](./mquery.md) - Automate yara hunts and download of the results.
 - [index.py](./index.md) - Can be used to index large amounts of data in a
    reliable way.
 - [compactall.py](./compactall.md) - Will compact datasets in the Ursadb instance
    as long, as there's anything left to compact.
 - [nanobench.py](./nanobench.md) - A small helper script, used by the developers
    to benchmark Ursadb performance on a given machine and with a given configuration.
 - [s3index.py](./s3index.md) - Helper script for indexing samples from S3.
    It serves as a demonstration, not a best practice. In the current version
    it suffers from a performance problems, so may not be suitable for big
    deployments.
