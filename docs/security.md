# security

## Secure Deployment

There are multiple components necessary to have a working mquery instance.
Some of them require special care from a security standpoint.

### Mquery

Mquery is a standard web application written in Python. By default, everyone has permission to do everything.
This default configuration is unsuitable for bigger organisations or public instances.
In such cases, it's recommended to enable user accounts (see [users.md](./users.md)),
and disallow anonymous users or at least don't give them admin rights.

### Mquery daemon (agent)

No special considerations. Every daemon process must have network
access to Redis and UrsaDB.

### Redis

Mquery web and daemon must have network access to Redis. No other access to
the Redis database is necessary. There is no support for securing Redis
with a password in the current version, so network isolation is
the only way to prevent attacks. Most importantly, Redis must not
be available from the public network.

### Ursadb

Mquery daemons must have network access to their respective ursadb instances.
Similarly to Redis, it's best to restrict network access to the UrsaDB instance. Ursadb protocol does not take malicious actors into account, and
unauthenticated users can, for example, remove indexed data from the database,
or cause a denial of service.

In the provided docker compose files, the UrsaDB user is overridden to root by
default. This is for
backwards compatibility, and to simplify deployment. For production instances
consider running ursadb with the default user (`ursa`, UID 1000). This means
that the shared index volume must be writable by UID 1000, and samples must
be readable by UID 1000.

## How to report a vulnerability

There is no dedicated email for reporting a security vulnerability. Please reach out
to cert@cert.pl or one of the maintainers directly. If the vulnerability is not
critical, the best way to report is via a GitHub issue.
