# components

There are four main independent components in mquery deployments:

- web frontend
- daemons (also called "agents" or "workers")
- Ursadb (backend database)
- Redis

In a normal situation, there is one web frontend, one shared Redis database, and
for every ursadb instance, there is a group of one or more agents dedicated to
it:

![](./distributed.png)

In most small-to-medium sized deployments there is only one ursadb instance, and
all workers are assigned to it.

More complex configurations are possible, for example, consider this deployment
with internal and external sample index:

![](./distribured-rev.png)

### Web frontend (mquery)

Mquery is a standard web application written in Python (using the
Fastapi framework).

It talks with Redis directly, and schedules tasks for the workers.

For some administrative tasks (like checking ongoing tasks) it also sends requests
to ursadb directly.

### Mquery daemon (agent)

The workhorse of the entire setup. There must be at least one daemon for
every ursadb instance. Daemon's tasks include querying the assigned ursadb
instance for samples and running YARA rules on candidate samples.

### Redis

Is just a shared database used for communication between daemon and mquery.
It is also used as a task queue for jobs scheduled for agents. And it's also
used for persistent storage of job results. Finally, it's used to store
plugin configuration and job cache for agents. In short, it's pretty overloaded
and used to store everything as the main database of the project.

### Ursadb

Ursadb is a [separate project](https://github.com/CERT-Polska/ursadb), used in
mquery as a backend database to optimise YARA rules. Ursadb itself has no
understanding of YARA syntax, so all rules are first transpiled by mquery to
a simpler Ursadb syntax before a query.
