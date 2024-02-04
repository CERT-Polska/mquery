# How the data is stored in redis

Please note that all this is 100% internal, and shouldn't be relied on.
Data format in redis can and does change between mquery releases.

Right now mquery is in the process of migrating internal storage to Postgres.

### Why redis?

Because very early daemon was a trivial piece of code, and Redis as a job
queue was the easiest solution. Since then mquery got extended with (in
no particular order) batching, users, jobs, commands, task cancellations,
distributed agents, configuration, and more.

I have thus learned the hard way that Redis is not a good database.

Nevertheless, that ship has sailed. There are no plans of migrating mquery
to another database. What we can do is to document the current data format.

### Redis quickstart

To connect to redis use `redis-cli`. For docker-compose use
`docker-compose -f docker-compose.dev.yml exec redis redis-cli`.

Redis command documentation is pretty good and available at https://redis.io/commands/.

### Job table (`job`)

Jobs are stored in a Job table.

Every job has ID, which is a random 12 character string like 2OV8UP4DUOWK (the
same string that is visible in urls like http://mquery.net/query/2OV8UP4DUOWK).

Possible job statuses are:

* "new" - Completely new job.
* "inprogress" - Job that is in progress.
* "done" - Job that was finished
* "cancelled" - Job was cancelled by the user or failed
* "removed" - Job is hidden in the UI (TODO: remove this status in the future)

### Meta objects (`meta:*`)

Meta object is a List represented by db.MatchInfo class.

It's a list of JSONs that reprent matches for a given job. Every list element
represents a single yara match (along with optional attributes from plugins).

Each job has exactly one related meta object. For example, job with key
`job:123456123456` will have corresponding meta object at `meta:123456123456`.

### Agentjob objects (`agentjob:*`)

Agentjob is a simple String (but only used as an integer).

In distributed environment it's sometimes hard to say when exactly agent's job
is finished. To work around this, each agent keeps a number of pending tasks
using agentjob key. For example, for job `123456123456` and agent `default`, redis key
`agentjob:default:123456123456` will contain the number of pending tasks.

This only matters during the task execution and can be discarded after task is done.

### Agents key (`agents`)

Agents is a unique List of active agent groups. It's stored in the key `agents`.  

Agent spec is represented by schema.AgentSpecSchema class.

When scheduling jobs, mquery needs to know how many agent groups are currently
waiting for tasks. In most cases there is only one, but in distributed environment
it may not be true.

### Cache objects (`cache:*`)

Cache objects are arbitrary strings.

Right now they are only optionally used by metadata plugins, to
cache expensive computation in redis.

### Configuration table (`configentry`)

Represented by models.configentry.ConfigEntry class.

For example, `plugin:TestPlugin` will store configuration for `TestPlugin` as a
dictionary. All plugins can expose their own arbitrary config options.

As a special case `plugin:Mquery` keeps configuration of the mquery itself.

### Rq objects (`rq:*`)

Objects used internally by https://python-rq.org/, task scheduler used by mquery. 

You can browse them using tools from https://python-rq.org/docs/monitoring/.
