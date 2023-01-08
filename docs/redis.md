# How the data is stored in redis

Please note that all this is 100% internal, and shouldn't be relied on.
Data format in redis can and does change between mquery releases.

### Why redis?

Because very early daemon was a trivial piece of code, and redis as a job
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

Redis is a key-value store. To see all available keys use:

```
KEYS *
```

Redis supports several datatypes along with operations on them. Ones relevant to us:

#### Strings:

...

#### Hashes:

...

#### Lists:

...

### Job objects

Job object is a SET represented by schema.JobSchema model.

Every job has ID, which is a random 12 character string like 2OV8UP4DUOWK (the
same string that is visible in urls like http://mquery.net/query/2OV8UP4DUOWK).

Possible job statuses are:

* "new" - ???
* "inprogress" - ???
* "cancelled" - the job was cancelled by the user or failed
* "removed" - the job is hidden in the UI (?)

### Meta objects

### Agentjob objects

### Rq objects

### Agents key

### Metadata cache objects
