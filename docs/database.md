# How the data is stored in the database

Currently, Postgres database is used to keep entities used by mquery.

With the default docker configuration, you can connect to the database
using the following oneliner:

```
sudo docker compose exec postgres psql -U postgres --dbname mquery
```

The followiung tables are defined:

### Job table (`job`)

Jobs are stored in the `job` table.

Every job has ID, which is a random 12 character string like 2OV8UP4DUOWK (the
same string that is visible in urls like http://mquery.net/query/2OV8UP4DUOWK).

Possible job statuses are:

* "new" - Completely new job.
* "inprogress" - Job that is in progress.
* "done" - Job that was finished
* "cancelled" - Job was cancelled by the user or failed
* "removed" - Job is hidden in the UI (TODO: remove this status in the future)

### Job agent table (`jobagent`)

It is a simple mapping between job_id and agent_id. Additionaly, it keeps track
of how many tasks are still in progress for a given agent assigned to this job.

### Match table (`match`)

Matches represent files matched to a job.

Every match represents a single yara rule match (along with optional attributes
from plugins).

### AgentGroup table (`agentgroup`)

When scheduling jobs, mquery needs to know how many agent groups are
waiting for tasks. In most cases there is only one, but in distributed environment
there may be more.

### Configuration table (`configentry`)

Represented by models.configentry.ConfigEntry class.

For example, `plugin:TestPlugin` will store configuration for `TestPlugin` as a
dictionary. All plugins can expose their own arbitrary config options.

As a special case `plugin:Mquery` keeps configuration of the mquery itself.
