# How the data is stored in redis

Please note that all this is 100% internal, and shouldn't be relied on.
Data format in redis can and does change between mquery releases.

### Why redis?

Because very early daemon was a trivial piece of code, and redis as a job
queue looked like the easiest solution. Since then mquery got extended with (in
no particular order) batching, users, jobs, commands, task cancellations,
distributed agents, configuration, and more.

I have thus learned the hard way that Redis is not a good database.

Nevertheless, that ship has sailed. There are no plans of migrating mquery
to another database. What we can do is to document the current data format.

