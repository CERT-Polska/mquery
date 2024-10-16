# How the data is stored in redis

In the older mquery versions, data used to be stored in Redis. In mquery
version 1.4.0 the data was migrated to a postgresql - see [database](./database.md).

Please note that all this is 100% internal, and shouldn't be relied on.
Data format in redis can and does change between mquery releases.

You can use `redis-cli` to connect to redis. With the default docker compose configuration,
use `docker compose exec redis redis-cli`.

Redis command documentation is pretty good and available at https://redis.io/commands/.

### Rq objects (`rq:*`)

Objects used internally by https://python-rq.org/, task scheduler used by mquery. 

You can browse them using tools from https://python-rq.org/docs/monitoring/.
