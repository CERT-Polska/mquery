# E2E tests

Slow test suite, used as a sanity test for mquery matching capabilities.
Hopefully it won't allow us to merge a completely broken version.

They are automatically built and run on every commit in the CI pipeline,
so you don't have to. But if you want to test locally, run:

```bash
$ docker build -t mquery_e2etests -f ./src/e2etests/Dockerfile .
$ docker run mquery_e2etests --net mquery_default -v $(readlink -f ./samples):/mnt/samples
```
