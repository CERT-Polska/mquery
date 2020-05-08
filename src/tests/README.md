# Unit tests

Small tests that should execute quickly. It may be useful to run them before
every commit.

To build and run, execute the following:

```bash
$ docker build -t mquery_tests -f ./src/tests/Dockerfile .
$ docker run mquery_tests
```
