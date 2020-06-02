# E2E tests

Slow test suite, used as a sanity test for mquery matching capabilities.
Hopefully it won't allow us to merge a completely broken version.

They are automatically built and ran on every commit in the CI pipeline,
so you don't have to. But if you want to test locally, run (from main directory of mquery):

```bash
$ rm -r  src/utils/e2e-state
$ docker-compose -f docker-compose.e2etests-local.yml up --build --exit-code-from e2etests-local
```

In test_api.py there are main test functions in the beginning and helper functions
with pytest fixtures below.
