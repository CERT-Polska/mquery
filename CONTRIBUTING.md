# Contribute to mquery

## How to start?

Great, so you want to join the development!

First, [set up a development environment](INSTALL.md#docker-compose-dev).
Since you're going to write new code, use the `docker-compose.dev.yml` method.

If everything went right, the system should be accessible at `http://localhost:80`.

## Development workflow

We use a standard [github fork workflow](
https://gist.github.com/Chaser324/ce0505fbed06b947d962).

1. Fork the repository.

2. Create a new branch. The name does not matter, but the recommended format
  is `feature/xxx` or `fix/yyy`.

3. Work on your changes!

4. If possible, add a test or two to the `src/tests/` directory. 
   We test every change on our Gitlab instance, but you can run them locally too:

```bash
$ docker build -t mquery_tests -f ./src/tests/Dockerfile .
$ docker run --net mquery_default -v $(readlink -f ./samples):/mnt/samples mquery_tests
```

5. Run code formatters and linters on your code to speed-up review (we run
them automatically on every commit, but currently only on our internal
GitLab instance):

- **Important:** we use [black](https://pypi.org/project/black/) for Python:

```bash
$ pip3 install black==19.10b0
$ black src/
```

- Important: we use [prettier](httpss://prettier.io/) for Javascript/React:

```bash
$ npm install -g prettier@2.0.2
$ prettier --tab-width=4 --write "src/mqueryfront/src/**/*.js"
```

- Verify that there are no type errors with [mypy](http://mypy-lang.org/):

```bash
$ pip install mypy==0.770
$ mypy src
```

- Find other style issues with [flake8](https://flake8.pycqa.org):

```bash
$ pip install flake8==3.7.9
$ flake8 src
```

(Lifehack: you can also plug them into your editor as on-save action).

6. When you feel like you're done, commit the files:

```bash
$ git add -A
$ git status  # check if included files match your expectations
$ git diff --cached  # check the diff for forgotten debug prints etc
$ git commit  # commit the changes (don't forget to add a commit message)
```

7. Push changes to your fork:

```
$ git push origin [your_branch_name]
```

8. Create a pull request with your changes from the GitHub interface and
   wait for review.

That's it! Thank you very much, we appreciate you help.
