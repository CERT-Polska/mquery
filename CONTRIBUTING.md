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

4. If possible, add a test or two to the `src/tests/` directory. You can run
  them with:

```bash
$ docker build -t mquery_tests -f ./src/tests/Dockerfile .
$ docker run mquery_tests
```

5. We run many code formatters and linters on the code to ensure expected
code quality. Your code will be checked automatically when you submit your
pull request, but you can also run the checks locally to speed-up review:

- **Important:** we use [black](https://pypi.org/project/black/) for Python:

```bash
$ pip3 install black==22.3.0
$ black src/
```

- Important: we use [prettier](httpss://prettier.io/) for Javascript/React:

```bash
$ npm install -g prettier@2.0.4
$ prettier --write src/mqueryfront/
```

- Verify that there are no type errors with [mypy](http://mypy-lang.org/):

```bash
$ pip install mypy==0.790
$ mypy src
```

- Find other style issues with [flake8](https://flake8.pycqa.org):

```bash
$ pip install flake8==3.7.9
$ flake8 src
```

(Lifehack: you can also plug them into your editor as on-save action).

You don't have to do this for every PR, but docstrings in this projects
were also formatted using:

```bash
pydocstringformatter --summary-quotes-same-line --max-summary-lines 10 --max-line-length=79 --no-split-summary-body -w src/
```

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
