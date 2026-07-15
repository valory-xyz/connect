# Contribution Guide

### Creating a pull request
- **Target branch:** double-check the PR is opened against the correct branch before submitting.
- **Naming convention:** the branch name should be in kebab case with no more than two or three words, e.g. `some-feature` or `feat/some-feature`.
- **Tag the relevant ticket/issue:** describe the purpose of the PR and link the ticket/issue. A label such as enhancement/bug/test also helps.
- **Include a sensible description:** it helps reviewers understand the purpose and context of the change.
- **Comment non-obvious code** to avoid confusion during review and keep the codebase maintainable.
- **Tests:** the PR must add or update tests for the code it changes. The suite enforces 100% coverage.
- **Linters and checks:** make sure every linter and check passes before you push. See below.

Also mention any potential effects your change may have on other branches or code.

### Checks to run before opening a PR

The toolchain lives in the `uv`-managed venv and the `tomte` lint suite runs via `tox`.

```bash
uv sync
uv run pytest -m "not integration"          # or: tox -e unit-tests-coverage (enforces 100%)
tox -p -e flake8 -e pylint -e black-check -e isort-check -e bandit -e safety -e mypy -e check-copyright
```

**Only if you changed a package under `packages/`:** re-lock the Olas package hashes so CI's check passes.

```bash
autonomy packages lock
```

**Integration tests** run against a Tenderly Gnosis fork and are skipped without an RPC:

```bash
GNOSIS_TESTNET_RPC=<tenderly-fork-url> tox -e integration-tests
```

### Documentation (docstrings and inline comments)

Write informative docstrings. A one-line docstring is fine for a simple method; a method with complex logic should document its behaviour, arguments, return value, and any exceptions it may raise. Prefer comments that explain *why* over comments that restate *what* the next line does.

### Some more suggestions to help you write better code

- Use guard clauses where possible. They lead to flatter, more readable code with less nesting.
