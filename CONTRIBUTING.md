# Contributing

Thank you for your interest in improving ActiveDirectoryMCP. By participating you agree to
follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting security issues

Do not open a public issue for a vulnerability. Follow [SECURITY.md](SECURITY.md) and use
the private reporting channel described there.

## Development setup

Python 3.11 or newer and [uv](https://docs.astral.sh/uv/) are required.

```bash
uv sync --locked --all-extras
.venv/bin/pytest -q
.venv/bin/ruff check src tests
.venv/bin/mypy src
```

`pyproject.toml` configures pytest, ruff (line length 100) and mypy. Dependencies are pinned
in the committed `uv.lock`; if you change dependencies in `pyproject.toml`, run `uv lock`
and commit the result.

## Test layout

- `tests/unit`: fast tests with a mocked directory (ldap3 mock). This is the suite that
  gates every pull request.
- `tests/e2e`: a live local HTTP server driven by a real MCP client against the mocked
  directory.
- `tests/integration`: needs a live LDAP server (the OpenLDAP lab in
  `docker-compose-openldap.yml`). Marked `integration` and deselected by default; run with
  `pytest -m integration` or `scripts/run_tests_with_ldap.sh`.
- `tests/manual`: scripts for hand checks against a real directory. Never run in CI.

Continuous integration must never talk to a live Active Directory. Do not add tests that
need one to the default suite.

## Rules for a pull request

- **Tool names and parameters are a frozen contract.** The stdio and HTTP tool surfaces are
  snapshotted in `tests/golden` and compared by `tests/unit/test_tool_surface.py`.
  Existing tools must not be renamed and their parameters must not change. A new tool is an
  additive change.
- **Adding a tool** requires all of the following:
  1. implement it in the matching module under `src/active_directory_mcp/tools/`;
  2. add its description to `tools/definitions.py` and register it in `registry.py`;
  3. classify it in `RISK_CLASSIFICATION` in `src/active_directory_mcp/policy.py`
     (read, write or destructive; unknown tools fail closed as destructive);
  4. regenerate the goldens with
     `UPDATE_GOLDEN=1 .venv/bin/pytest tests/unit/test_tool_surface.py -q` (this rewrites the
     single-domain and the multi-domain snapshots), check that the diff only adds entries, add the tool to `ADDITIVE_TOOLS` in
     `tests/unit/test_golden_additive.py`, and record it in `CHANGELOG.md`;
  5. add unit tests, including the policy gate behavior.
- All LDAP filters, DNs and attribute names that come from tool arguments must pass through
  `src/active_directory_mcp/validation.py` (see `docs/input-validation.md`). Never build a
  filter or DN with string concatenation of raw input.
- Never commit secrets: no passwords, API keys, tokens, real DNs or host names. Use
  placeholders such as `example.com`. Logs and error responses must go through the existing
  redaction.
- Update the documentation and `CHANGELOG.md` for user-visible changes. Breaking changes
  are listed first in the release entry.
- Run the two repository scans before opening the pull request:

  ```bash
  .venv/bin/python scripts/secret_scan.py
  .venv/bin/python scripts/ai_residue_scan.py
  ```

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/), for example
`fix(users): escape trailing space in RDN values` or `feat(tools): add get_rootdse_info`.
Keep commits atomic. Do not add AI or tooling attribution lines to commit messages, code or
documentation.
