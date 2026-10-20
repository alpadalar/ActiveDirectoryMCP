# Testing Guide

ActiveDirectoryMCP has three kinds of checks: unit tests, live integration tests against an OpenLDAP lab, and manual smoke scripts. Install everything first:

```bash
uv sync --all-extras
```

## 1. Unit tests

```bash
uv run pytest
```

- Located in `tests/unit/`.
- ldap3 is mocked; no directory server is needed.
- Tests marked `integration` are deselected by default.

## 2. Integration tests (OpenLDAP lab)

```bash
scripts/run_tests_with_ldap.sh          # runs `pytest -m integration`
scripts/run_tests_with_ldap.sh -k user  # extra arguments go to pytest
```

The script generates a throwaway lab password per run, starts the `openldap` service from `docker-compose-openldap.yml`, writes a temporary config, runs `uv run --locked pytest -m integration`, and always tears everything down. It needs Docker and free ports 389 and 636.

You can also run the tests against a lab you started yourself by setting `AD_MCP_CONFIG` to a config file and running `uv run pytest -m integration`. Without `AD_MCP_CONFIG` the integration tests skip.

### Lab limitations

The lab is OpenLDAP (osixia/openldap, RFC2307bis, inetOrgPerson/groupOfNames). It is NOT Active Directory and NOT Samba AD. In particular it does not provide:

- userAccountControl semantics (enable/disable, lockout flags)
- unicodePwd and the TLS requirement for password changes
- lastLogon / lastLogonTimestamp replication
- AD ACLs and AD-only attributes such as `sAMAccountName`

Green integration results therefore show that the LDAP plumbing works, not that AD-specific behaviour is correct. Some fixtures currently use AD-only attributes and fail against the lab for that reason.

Integration fixtures only create and delete a uuid-named temporary OU. Do not point them at a production directory.

## 3. Manual smoke scripts

Located in `tests/manual/` and never collected by pytest:

```bash
uv run python tests/manual/http_server_smoke.py [URL]   # needs a running HTTP server
uv run python tests/manual/real_ad_smoke.py             # needs AD_MCP_CONFIG
```

See `tests/manual/README.md`.
