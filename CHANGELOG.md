# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

The MCP tool names and parameters are unchanged in this release line. They are frozen
and enforced by the golden snapshots in `tests/golden/`.

### Changed (breaking)

- Minimum Python version is now 3.11 (3.11, 3.12 and 3.13 are tested).
- `fastmcp` is now `>=3.2,<4` (was `>=0.2,<0.4`); `mcp` is `>=1.28,<2`. The fastmcp
  import-fallback shim was removed.
- Azure Key Vault packages (`azure-identity`, `azure-keyvault-secrets`) moved to the
  optional `azure` extra. Install them with `uv sync --extra azure`; the Docker image
  includes them.
- `requirements.in` and `requirements-dev.in` were removed in favor of `pyproject.toml`
  and the committed `uv.lock`. Install with `uv sync --locked`.
- The `cryptography` upper bound (`<42`) was lifted.
- Unused dependencies were removed: `python-dateutil`, `asgiref` and the `django` extra;
  `requests` moved to the dev dependencies.
- The Docker image is built from `uv.lock` on a digest-pinned Python 3.13 base and no
  longer installs build toolchains.
- `docker-compose-ad.yml` was renamed `docker-compose-openldap.yml` (the lab is OpenLDAP,
  not Samba AD) and now requires `LAB_LDAP_PASSWORD`; no password literal is shipped.
- Root-level ad-hoc test scripts were removed or moved to `tests/manual/`.
- The `organizational_units` configuration section is now optional. Missing entries
  default to the built-in containers under `base_dn` (`CN=Computers,<base_dn>` for
  computers, `CN=Users,<base_dn>` for users, groups and service accounts).

### Fixed

- Expired accounts are now detected when ldap3 returns a datetime for `accountExpires`
  (previously always reported as not expired).
- Days since last logon and password age are computed correctly for the values real AD
  returns (timezone-aware datetimes, FILETIME integers, numeric strings) instead of
  silently becoming empty or -1.
- Computers that never logged on are no longer reported as having logged on just now.
- `audit_admin_accounts` no longer skips whole privileged groups when `lastLogon` is a
  datetime; its risk counts are correct and results are ordered by severity (high,
  medium, low). Security recommendations now match the assessed risk level instead of
  always falling back to the generic message.
- `get_inactive_users`, `get_password_policy_violations` and `get_stale_computers` no
  longer fail on datetime values; `get_stale_computers` no longer errors with a
  `NameError` whenever a stale computer exists.
- `delete_ou` refuses to proceed when counting child objects fails (an LDAP error was
  previously treated as an empty OU). With `force=True`, a failure deleting or listing a
  child is reported and the OU itself is not deleted.
- Password-policy intervals (`lockout_duration`, `max_password_age`, `min_password_age`)
  report "Never" for never-expiring values instead of roughly 999999999 days, and handle
  numeric strings.
- `get_user` no longer fails with a `NameError` for every existing user.
- `list_users` no longer reports `enabled: true` when `userAccountControl` is unreadable
  (it is reported as unknown).
- LDAP filter escaping no longer double-escapes special characters (backslash is escaped
  first), so filters match the intended value.
- A password with `pwdLastSet` of 0 (ldap3 year-1601 datetime) is now treated as
  "must change at next logon".
- `check_password_policy` returns real JSON with the correct policy keys, and
  `generate_security_report` works again (it always returned an error).
- `create_computer` and `create_group` no longer raise `AttributeError` when `ou` is
  omitted.

### Output changes

- `get_domain_info` `password_policy.*.raw` (`lockout_duration`, `max_password_age`,
  `min_password_age`) is now a non-negative integer count of 100-nanosecond ticks for
  every input type (previously float seconds for real AD values, signed ticks for
  integers). `seconds` still carries seconds.
- Never-expiring policies report `{"raw": 0 or 9223372036854775807, "description":
  "Never"}` with no `seconds` key.
- `get_inactive_users.cutoff_date` is now an ISO string with a `+00:00` (UTC) offset
  instead of naive local time; `last_logon` and `pwd_last_set` are timezone-aware UTC
  values. Timestamps derived from AD time attributes are UTC throughout.
- `check_password_policy` returns `policy_compliant`, `recommendations` and
  `password_policy`; the always-empty `lockout_policy` key was dropped.

### Added

- Unit test suite under `tests/unit` (mocked LDAP, no directory server needed).
- Integration suite under `tests/integration`, deselected by default
  (`pytest -m integration`; `scripts/run_tests_with_ldap.sh` starts the OpenLDAP lab).
- Golden tool-surface snapshots for the stdio and HTTP transports under `tests/golden`,
  plus `scripts/check_python_matrix.sh` to verify they are identical on Python 3.11-3.13.
- Shared AD time helpers on `BaseTool` replacing the divergent per-module converters.
