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

- `security.require_secure_connection` defaults to `true` again and is now enforced by
  `validate_config`: a plaintext `ldap://` server (or `use_ssl: false`) is rejected at
  startup unless you set `"require_secure_connection": false` explicitly (as the lab
  configs do). Phase 2 owns the remaining plaintext-LDAP gate.

- Configuration is strict: unknown keys in any section (for example
  `security.check_names` or a typo such as `passwrd`) now fail at load time instead of
  being ignored. Remove stale keys from existing configuration files.
- `${VAR}` placeholders are expanded anywhere inside a string and variable names are
  limited to `[A-Za-z_][A-Za-z0-9_]*`; an unset variable without a default fails with a
  message that names only the variable.
- `security.require_secure_connection: true` now also rejects `security.enable_tls: false`.
- User, group, computer and OU tools reject DNs (`ou`, `parent_ou`, `ou_dn`,
  `new_parent_dn`, `member_dn`) that are outside the configured `base_dn`, and
  `get_members` skips nested members outside it. Multi-root deployments are not
  supported.
- `filter_criteria` is validated (balanced parenthesized terms, at most 1024 characters,
  must parse as an LDAP filter). Previously any string was interpolated into the search
  filter. See `docs/input-validation.md`.
- `*_object_class` configuration values are validated and rejected if they contain filter
  metacharacters.
- The bind password is a `SecretStr`; its repr and JSON dump are masked, and registered
  secrets are redacted from all log handlers, connection errors and tool error responses.

- `filter_criteria` now rejects terms on sensitive attributes (password hashes,
  `unicodePwd`, LAPS, gMSA, key credentials, security descriptors, BitLocker recovery
  data) and extensible-match terms such as `memberOf:1.2.840.113556.1.4.1941:=`, which
  closes a blind-oracle probe of secrets. See `docs/input-validation.md`.
- `delete_ou`, `modify_ou` and `move_ou` (source) now reject `base_dn` itself, and
  `move_ou` rejects a target parent that is the OU or beneath it. Read operations may
  still target `base_dn`.
- RDN values with a trailing space are now written with the `\20` escape instead of
  failing with "Malformed DN".
- Passwords passed to `create_user` and `reset_password` (including generated ones) are
  registered for redaction, so they are scrubbed from logs and error responses. The
  `reset_password` success response still returns the new password by design.

### Deprecated

- `performance.connection_pool_size` is accepted but ignored (one serialized LDAP
  connection is used); a warning is logged at startup. It will be removed in a later
  release.

### Fixed

- DN confinement could be bypassed with a multi-valued RDN such as
  `CN=a+DC=corp,DC=example,DC=com`; DNs are now compared RDN by RDN.
- Attribute and objectClass names with a trailing newline were accepted.
- Log redaction is installed at record creation, so records from other loggers
  (fastmcp, uvicorn, ldap3), handlers added later and pre-setup records are redacted. It
  also covers JSON/repr-escaped and `unicodePwd` encodings of a secret, and fails closed
  (the record is replaced by a placeholder) instead of passing the raw record through.

- `LDAPManager.search` no longer raises "Search failed" when a search returns zero entries
  (or an empty last page) with result code 0; it returns an empty list. This fixes lookups
  of missing users and the create-user existing-user probe.
- A BASE-scope search on a missing entry returns an empty list instead of raising
  noSuchObject, so `create_ou` no longer fails its existence check.
- Group and user-group tools no longer request the non-existent attributes `dn` and
  `groupScope`, which failed against schema-checked servers.
- Expired accounts are now detected when ldap3 returns a datetime for `accountExpires`
  (previously always reported as not expired).
- Days since last logon and password age are computed correctly for the values real AD
  returns (timezone-aware datetimes, FILETIME integers, numeric strings) instead of
  silently becoming empty or -1.
- Config `${VAR}` / `${VAR:default}` placeholders are now expanded anywhere inside a
  string value (for example `ldaps://${AD_HOST}:636`), not only when the whole value is
  a placeholder, and a default may contain `:`. An unset variable without a default
  still fails at startup.
- Computer searches (`list_computers`, `get_computer`, status/groups/modify/delete lookups
  and OU object listings) now honour `computer_object_class`; it was defined but ignored.
- `create_user` now creates users in the configured `organizational_units.users_ou`
  (previously hard-coded to `CN=Users,<base_dn>`) when no `ou` is passed.
- `get_password_policy_violations` no longer fails with a TypeError when `maxPwdAge`
  arrives as a numeric string, and the "never expires" values (`0`, `-2**63`) no longer
  flag every `DONT_EXPIRE_PASSWORD` account as a violation.
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

- `create_user`, `create_group`, `create_computer` and `create_ou` now escape the
  RDN value, so names containing `,`, `+`, `=` and similar characters create one object
  in the intended container instead of a malformed or misplaced DN (review finding WR-04).
- `create_user` honours `organizational_units.users_ou` (WR-03) and computer
  operations honour `computer_object_class` with validated object-class values (WR-05).
- the stdio server now reports the package version (`__version__`) in the MCP handshake
  instead of a hard-coded `0.1.0`, and a missing required tool argument returns
  `{"error": "Missing required argument: <name>"}` instead of a Python `TypeError` text.
- the `health` tool no longer reports `status: "ok"` on stdio when the LDAP probe fails;
  a probe failure keeps `status: "degraded"` regardless of the stdio test status.
- the environment placeholder resolver expands in-string placeholders and
  colon-containing defaults (WR-06).
- bare `except:` handlers were removed and silent exception swallowing now logs a
  warning; `list_*` tools no longer hit an unbound variable when validation fails early.

- `uvicorn` (`>=0.40,<1`) and `starlette` (`>=1.0,<2`) are now declared dependencies; the
  HTTP server imports them directly and previously relied on `fastmcp`'s transitive pins.

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
- `GET /health` on the HTTP server: unauthenticated liveness endpoint returning
  `{"status", "server", "version"}`; it performs no LDAP probe and discloses no hostnames
  or credentials. The `health` MCP tool remains the LDAP-aware status call.
- `X-Request-ID` (a valid inbound id is echoed, otherwise generated), `X-Content-Type-Options:
  nosniff` and `Cache-Control: no-store` (unless the response sets its own) on HTTP responses.
- Both transports now register their 42 tools from one registry (`registry.py`) and the
  HTTP server serves the output of one app factory (`http_app.build_http_app`).
- Deterministic mocked-LDAP test harness (`tests/support/mock_directory.py`, ldap3
  MOCK_SYNC) and a live-uvicorn end-to-end test with a real MCP client session
  (`tests/e2e`).

### Changed (server consolidation)

- Tool descriptions are now served from `tools/definitions.py` and are identical on the
  stdio and HTTP transports (previously two different short strings). Tool names,
  parameters and schemas are unchanged; the golden snapshots are byte-identical.
- The `health` tool is one shared implementation: both transports report `status`,
  `server`, `timestamp` and `ldap_connection`/`ldap_server`; the stdio transport adds
  `tests_passed` and its derived `status`. The HTTP `health` response now includes
  `timestamp`.
- HTTP server shutdown is handled by uvicorn's SIGINT/SIGTERM handling; the custom signal
  handlers were removed. The LDAP connection is closed inside uvicorn's graceful shutdown
  (uvicorn re-raises SIGTERM before `serve()` returns, so closing it afterwards was
  skipped), and a signal-initiated stop exits with code 0.
- The docker-compose healthcheck uses `GET /health` (the previous JSON-RPC POST check was
  also malformed YAML).

### Security enforcement (breaking)

- HTTP transport requires authentication by default. Set `AD_MCP_HTTP_API_KEY` or
  `AD_MCP_HTTP_API_KEY_SHA256`, or `security.http_auth.api_key_sha256`; startup fails
  without one. Opt out with `security.http_auth.required=false`. `/health` stays
  unauthenticated; stdio is unaffected.
- Write and destructive tools are refused by default. Enable them with
  `security.allow_writes` and `security.allow_destructive` (destructive tools need both;
  `delete_organizational_unit` is destructive).
- `modify_user`, `modify_group`, `modify_computer` and `modify_organizational_unit` accept
  only allow-listed attributes, and `create_*` `additional_attributes` are validated the
  same way. `modify_user` no longer accepts a `password` key; use `reset_user_password`.
- List and report tools are capped at `security.max_list_results` (default 1000, 0 =
  unlimited); responses carry `truncated` and `result_limit`.
- Password operations refuse non-TLS connections (`unicodePwd_requires_tls`). A TLS
  connection with `security.validate_certificate: false` no longer counts as secure for
  password writes.
- `add_group_member`, `remove_group_member` and `reset_user_password` refuse privileged
  targets (Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account/Backup/
  Server/Print Operators, `krbtgt`, `Administrator`, and any object with `adminCount=1`)
  with `protected_target`. Set `security.protect_privileged_targets` to `false` to opt out
  (default `true`).
- `get_inactive_users`, `get_password_policy_violations` and `get_stale_computers` scan
  the whole directory; `security.max_list_results` caps only the findings they return
  (`truncated`/`result_limit` still apply), so offenders are not missed in large domains.
- Calls blocked by the policy gate are logged at WARNING (tool name and risk only).

### Fixed (security enforcement)

- `create_computer` validates `dns_hostname` (must be a valid host inside the configured
  domain) and the computer name before deriving `dNSHostName` and the `HOST/` SPNs.
- A plaintext `AD_MCP_HTTP_API_KEY` is stripped before hashing, like the presented key, so
  a trailing newline from a secret file no longer causes 401 for every request.
- The auth-failure log line writes a truncated `repr` of the request path (no log
  forging).
- `health` and `test_connection` error text is redacted; non-object `attributes` are
  rejected with a clear message.

- `reset_computer_password` now actually sets the generated 120-character password
  (`unicodePwd`, TLS required, `secrets`-based) and reports success only after the
  directory accepted it. Previously it only wrote `pwdLastSet=0` and returned a password
  that was never applied. The machine must be rejoined or re-synced afterwards.

### Removed

- Unregistered methods that returned fabricated sample data: `find_weak_passwords`,
  `analyze_permissions`, `detect_privilege_escalation`, `check_service_accounts`,
  `get_ou_permissions`, `delegate_ou_control`, `get_computer_status`,
  `search_stale_computers`, `get_computer_groups`. None was a registered MCP tool.
- `get_schema_info` for computers no longer names `search_stale_computers`
  (it lists `get_stale_computers`).

### Added (security enforcement)

- `accuracy_note` on `get_inactive_users`, `get_stale_computers` and `audit_admin_accounts`
  (and `list_users` with `lastLogon`): `lastLogon` is per-DC and not replicated, while
  `lastLogonTimestamp` is replicated but can lag by up to 14 days.
