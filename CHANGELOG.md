# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [1.0.0] - Unreleased (date is set when the owner tags)

The MCP tool names and parameters of the 42 original tools are unchanged in this release.
They are frozen and enforced by the golden snapshots in `tests/golden/`. Three additive
read-only tools were added (see Added). A configuration with several domains adds an optional
`domain` argument to every tool and a read-only `list_domains` tool; with one domain the tool
surface is exactly the frozen one. For vulnerability reporting and the supported
security model, see [SECURITY.md](SECURITY.md).

### Breaking changes (read before upgrading)

1. **The HTTP transport requires an API key by default.** Set `AD_MCP_HTTP_API_KEY`
   (plaintext, stripped before hashing) or `AD_MCP_HTTP_API_KEY_SHA256`, or list digests in
   `security.http_auth.api_key_sha256`; startup fails without one. Clients send it as a
   Bearer token or `X-API-Key`. Migration: provide a key, or for trusted local-only use set
   `security.http_auth.required=false`. `GET /health` stays unauthenticated and the stdio
   transport is unaffected.
2. **Read-only by default.** Write tools (create, modify, enable, disable, move, group
   membership, password resets) are refused unless `security.allow_writes` is `true`.
   Delete tools are destructive and need both `security.allow_writes` and
   `security.allow_destructive` set to `true` (`delete_organizational_unit` is destructive
   even for an empty OU). Migration: set the flags you need in the `security` section.
3. **DN confinement to `base_dn`.** User, group, computer and OU tools reject DNs (`ou`,
   `parent_ou`, `ou_dn`, `new_parent_dn`, `member_dn`) outside the configured `base_dn`, and
   `get_members` skips nested members outside it. Multi-root deployments are not supported.
   Migration: point `base_dn` at the common root of the objects you manage.
4. **`security.require_secure_connection` defaults to `true` and is enforced.** A plaintext
   `ldap://` server, `use_ssl: false` or `security.enable_tls: false` is rejected at startup.
   Migration: use `ldaps://` (or StartTLS), or set `"require_secure_connection": false`
   explicitly for a lab.
5. **Configuration is strict.** Unknown keys in any section (for example
   `security.check_names` or a typo such as `passwrd`) fail at load time. Remove stale keys.
6. **`modify_*` attribute allow-lists.** `modify_user`, `modify_group`, `modify_computer` and
   `modify_organizational_unit` accept only allow-listed attributes, and `additional_attributes`
   of `create_*` tools are validated the same way. `modify_user` no longer accepts a
   `password` key; use `reset_user_password`.
7. **List and report results are capped** at `security.max_list_results` (default 1000,
   `0` = unlimited). Responses carry `truncated` and `result_limit`.
8. **Python 3.11 or newer** is required (3.11, 3.12 and 3.13 are tested), and dependency
   majors changed: `fastmcp>=3.2,<4` (was `>=0.2,<0.4`) and `mcp>=1.28,<2`.
9. **Removed fabricated methods and files** (see Removed), including the renamed lab
   compose file `docker-compose-openldap.yml`.

See [SECURITY.md](SECURITY.md) for the security model behind these defaults.

### Added

- Audit trail: every write and destructive tool call is recorded as one JSON line
  (timestamp, tool, risk, target, outcome, redacted arguments) in the file set by the new
  `security.audit_log_path` option (opened in append mode, mode `0600`; passwords are never stored).
- Three new read-only tools: `get_nested_group_members` (transitive membership through one
  server-side chain query), `get_rootdse_info` (allow-listed rootDSE attributes) and
  `get_tls_posture` (configured TLS settings, live channel ldaps/starttls/plaintext, TLS
  version and cipher when available, and findings; no secrets or paths are returned).
- The tool count goes from 42 to 45: the 42 original tools unchanged plus 3 additive
  read-only tools. The golden snapshots changed additively only: the original 42 entries
  are byte-identical (enforced by a fingerprint test, `tests/unit/test_golden_additive.py`);
  the only altered existing line is `tool_count`.
- One server instance can serve several Active Directory domains. A config file with a
  `domains` object lists each domain as a path to a single-domain config or inline, plus
  `default_domain`, top-level `logging` and `http_auth`. With more than one domain every tool
  takes an optional `domain` argument and the read-only `list_domains` tool reports the
  configured domains; the number of tools does not grow with the number of domains. Each domain
  keeps its own `security` settings (write policy, audit trail), and audit records carry the
  domain name. The multi-domain tool surface has its own golden snapshots
  (`tests/golden/tool_surface_multi_*.json`).
- `active_directory.skip_schema` turns schema-less mode on per domain. `AD_MCP_SKIP_SCHEMA`
  still sets the default.
- New option `security.audit_fail_closed` (default `false`, requires `audit_log_path`):
  refuse write and destructive calls with `audit_unavailable` when the intent record cannot
  be written.
- `accuracy_note` on `get_inactive_users`, `get_stale_computers` and `audit_admin_accounts`
  (and `list_users` with `lastLogon`): `lastLogon` is per-DC and not replicated, while
  `lastLogonTimestamp` is replicated but can lag by up to 14 days.
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
- Both transports now register their tools from one registry (`registry.py`) and the
  HTTP server serves the output of one app factory (`http_app.build_http_app`).
- Deterministic mocked-LDAP test harness (`tests/support/mock_directory.py`, ldap3
  MOCK_SYNC) and a live-uvicorn end-to-end test with a real MCP client session
  (`tests/e2e`).

### Changed

- The startup LDAP connection check runs in the background, one probe per domain, so an
  unreachable domain controller no longer delays the MCP handshake or the other domains.
- With several domains configured, startup refuses `AD_BIND_DN`, `AD_PASSWORD` and the
  `AZURE_KEYVAULT_*` variables, because they would overwrite every domain's credentials. Set
  credentials per domain (`${VAR}` placeholders or `key_vault`).
- `fastmcp` is now `>=3.2,<4` and `mcp` is `>=1.28,<2`. The fastmcp import-fallback shim
  was removed.
- Azure Key Vault packages (`azure-identity`, `azure-keyvault-secrets`) moved to the
  optional `azure` extra. Install them with `uv sync --extra azure`; the Docker image
  includes them.
- `requirements.in` and `requirements-dev.in` were removed in favor of `pyproject.toml`
  and the committed `uv.lock`. Install with `uv sync --locked`.
- The `cryptography` upper bound (`<42`) was lifted.
- Unused dependencies were removed: `python-dateutil`, `asgiref` and the `django` extra;
  `requests` moved to the dev dependencies.
- `uvicorn` (`>=0.40,<1`) and `starlette` (`>=1.0,<2`) are now declared dependencies; the
  HTTP server imports them directly and previously relied on `fastmcp`'s transitive pins.
- The Docker image is built from `uv.lock` on a digest-pinned Python 3.13 base and no
  longer installs build toolchains.
- `docker-compose-ad.yml` was renamed `docker-compose-openldap.yml` (the lab is OpenLDAP,
  not Samba AD) and now requires `LAB_LDAP_PASSWORD`; no password literal is shipped.
- Root-level ad-hoc test scripts were removed or moved to `tests/manual/`.
- The `organizational_units` configuration section is now optional. Missing entries
  default to the built-in containers under `base_dn` (`CN=Computers,<base_dn>` for
  computers, `CN=Users,<base_dn>` for users, groups and service accounts).
- `${VAR}` placeholders are expanded anywhere inside a string and variable names are
  limited to `[A-Za-z_][A-Za-z0-9_]*`; an unset variable without a default fails with a
  message that names only the variable.
- `filter_criteria` is validated (balanced parenthesized terms, at most 1024 characters,
  must parse as an LDAP filter). Previously any string was interpolated into the search
  filter. See `docs/input-validation.md`.
- `filter_criteria` rejects terms on sensitive attributes (password hashes, `unicodePwd`,
  LAPS, gMSA, key credentials, security descriptors, BitLocker recovery data) and
  extensible-match terms such as `memberOf:1.2.840.113556.1.4.1941:=`, which closes a
  blind-oracle probe of secrets.
- `*_object_class` configuration values are validated and rejected if they contain filter
  metacharacters.
- The bind password is a `SecretStr`; its repr and JSON dump are masked, and registered
  secrets are redacted from all log handlers, connection errors and tool error responses.
- `delete_ou`, `modify_ou` and `move_ou` (source) now reject `base_dn` itself, and
  `move_ou` rejects a target parent that is the OU or beneath it. Read operations may
  still target `base_dn`.
- RDN values with a trailing space are now written with the `\20` escape instead of
  failing with "Malformed DN".
- Passwords passed to `create_user` and `reset_password` (including generated ones) are
  registered for redaction, so they are scrubbed from logs and error responses. The
  `reset_password` success response still returns the new password by design.
- Password operations refuse non-TLS connections (`unicodePwd_requires_tls`). A TLS
  connection with `security.validate_certificate: false` no longer counts as secure for
  password writes.
- `get_inactive_users`, `get_password_policy_violations` and `get_stale_computers` scan
  the whole directory; `security.max_list_results` caps only the findings they return
  (`truncated`/`result_limit` still apply), so offenders are not missed in large domains.
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
- `get_schema_info` reports the directory tools; `get_rootdse_info` matches attribute names
  case-insensitively.

### Deprecated

- `performance.connection_pool_size` is accepted but ignored (one serialized LDAP
  connection is used); a warning is logged at startup. It will be removed in a later
  release.

### Removed

- Unregistered methods that returned fabricated sample data: `find_weak_passwords`,
  `analyze_permissions`, `detect_privilege_escalation`, `check_service_accounts`,
  `get_ou_permissions`, `delegate_ou_control`, `get_computer_status`,
  `search_stale_computers`, `get_computer_groups`. None was a registered MCP tool.
- `get_schema_info` for computers no longer names `search_stale_computers`
  (it lists `get_stale_computers`).
- `requirements.in`, `requirements-dev.in` and the root-level ad-hoc test scripts (see
  Changed).

### Fixed

- Docker images (release and the CI container scan) rebuild the runtime stage instead of
  reusing it from the build cache, so they pick up current Debian security fixes; the
  dependency stage is still cached.
- Release workflow: the pyproject version check also covers non-dry-run dispatches, the
  tagged commit must be an ancestor of `origin/main`, publishing waits for the reused test
  and lint workflows, and `:latest` only moves when the tag is the highest stable `vX.Y.Z`.
- `get_ou_statistics` reports real counts (`total_objects`, `users`, `groups`, `computers`,
  `sub_ous`) taken from the `get_ou_contents` payload instead of always returning zeros, and
  passes through `truncated` / `result_limit`.
- `LDAPManager.move` keeps every component of a multi-valued RDN (`CN=a+SN=b`).
- `LDAPManager.search` rejects boolean, out-of-range and unknown `search_scope` values with
  `ValueError` before any connection is made.
- `.env.example` no longer activates Azure Key Vault by default (it overrode `AD_BIND_DN` and
  `AD_PASSWORD` and failed startup against a placeholder vault); both credential options are
  commented and the file is safe for the `.sh` and `.bat` launchers.
- `docker-compose.yml` passes `AD_BIND_DN` and `AD_PASSWORD` through to the container and the
  README Docker quickstart sets them, so the container no longer exits and restarts in a loop.
  The dead `AD_SERVER`, `AD_BASE_DN` and `HTTP_*` overrides were removed (the image fixes the
  HTTP address).
- `ad-config/production-config.example.json` uses `ldaps://` and no longer points at a CA file
  the repository does not ship, so it passes startup validation as shipped.
- `ldap-init/01-structure.ldif` no longer carries literal `userPassword` values.
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
  in the intended container instead of a malformed or misplaced DN.
- The stdio server now reports the package version (`__version__`) in the MCP handshake
  instead of a hard-coded `0.1.0`, and a missing required tool argument returns
  `{"error": "Missing required argument: <name>"}` instead of a Python `TypeError` text.
- The `health` tool no longer reports `status: "ok"` on stdio when the LDAP probe fails;
  a probe failure keeps `status: "degraded"` regardless of the stdio test status.
- Bare `except:` handlers were removed and silent exception swallowing now logs a
  warning; `list_*` tools no longer hit an unbound variable when validation fails early.
- `create_computer` validates `dns_hostname` (must be a valid host inside the configured
  domain) and the computer name before deriving `dNSHostName` and the `HOST/` SPNs.
- A plaintext `AD_MCP_HTTP_API_KEY` is stripped before hashing, like the presented key, so
  a trailing newline from a secret file no longer causes 401 for every request.
- `health` and `test_connection` error text is redacted; non-object `attributes` are
  rejected with a clear message.
- `reset_computer_password` now actually sets the generated 120-character password
  (`unicodePwd`, TLS required, `secrets`-based) and reports success only after the
  directory accepted it. Previously it only wrote `pwdLastSet=0` and returned a password
  that was never applied. The machine must be rejoined or re-synced afterwards.
- `get_nested_group_members`: accepts group names containing `(`, `)`, `*` and `\` (they are
  escaped, not rejected); errors on an ambiguous group name; the chain query has a 30 s server
  time limit and a hard 10000-entry ceiling that also applies when `max_list_results` is `0`.
  Members whose primary group is the target (for example Domain Users) are not returned by
  the chain rule, and results past the cap are an arbitrary subset (`truncated` is set).
- `get_tls_posture`: connection failures return the fixed code `connect_failed` and a
  `connection_failed` finding instead of raw exception text; the probe makes one bind attempt
  and flags SSLv3, TLS 1.0 and TLS 1.1 as `weak_tls_version`.

### Security

- Release secret scan: the allow-list now matches the whole captured value against exact
  placeholder shapes instead of any substring, the baseline stores per-value fingerprints so a new
  credential in an already-baselined file is reported, merge-commit diffs are scanned, and the
  rules cover unquoted, single-quoted, `:`-separated, `secret`/`api_key`/`token` and
  credentials embedded in LDAP URLs.
- AI-residue scan: also detects agent session trailers, agent code-session links, agent-named author
  e-mails and annotated tag messages; history allow-list entries need at least 12 hex digits.
- SECURITY.md and the generated tool-risk table state that auditing is opt-in
  (`security.audit_log_path`, unset by default). The README no longer claims nothing leaves the
  host except to the directory server (Azure Key Vault is contacted when configured).
- `add_group_member`, `remove_group_member` and `reset_user_password` refuse privileged
  targets (Domain Admins, Enterprise Admins, Schema Admins, Administrators, Account/Backup/
  Server/Print Operators, `krbtgt`, `Administrator`, and any object with `adminCount=1`)
  with `protected_target`. Set `security.protect_privileged_targets` to `false` to opt out
  (default `true`).
- Calls blocked by the policy gate are logged at WARNING (tool name and risk only).
- The auth-failure log line writes a truncated `repr` of the request path (no log
  forging).
- Audit file hardening: opened with `O_NOFOLLOW`, must be a regular file owned by the
  server user, and an existing looser mode is tightened to `0600`. The path is re-checked on
  every record, so rotation by rename or deletion no longer sends records to an orphaned
  file; destructive records are fsynced. `AuditLogger.failed_writes` counts failed writes.
- Destructive calls write an `intent` record before the action and an outcome record
  after it; interrupts (`KeyboardInterrupt`, cancellation) are recorded as `error`. Results
  that cannot be read are recorded as `unknown` instead of `success`. HTTP calls add an
  `actor` (key id = first 8 hex of the key digest, client address, request id). Target values
  must be strings and are truncated to 512 characters.
