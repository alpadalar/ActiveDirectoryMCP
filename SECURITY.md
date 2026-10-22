# Security Policy

This document covers how to report a vulnerability, what the server can do to your directory, the
controls that limit it, and a credential exposure in the repository history that you should know
about before you use or fork this project. See also the [README](README.md),
[CONTRIBUTING](CONTRIBUTING.md) and [CHANGELOG](CHANGELOG.md).

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |
| earlier | No |

Only the latest release line receives security fixes.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

- Preferred: use GitHub private vulnerability reporting ("Report a vulnerability" on the
  repository's Security tab). This channel exists only after the repository owner has enabled the
  feature; if the button is not there, it is not enabled yet.
- Fallback, valid today: email alp.adalar@gmail.com with the subject "ActiveDirectoryMCP security".

Include the affected version, a description, reproduction steps and the impact you see. Do not
include real credentials or production data.

This is a volunteer-maintained project. There is no guaranteed response time. Reports are
acknowledged and triaged on a best-effort basis, and a fix is released with a CHANGELOG entry and
credit to the reporter if wanted.

### Scope

In scope: the server code in `src/active_directory_mcp`, its HTTP transport and authentication,
the policy, validation and redaction layers, the Docker image and the example configurations.

Out of scope: weaknesses of Active Directory itself, of the MCP client or the language model, of
your reverse proxy or network, and a service account that was given more rights than this document
recommends.

## Threat model: what can this server do to your domain

The server binds to the directory with exactly one service account. Every tool call, whoever or
whatever triggered it, runs with that account's rights. The server's reach therefore equals the
rights of that account, and the server's own controls can only narrow it further.

What each risk class can do (the full per-tool table is generated below):

- read: enumerate users, groups, computers and organizational units, group membership (including
  nested membership), password policy and policy violations, privileged group membership, the
  rootDSE and the schema summary, and the TLS posture of the directory connection.
- write: create, modify, enable and disable user, group and computer accounts, add and remove group
  members (a privilege escalation path when pointed at privileged groups), reset user and computer
  passwords, create, modify and move organizational units.
- destructive: delete users, groups, computers and organizational units, including recursive
  deletion of an organizational unit with its contents (`force`).

Write and destructive tools are refused by default.

### Risks that remain

- LLM client prompt injection and confused deputy: text the model reads (a user description, a
  group name, a document) can steer it into calling tools the human did not intend. The server
  cannot distinguish an injected call from an intended one. Keep `security.allow_writes` off unless
  the session needs it, use a read-only account for exploration, and review tool calls in the client.
- Data returned to the model: results contain personal data (names, mail addresses, phone numbers,
  group memberships, last logon times). It is sent to whichever model and client you connect.
- `reset_user_password` and `reset_computer_password` return the new password in the tool response.
  The server registers it for log redaction and does not write it to its logs or audit file, but it
  is visible in the MCP client transcript. Treat client transcripts and logs as secrets.
- Shared key authentication: the HTTP transport uses a shared API key. There is no per-user
  identity; the audit record stores a key identifier and client address, not a person.

### What the server does not do

- No per-user delegation or impersonation: callers share the one bind account.
- No rate limiting or request quotas (a search of the source finds none). Put limits in front of the
  server if you need them. Result sizes are capped by `security.max_list_results`.
- No TLS termination for the HTTP transport: it serves plain HTTP. Run it behind a TLS-terminating
  reverse proxy or on a private network.
- No Kerberos or NTLM: authentication to the directory is a simple bind (use LDAPS or StartTLS).
- It does not make the bind account safe: a Domain Admin account makes every tool a Domain Admin tool.

## Controls

Each row names the enforcing code and a test that exercises it.

| Threat | Control | Code | Test |
| --- | --- | --- | --- |
| Unintended writes or deletes | Read-only by default; write and destructive tools are refused before any LDAP call; unknown tools are treated as destructive; `security.allow_destructive` requires `security.allow_writes` | `policy.py`, `config/models.py` | `tests/unit/test_policy.py`, `tests/unit/test_config.py` |
| Unauthenticated HTTP access | API key required on every request except `/health`; keys compared in constant time (`hmac.compare_digest`) against SHA-256 digests; startup fails without a key unless `security.http_auth.required` is set to false | `auth.py`, `http_app.py` | `tests/unit/test_auth.py`, `tests/unit/test_http_app.py` |
| Searching or acting outside the configured domain | Every DN parameter must be under `active_directory.base_dn`; DN components are parsed and escaped, not concatenated | `validation.py` | `tests/unit/test_validation.py`, `tests/unit/test_hardening_guards.py` |
| LDAP filter injection and secret-attribute oracles | Values are escaped; `filter_criteria` is parsed and restricted (length limit, no extensible match, secret-bearing attributes such as `userPassword`, `unicodePwd`, `msLAPS-Password` rejected) | `validation.py` | `tests/unit/test_validation.py`, `tests/unit/test_hardening_guards.py` |
| Privilege escalation through generic modify tools | `modify_*` tools accept only attribute allow-lists per object type; a hard-deny set (`userAccountControl`, `memberOf`, `servicePrincipalName`, `gPLink`, `nTSecurityDescriptor`, ...) is never allowed. Widening a list is a code change | `attribute_policy.py` | `tests/unit/test_attribute_policy.py` |
| Membership or password changes on privileged accounts | `security.protect_privileged_targets` (default true) refuses member changes and password resets on privileged groups and accounts | `tools/` | `tests/unit/test_group_tools.py`, `tests/unit/test_user_tools.py`, `tests/unit/test_computer_tools.py` |
| Passwords over a clear channel | `unicodePwd` writes are refused unless the connection is LDAPS or StartTLS (`unicodePwd_requires_tls`); `security.require_secure_connection` (default true) refuses plaintext at startup | `tools/base.py`, `config/models.py` | `tests/unit/test_user_tools.py`, `tests/unit/test_computer_tools.py`, `tests/unit/test_config.py` |
| Bulk data exfiltration | List and search tools stop at `security.max_list_results` and report `truncated` | `tools/base.py` | `tests/unit/test_base_helpers.py` |
| Secrets in logs | Configured and generated passwords are registered with a redacting log filter installed at record creation | `redaction.py`, `core/logging.py` | `tests/unit/test_redaction.py`, `tests/unit/test_credential_leak.py` |
| No record of what was changed | Opt-in, off by default: when `security.audit_log_path` is set, every write and destructive call (including blocked calls) is appended to a JSON-lines audit file (mode 0600, no symlink following, arguments redacted); `security.audit_fail_closed` refuses calls when the file is unwritable. With the path unset (the default) no call is audited | `audit.py`, `policy.py` | `tests/unit/test_audit.py`, `tests/unit/test_policy.py` |
| Drift of the tables in this document | The tool-risk table is generated from the code and compared in a test | `scripts/gen_security_table.py` | `tests/unit/test_security_md.py` |

## Tool risk table

Generated from `RISK_CLASSIFICATION` in `src/active_directory_mcp/policy.py` by
`scripts/gen_security_table.py`. Do not edit by hand; run
`python scripts/gen_security_table.py --write` after changing the classification.

<!-- BEGIN GENERATED: tool-risk-table -->
| Tool | Risk | Enabled by | Audited |
| --- | --- | --- | --- |
| `audit_admin_accounts` | read | always enabled | no |
| `get_computer` | read | always enabled | no |
| `get_domain_info` | read | always enabled | no |
| `get_group` | read | always enabled | no |
| `get_group_members` | read | always enabled | no |
| `get_inactive_users` | read | always enabled | no |
| `get_nested_group_members` | read | always enabled | no |
| `get_organizational_unit` | read | always enabled | no |
| `get_organizational_unit_contents` | read | always enabled | no |
| `get_password_policy_violations` | read | always enabled | no |
| `get_privileged_groups` | read | always enabled | no |
| `get_rootdse_info` | read | always enabled | no |
| `get_schema_info` | read | always enabled | no |
| `get_stale_computers` | read | always enabled | no |
| `get_tls_posture` | read | always enabled | no |
| `get_user` | read | always enabled | no |
| `get_user_groups` | read | always enabled | no |
| `get_user_permissions` | read | always enabled | no |
| `health` | read | always enabled | no |
| `list_computers` | read | always enabled | no |
| `list_domains` | read | always enabled | no |
| `list_groups` | read | always enabled | no |
| `list_organizational_units` | read | always enabled | no |
| `list_users` | read | always enabled | no |
| `test_connection` | read | always enabled | no |
| `add_group_member` | write | `security.allow_writes` | only if `security.audit_log_path` is set |
| `create_computer` | write | `security.allow_writes` | only if `security.audit_log_path` is set |
| `create_group` | write | `security.allow_writes` | only if `security.audit_log_path` is set |
| `create_organizational_unit` | write | `security.allow_writes` | only if `security.audit_log_path` is set |
| `create_user` | write | `security.allow_writes` | only if `security.audit_log_path` is set |
| `disable_computer` | write | `security.allow_writes` | only if `security.audit_log_path` is set |
| `disable_user` | write | `security.allow_writes` | only if `security.audit_log_path` is set |
| `enable_computer` | write | `security.allow_writes` | only if `security.audit_log_path` is set |
| `enable_user` | write | `security.allow_writes` | only if `security.audit_log_path` is set |
| `modify_computer` | write | `security.allow_writes` | only if `security.audit_log_path` is set |
| `modify_group` | write | `security.allow_writes` | only if `security.audit_log_path` is set |
| `modify_organizational_unit` | write | `security.allow_writes` | only if `security.audit_log_path` is set |
| `modify_user` | write | `security.allow_writes` | only if `security.audit_log_path` is set |
| `move_organizational_unit` | write | `security.allow_writes` | only if `security.audit_log_path` is set |
| `remove_group_member` | write | `security.allow_writes` | only if `security.audit_log_path` is set |
| `reset_computer_password` | write | `security.allow_writes` | only if `security.audit_log_path` is set |
| `reset_user_password` | write | `security.allow_writes` | only if `security.audit_log_path` is set |
| `delete_computer` | destructive | `security.allow_writes` and `security.allow_destructive` | only if `security.audit_log_path` is set |
| `delete_group` | destructive | `security.allow_writes` and `security.allow_destructive` | only if `security.audit_log_path` is set |
| `delete_organizational_unit` | destructive | `security.allow_writes` and `security.allow_destructive` | only if `security.audit_log_path` is set |
| `delete_user` | destructive | `security.allow_writes` and `security.allow_destructive` | only if `security.audit_log_path` is set |
<!-- END GENERATED: tool-risk-table -->

## Least-privilege delegation

None of the commands below were executed against a live Active Directory by this project. No such
environment was available. The syntax was checked against Microsoft documentation (`dsacls`, the
User-Force-Change-Password extended right, and the protected accounts appendix) but test every
change in a lab domain first.

Principles:

- Use a dedicated service account. Never use a member of Domain Admins, Enterprise Admins,
  Administrators or Account Operators.
- Use one account per posture: a read-only account for reporting (`security.allow_writes` false),
  and a separate write-enabled account for provisioning, used only in sessions that need it.
- Delegate on the specific organizational units the tools should touch, not on the domain root.
- Set `active_directory.base_dn` and the OU settings to the delegated subtree.

Permissions needed per risk class (on the delegated OU, inherited by its children):

| Risk class | Needed on the delegated OU |
| --- | --- |
| read | Default authenticated read access. Deny read on attributes you do not want exposed |
| write: create or modify users, groups, computers | Create child objects of the matching type; write the allow-listed properties |
| write: password reset | Extended right "Reset Password"; write `pwdLastSet` and `lockoutTime` |
| write: group membership | Write the `member` property on the specific groups only |
| write: organizational units | Create child organizational units; write their allow-listed properties |
| destructive | Delete child objects of the matching type (`DC` on the parent, or `SD` on the objects); delete subtree (`DT`) only if recursive OU deletion is intended |

Example with placeholder names, using the Active Directory `dsacls` syntax
`<account>:<permissions>[;<object type or property>][;<inherited object type>]`. Run in an
elevated prompt on a domain-joined host:

```
:: allow the account to create and delete user objects in one OU
dsacls "OU=Managed,DC=example,DC=com" /I:T /G "EXAMPLE\svc-ad-mcp-write:CCDC;user"

:: allow the account to reset passwords on user objects in that OU
dsacls "OU=Managed,DC=example,DC=com" /I:S /G "EXAMPLE\svc-ad-mcp-write:CA;Reset Password;user"

:: allow it to read and write the lockout and last-set properties of users
dsacls "OU=Managed,DC=example,DC=com" /I:S /G "EXAMPLE\svc-ad-mcp-write:RPWP;lockoutTime;user" "EXAMPLE\svc-ad-mcp-write:RPWP;pwdLastSet;user"

:: allow it to change membership of one specific group
dsacls "CN=Project Team,OU=Groups,DC=example,DC=com" /G "EXAMPLE\svc-ad-mcp-write:WP;member"
```

The Delegation of Control wizard (Active Directory Users and Computers, right-click the OU,
"Delegate Control...") can express the same grants through a custom task; review the resulting
entries with `dsacls "<OU DN>"` afterwards. Verify with a test account that each tool works only
with the rights you delegated.

Protected accounts: Active Directory resets the permissions of members of protected groups (for
example Domain Admins, Account Operators, Backup Operators) from the AdminSDHolder object
(`CN=AdminSDHolder,CN=System,<domain DN>`), so delegation on an OU does not apply to them. The
server's `security.protect_privileged_targets` setting adds a second barrier for those targets.

## Deployment hardening

- Use `ldaps://` (or StartTLS) with a certificate chain your host trusts, keep
  `security.validate_certificate` true and `security.require_secure_connection` true. For an internal CA
  set `security.ca_cert_file`. `get_tls_posture` reports what the connection actually negotiated.
- Keep `security.allow_writes` false unless the session needs writes; keep `security.allow_destructive` false
  unless deletion is intended.
- The Docker image listens on `0.0.0.0` inside the container. Publish the port only to a trusted
  interface and put a TLS-terminating reverse proxy in front of it; the API key travels in a header.
- Generate a long random API key, store only its SHA-256 digest in `security.http_auth.api_key_sha256` (or
  pass the key through the environment), and rotate it by adding the new digest, switching clients, then
  removing the old one.
- Keep secrets out of config files: use environment variables or Azure Key Vault. `ad-config/ad-config.json`
  is git-ignored; do not commit it.
- Set `security.audit_log_path` to a directory only the service user can write; the file is created with
  mode 0600. Ship it to your log system.
- Log hygiene: keep `logging.level` at INFO or above in production, and still treat log files as sensitive
  (they contain DNs and account names).
- Docker: the image runs as the non-root user `aduser` (UID 1000); the virtual environment and code are
  root-owned, and `docker-compose.yml` mounts `ad-config` read-only. The root filesystem of the container is
  not set read-only by the compose file.

## Credential exposure advisory and residual risk

An earlier version of `ad-config/ad-config.json` that contained a lab bind password was tracked from
the first commit of this repository, and the same value also appears in other files of the first
commits (compose files, README, LDIF fixtures and test scripts). It is in the public git history.

- As of 1.0.0 the file is untracked and every tracked example is placeholder-only. The history was
  not rewritten, so the value remains retrievable from the repository and from every existing fork
  and clone.
- Treat the value as compromised. Rotate it everywhere it was or may have been used, and never reuse it.
- The maintainer's checklist tracks as pending, owner-side actions: a decision on purging the history,
  enabling GitHub secret scanning with push protection, and enabling private vulnerability reporting.
- Scan results (scan of 2026-10-20, re-run after the pre-release review fixes): the scripted full-history
  and tree scan (`scripts/secret_scan.py` with the custom rules in `.gitleaks.toml`) covers all refs,
  including merge-commit diffs, and the tracked tree. The gitleaks binary was not available, so the
  `useDefault` gitleaks rules were not exercised; only the custom rules ran. The allow-list accepts
  exact placeholder values only (`${VAR}`, `<name>`, `changeme`, `YourSecurePassword`,
  `REPLACE_WITH_...`), not substrings. Every remaining finding is in the committed baseline
  `scripts/secret_scan_baseline.txt`, which stores a per-value fingerprint, the path and the rule, never
  a value, so a new credential in an already-baselined file is still reported. The baseline holds the
  lab credential in the first commits and later compose and script edits, plus synthetic test and
  documentation strings reviewed by hand. The gate fails on any new finding.
- Baseline review (2026-10-20): the 101 fingerprints in `.gitleaksignore` were re-checked with a
  throwaway script that resolves each `commit:file:rule:line` to the blob, re-applies the rule from
  `.gitleaks.toml` and prints only a classification and counts, never a matched value. Result: no
  finding looks like real secret material. Matches are environment references (`${VAR}`), documented
  placeholders and word-based example values (README Azure sections), prose or comments (the CHANGELOG
  URL-shape sentence, the "throwaway value" compose comment), an environment variable name constant
  (not a key), test fixtures under `tests/`, and the lab and LDIF fixture values already described
  above, which are treated as compromised and must not be reused. High-entropy strings outside
  `tests/`, `ad-config/` and `ldap-init/` were not found.
- AI-residue scan (`scripts/ai_residue_scan.py`): the tracked tree and all commit messages are clean except
  one merged upstream pull request commit that carries third-party `Co-authored-by` trailers. It is allow-listed
  by SHA in `scripts/ai_residue_allowlist.txt` and was not rewritten.

The credential value is intentionally not written in this document or in the scan evidence.
