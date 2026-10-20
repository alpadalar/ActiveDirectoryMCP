# Input validation, configuration strictness and secrets

This page describes what the server accepts and rejects, so operators can judge how
far the tools can be exposed. All rules are enforced centrally in
`src/active_directory_mcp/validation.py`; tools do not build filters or DNs by hand.

## Trusted-input policy for `filter_criteria`

`list_users`, `list_groups`, `list_computers` and `list_ous` accept an optional
`filter_criteria` string that is ANDed with the tool's own filter.

Accepted:

- One or more complete, parenthesized LDAP filter terms, for example
  `(department=IT)` or `(&(department=IT)(title=Engineer))`.
- At most 1024 characters.
- Anything that parses as a valid LDAP filter once wrapped as `(&<fragment>)`.

Rejected (the tool returns an error and sends nothing to the directory):

- Unbalanced parentheses, so the fragment cannot close the enclosing filter or
  start a new top-level term.
- NUL bytes and other control characters.
- Fragments that do not parse as an LDAP filter, and empty fragments.
- Terms on sensitive attributes (`userPassword`, `unicodePwd`, `ntSecurityDescriptor`,
  `msDS-KeyCredentialLink`, `ms-Mcs-AdmPwd`, `msLAPS-*`, `msDS-ManagedPassword*`,
  `msFVE-*`, trust auth blobs and similar; the full list is
  `validation.SENSITIVE_FILTER_ATTRIBUTES`) and attributes written as OIDs. Why: a
  filter is a blind oracle, since result counts reveal a secret attribute one prefix
  at a time even when output is filtered.
- Extensible-match terms (`attr:rule:=value`, `:dn:=`), including the expensive
  `memberOf:1.2.840.113556.1.4.1941:=` matching-rule-in-chain query.

Limits you must understand:

- The fragment is a filter expression, not a value. Attribute values inside it are
  the caller's responsibility: the server does not rewrite them. A caller can still
  express any read-only search the bind account is allowed to run (for example
  `(adminCount=1)`).
- The deny-list is not a substitute for directory ACLs: give the bind account no read
  access to secrets it does not need. Treat `filter_criteria` as trusted-caller input. Do not expose the parameter to
  untrusted prompts or end users without a proxy that constrains what the model can
  send, and give the bind account only the read rights you are happy to expose.

Single values the tools interpolate themselves (user names, group names, computer
names) are escaped with the ldap3 escaper and need no caller care.

## DN confinement to `base_dn`

The parameters `ou`, `parent_ou`, `ou_dn`, `new_parent_dn` and `member_dn` must be
located at or below the single configured `active_directory.base_dn`.

- The comparison is component-aware (DN components, not a string suffix) and
  case-insensitive, so `OU=a,DC=evil,DC=test,DC=local` and look-alike suffixes such as
  `XDC=test,DC=local` are rejected.
- Malformed DNs are rejected with "Invalid DN format"; well-formed DNs outside the base
  are rejected with "DN is outside the configured base DN". No LDAP call is made in
  either case.
- Multi-root deployments (several unrelated base DNs, or a forest-wide search) are not
  supported in this release. Run one server instance per base DN.
- `get_members` skips nested group members that are outside `base_dn`.

## RDN escaping for `create_*`

`create_user`, `create_group`, `create_computer` and `create_ou` build the new DN with
RDN escaping. A name containing `,`, `+`, `=`, `"`, `\`, `<`, `>`, `;` or a leading `#`
or space produces a single RDN (for example `CN=Smith\, John,OU=...`) instead of
creating an object in a different container. Object-class values from the
configuration are validated against filter metacharacters.

## Configuration strictness

- Unknown keys in any configuration section are rejected at load time (typos such as
  `passwrd` fail instead of being ignored). Error messages show the key path and reason,
  never the offending value.
- `performance.connection_pool_size` is deprecated. It is still accepted so existing
  files keep loading, but it is ignored (the server uses one serialized LDAP
  connection) and a warning is logged at startup. Remove it from your configuration.
- `${VAR}` and `${VAR:default}` placeholders are expanded anywhere inside a string.
  An unset variable without a default fails at startup naming only the variable.
- With `security.require_secure_connection: true` (the default) the server refuses to
  start unless `use_ssl` is true, the URL is `ldaps://` and `security.enable_tls` is
  true. Setting it to `false` is explicit and logs a plaintext warning.
  `validate_certificate: false` only logs a warning; prefer `ca_cert_file`.

## Credentials and log redaction

The bind password is held as a pydantic `SecretStr`: `repr`, `str`, `model_dump()` and
`model_dump_json()` of the configuration show a mask, and the real value is unwrapped
only when the ldap3 connection is created.

Sources are resolved in this order:

1. Azure Key Vault (`key_vault` section or `AZURE_KEYVAULT_*` environment variables).
2. `AD_BIND_DN` / `AD_PASSWORD` environment variables.
3. Values in the configuration file (a plaintext password logs a warning; use a
   `${VAR}` placeholder or Key Vault instead).

Whatever the source, the final password is registered with a redaction filter that is
installed on every log handler (console and file). Registered secrets, and their URL-quoted
and base64 forms, are replaced by `***REDACTED***` in log messages, arguments and
exception text. The same redaction is applied to the text of connection failures and
tool error responses.

Limits:

- Only registered secrets are redacted. A password that was never loaded through the
  configuration (for example typed into a tool argument by a user) is not known to the
  filter.
- Other encodings (hex, partial substrings, passwords split across log records) are not
  detected.
- Redaction applies to the `active-directory-mcp` logger hierarchy. Do not add handlers
  to the root logger without attaching `active_directory_mcp.redaction.RedactingFilter`.
