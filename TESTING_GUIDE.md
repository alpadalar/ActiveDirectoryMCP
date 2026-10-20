# Testing Guide

ActiveDirectoryMCP has three kinds of checks: unit tests, live integration tests against an OpenLDAP lab, and manual smoke scripts. The unit layer includes a mocked-LDAP harness (see "Mocked-LDAP harness" below). Install everything first:

```bash
uv sync --all-extras
```

## 1. Unit tests

```bash
uv run pytest
```

- Located in `tests/unit/` (plus the in-process server tests in `tests/e2e/`).
- ldap3 is mocked; no directory server is needed.
- Tests marked `integration` are deselected by default.
- The golden files in `tests/golden/` pin the exposed tool surface (45 tools, names and parameters). A surface change must be intentional: regenerate the goldens and review the diff.

### Security behaviour under test

- Write tools are refused unless the config sets `security.allow_writes: true`; delete tools additionally need `security.allow_destructive: true`. Tests that exercise a write path build their configuration with these flags, for example `directory.security_config(allow_writes=True)`.
- The HTTP transport requires an API key by default. The e2e tests install a per-run random key through `AD_MCP_HTTP_API_KEY` and send it as `Authorization: Bearer <key>`.
- `tests/unit/test_repo_hygiene.py` guards the repository itself: no tracked real config, placeholder-only examples, no AI or tooling residue in tracked files, a clean secret scan against the committed baseline. The same scans can be run by hand: `uv run python scripts/secret_scan.py --history --tree` and `uv run python scripts/ai_residue_scan.py`.

### Mocked-LDAP harness

`tests/support/mock_directory.py` provides `MockDirectory`, a deterministic in-memory directory built on ldap3's `MOCK_SYNC` strategy. It replaces `Server` and `Connection` where `core.ldap_manager` looks them up, so the real `LDAPManager` and the real tool classes run end to end with no network and no directory server. Seed data is declared in code (`add_user`, `add_group`, `add_computer`, `add_ou`, `add_entry`); there is no randomness, clock or socket use.

```python
directory = MockDirectory()
directory.add_user("alice", displayName="Alice")
with directory.patch():  # patch(schema_less=True) mirrors AD_MCP_SKIP_SCHEMA
    manager = directory.make_manager(page_size=2)
    UserTools(manager).disable_user("alice")
    directory.search(
        "(sAMAccountName=alice)", ["userAccountControl"]
    )  # [{"dn": ..., "attributes": {...: [514]}}]
```

`directory.ad_config()`, `ou_config()`, `security_config()`, `performance_config()` build ready configuration models; `directory.env(tmp_path)` returns `AD_MCP_CONFIG` and `AD_PASSWORD` for `patch.dict(os.environ, ...)`. The bind password defaults to the placeholder `mock-bind-secret`. Each new connection replays the seeds into its own store, so one `LDAPManager` (which caches a single connection) sees its own writes consistently.

Test layers:

| Layer | What runs | Use it for |
| --- | --- | --- |
| `Mock(spec=LDAPManager)` unit tests | Tool code only; LDAP results are canned | Tool logic, validation, response shaping |
| MOCK_SYNC harness | Real `LDAPManager` + real tools + real ldap3 filter parsing and result handling | Wiring, filter syntax acceptance, paging loop, result shaping |
| Live-LDAP integration suite (`-m integration`) | A real OpenLDAP lab or directory | Server-side semantics (see "Lab limitations") |

The harness verifies wiring, filter syntax acceptance and result shaping. It does NOT verify Active Directory semantics. Password-set TLS enforcement needs its own tests at the `LDAPManager` boundary; do not rely on the mock for it.

#### Fidelity limits

Each row is pinned by the test named in the last column; if the mock changes, that test fails and this table must be updated. Live checks are tracked in the live-AD checklist.

| Limit | Mock behaviour | Real AD behaviour | Pinned by |
| --- | --- | --- | --- |
| Extensible-match filters (bit-AND `:803:`, IN_CHAIN `:1941:`) | Raise `LDAPAttributeError` (also through `LDAPManager.search`) | Evaluated server-side | `test_fidelity_extensible_match_filters_unsupported` |
| `unicodePwd` writes | Succeed on a non-TLS connection with any bytes | Require a TLS bind and UTF-16LE quoted encoding | `test_fidelity_unicodepwd_write_has_no_tls_or_encoding_enforcement` |
| TLS and certificate validation | `Server.ssl` follows the URL scheme; no TLS session, no chain check, configured `Tls` is dropped | Certificates validated per configuration | `test_fidelity_tls_not_emulated` |
| Paged search | Opaque random cookies; empty cookie on the last page; `size_limit` shrinks the page; an exact multiple of `page_size` yields a non-empty cookie then an empty final page, which `LDAPManager.search` treats as success (all entries are returned) | Server-controlled paging; boundary behaviour unverified here | `test_fidelity_paged_search_cookie_behaviour` |
| Empty search results | ldap3 reports zero entries as `False` with result code 0; `LDAPManager.search` treats that as success and returns `[]` in both schema and schema-less modes | Same: an empty result is success | `test_empty_result_returns_empty_list_in_both_modes` |
| Non-leaf delete | Succeeds, children stay | Refused (`notAllowedOnNonLeaf`) | `test_fidelity_non_leaf_delete_allowed` |
| Add under a missing parent | Succeeds | `noSuchObject` | `test_fidelity_add_under_missing_parent_allowed` |
| Duplicate add | Raises `LDAPEntryAlreadyExistsResult` | `entryAlreadyExists` result with AD diagnostic text | `test_fidelity_duplicate_add_exception_type` |
| One-level scope | Includes the base entry | Children only | `test_fidelity_onelevel_scope_includes_base` |
| AD-computed attributes | `memberOf`, `whenCreated`, `pwdLastSet`, `objectGUID`, `objectSid` stay empty unless seeded | Maintained by the DC | `test_fidelity_no_ad_computed_attributes` |
| Connection state | Per `Connection` object; a new connection sees only the seeds | One shared directory | `test_fidelity_state_is_per_connection` |
| Case handling | DN, attribute names and `sAMAccountName` values compare case-insensitively; returned keys use the schema's canonical case | Same for these; other matching rules differ per attribute syntax | `test_fidelity_case_handling` |
| Privileges | No ACLs; the bind account may modify anything | ACL-controlled | `test_fidelity_any_privilege_is_granted` |

Schema-less mode (`patch(schema_less=True)`) additionally returns integer attributes as stringified bytes such as `"b'512'"`, so typed assertions need the default schema mode.

## 2. Integration tests (OpenLDAP lab)

```bash
scripts/run_tests_with_ldap.sh          # runs `pytest -m integration`
scripts/run_tests_with_ldap.sh -k user  # extra arguments go to pytest
```

The lab config template is `ad-config/openldap-lab.example.json`; it reads the bind password from `${LAB_LDAP_PASSWORD}`. The script generates a throwaway lab password per run, starts the `openldap` service from `docker-compose-openldap.yml`, writes a temporary config, runs `uv run --locked pytest -m integration`, and always tears everything down. It needs Docker and free ports 389 and 636.

To start the lab by hand, export `LAB_LDAP_PASSWORD` (any throwaway value) first; the compose file refuses to start without it. You can also run the tests against a lab you started yourself by setting `AD_MCP_CONFIG` to a config file and running `uv run pytest -m integration`. Without `AD_MCP_CONFIG` the integration tests skip.

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
uv run python tests/manual/http_server_smoke.py [URL]   # needs a running HTTP server and AD_MCP_HTTP_API_KEY set to its key
uv run python tests/manual/real_ad_smoke.py             # needs AD_MCP_CONFIG
```

See `tests/manual/README.md`.
