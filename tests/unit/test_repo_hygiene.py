"""Repository hygiene guards and the behaviour of the release scan scripts."""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "scripts"


def _load(name: str):
    path = SCRIPTS / f"{name}.py"
    if not path.exists():
        pytest.skip(f"{path.name} not present (sdist?)")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=T",
            "-c",
            "user.email=t@example.com",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def _commit(repo: Path, rel: str, content: str, message: str = "change") -> str:
    target = repo / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    _git(repo, "add", rel)
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD").strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q")
    return tmp_path


# The literal is assembled at runtime so this file never matches its own rules.
LEAK = "hunter2" + "hunter2"


def _leak_line(value: str = LEAK) -> str:
    return json.dumps({"password": value}, indent=2) + "\n"


def _run_scan(repo: Path, baseline: Path, report: Path | None = None, *extra: str):
    cmd = [
        sys.executable,
        str(SCRIPTS / "secret_scan.py"),
        "--history",
        "--repo",
        str(repo),
        "--config",
        str(REPO_ROOT / ".gitleaks.toml"),
        "--baseline",
        str(baseline),
        *extra,
    ]
    if report:
        cmd += ["--report", str(report)]
    return subprocess.run(cmd, capture_output=True, text=True)


# --- secret_scan -----------------------------------------------------------------------


def test_secret_scan_finds_historical_leak_without_printing_it(repo, tmp_path_factory):
    sha = _commit(repo, "cfg/app.json", _leak_line())
    _commit(repo, "cfg/app.json", json.dumps({"password": "${AD_PASSWORD}"}) + "\n")
    out = tmp_path_factory.mktemp("out")
    report = out / "report.jsonl"
    baseline = out / "baseline.txt"
    baseline.write_text("", encoding="utf-8")
    res = _run_scan(repo, baseline, report)
    assert res.returncode == 1
    assert f"{sha[:12]} cfg/app.json ldap-bind-password [REDACTED] fp=" in res.stdout
    assert "1 new" in res.stdout
    for blob in (res.stdout, res.stderr, report.read_text(encoding="utf-8")):
        assert LEAK not in blob


def _fp(rule: str, path: str, value: str) -> str:
    mod = _load("secret_scan")
    return mod.fingerprint(rule, path, value)


def test_secret_scan_baseline_absorbs_known_but_not_new_finding(repo, tmp_path_factory):
    _commit(repo, "cfg/app.json", _leak_line())
    out = tmp_path_factory.mktemp("out")
    baseline = out / "baseline.txt"
    fp = _fp("ldap-bind-password", "cfg/app.json", LEAK)
    baseline.write_text(f"# known\n{fp} cfg/app.json ldap-bind-password\n", encoding="utf-8")
    assert _run_scan(repo, baseline).returncode == 0
    _commit(repo, "other/b.json", _leak_line("another" + "secretvalue"))
    res = _run_scan(repo, baseline)
    assert res.returncode == 1
    assert "other/b.json" in res.stdout
    assert "secretvalue" not in res.stdout


def test_secret_scan_baseline_does_not_cover_a_different_secret_in_the_same_file(
    repo, tmp_path_factory
):
    """CR-02: a baselined (path, rule) must not hide a new credential in that file."""
    _commit(repo, "cfg/app.json", _leak_line())
    baseline = tmp_path_factory.mktemp("out") / "baseline.txt"
    fp = _fp("ldap-bind-password", "cfg/app.json", LEAK)
    baseline.write_text(f"{fp} cfg/app.json ldap-bind-password\n", encoding="utf-8")
    assert _run_scan(repo, baseline).returncode == 0
    new_value = "brandnew" + "credential9"
    _commit(repo, "cfg/app.json", _leak_line(new_value))
    res = _run_scan(repo, baseline)
    assert res.returncode == 1
    assert "1 new" in res.stdout
    assert new_value not in res.stdout + res.stderr


def test_secret_scan_rejects_legacy_baseline_lines(repo, tmp_path_factory):
    _commit(repo, "a.txt", "nothing\n")
    baseline = tmp_path_factory.mktemp("out") / "baseline.txt"
    baseline.write_text("deadbeef" * 5 + " gone.json ldap-bind-password\n", encoding="utf-8")
    assert _run_scan(repo, baseline).returncode == 2


def test_secret_scan_stale_baseline_entry_is_only_a_warning(repo, tmp_path_factory):
    _commit(repo, "a.txt", "nothing\n")
    baseline = tmp_path_factory.mktemp("out") / "baseline.txt"
    baseline.write_text("0123456789abcdef gone.json ldap-bind-password\n", encoding="utf-8")
    res = _run_scan(repo, baseline)
    assert res.returncode == 0
    assert "stale baseline entry" in res.stdout


def test_secret_scan_sees_credentials_introduced_only_in_a_merge(repo, tmp_path_factory):
    """WR-02: ``git log -p`` shows no diff for merges; the scan must use -m."""
    _commit(repo, "cfg/app.json", json.dumps({"mode": "a"}) + "\n", "base")
    default = _git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip()
    _git(repo, "checkout", "-q", "-b", "side")
    _commit(repo, "cfg/app.json", json.dumps({"mode": "side"}) + "\n", "side")
    _git(repo, "checkout", "-q", default)
    _commit(repo, "cfg/app.json", json.dumps({"mode": "main"}) + "\n", "main")
    res = subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=T",
            "-c",
            "user.email=t@example.com",
            "-c",
            "commit.gpgsign=false",
            "merge",
            "-q",
            "--no-commit",
            "side",
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode != 0  # conflict, resolved by hand below
    (repo / "cfg" / "app.json").write_text(_leak_line(), encoding="utf-8")
    _git(repo, "add", "cfg/app.json")
    _git(repo, "commit", "-q", "-m", "merge side")
    baseline = tmp_path_factory.mktemp("out") / "baseline.txt"
    baseline.write_text("", encoding="utf-8")
    res = _run_scan(repo, baseline)
    assert res.returncode == 1
    assert "cfg/app.json ldap-bind-password" in res.stdout
    assert LEAK not in res.stdout + res.stderr


def test_secret_scan_does_not_mistake_added_plus_lines_for_file_headers(repo, tmp_path_factory):
    _commit(repo, "a.txt", "x\n")
    _commit(repo, "cfg.ini", '++ password = "' + LEAK + '"\n')
    baseline = tmp_path_factory.mktemp("out") / "baseline.txt"
    baseline.write_text("", encoding="utf-8")
    res = _run_scan(repo, baseline)
    assert res.returncode == 1 and "cfg.ini" in res.stdout


@pytest.mark.parametrize(
    "line",
    [
        json.dumps({"password": "${AD_PASSWORD}"}),
        json.dumps({"password": "<password>"}),
        json.dumps({"password": "changeme"}),
        json.dumps({"password": "CHANGE_ME"}),
        json.dumps({"password": ""}),
        "AD_PASSWORD=${LAB_LDAP_PASSWORD}",
        "# AD_PASSWORD=YourSecurePassword",
        "AD_PASSWORD=",
        json.dumps({"password": "${{ secrets.AD_PASSWORD }}"}),
    ],
)
def test_secret_scan_ignores_placeholders(line):
    mod = _load("secret_scan")
    rules = mod.load_rules(REPO_ROOT / ".gitleaks.toml")
    assert list(mod.scan_line(rules, "x/config.json", line)) == []


@pytest.mark.parametrize(
    "line",
    [
        "          token: ${{ secrets.CODECOV_TOKEN }}",
        "          password: ${{ secrets.GITHUB_TOKEN }}",
    ],
)
def test_secret_scan_ignores_github_actions_expressions(line):
    mod = _load("secret_scan")
    rules = mod.load_rules(REPO_ROOT / ".gitleaks.toml")
    assert list(mod.scan_line(rules, ".github/workflows/x.yml", line)) == []


@pytest.mark.parametrize(
    "line",
    [
        '          token: "${{ secrets.X }}' + 'realsecret"',
        "          token: x${{ secrets.X }}",
        "          token: ${{ secrets.X || 'hunter2hunter2' }}",
        "          token: ${{ hunter2hunter2 }}",
    ],
)
def test_secret_scan_github_expression_rule_is_exact_shape(line):
    mod = _load("secret_scan")
    rules = mod.load_rules(REPO_ROOT / ".gitleaks.toml")
    assert list(mod.scan_line(rules, ".github/workflows/x.yml", line)) != []


def test_secret_scan_flags_env_and_ldif_literals():
    mod = _load("secret_scan")
    rules = mod.load_rules(REPO_ROOT / ".gitleaks.toml")
    assert list(mod.scan_line(rules, ".env", "AD_PASSWORD=" + "realvalue1")) == [
        "ldap-env-password"
    ]
    assert list(mod.scan_line(rules, "x.ldif", "user" + "Password: " + "realvalue1")) == [
        "ldif-user-password"
    ]


@pytest.mark.parametrize(
    "value",
    [
        "Example" + "2024!Prod",
        "<x>" + "realsecret",
        "${x}" + "realsecret",
        "your-" + "secret-pw",
        "Change" + "Me2024!",
        "YourSecurePassword" + "1",
        "REPLACE_WITH_X" + "realsecret",
        "example",
    ],
)
def test_secret_scan_allowlist_only_accepts_whole_value_placeholders(value):
    """CR-01: a real password merely containing a placeholder word must still be flagged."""
    mod = _load("secret_scan")
    rules = mod.load_rules(REPO_ROOT / ".gitleaks.toml")
    line = json.dumps({"password": value})
    assert list(mod.scan_line(rules, "x/config.json", line)) == ["ldap-bind-password"]


@pytest.mark.parametrize(
    ("path", "line"),
    [
        ("c.yml", "password: " + "hunter2hunter2"),
        ("c.json", "{'password': '" + "hunter2hunter2" + "'}"),
        ("app.py", "password='" + "hunter2hunter2" + "'"),
        ("c.json", json.dumps({"client_secret": "hunter2hunter2"})),
        ("c.json", json.dumps({"api_key": "hunter2hunter2"})),
        ("c.json", json.dumps({"ad_password": "hunter2hunter2"})),
        ("c.json", json.dumps({"password": "two words here"})),
        ("c.json", json.dumps({"password": "abc"})),
        ("c.json", '{"password": "pa\\"ss' + 'word1"}'),
        ("c.ini", "ad_password=" + "hunter2hunter2"),
        ("docker-compose.yml", "      LDAP_ADMIN_PASSWORD: " + "hunter2hunter2"),
        ("docker-compose.yml", "      - LDAP_ADMIN_PASSWORD=" + "hunter2hunter2"),
        ("c.json", "ldap://svc:" + "hunter2hunter2" + "@dc.example.com"),
        ("c.yml", "token: " + "hunter2hunter2"),
    ],
)
def test_secret_scan_flags_widened_credential_shapes(path, line):
    """WR-02: shapes the first rule set missed."""
    mod = _load("secret_scan")
    rules = mod.load_rules(REPO_ROOT / ".gitleaks.toml")
    assert list(mod.scan_line(rules, path, line)) != []


@pytest.mark.parametrize(
    ("path", "line"),
    [
        ("c.yml", "password: ${AD_PASSWORD}"),
        ("c.yml", "AD_MCP_HTTP_API_KEY=${AD_MCP_HTTP_API_KEY:?set it (see README)}"),
        ("c.yml", "      - AD_MCP_HTTP_API_KEY=${AD_MCP_HTTP_API_KEY:-}"),
        ("README.md", "export AD_MCP_HTTP_API_KEY=\"$(python3 -c 'import x')\""),
        ("c.json", json.dumps({"password": "${env:AD_PASSWORD}"})),
        ("app.py", "password: Optional[str] = None"),
    ],
)
def test_secret_scan_ignores_references_and_non_credential_code(path, line):
    mod = _load("secret_scan")
    rules = mod.load_rules(REPO_ROOT / ".gitleaks.toml")
    assert list(mod.scan_line(rules, path, line)) == []


def test_secret_scan_has_no_blanket_path_allowlist_except_the_digest_fixture():
    """CR-02: only the sha256 digest map may be path-exempt; LDIF and test support are scanned."""
    mod = _load("secret_scan")
    rules = mod.load_rules(REPO_ROOT / ".gitleaks.toml")
    line = "user" + "Password: realvalue1"
    assert list(mod.scan_line(rules, "ldap-init/01-structure.ldif", line)) == ["ldif-user-password"]
    assert [p.pattern for p in rules.allow_paths] == [
        r"^tests/golden/original_tools\.sha256\.json$"
    ]


def test_committed_baseline_holds_only_fingerprints():
    mod = _load("secret_scan")
    entries = mod.load_baseline(SCRIPTS / "secret_scan_baseline.txt")
    assert entries
    for fp, path, rule in entries:
        assert len(fp) == 16 and path and rule


def test_tracked_tree_secret_scan_is_clean_against_committed_baseline():
    mod = _load("secret_scan")
    if not (REPO_ROOT / ".git").exists():
        pytest.skip("not inside a git checkout")
    rules = mod.load_rules(REPO_ROOT / ".gitleaks.toml")
    findings, _files = mod.tree_findings(REPO_ROOT, rules)
    new, _stale = mod.compare(findings, mod.load_baseline(SCRIPTS / "secret_scan_baseline.txt"))
    assert new == []


# --- ai_residue_scan -------------------------------------------------------------------

TRAILER = "Co-authored-by: " + "Claude <noreply@" + "anthropic.com>"


def _run_ai(repo: Path, allowlist: Path, *flags: str):
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPTS / "ai_residue_scan.py"),
            "--repo",
            str(repo),
            "--allowlist",
            str(allowlist),
            *flags,
        ],
        capture_output=True,
        text=True,
    )


def test_ai_scan_clean_repo_passes(repo, tmp_path_factory):
    _commit(repo, "a.txt", "hello\n", "add greeting")
    allow = tmp_path_factory.mktemp("o") / "allow.txt"
    allow.write_text("", encoding="utf-8")
    assert _run_ai(repo, allow).returncode == 0


def test_ai_scan_flags_tracked_file_and_commit_message(repo, tmp_path_factory):
    allow = tmp_path_factory.mktemp("o") / "allow.txt"
    allow.write_text("", encoding="utf-8")
    _commit(repo, "notes.md", f"text\n{TRAILER}\n", "add notes")
    res = _run_ai(repo, allow, "--tree")
    assert res.returncode == 1 and "notes.md" in res.stdout
    sha = _commit(repo, "b.txt", "x\n", f"feat: thing\n\n{TRAILER}")
    res = _run_ai(repo, allow, "--history")
    assert res.returncode == 1 and sha[:12] in res.stdout


def test_ai_scan_honors_sha_allowlist(repo, tmp_path_factory):
    sha = _commit(repo, "b.txt", "x\n", f"feat: thing\n\n{TRAILER}")
    allow = tmp_path_factory.mktemp("o") / "allow.txt"
    allow.write_text(f"{sha} # third-party trailer\n", encoding="utf-8")
    assert _run_ai(repo, allow, "--history").returncode == 0
    _commit(repo, "c.txt", "y\n", f"feat: other\n\n{TRAILER}")
    assert _run_ai(repo, allow, "--history").returncode == 1


SESSION_TRAILER = "Claude-" + "Session: https://claude" + ".ai/code/session_abc123"


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        (SESSION_TRAILER, "claude-session-trailer"),
        ("see https://claude" + ".ai/code/session_x", "claude-code-link"),
        ("Dev <noreply@" + "anthropic.com>", "anthropic-noreply"),
        ("claude-bot" + "@users.noreply.github.com", "agent-email"),
        ("Co-Authored-By: " + "Noreply <noreply@anthropic" + ".com>", "anthropic-noreply"),
    ],
)
def test_ai_scan_matches_session_trailers_links_and_agent_emails(text, rule):
    mod = _load("ai_residue_scan")
    assert rule in mod._match(text)


def test_ai_scan_flags_session_trailer_in_history_and_agent_author_email(repo, tmp_path_factory):
    allow = tmp_path_factory.mktemp("o") / "allow.txt"
    allow.write_text("", encoding="utf-8")
    sha = _commit(repo, "b.txt", "x\n", f"feat: thing\n\n{SESSION_TRAILER}")
    res = _run_ai(repo, allow, "--history")
    assert res.returncode == 1 and sha[:12] in res.stdout
    other = tmp_path_factory.mktemp("r")
    _git(other, "init", "-q")
    (other / "a.txt").write_text("x\n", encoding="utf-8")
    _git(other, "add", "a.txt")
    subprocess.run(
        [
            "git",
            "-C",
            str(other),
            "-c",
            "user.name=Dev",
            "-c",
            "user.email=codex" + "@example.org",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "plain message",
        ],
        check=True,
        capture_output=True,
    )
    res = _run_ai(other, allow, "--history")
    assert res.returncode == 1 and "agent-email" in res.stdout


def test_ai_scan_flags_annotated_tag_messages(repo, tmp_path_factory):
    allow = tmp_path_factory.mktemp("o") / "allow.txt"
    allow.write_text("", encoding="utf-8")
    _commit(repo, "a.txt", "x\n", "add file")
    _git(repo, "tag", "-a", "v1", "-m", f"release\n\n{TRAILER}")
    res = _run_ai(repo, allow, "--history")
    assert res.returncode == 1 and "tag v1" in res.stdout


def test_ai_scan_allowlist_rejects_short_sha_prefixes(repo, tmp_path_factory):
    sha = _commit(repo, "b.txt", "x\n", f"feat: thing\n\n{TRAILER}")
    allow = tmp_path_factory.mktemp("o") / "allow.txt"
    allow.write_text(f"{sha[:6]} # too short, would match many commits\n", encoding="utf-8")
    assert _run_ai(repo, allow, "--history").returncode == 2
    allow.write_text(f"{sha[:12]} # ok\n", encoding="utf-8")
    assert _run_ai(repo, allow, "--history").returncode == 0


def test_committed_ai_allowlist_only_names_full_length_shas():
    mod = _load("ai_residue_scan")
    entries = mod.load_allowlist(SCRIPTS / "ai_residue_allowlist.txt")
    assert entries and all(len(e) == 40 for e in entries)


def test_ai_scan_does_not_flag_mcp_client_names():
    mod = _load("ai_residue_scan")
    assert mod._match("Works with Claude Desktop and Claude Code") == []


def test_ai_scan_generated_with_needs_an_assistant_name():
    mod = _load("ai_residue_scan")
    assert mod._match("regenerated with the dump script") == []
    assert mod._match("Generated with [" + "Claude Code]") == ["generated-with"]


# --- tracked-tree hygiene --------------------------------------------------------------


def _tracked() -> list[str]:
    res = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files"], capture_output=True, text=True, check=False
    )
    if res.returncode != 0:
        pytest.skip("not inside a git checkout")
    return res.stdout.splitlines()


def _check_ignore(rel: str) -> bool:
    res = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "check-ignore", "-q", rel], capture_output=True
    )
    if res.returncode not in (0, 1):
        pytest.skip("not inside a git checkout")
    return res.returncode == 0


def test_only_example_configs_are_tracked_under_ad_config():
    stray = [
        p for p in _tracked() if p.startswith("ad-config/") and not p.endswith(".example.json")
    ]
    assert stray == []


def test_ignore_rules_match_real_filenames():
    assert _check_ignore("ad-config/ad-config.json")
    assert _check_ignore("ad-config/anything-else.json")
    assert not _check_ignore("ad-config/config.example.json")
    assert not _check_ignore("ad-config/openldap-lab.example.json")
    assert _check_ignore(".venv.freeze.txt")
    assert _check_ignore(".env")
    assert not _check_ignore(".env.example")


def test_local_tooling_files_are_not_tracked_nor_named_in_ignore_files():
    tracked = _tracked()
    forbidden = ("CLAUDE.md", "REVIZYON-BRIEF.md", ".planning", "graphify-out")
    for path in tracked:
        assert not any(path == f or path.startswith(f + "/") for f in forbidden), path
    for name in (".gitignore", ".dockerignore"):
        lines = (REPO_ROOT / name).read_text(encoding="utf-8").splitlines()
        for line in lines:
            if name == ".dockerignore" and line.strip() in (".planning", "graphify-out"):
                continue
            assert not any(f in line for f in forbidden), (name, line)


EXAMPLES = (
    sorted(p for p in (REPO_ROOT / "ad-config").glob("*.example.json"))
    if (REPO_ROOT / "ad-config").is_dir()
    else []
)

_PASSWORD_KEYS = {"password", "bind_password", "client_secret", "api_key"}
_ALLOWED_HOSTS = (
    "example.com",
    "example",
    "localhost",
    "test.local",
    "yourdomain.com",
    "domain.com",
    "192.168.1.100",
)


def _host_allowed(host: str) -> bool:
    """Exact host or a true subdomain: ``mydomain.com`` must not pass for ``domain.com``."""
    return host.startswith("your-") or any(
        host == allowed or host.endswith("." + allowed) for allowed in _ALLOWED_HOSTS
    )


def _walk(node, path=""):
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _walk(value, f"{path}/{key}")
            if key.lower() in _PASSWORD_KEYS:
                yield path + "/" + key, value
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _walk(value, f"{path}[{index}]")


@pytest.mark.parametrize("example", EXAMPLES, ids=lambda p: p.name)
def test_example_configs_are_placeholder_only(example, monkeypatch):
    data = json.loads(example.read_text(encoding="utf-8"))
    for where, value in _walk(data):
        assert value in (None, "") or re.fullmatch(r"\$\{[A-Z_][A-Z0-9_]*\}", str(value)), where
    ad = data["active_directory"]
    for server in [ad["server"], *ad.get("server_pool", [])]:
        host = server.split("://", 1)[-1].split(":")[0]
        assert _host_allowed(host), server
    from active_directory_mcp.config.models import Config

    assert Config(**data)


def test_env_and_compose_files_hold_no_literal_credentials():
    pattern = re.compile(
        r"^\s*-?\s*(AD_PASSWORD|LDAP_ADMIN_PASSWORD|LDAP_CONFIG_PASSWORD|AZURE_CLIENT_SECRET)"
        r"\s*[=:]\s*(?P<value>\S*)",
        re.M,
    )
    for rel in (".env.example", "docker-compose.yml", "docker-compose-openldap.yml"):
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        for line in text.splitlines():
            if line.lstrip().startswith("#"):
                continue
            match = pattern.match(line)
            if match:
                value = match.group("value").strip("\"'")
                assert value == "" or value.startswith("${"), (rel, line.split("=")[0])


def test_tracked_tree_has_no_ai_residue():
    mod = _load("ai_residue_scan")
    if not (REPO_ROOT / ".git").exists():
        pytest.skip("not inside a git checkout")
    assert mod.scan_tree(REPO_ROOT) == []


def test_config_example_loads_as_shipped(monkeypatch):
    """A copied ad-config/config.example.json must pass config validation unchanged."""
    from active_directory_mcp.config.loader import load_config

    monkeypatch.setenv("AD_BIND_DN", "CN=svc,DC=example,DC=com")
    monkeypatch.setenv("AD_PASSWORD", "placeholder-pw")
    config = load_config(str(REPO_ROOT / "ad-config" / "config.example.json"))
    assert config.active_directory.server.startswith("ldaps://")
    assert config.security.ca_cert_file is None
    assert config.key_vault is None or not config.key_vault.vault_url


def _active_env_assignments(rel: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in (REPO_ROOT / rel).read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, _, value = stripped.partition("=")
        values[key] = value
    return values


def test_env_example_does_not_enable_key_vault_by_default():
    """CR-03: a copied .env must not route startup through Azure Key Vault."""
    active = _active_env_assignments(".env.example")
    for key, value in active.items():
        if key.startswith("AZURE_"):
            assert value == "", key
    assert not active.get("AZURE_KEYVAULT_URL")


def test_env_example_values_are_launcher_safe():
    """The .sh launchers `source` the file and the .bat launchers read it literally."""
    for key, value in _active_env_assignments(".env.example").items():
        assert not any(ch in value for ch in " \"'"), key


def test_copied_env_example_plus_plaintext_credentials_loads_without_azure(monkeypatch):
    from active_directory_mcp.config.loader import load_config

    for key, value in _active_env_assignments(".env.example").items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("AD_BIND_DN", "CN=svc,DC=example,DC=com")
    monkeypatch.setenv("AD_PASSWORD", "placeholder-pw")
    config = load_config(str(REPO_ROOT / "ad-config" / "config.example.json"))
    assert config.active_directory.password.get_secret_value() == "placeholder-pw"


@pytest.mark.parametrize("example", EXAMPLES, ids=lambda p: p.name)
def test_every_example_config_passes_startup_validation_as_shipped(example, monkeypatch):
    """WR-07: load AND validate each example the way server startup does, Key Vault mocked."""
    from active_directory_mcp.config import loader

    monkeypatch.setenv("AD_BIND_DN", "CN=svc,DC=example,DC=com")
    monkeypatch.setenv("AD_PASSWORD", "placeholder-pw")
    monkeypatch.setenv("LAB_LDAP_PASSWORD", "placeholder-pw")
    for name in (
        "AZURE_KEYVAULT_URL",
        "AZURE_KEYVAULT_SECRET_USERNAME",
        "AZURE_KEYVAULT_SECRET_PASSWORD",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(loader, "get_secret", lambda _url, _name: "placeholder-pw")
    config = loader.load_config(str(example))
    loader.validate_config(config)
    # A shipped path to a file the repository does not provide fails at connect time.
    assert not config.security.ca_cert_file or Path(config.security.ca_cert_file).exists()


def test_production_example_is_secure_by_default():
    data = json.loads(
        (REPO_ROOT / "ad-config" / "production-config.example.json").read_text(encoding="utf-8")
    )
    assert data["active_directory"]["server"].startswith("ldaps://")
    assert data["security"]["require_secure_connection"] is True


def test_lab_ldif_holds_no_password_material():
    """WR-10: LDIF fixtures carry no password attribute; the lab admin password is per-run."""
    mod = _load("secret_scan")
    rules = mod.load_rules(REPO_ROOT / ".gitleaks.toml")
    files = sorted((REPO_ROOT / "ldap-init").glob("*.ldif"))
    assert files
    for path in files:
        for line in path.read_text(encoding="utf-8").splitlines():
            assert not line.lower().startswith("userpassword"), path.name
            assert list(mod.scan_line(rules, f"ldap-init/{path.name}", line)) == []


@pytest.mark.parametrize("host", ["mydomain.com", "notexample.com", "evil-example.com"])
def test_example_host_check_rejects_lookalike_registrable_domains(host):
    assert not _host_allowed(host)


@pytest.mark.parametrize("host", ["dc.example.com", "example.com", "dc1.domain.com", "localhost"])
def test_example_host_check_accepts_reserved_and_subdomain_hosts(host):
    assert _host_allowed(host)
