"""Source-level guards that keep the Phase 2 hardening from eroding (CONF-02..CONF-04).

These parse the code under src/ with ``ast`` and fail on regressions: bare or silent
exception handlers, hand-rolled LDAP escaping, filters built from unvalidated input, DN
parameters that skip base_dn confinement, and servers that skip ``validate_config``.
"""

import ast
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "active_directory_mcp"
TOOLS = SRC / "tools"

#: DN-bearing tool parameters that must be confined to the configured base_dn.
CONFINED_PARAMS = {"ou", "parent_ou", "ou_dn", "new_parent_dn", "member_dn"}
#: Calls that count as confinement / central validation of a DN parameter.
DN_VALIDATORS = ("_confined_dn", "_validate_dn", "_build_dn", "validation.", "_dn_error")
#: Legacy alias wrappers that only delegate to a validated primary tool method.
ALIAS_WRAPPERS = {
    "list_organizational_units": "list_ous",
    "get_organizational_unit": "get_ou",
    "create_organizational_unit": "create_ou",
    "modify_organizational_unit": "modify_ou",
    "delete_organizational_unit": "delete_ou",
    "move_organizational_unit": "move_ou",
    "get_ou_children": "get_ou_contents",
}
FILTER_FUNCS = {"combine_filters", "validate_filter_criteria"}


def _py_files(root: Path) -> List[Path]:
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def _parents(tree: ast.AST) -> Dict[ast.AST, ast.AST]:
    return {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}


# --- bare / silent exception handlers -------------------------------------------------

def _is_logger_call(node: ast.AST) -> bool:
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        target = node.func.value
        text = ast.unparse(target)
        return "log" in text.lower() and node.func.attr in {
            "debug", "info", "warning", "warn", "error", "exception", "critical"}
    return False


def find_bad_handlers(source: str) -> List[Tuple[int, str]]:
    """Return (line, reason) for bare excepts and handlers that silently swallow errors."""
    problems: List[Tuple[int, str]] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.ExceptHandler):
            continue
        if node.type is None:
            problems.append((node.lineno, "bare except"))
            continue
        silent = all(
            isinstance(stmt, ast.Pass)
            or (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant)
                and stmt.value.value is Ellipsis)
            for stmt in node.body
        )
        has_log = any(_is_logger_call(n) for stmt in node.body for n in ast.walk(stmt))
        if silent and not has_log:
            problems.append((node.lineno, "handler swallows the exception without logging"))
    return problems


def test_guard_detects_bare_and_silent_handlers():
    assert find_bad_handlers("try:\n    x()\nexcept:\n    y()\n")[0][1] == "bare except"
    assert find_bad_handlers("try:\n    x()\nexcept Exception:\n    pass\n")
    assert find_bad_handlers("try:\n    x()\nexcept ValueError:\n    ...\n")
    assert not find_bad_handlers(
        "try:\n    x()\nexcept Exception as e:\n    logger.warning('x %s', e)\n")
    assert not find_bad_handlers("try:\n    x()\nexcept ValueError:\n    return 1\n")


@pytest.mark.parametrize("path", _py_files(SRC), ids=lambda p: str(p.relative_to(SRC)))
def test_no_bare_or_silent_except(path):
    problems = find_bad_handlers(path.read_text(encoding="utf-8"))
    if path.name == "redaction.py":
        # RedactingFilter.filter must never raise into the logging machinery, and it cannot
        # log its own failure (that would recurse into the same filter). Exactly one allowed.
        assert [reason for _, reason in problems] == [
            "handler swallows the exception without logging"]
        return
    assert problems == []


# --- hand-rolled escaping ----------------------------------------------------------------

ESCAPE_LITERALS = ("\\5c", "\\2a", "\\28", "\\29", "\\00")


@pytest.mark.parametrize(
    "path", [p for p in _py_files(SRC) if p.name != "validation.py"],
    ids=lambda p: str(p.relative_to(SRC)),
)
def test_no_hand_rolled_escape_chain(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            lowered = node.value.lower()
            assert not any(lit in lowered for lit in ESCAPE_LITERALS), (
                f"{path.name}:{node.lineno} hand-rolled LDAP escape sequence; use validation.py")
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "replace" and node.args
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value in {"(", ")", "*", "\\"}):
            pytest.fail(f"{path.name}:{node.lineno} str.replace on a filter metacharacter")


# --- filters built only from escaped / validated pieces -----------------------------------

def _safe_filter_expr(expr: ast.AST) -> bool:
    """True when an interpolated expression in a filter f-string is known-safe."""
    text = ast.unparse(expr)
    if isinstance(expr, ast.Call):
        callee = ast.unparse(expr.func)
        if callee in {"self._escape_ldap_filter", "validation.escape_filter_value",
                      "validation.eq_filter", "validation.combine_filters",
                      "self._computer_filter", "validation.validate_object_class"}:
            return True
        if callee == "''.join" and expr.args:
            return all(_is_filter_parts(a) for a in expr.args)
    if isinstance(expr, ast.Attribute) and text.startswith("self.ldap.ad_config.") \
            and text.endswith("_object_class"):
        return True
    if isinstance(expr, ast.Name) and (
            expr.id.startswith("escaped_") or expr.id.endswith("_object_class")
            or expr.id in {"base_filter", "search_filter"}):
        return True
    return False


def _is_filter_parts(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id == "filter_parts"


def _filter_fstrings(tree: ast.AST) -> Iterator[ast.JoinedStr]:
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            head = node.values[0] if node.values else None
            if isinstance(head, ast.Constant) and isinstance(head.value, str) \
                    and head.value.startswith("("):
                yield node


@pytest.mark.parametrize("path", _py_files(TOOLS), ids=lambda p: p.name)
def test_filter_fstrings_interpolate_only_escaped_values(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for fstr in _filter_fstrings(tree):
        for part in fstr.values:
            if isinstance(part, ast.FormattedValue):
                assert _safe_filter_expr(part.value), (
                    f"{path.name}:{fstr.lineno} unescaped interpolation "
                    f"{{{ast.unparse(part.value)}}} in an LDAP filter")


def test_filter_guard_rejects_raw_interpolation():
    tree = ast.parse("f = f'(sAMAccountName={username})'")
    (fstr,) = list(_filter_fstrings(tree))
    assert not _safe_filter_expr(fstr.values[1].value)
    tree = ast.parse("f = f'(sAMAccountName={self._escape_ldap_filter(username)})'")
    (fstr,) = list(_filter_fstrings(tree))
    assert _safe_filter_expr(fstr.values[1].value)


def _enclosing_function(node: ast.AST, parents: Dict[ast.AST, ast.AST]) -> Optional[str]:
    while node in parents:
        node = parents[node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node.name
    return None


def unvalidated_filter_criteria_uses(source: str) -> List[int]:
    tree = ast.parse(source)
    parents = _parents(tree)
    bad = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Name) and node.id == "filter_criteria"
                and isinstance(node.ctx, ast.Load)):
            continue
        ancestor = parents.get(node)
        call = None
        while ancestor is not None:
            if isinstance(ancestor, ast.Call):
                call = ancestor
                break
            ancestor = parents.get(ancestor)
        callee = ast.unparse(call.func).split(".")[-1] if call is not None else ""
        if callee in FILTER_FUNCS:
            continue
        if _enclosing_function(node, parents) in ALIAS_WRAPPERS and callee in set(
                ALIAS_WRAPPERS.values()):
            continue
        bad.append(node.lineno)
    return bad


@pytest.mark.parametrize("path", _py_files(TOOLS), ids=lambda p: p.name)
def test_filter_criteria_always_goes_through_validation(path):
    assert unvalidated_filter_criteria_uses(path.read_text(encoding="utf-8")) == []


def test_filter_criteria_guard_detects_raw_use():
    raw = "def f(filter_criteria):\n    return '(&(a=b)' + filter_criteria + ')'\n"
    assert unvalidated_filter_criteria_uses(raw)
    raw = "def f(filter_criteria):\n    return f'(&(a=b){filter_criteria})'\n"
    assert unvalidated_filter_criteria_uses(raw)
    ok = ("def f(filter_criteria):\n"
          "    return validation.combine_filters('(a=b)', filter_criteria)\n")
    assert not unvalidated_filter_criteria_uses(ok)


# --- DN parameters go through confinement ------------------------------------------------

def _tool_functions(path: Path) -> Iterator[Tuple[ast.FunctionDef, str]]:
    source = path.read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.FunctionDef) and not node.name.startswith("_"):
            yield node, ast.get_source_segment(source, node) or ""


def _dn_cases():
    cases = []
    for path in _py_files(TOOLS):
        for func, segment in _tool_functions(path):
            params = {a.arg for a in func.args.args + func.args.kwonlyargs}
            used = sorted(params & CONFINED_PARAMS)
            if used and func.name not in ALIAS_WRAPPERS:
                cases.append(pytest.param(segment, used, id=f"{path.name}::{func.name}"))
    return cases


@pytest.mark.parametrize("segment,used", _dn_cases())
def test_dn_parameters_are_confined(segment, used):
    if "self.ldap" not in segment:
        # Cannot reach the directory itself; anything it delegates to is checked on its own.
        return
    assert any(token in segment for token in DN_VALIDATORS), (
        f"DN parameter(s) {used} are used without base_dn confinement")


def test_dn_guard_covers_the_confined_tools():
    names = {p.id for p in _dn_cases()}
    for expected in ("user.py::list_users", "user.py::create_user", "group.py::add_member",
                     "computer.py::create_computer", "organizational_unit.py::move_ou"):
        assert expected in names


def test_alias_wrappers_only_delegate():
    path = TOOLS / "organizational_unit.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for func in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)):
        if func.name in ALIAS_WRAPPERS:
            calls = [n for n in ast.walk(func) if isinstance(n, ast.Call)]
            targets = {ast.unparse(c.func) for c in calls}
            assert f"self.{ALIAS_WRAPPERS[func.name]}" in targets, func.name
            assert not any("ldap" in t for t in targets), (
                f"{func.name} must only delegate, not talk to LDAP itself")


# --- servers keep enforcing validate_config ----------------------------------------------

@pytest.mark.parametrize("module", ["server.py", "server_http.py"])
def test_servers_validate_config_right_after_load(module):
    source = (SRC / module).read_text(encoding="utf-8")
    lines = [ln.strip() for ln in source.splitlines()]
    load_idx = next(i for i, ln in enumerate(lines) if "= load_config(" in ln)
    assert lines[load_idx + 1].startswith("validate_config(")
