#!/usr/bin/env bash
# Prove the tool-surface snapshot is byte-identical under several Python versions.
# Usage: scripts/check_python_matrix.sh [VERSION ...]   (default: 3.11 3.12 3.13)
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
versions=("$@")
[ ${#versions[@]} -gt 0 ] || versions=(3.11 3.12 3.13)

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

missing=()
failed=()
cd "$repo"

for v in "${versions[@]}"; do
  venv="$tmp/venv-$v"
  if ! UV_PROJECT_ENVIRONMENT="$venv" uv sync --locked --all-extras --python "$v" -q 2>"$tmp/sync-$v.log"; then
    echo "py$v: cannot provision interpreter/environment (see below)" >&2
    tail -3 "$tmp/sync-$v.log" >&2
    missing+=("$v")
    continue
  fi
  if ! TOOL_SURFACE_DUMP_DIR="$tmp/dump-$v" "$venv/bin/pytest" tests/unit/test_tool_surface.py \
      -q -p no:cacheprovider >"$tmp/test-$v.log" 2>&1; then
    tail -15 "$tmp/test-$v.log" >&2
    failed+=("$v")
    continue
  fi
  for t in stdio http; do
    if ! cmp -s "$tmp/dump-$v/tool_surface_$t.json" "tests/golden/tool_surface_$t.json"; then
      echo "py$v: $t dump differs from committed golden" >&2
      failed+=("$v")
    fi
  done
  echo "py$v: stdio=$(sha256sum "$tmp/dump-$v/tool_surface_stdio.json" | cut -c1-16)" \
       "http=$(sha256sum "$tmp/dump-$v/tool_surface_http.json" | cut -c1-16)"
done

# Cross-version comparison against the first version that ran.
ref=""
for v in "${versions[@]}"; do
  [ -d "$tmp/dump-$v" ] || continue
  if [ -z "$ref" ]; then ref="$v"; continue; fi
  for t in stdio http; do
    cmp -s "$tmp/dump-$ref/tool_surface_$t.json" "$tmp/dump-$v/tool_surface_$t.json" \
      || { echo "$t surface differs between py$ref and py$v" >&2; failed+=("$v"); }
  done
done

if [ ${#missing[@]} -gt 0 ]; then
  echo "FAIL: could not provision Python: ${missing[*]}" >&2
  exit 2
fi
if [ ${#failed[@]} -gt 0 ]; then
  echo "FAIL: mismatch/test failure for Python: ${failed[*]}" >&2
  exit 1
fi
echo "OK: tool surface byte-identical across Python ${versions[*]}"
