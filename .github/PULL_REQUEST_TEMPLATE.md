## Summary

What does this change do, and why?

## Checklist

- [ ] Tests added or updated (`.venv/bin/pytest -q` passes)
- [ ] The golden snapshots in `tests/golden` are unchanged, or the change is additive and
      recorded in `CHANGELOG.md`
- [ ] `RISK_CLASSIFICATION` in `src/active_directory_mcp/policy.py` is updated for any new tool
- [ ] Documentation updated (README, `docs/`, `CHANGELOG.md`)
- [ ] No secrets, real DNs or host names are included
- [ ] `scripts/secret_scan.py` and `scripts/ai_residue_scan.py` were run and are clean
