## Summary

<!-- What does this pull request change, and why? -->

## Linked Issue

<!-- Use "Closes #<number>" so the issue closes automatically on merge. -->

Closes #

## Type of Change

- [ ] New script
- [ ] Bug fix
- [ ] Documentation update
- [ ] Refactor (no behaviour change)
- [ ] Chore / tooling / CI

## What Changed

<!-- Bulleted list of the notable changes. -->

-
-

## New or Modified Scripts

| Script | Language | Change |
| --- | --- | --- |
|  |  |  |

## Safety Review

<!-- Required for any script that changes system state. -->

- [ ] This script only performs actions the user explicitly requests
- [ ] Any destructive operation requires an explicit flag and supports `--dry-run`
- [ ] Any state-changing action is printed before it is carried out
- [ ] No credentials, API keys or tokens are committed
- [ ] No hardcoded personal or machine-specific paths

## Testing Checklist

- [ ] `python3 -m py_compile python_scripts/*.py` passes
- [ ] `flake8 python_scripts --select=E9,F63,F7,F82,F821,F823 --max-line-length=120` passes
- [ ] `for f in bash_scripts/*.sh; do bash -n "$f"; done` passes
- [ ] `shellcheck bash_scripts/*.sh` reports no errors (advisory)
- [ ] I ran the new or changed script end to end on a machine I am permitted to test
- [ ] I tested the `--help` output
- [ ] I tested the failure path (missing argument, bad path, no permissions)
- [ ] No new console warnings or unhandled errors

## Documentation

- [ ] I added the script to the index in `README.md` in the correct numeric position
- [ ] The script has a module docstring / header comment explaining what it does
- [ ] Non-obvious logic is commented

## Code Quality Checklist

- [ ] My code follows the standards in [CONTRIBUTING.md](../CONTRIBUTING.md)
- [ ] Imports are at the top of the file, not inside functions
- [ ] I have performed a self-review of my own code
- [ ] I have removed debugging code and unused imports

## Additional Notes

<!-- Anything reviewers should know: follow-up work, known limitations, etc. -->
