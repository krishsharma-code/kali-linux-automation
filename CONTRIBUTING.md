# Contributing to Kali Linux Automation

Thanks for your interest in improving this toolkit. This guide covers the scripting
standards, folder layout and pull request process.

By participating you agree to follow our [Code of Conduct](CODE_OF_CONDUCT.md).

> **Authorised use only.** These scripts are for system administration and for
> security testing you have explicit permission to perform. Do not submit scripts
> whose purpose is to attack systems you do not own or operate.

---

## Table of Contents

- [Repository Layout](#repository-layout)
- [Adding a New Script](#adding-a-new-script)
- [Python Standards](#python-standards)
- [Bash Standards](#bash-standards)
- [Running the Checks Locally](#running-the-checks-locally)
- [Branch Naming](#branch-naming)
- [Commit Messages](#commit-messages)
- [Pull Request Guidelines](#pull-request-guidelines)
- [Reporting Bugs and Requesting Scripts](#reporting-bugs-and-requesting-scripts)

---

## Repository Layout

```
kali-linux-automation/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── new_script_request.md
│   ├── pull_request_template.md
│   └── workflows/
│       └── ci.yml
├── bash_scripts/        # Shell scripts, numbered (01_*.sh ... 120_*.sh)
├── python_scripts/      # Python scripts, numbered (01_*.py ... 115_*.py)
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── LICENSE
└── README.md
```

- **`bash_scripts/`** holds shell scripts. Every file ends in `.sh`.
- **`python_scripts/`** holds Python scripts. Every file ends in `.py`.
- Both folders use a **numeric prefix** to keep the toolkit ordered:
  `NN_snake_case_name.ext` — for example `105_api_key_leak_scanner.py`.
- **Always use the next free number** in the relevant folder. Never renumber or
  rename existing scripts; people link to them directly.

## Adding a New Script

1. Pick the right folder for the language.
2. Find the highest existing number in that folder and add one.
3. Follow the standards below for that language.
4. Add a one-line entry to the **script index in `README.md`**, in the correct
   numeric position, so the index stays in sync with the folder.
5. Open a pull request using the template.

## Python Standards

Follow [PEP 8](https://peps.python.org/pep-0008/), with the relaxations noted below.
The CI enforces a maximum line length of **120 characters**.

- **Imports at the top of the file**, never inside a function or the `__main__`
  block. (A late import is a real bug — the name is undefined when it is first used.)
- Add a **module docstring** at the top describing what the script does.
- Add a **docstring to every function**, including arguments and what it returns.
- Guard executable code with:

  ```python
  if __name__ == "__main__":
      main()
  ```

- Accept arguments with `argparse` rather than raw `sys.argv`, and always provide
  a `--help` path.
- Prefer `pathlib` over manual string path joining.
- Never use a bare `except:`. Catch the specific exception you expect.
- Do not commit unused imports or unused variables.
- Avoid destructive operations (deleting files, killing processes, modifying
  firewall rules) unless the user explicitly asks for them with a flag.

**CI gates on real errors only** — undefined names, syntax errors and other
pyflakes-level faults. Stylistic warnings are reported but do not fail the build.

## Bash Standards

Every shell script must:

- Start with the shebang `#!/usr/bin/env bash`.
- Set strict mode near the top:

  ```bash
  set -euo pipefail
  ```

- Quote every variable expansion: `"$var"`, not `$var`.
- Prefer `[[ ... ]]` over `[ ... ]`.
- Declare locals inside functions with `local`.
- Provide a `usage()` function and support `-h` / `--help`.
- Pass `bash -n` (syntax check) — the CI enforces this.
- Pass [ShellCheck](https://www.shellcheck.net/) with no errors. ShellCheck runs
  in CI as an advisory check, so please run it locally before opening a PR.

Avoid destructive defaults. If a script can delete data or change system state,
require an explicit confirmation flag and print what it is about to do.

## Running the Checks Locally

Run the same checks CI runs before you push:

```bash
# Python: syntax check on every script
python3 -m py_compile python_scripts/*.py

# Python: real errors (what CI blocks on)
pip install flake8
flake8 python_scripts --select=E9,F63,F7,F82,F821,F823 --max-line-length=120

# Python: full style report (advisory)
flake8 python_scripts --max-line-length=120 --statistics

# Bash: syntax check on every script
for f in bash_scripts/*.sh; do bash -n "$f"; done

# Bash: lint (advisory)
shellcheck bash_scripts/*.sh
```

## Branch Naming

Branch off an up-to-date `main`:

| Prefix | Use for | Example |
| --- | --- | --- |
| `feat/` | New script or capability | `feat/arp-monitor` |
| `fix/` | Fixing a defect | `fix/import-sys-scanner` |
| `docs/` | Documentation only | `docs/update-index` |
| `refactor/` | Behaviour-preserving cleanup | `refactor/log-parser` |
| `chore/` | Tooling and config | `chore/bump-ci` |

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>
```

Examples:

```
feat(bash): add automated log rotation utility
fix(python): import sys at module top in api key scanner
docs(readme): update automation toolkit index
```

## Pull Request Guidelines

1. Open an issue first for anything substantial, so the approach can be agreed
   before you write it.
2. Keep one logical change per pull request.
3. Fill in the pull request template, including the testing checklist.
4. Confirm the CI checks pass. A red build will not be reviewed.
5. Respond to review comments on the same branch rather than opening a new PR.

## Reporting Bugs and Requesting Scripts

- Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md) for defects.
- Use the [new script request template](.github/ISSUE_TEMPLATE/new_script_request.md)
  to propose a script.
