# BobGuard Build Plan

## Overview

Build three Python modules — `scanner.py`, `hook_manager.py`, and `report_generator.py` — inside `bobguard-agent/`, plus a `requirements.txt` and the git pre-commit hook integration.

The system intercepts `git commit`, scans the staged diff for secret leaks and SQL injection patterns using Regex and Shannon entropy, and emits a structured JSON report consumed by IBM Bob Agent.

**Flat layout:** all files live directly under `bobguard-agent/`.

---

## Architecture

```
git commit
    └─► .git/hooks/pre-commit (shell, written by hook_manager.py install)
            └─► python hook_manager.py run
                    ├─► scanner.py        ← scans git diff lines
                    └─► report_generator.py ← formats findings to JSON
                            ├─► bobguard-report.json  (written to repo root)
                            └─► stdout                (piped to Bob Agent)
```

---

## Setup Instructions

```bash
# 1. Clone / navigate to the repo you want to protect
cd <your-repo>

# 2. Activate the BobGuard virtualenv
source path/to/bobguard-agent/venv/Scripts/activate   # Windows
# or
source path/to/bobguard-agent/venv/bin/activate        # Linux/macOS

# 3. Install dependencies
pip install -r bobguard-agent/requirements.txt

# 4. Register the pre-commit hook (run once per repo)
python bobguard-agent/hook_manager.py install

# 5. From this point, every `git commit` will auto-scan staged diffs.
#    Findings are printed to stdout and saved to bobguard-report.json.
```

---

## Regex Patterns for Secret Detection

| Secret Type       | Pattern                                                              | Notes                                      |
|-------------------|----------------------------------------------------------------------|--------------------------------------------|
| AWS Access Key ID | `AKIA[0-9A-Z]{16}`                                                  | Literal prefix + 16 uppercase alphanumeric |
| AWS Secret Key    | `(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]`          | Context keyword + base64 body              |
| OpenAI API Key    | `sk-[a-zA-Z0-9]{32,64}`                                             | Standard sk- prefix                        |
| Generic API Key   | `(?i)(api_key|apikey|api-key)\s*[=:]\s*['\"]?[0-9a-zA-Z\-_]{20,}` | Keyword + value heuristic                  |
| DB URI (Postgres) | `postgres(?:ql)?://[^:]+:[^@]+@[^\s'"]+`                           | Protocol + credentials in authority        |
| DB URI (MySQL)    | `mysql(?:\+[a-z]+)?://[^:]+:[^@]+@[^\s'"]+`                        | Same shape for MySQL                       |
| DB URI (generic)  | `(?i)(database_url|db_url|db_uri)\s*[=:]\s*['\"]?[^\s'"]{10,}`    | Env-var style assignment                   |
| SQL Injection     | `(?i)(union\s+select\|drop\s+table\|;\s*--)` | Classic SQLi payloads in diff lines |
| High-entropy blob | Shannon entropy ≥ 4.5 on tokens ≥ 20 chars (computed, not regex)   | Catches unrecognised secrets               |

---

## Sub-Tasks

---

### Task 1 — `requirements.txt`

**Status:** `[ ] pending`

**Intent**
Declare the only runtime dependency so the venv can be reproduced cleanly.

**Expected Outcomes**
- `bobguard-agent/requirements.txt` exists with pinned versions.

**Todo List**
1. Create `bobguard-agent/requirements.txt` with no external deps (stdlib only — `re`, `math`, `json`, `subprocess`, `sys`, `os`, `stat`, `pathlib`). Add a comment explaining each module used.

**Relevant Context**
- The virtualenv at `bobguard-agent/venv/` already has pip 21.2.3 and setuptools.
- All scanner logic relies on stdlib; no third-party packages are needed.

---

### Task 2 — `scanner.py`

**Status:** `[ ] pending`

**Intent**
Implement the core detection engine: apply all Regex patterns and the entropy heuristic to a list of diff lines, returning a list of `Finding` dicts.

**Expected Outcomes**
- `bobguard-agent/scanner.py` is importable and exports a single public function `scan_diff(lines: list[str]) -> list[dict]`.
- Each finding dict has keys: `rule`, `line_no`, `line`, `matched`.
- Entropy-based findings have `rule = "high-entropy"` and `matched` set to the offending token.
- Running `python scanner.py` with no args prints a brief self-test result to stdout.

**Todo List**
1. Define the `PATTERNS` list — each entry is `{"rule": str, "regex": compiled_re}`.
2. Implement `shannon_entropy(token: str) -> float` using `math.log2`.
3. Implement `scan_line(line_no: int, line: str) -> list[dict]` that runs all patterns then the entropy check.
4. Implement `scan_diff(lines: list[str]) -> list[dict]` that calls `scan_line` for every line and returns the aggregated findings.
5. Add a `__main__` block with 3–4 hard-coded test lines (one clean, one AWS key, one OpenAI key, one high-entropy string) and assert the expected finding count.

**Relevant Context**
- All patterns are listed in the "Regex Patterns" table above.
- Only scan lines starting with `+` in a unified diff (added lines); skip `-` and `@@` lines.
- Entropy threshold: 4.5 on tokens of length ≥ 20.

---

### Task 3 — `report_generator.py`

**Status:** `[ ] pending`

**Intent**
Convert the raw `findings` list from `scanner.py` into a structured JSON payload consumed by IBM Bob Agent.

**Expected Outcomes**
- `bobguard-agent/report_generator.py` exports `generate_report(findings: list[dict], diff_source: str) -> dict` and `write_report(report: dict, output_path: str | Path)`.
- `write_report` saves to the given path AND prints the JSON to stdout.
- The JSON schema is:
  ```json
  {
    "tool": "BobGuard",
    "version": "1.0.0",
    "diff_source": "<branch or file name>",
    "findings_count": 3,
    "findings": [
      {
        "rule": "aws-access-key",
        "line_no": 12,
        "line": "...",
        "matched": "AKIAIOSFODNN7EXAMPLE"
      }
    ]
  }
  ```
- Running `python report_generator.py` prints a sample report to stdout.

**Todo List**
1. Implement `generate_report(findings, diff_source)` — build and return the dict above.
2. Implement `write_report(report, output_path)` — serialize to JSON with `indent=2`, write file, then `print()` to stdout.
3. Add a `__main__` block with a sample finding to demonstrate output.

**Relevant Context**
- `output_path` defaults to `Path("bobguard-report.json")` in the repo root (CWD at hook runtime).
- Keep the schema stable — Bob Agent parses the `findings` array.

---

### Task 4 — `hook_manager.py`

**Status:** `[ ] pending`

**Intent**
Provide `install` and `run` sub-commands. `install` writes `.git/hooks/pre-commit`. `run` is invoked by the hook: it captures the git diff, calls scanner and report generator, and exits non-zero if findings exist (blocking the commit).

**Expected Outcomes**
- `python hook_manager.py install` writes an executable `.git/hooks/pre-commit` that calls `python <abs-path>/hook_manager.py run`.
- `python hook_manager.py run` runs `git diff --cached --unified=0`, passes lines to `scanner.scan_diff`, calls `report_generator.write_report`, prints a summary, and exits `1` if `findings_count > 0`.
- `python hook_manager.py install` is idempotent (safe to re-run).

**Todo List**
1. Implement `install(repo_root: Path)` — locate `.git/hooks/`, write the shell script with the absolute path to `hook_manager.py`, set executable bit via `os.chmod`.
2. Implement `run(repo_root: Path)` — call `subprocess.run(["git", "diff", "--cached", "--unified=0"], capture_output=True, text=True)`, split stdout into lines, pass to `scanner.scan_diff`.
3. Call `report_generator.generate_report` and `write_report` inside `run`.
4. Print a human-readable summary to stderr (findings table or "No secrets found.").
5. `sys.exit(1)` when findings exist; `sys.exit(0)` otherwise.
6. Add `__main__` dispatch: `sys.argv[1]` routes to `install` or `run`; print usage otherwise.

**Relevant Context**
- `repo_root` is determined at runtime as the directory containing `.git/` (walk up from `__file__`).
- On Windows, the pre-commit hook is a bash script (`#!/bin/sh`); Git for Windows ships bash.
- `os.chmod(hook_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)` sets `755` permissions.

---

## Task Dependency Order

```
Task 1 (requirements.txt) ── independent
Task 2 (scanner.py)        ── independent
Task 3 (report_generator)  ── independent
Task 4 (hook_manager)      ── depends on Task 2 and Task 3
```

Tasks 1–3 can be implemented in parallel; Task 4 must come last.
