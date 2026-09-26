"""
hook_manager.py — BobGuard git pre-commit hook installer and runner.

Sub-commands
------------
    python hook_manager.py install
        Writes an executable shell script to .git/hooks/pre-commit that
        invokes ``python <abs-path>/hook_manager.py run`` at every commit.
        Safe to re-run (idempotent).

    python hook_manager.py run
        Called automatically by the pre-commit hook.
        Captures ``git diff --cached --unified=0``, passes the lines to
        scanner.scan_diff(), formats the report via report_generator, writes
        bobguard-report.json, and exits 1 when findings exist (blocking the
        commit).

    python hook_manager.py --help | -h | (no args)
        Prints usage information.

Dependencies (all stdlib + sibling modules)
-------------------------------------------
    scanner          — scan_diff()
    report_generator — generate_report(), write_report()
    subprocess       — run git diff
    sys              — argv dispatch and exit codes
    os / stat        — chmod the hook file to 755
    pathlib          — cross-platform path handling
"""

import os
import stat
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Locate sibling modules regardless of CWD
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import scanner           # noqa: E402  (must come after sys.path patch)
import report_generator  # noqa: E402

# ---------------------------------------------------------------------------
# Pre-commit shell script template
# ---------------------------------------------------------------------------
_HOOK_TEMPLATE = """\
#!/bin/sh
# BobGuard pre-commit hook — auto-generated, do not edit manually.
# Re-run `python {hook_manager_path} install` to update.
python "{hook_manager_path}" run
"""

_HOOK_PERMS = (
    stat.S_IRWXU  # owner:  rwx
    | stat.S_IRGRP | stat.S_IXGRP   # group:  r-x
    | stat.S_IROTH | stat.S_IXOTH   # others: r-x
)  # => 0o755


# ---------------------------------------------------------------------------
# Helper: find the repo root (first ancestor that contains a .git directory)
# ---------------------------------------------------------------------------

def _find_repo_root(start: Path) -> Path:
    """Walk up from *start* until a directory containing '.git' is found."""
    current = start.resolve()
    for candidate in [current, *current.parents]:
        if (candidate / ".git").exists():
            return candidate
    raise RuntimeError(
        f"Could not find a git repository root above: {start}\n"
        "Run `git init` first, or execute hook_manager.py from inside a git repo."
    )


# ---------------------------------------------------------------------------
# install sub-command
# ---------------------------------------------------------------------------

def install(repo_root: Path) -> None:
    """
    Write (or overwrite) .git/hooks/pre-commit with the BobGuard hook script.

    Parameters
    ----------
    repo_root : Path
        Root directory of the target git repository (contains the .git/ dir).
    """
    hooks_dir = repo_root / ".git" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)

    hook_path = hooks_dir / "pre-commit"
    hook_manager_abs = Path(__file__).resolve()

    script = _HOOK_TEMPLATE.format(hook_manager_path=str(hook_manager_abs))
    hook_path.write_text(script, encoding="utf-8")
    os.chmod(hook_path, _HOOK_PERMS)

    print(f"[BobGuard] pre-commit hook installed at: {hook_path}")
    print(f"           runs: python {hook_manager_abs} run")


# ---------------------------------------------------------------------------
# run sub-command
# ---------------------------------------------------------------------------

def run(repo_root: Path) -> None:
    """
    Capture staged diff, scan for secrets, write report, and block commit on
    any findings.

    Parameters
    ----------
    repo_root : Path
        Root directory of the target git repository.
    """
    # 1. Capture staged diff
    result = subprocess.run(
        ["git", "diff", "--cached", "--unified=0"],
        capture_output=True,
        text=True,
        cwd=str(repo_root),
    )

    if result.returncode != 0:
        print(f"[BobGuard] git diff failed: {result.stderr.strip()}", file=sys.stderr)
        sys.exit(1)

    lines = result.stdout.splitlines()

    # 2. Scan diff lines
    findings = scanner.scan_diff(lines)

    # 3. Generate and write JSON report to repo root
    report = report_generator.generate_report(
        findings, diff_source="staged changes"
    )
    report_path = repo_root / "bobguard-report.json"
    report_generator.write_report(report, output_path=report_path)

    # 4. Print human-readable summary to stderr (visible in the terminal)
    sep = "-" * 64
    print(sep, file=sys.stderr)
    print("BobGuard Security Scan", file=sys.stderr)
    print(sep, file=sys.stderr)

    if findings:
        print(
            "  {:<26}  {:>4}  MATCHED".format("RULE", "LINE"),
            file=sys.stderr,
        )
        print("  {}  {}  {}".format("-"*26, "-"*4, "-"*30), file=sys.stderr)
        for f in findings:
            print(
                "  {:<26}  {:>4}  {:.50s}".format(
                    f["rule"], f["line_no"], f["matched"]),
                file=sys.stderr,
            )
        print(sep, file=sys.stderr)
        print(
            "  {} finding(s) detected. Commit BLOCKED.".format(len(findings)),
            file=sys.stderr,
        )
        print("  Report written to: {}".format(report_path), file=sys.stderr)
        print(sep, file=sys.stderr)
        sys.exit(1)
    else:
        print("  No secrets or SQL risks found.", file=sys.stderr)
        print(sep, file=sys.stderr)
        sys.exit(0)


# ---------------------------------------------------------------------------
# __main__ dispatch
# ---------------------------------------------------------------------------

_USAGE = """\
BobGuard hook_manager — pre-commit hook installer and runner

Usage:
  python hook_manager.py install   Write .git/hooks/pre-commit for this repo
  python hook_manager.py run       Run the scanner on staged changes (used by hook)
  python hook_manager.py --help    Show this message

Setup (run once per repository you want to protect):
  python path/to/hook_manager.py install

After install, every `git commit` will automatically trigger BobGuard.
Findings are printed to stderr and written to bobguard-report.json.
"""

if __name__ == "__main__":
    args = sys.argv[1:]

    if not args or args[0] in ("--help", "-h", "help"):
        print(_USAGE)
        sys.exit(0)

    cmd = args[0]

    try:
        repo_root = _find_repo_root(Path.cwd())
    except RuntimeError as exc:
        print(f"[BobGuard] Error: {exc}", file=sys.stderr)
        sys.exit(1)

    if cmd == "install":
        install(repo_root)
    elif cmd == "run":
        run(repo_root)
    else:
        print(f"[BobGuard] Unknown command: {cmd!r}", file=sys.stderr)
        print(_USAGE, file=sys.stderr)
        sys.exit(1)
