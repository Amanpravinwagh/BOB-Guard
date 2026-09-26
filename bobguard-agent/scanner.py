"""
scanner.py — BobGuard core detection engine.

Scans lines from a unified git diff for hardcoded secrets, dangerous DB URIs,
raw SQL string concatenation, and SQL injection payloads.

Detection strategies
--------------------
  1. Regex patterns (PATTERNS list) — each rule carries a compiled regex that
     is applied to the content portion of every added diff line (lines that
     begin with '+', excluding the '+++' file-header lines).

  2. Shannon entropy heuristic — any whitespace/punctuation-delimited token
     that is at least 20 characters long and has entropy >= 4.5 bits is
     flagged as a potential unrecognised secret.

Patterns covered
----------------
  - AWS Access Key ID       AKIA[0-9A-Z]{16}
  - AWS Secret Access Key   context keyword near a 40-char base64 value
  - OpenAI API key          sk-... (32-64 alphanumeric chars)
  - Generic API key         api_key / apikey / api-key assignment
  - PostgreSQL URI          postgres[ql]://user:pass@host/db
  - MySQL URI               mysql[+driver]://user:pass@host/db
  - Generic DB URL env var  DATABASE_URL / DB_URL / DB_URI assignment
  - SQL string concat       SQL keyword followed by string + variable concat
  - SQL injection payload   UNION SELECT, DROP TABLE, ;--, OR 1=1, etc.
  - High-entropy token      Shannon entropy >= 4.5, length >= 20

Public API
----------
    scan_diff(lines: list[str]) -> list[dict]

Each finding dict:
    {
        "rule":    str,   # rule identifier, e.g. "aws-access-key-id"
        "line_no": int,   # 1-based position within the supplied lines list
        "line":    str,   # full original diff line (rstripped)
        "matched": str    # the specific token / substring that matched
    }
"""

import math
import re
from typing import Optional

# ---------------------------------------------------------------------------
# Regex pattern registry
# ---------------------------------------------------------------------------

PATTERNS: list[dict] = [
    # ------------------------------------------------------------------
    # AWS credentials
    # ------------------------------------------------------------------
    {
        "rule": "aws-access-key-id",
        # 20-char key: fixed prefix AKIA + 16 uppercase alphanumeric chars
        "regex": re.compile(r"AKIA[0-9A-Z]{16}"),
    },
    {
        "rule": "aws-secret-key",
        # Context: word "aws" … "secret" … quoted 40-char base64 value
        "regex": re.compile(
            r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"
        ),
    },
    # ------------------------------------------------------------------
    # API keys
    # ------------------------------------------------------------------
    {
        "rule": "openai-api-key",
        # Standard OpenAI key format: sk- followed by 32-64 alphanumeric chars
        "regex": re.compile(r"sk-[a-zA-Z0-9]{32,64}"),
    },
    {
        "rule": "generic-api-key",
        # Matches: api_key = "...", apikey: '...', api-key="..." (20+ char value)
        "regex": re.compile(
            r"(?i)(api_key|apikey|api[-_]key)\s*[=:]\s*['\"]?[0-9a-zA-Z\-_]{20,}"
        ),
    },
    # ------------------------------------------------------------------
    # Database connection URIs with embedded credentials
    # ------------------------------------------------------------------
    {
        "rule": "db-uri-postgres",
        # postgres://user:password@host/db  or  postgresql://...
        "regex": re.compile(r"postgres(?:ql)?://[^:]+:[^@]+@[^\s'\"]+"),
    },
    {
        "rule": "db-uri-mysql",
        # mysql://user:pass@host  or  mysql+pymysql://user:pass@host
        "regex": re.compile(r"mysql(?:\+[a-z]+)?://[^:]+:[^@]+@[^\s'\"]+"),
    },
    {
        "rule": "db-uri-generic",
        # Environment-variable style: DATABASE_URL = "..." (10+ char value)
        "regex": re.compile(
            r"(?i)(database_url|db_url|db_uri)\s*[=:]\s*['\"]?[^\s'\"]{10,}"
        ),
    },
    # ------------------------------------------------------------------
    # SQL risks
    # ------------------------------------------------------------------
    {
        "rule": "sql-string-concat",
        # SQL keyword near a string literal + concatenation operator OR f-string
        # e.g.  query = "SELECT * FROM users WHERE id = " + user_id
        #        sql = f"DELETE FROM {table}"
        "regex": re.compile(
            r"(?i)(select|insert\s+into|update|delete\s+from|from|where)\b"
            r".{0,80}"
            r'(["\'][^"\']{0,60}["\']?\s*\+\s*\w|f["\'][^"\']*\{)'
        ),
    },
    {
        "rule": "sql-injection-payload",
        # Classic SQLi payloads that should never appear in committed code
        "regex": re.compile(
            r"(?i)(union\s+select|drop\s+table|;\s*--|or\s+1\s*=\s*1|'\s*or\s*')"
        ),
    },
]

# ---------------------------------------------------------------------------
# Shannon entropy
# ---------------------------------------------------------------------------

_ENTROPY_MIN_LEN: int = 20
_ENTROPY_THRESHOLD: float = 4.5


def shannon_entropy(token: str) -> float:
    """Return the Shannon entropy (bits per symbol) of *token*."""
    if not token:
        return 0.0
    freq: dict[str, int] = {}
    for ch in token:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(token)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _entropy_findings(line_no: int, content: str) -> list[dict]:
    """
    Split *content* on whitespace/punctuation and flag any token whose length
    is >= _ENTROPY_MIN_LEN and whose entropy is >= _ENTROPY_THRESHOLD.
    """
    findings: list[dict] = []
    for token in re.split(r'[\s"\'=:,(){}\[\]<>!@#$%^&*;]+', content):
        if len(token) >= _ENTROPY_MIN_LEN and shannon_entropy(token) >= _ENTROPY_THRESHOLD:
            findings.append(
                {
                    "rule": "high-entropy",
                    "line_no": line_no,
                    "line": content,
                    "matched": token,
                }
            )
    return findings


# ---------------------------------------------------------------------------
# Core scanning functions
# ---------------------------------------------------------------------------

def scan_line(line_no: int, line: str) -> list[dict]:
    """
    Scan a single unified-diff line and return all findings.

    Only lines beginning with '+' are considered (added lines).  The '+++'
    file-header marker is excluded.  The leading '+' is stripped before
    matching so it does not interfere with patterns anchored at position 0.
    """
    stripped = line.rstrip()

    # Skip context lines, removed lines, and the +++ / --- file header
    if not stripped.startswith("+") or stripped.startswith("+++"):
        return []

    content = stripped[1:]  # remove the leading diff marker

    findings: list[dict] = []

    # Apply every regex pattern
    for pat in PATTERNS:
        m: Optional[re.Match] = pat["regex"].search(content)
        if m:
            findings.append(
                {
                    "rule": pat["rule"],
                    "line_no": line_no,
                    "line": stripped,
                    "matched": m.group(0),
                }
            )

    # Run entropy check only when no pattern matched (avoids duplicate entries)
    if not findings:
        findings.extend(_entropy_findings(line_no, content))

    return findings


def scan_diff(lines: list[str]) -> list[dict]:
    """
    Scan all *lines* from a unified git diff and return aggregated findings.

    Parameters
    ----------
    lines : list[str]
        Output of ``git diff --cached --unified=0``, split on newlines.
        Lines must retain their leading diff markers ('+', '-', ' ', '@@').

    Returns
    -------
    list[dict]
        All findings across all lines.  Each dict has keys:
        ``rule``, ``line_no``, ``line``, ``matched``.
    """
    all_findings: list[dict] = []
    for line_no, line in enumerate(lines, start=1):
        all_findings.extend(scan_line(line_no, line))
    return all_findings


# ---------------------------------------------------------------------------
# Self-test  (python scanner.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    _TEST_LINES = [
        # 1 — clean line: should produce NO findings
        "+# This is a harmless comment",
        # 2 — AWS Access Key ID
        "+AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'",
        # 3 — OpenAI API key
        "+OPENAI_KEY = 'sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGH'",
        # 4 — Raw SQL string concatenation
        "+query = \"SELECT * FROM users WHERE id = \" + user_id",
        # 5 — PostgreSQL URI with credentials
        "+DATABASE_URL = 'postgres://admin:s3cr3t@db.prod.example.com/mydb'",
        # 6 — removed line: must be IGNORED
        "-old_key = 'AKIAIOSFODNN7REMOVED1'",
        # 7 — context line: must be IGNORED
        " some_other_variable = 42",
        # 8 — high-entropy random string (no prefix match)
        "+token = xK9mP2nQ8rT5vW3yZ6jL1hN4qB7dF0eA",
    ]

    results = scan_diff(_TEST_LINES)

    sep = "-" * 64
    print(sep)
    print("BobGuard Scanner - self-test  ({} input lines)".format(len(_TEST_LINES)))
    print(sep)
    for f in results:
        print("  [{:26s}] line {:2d}  matched: {:.55s}".format(
            f["rule"], f["line_no"], f["matched"]))
    print(sep)
    print("Total findings: {}".format(len(results)))
    print()

    # --- assertions ---------------------------------------------------------
    rules = {f["rule"] for f in results}

    assert "aws-access-key-id" in rules, "FAIL: expected aws-access-key-id"
    assert "openai-api-key" in rules,    "FAIL: expected openai-api-key"
    assert "sql-string-concat" in rules, "FAIL: expected sql-string-concat"
    assert "db-uri-postgres" in rules,   "FAIL: expected db-uri-postgres"

    # Removed (line 6) and context (line 7) lines must produce no findings
    ignored_findings = [f for f in results if f["line_no"] in {6, 7}]
    assert not ignored_findings, "FAIL: removed/context lines must not produce findings"

    print("All assertions passed.")
