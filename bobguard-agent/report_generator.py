"""
report_generator.py — BobGuard structured JSON report formatter.

Converts the raw findings list produced by scanner.scan_diff() into a
structured JSON payload that IBM Bob Agent can consume directly.

JSON schema
-----------
{
    "tool":           "BobGuard",
    "version":        "1.0.0",
    "diff_source":    "<staged diff / branch name / file path>",
    "findings_count": <int>,
    "findings": [
        {
            "rule":    "<rule-id>",
            "line_no": <int>,
            "line":    "<full diff line>",
            "matched": "<matched token>"
        },
        ...
    ]
}

Public API
----------
    generate_report(findings: list[dict], diff_source: str) -> dict
    write_report(report: dict, output_path: str | Path = "bobguard-report.json")

write_report() writes the JSON file to *output_path* AND prints it to stdout
so that IBM Bob Agent can capture the output via pipe.
"""

import json
import sys
from pathlib import Path
from typing import Union

_TOOL_NAME = "BobGuard"
_TOOL_VERSION = "1.0.0"
_DEFAULT_OUTPUT = Path("bobguard-report.json")


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

def generate_report(findings: list[dict], diff_source: str) -> dict:
    """
    Build and return the BobGuard report dict.

    Parameters
    ----------
    findings : list[dict]
        Output of scanner.scan_diff().  Each dict must have keys:
        ``rule``, ``line_no``, ``line``, ``matched``.
    diff_source : str
        Human-readable label for the diff origin, e.g. "staged changes",
        a branch name, or a file path.

    Returns
    -------
    dict
        Fully populated report dictionary.
    """
    return {
        "tool": _TOOL_NAME,
        "version": _TOOL_VERSION,
        "diff_source": diff_source,
        "findings_count": len(findings),
        "findings": findings,
    }


def write_report(
    report: dict,
    output_path: Union[str, Path] = _DEFAULT_OUTPUT,
) -> None:
    """
    Serialise *report* to JSON, write it to *output_path*, and print to stdout.

    Parameters
    ----------
    report : dict
        Return value of generate_report().
    output_path : str or Path
        Destination file.  Defaults to ``bobguard-report.json`` in the current
        working directory (which is the repo root at hook runtime).
    """
    json_text = json.dumps(report, indent=2)

    # Write file
    output_path = Path(output_path)
    output_path.write_text(json_text, encoding="utf-8")

    # Print to stdout for IBM Bob Agent to capture via pipe
    print(json_text)


# ---------------------------------------------------------------------------
# Self-test  (python report_generator.py)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    _SAMPLE_FINDINGS = [
        {
            "rule": "aws-access-key-id",
            "line_no": 3,
            "line": "+AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'",
            "matched": "AKIAIOSFODNN7EXAMPLE",
        },
        {
            "rule": "db-uri-postgres",
            "line_no": 7,
            "line": "+DATABASE_URL = 'postgres://admin:s3cr3t@db.prod.example.com/mydb'",
            "matched": "postgres://admin:s3cr3t@db.prod.example.com/mydb",
        },
        {
            "rule": "sql-string-concat",
            "line_no": 12,
            "line": '+query = "SELECT * FROM users WHERE id = " + user_id',
            "matched": 'SELECT * FROM users WHERE id = " + user_id',
        },
    ]

    report = generate_report(_SAMPLE_FINDINGS, diff_source="staged changes (demo)")

    sep = "-" * 64
    print(sep, file=sys.stderr)
    print("BobGuard ReportGenerator - self-test", file=sys.stderr)
    print(sep, file=sys.stderr)

    # write_report prints JSON to stdout and writes bobguard-report.json
    import tempfile, os
    tmp = Path(tempfile.mktemp(suffix=".json"))
    write_report(report, output_path=tmp)

    # Verify round-trip
    loaded = json.loads(tmp.read_text(encoding="utf-8"))
    assert loaded["tool"] == "BobGuard",         "FAIL: tool field mismatch"
    assert loaded["version"] == "1.0.0",          "FAIL: version field mismatch"
    assert loaded["findings_count"] == 3,         "FAIL: findings_count mismatch"
    assert len(loaded["findings"]) == 3,          "FAIL: findings array length mismatch"
    assert loaded["findings"][0]["rule"] == "aws-access-key-id", "FAIL: rule mismatch"

    os.unlink(tmp)

    print(sep, file=sys.stderr)
    print("All assertions passed.", file=sys.stderr)
