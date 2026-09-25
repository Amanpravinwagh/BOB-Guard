# BobGuard 🛡️

**BobGuard** is an agentic DevSecOps security gatekeeper that intercepts Git commits, scans staged diffs for hardcoded credentials and SQL injection risks, and leverages **IBM Bob** for autonomous self-healing code remediation.

---

## 🚀 Overview

Traditional static analysis tools report vulnerabilities after they enter the codebase or CI/CD pipelines. **BobGuard** shifts security left to the local developer environment:
1. **Interception:** A Git pre-commit hook pauses commits instantly upon running `git commit`.
2. **Detection:** A lightweight Python static engine uses regex pattern matching and Shannon entropy calculations on staged diffs (`git diff --cached`).
3. **Structured Audit:** Flags findings into a standard JSON security report (`bobguard-report.json`).
4. **Autonomous Self-Healing:** **IBM Bob** parses the report findings, refactors non-compliant code (e.g., swapping hardcoded credentials for `os.getenv` environment variables), and allows the re-scanned commit to pass cleanly.

---

## ✨ Key Features

* **Zero-Trust Pre-Commit Hook:** Automatic interception before sensitive data enters Git history.
* **High-Entropy Secret Detection:** Detects high-randomness strings (API keys, tokens, private keys) alongside known regex patterns (AWS keys, DB URIs).
* **SQL Injection Guard:** Identifies unsafe inline dynamic SQL constructions in staged changes.
* **Agentic Remediation via IBM Bob:** Seamless integration with IBM Bob's agentic loop to automatically remediate flagged code without manual developer intervention.
* **JSON Audit Artifacts:** Standardized machine-readable outputs for compliance reporting.

---

## 🛠️ Tech Stack

* **Language:** Python 3.x
* **Core Modules:** `re` (Pattern Matching), `math` (Shannon Entropy Analysis), `subprocess` (Git CLI Execution)
* **Agentic AI:** IBM Bob (Agent Mode)
* **DevSecOps & VCS:** Git Hooks (`.git/hooks/pre-commit`)
* **Data Format:** JSON
bobguard-agent/
├── scanner.py             # Core detection engine (regex + Shannon entropy)
├── hook_manager.py        # Lifecycle installer for Git pre-commit hooks
├── report_generator.py    # Structured JSON report builder
├── requirements.txt       # Dependencies
├── bobguard-report.json   # Output report artifact (generated on blocked commits)
└── README.md              # Project documentation


---

## 📦 Installation & Setup

1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/YOUR_USERNAME/BobGuard.git](https://github.com/YOUR_USERNAME/BobGuard.git)
   cd BobGuard
Set Up Virtual Environment:

PowerShell
python -m venv venv
.\venv\Scripts\Activate.ps1
Install Dependencies:

Bash
pip install -r requirements.txt
Install the Pre-Commit Hook:

Bash
python hook_manager.py install
🧪 Demonstration / Workflow
1. Detection & Blocking
When a developer accidentally commits a file containing a hardcoded secret:

PowerShell
# Stage a file with a secret key
git add test_secret.py
git commit -m "add AWS configuration"
Result: BobGuard intercepts the commit, outputs the security scan report in the terminal, generates bobguard-report.json, and blocks the commit with a non-zero exit code.

2. Autonomous Self-Healing
Prompt IBM Bob inside VS Code using bobguard-report.json:

"Fix the security vulnerabilities flagged in bobguard-report.json."

IBM Bob refactors test_secret.py to fetch credentials securely via environment variables:

Python
import os
AWS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
3. Validation & Commit Approval
PowerShell
git add test_secret.py
git commit -m "fix: load AWS key from environment variable"
Result: BobGuard re-scans the staged diff, finds 0 findings, prints No secrets or SQL risks found, and allows the commit to complete successfully.


---

### What to do with this file:
Save this directly as `README.md` in your project root directory (`bobguard-agent/`). It covers everything required for both your GitHub repository and your lablab.ai submission text!
--.
