# BobGuard - Automated Security & Secret Leak Prevention Sensor

## Objective
Detect exposed API keys, hardcoded secrets, and SQL injection flaws in code diffs before commits are staged, and trigger IBM Bob to fix them autonomously.

## Components
1. scanner.py: RegEx & entropy-based scanner for secret leaks (AWS keys, OpenAI tokens, DB URIs).
2. hook_manager.py: Pre-commit hook trigger running static analysis on git diffs.
3. report_generator.py: Formats security output into structured JSON for IBM Bob Agent input.