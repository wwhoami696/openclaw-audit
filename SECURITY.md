# Security Policy

## Scope

This tool is a **read-only defensive auditor** — it inspects your local filesystem, running processes, and config files. It does not:

- Make network requests (except `npm view` for version checks)
- Write or modify any files
- Execute commands that could cause harm
- Collect or transmit any data

## Reporting a Vulnerability

If you find a security issue in this tool itself (e.g. a path traversal in how we read config files, or a command injection in how we run shell commands):

1. **Do not open a public issue**
2. Email the maintainer or open a [GitHub Security Advisory](https://docs.github.com/en/code-security/security-advisories)
3. Include: description, reproduction steps, potential impact

We'll respond within 48 hours and coordinate a fix + disclosure.

## Responsible Use

This tool is intended **only for auditing your own OpenClaw installation**. Using it against systems you do not own or have explicit permission to test may violate computer fraud laws in your jurisdiction.
