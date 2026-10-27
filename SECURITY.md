# Security Policy

## Reporting a vulnerability

Please do not publish credentials, private project data, or detailed exploit material in a public issue.

For a vulnerability in Scan itself, use GitHub's private vulnerability reporting / security advisory flow for this repository when available. If that channel is unavailable, contact the repository owner privately before disclosing sensitive technical details publicly.

## Scope

Security reports are especially useful for issues involving:

- unsafe execution of inspected target content;
- archive traversal or decompression handling;
- secret exposure in generated reports;
- unsafe parsing or deserialization;
- evidence/state injection that could misrepresent scan results;
- validator behavior that accepts structurally misleading state.

Scan is designed around static-first inspection. A generated report or validator `PASS` is not a security certification of the inspected target.
