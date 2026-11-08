# Security Policy

## Supported project

SYSTEM SCANNER V2 — CYBER COMMAND is experimental software. It has not undergone a professional security audit, and its Windows PowerShell collectors and repair actions require testing on real Windows 10/11 systems.

## Reporting a vulnerability

Please use GitHub's **Private vulnerability reporting** feature (when enabled for this repository) rather than opening a public issue containing exploit details. Include:

- A concise description and affected component.
- Reproduction steps and relevant sanitized error output.
- The potential security impact.
- A suggested mitigation, if known.

Do not include passwords, tokens, private diagnostic exports, usernames, private paths, or other personal information.

## Security principles

Contributions should preserve these project principles:

1. Local-first processing; no hidden telemetry or automatic uploads.
2. Explicit consent before scans and separate confirmation before repairs.
3. Narrowly allowlisted file and startup actions.
4. No silent persistence, surveillance, keylogging, or automatic mass deletion.
5. Clear separation between confirmed security-product detections and suspicious indicators.
6. Graceful failure when a check is unavailable or permission is insufficient.

## Scope

Reports are welcome for the Python local server, PowerShell collectors, browser dashboard, consent controls, local API, quarantine/restore logic, and documentation.

Only test on systems and files you own or are authorized to administer. Keep Microsoft Defender or another trusted antivirus enabled; this project is not a replacement for endpoint protection.