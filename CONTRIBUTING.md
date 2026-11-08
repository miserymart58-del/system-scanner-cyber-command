# Contributing

Thank you for considering a contribution to SYSTEM SCANNER V2 — CYBER COMMAND.

## Areas where contributions help

- Dashboard usability, accessibility, and responsive layout.
- Windows diagnostics and PowerShell reliability.
- Python API correctness and repair safeguards.
- Performance measurement and historical analysis.
- Cross-platform reduced-mode support.
- Documentation, test coverage, and reproducible bug reports.

## Development principles

### Privacy first

Do not add hidden telemetry, analytics, automatic uploads, credential collection, browser-history collection, or document-content inspection.

### Consent first

Every new scan category must state exactly what it reads and require explicit opt-in. Live monitoring requires its own opt-in. Any modifying action needs a distinct confirmation.

### Safe repair behavior

Use narrowly scoped allowlists, revalidate targets immediately before acting, and provide a recovery path where practical. Do not add mass deletion, arbitrary path actions, hidden startup persistence, process termination, or broad service-disabling behavior.

### Accurate findings

Do not label a process, extension, or file as malware based only on a filename, path, or heuristic. Separate confirmed detections from suspicious indicators and clearly state confidence and limitations.

### Graceful failure

Missing commands, unsupported operating systems, access-denied results, and partial scans must be reported instead of silently treated as clean results.

## Pull request checklist

- [ ] Explain the problem or feature and affected files.
- [ ] Document any new data collected or permissions required.
- [ ] Preserve the local-only and consent-based behavior.
- [ ] Test with disposable data or a non-critical environment.
- [ ] State which OS and PowerShell/Python versions were actually tested.
- [ ] Do not attach real diagnostic reports or other personal data.
- [ ] Update README and relevant documentation.

## Bug reports

Include the OS/version, Python version, PowerShell version, reproduction steps, expected behavior, actual behavior, and sanitized error messages. Remove usernames, private paths, IP addresses, and personal filenames before posting.