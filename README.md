# SYSTEM SCANNER V2 — CYBER COMMAND

A Windows-first, permission-based endpoint diagnostics dashboard with local live monitoring and an owner-controlled repair center. It uses an HTML/CSS/JavaScript interface, a Python standard-library server bound to `127.0.0.1`, and PowerShell collectors. No cloud service, telemetry endpoint, third-party JavaScript, or external hash lookup is used.

This is a diagnostic assistant, **not an antivirus, EDR, forensic suite, or guarantee that a computer is clean**. Microsoft Defender or another trusted security product should remain enabled.

## Dashboard preview

![SYSTEM SCANNER V2 dashboard preview](assets/dashboard-preview.png)


## Architecture choice

| Architecture | Can do | Cannot do / trade-off |
|---|---|---|
| Browser-only HTML/JS | Display dashboards, charts, imported reports and user-entered data | Browser sandbox prevents direct inventory of OS processes, RAM, services, registry, Defender and disk counters |
| HTML + local Python/PowerShell (this project) | Read native Windows diagnostics after consent; host a loopback-only dashboard; perform narrowly allowlisted repairs after a second confirmation | Requires a Windows collector; some telemetry and inventory require native cmdlets or permissions |
| Electron/native desktop | Package UI and native OS APIs as a desktop installer | Larger app and maintenance/security surface; still needs platform-specific collectors and a careful permission model |

The local server is the best fit for this Windows-first tool: small, inspectable, dependency-free and not exposed to the LAN. The browser is a presentation layer; the PowerShell collector does the Windows-specific work.

## Files

```text
system-health-scanner/
├── server.py              # Loopback-only HTTP API, scan orchestration, consent gates, repair allowlist
├── collector.ps1          # Windows scan modules (Defender, processes, startup, storage, etc.)
├── live.ps1               # Explicitly enabled live CPU/RAM/process/disk/network snapshot
├── index.html             # CYBER COMMAND UI, consent, live monitor, reports and repair center
├── run.bat                # Windows launcher
├── sample-report.json     # Synthetic illustrative report; not a real PC scan
└── README.md
```

## Requirements and run steps

- Windows 10 or Windows 11 for the full feature set.
- Python 3.10+ (3.11+ recommended); no pip packages are required.
- Windows PowerShell 5.1 (normally included) or PowerShell 7.

1. Clone this repository, or extract the source archive to a folder you control, e.g. `C:\Tools\system-health-scanner`:

   ```powershell
   git clone https://github.com/miserymart58-del/system-scanner-cyber-command.git
   cd system-scanner-cyber-command
   ```

2. Keep `server.py`, `collector.ps1`, `live.ps1`, `index.html`, and `run.bat` together.
3. Double-click `run.bat`. Alternatively, open Command Prompt in the folder and run `py -3 server.py`.
4. Open `http://127.0.0.1:8765/` if the browser does not open automatically.
5. Read the scan categories. Every category starts unchecked. Select only the areas you wish to inspect, confirm that you own/administer the PC, and start the scan.
6. Live monitoring is a separate opt-in. Read its disclosure, tick the separate live-consent box and press **Start live monitor**. Stop it at any time.
7. Review the report. In **Smart repair center**, inspect every candidate's exact path and choose an individual action. The action log and restore controls are shown in **Quarantine & activity**.
8. Export JSON or print/save the report as PDF. Keep exported files private because they can contain usernames, local paths, filenames and IP addresses.
9. Close the Python console or press `Ctrl+C` to stop the local server.

Administrator privileges are not required to start the app. If a module cannot read a protected field, it reports the limitation. Use elevation only on a PC you own/administer and only where required for a specific check.

## Permission and privacy model

### Scan consent

No scan starts on page load. Each category checkbox is initially clear. The owner/authority checkbox plus the Start button are both required. The seven modules read:

| Module | Data read |
|---|---|
| Security | Defender status/signature timestamp/history metadata, registered antivirus provider names, firewall profiles, account posture, non-comment hosts-file mappings |
| Processes and network | Process names/PIDs/executable paths; established TCP IP/port endpoints; top-level executable/script filename/size/date metadata from Downloads and Temp |
| Startup and background | Run/RunOnce registry value names and parsed executable paths, current-user and shared Startup-folder item metadata, non-Microsoft scheduled-task action paths, automatic service metadata. Startup command strings are read locally to parse executable paths; raw arguments are excluded from scan output. |
| Storage | Volume capacity, disk health/reliability counters where supported, file metadata from common user folders and Temp, large-file candidates, up to 30 top-level Temp files older than 14 days as optional cleanup candidates |
| RAM and CPU | RAM counters, pagefile usage, top process memory, short CPU and working-set-growth samples |
| System integrity | OS/build, installed-program metadata, latest listed hotfix, restart indicators, account/admin counts, recent event IDs/provider names (not event messages) |
| Browser extensions | Extension name/ID/version/profile and declared permissions from supported Chrome, Edge and Firefox profiles |

The scanner does not read document contents, photos, passwords, cookies, browsing history, page contents, process command-line arguments or environment variables. Startup registry command strings are read locally to parse executable paths, but their raw arguments are not included in scan output. It does not upload data. It has no analytics, external APIs or third-party scripts.

### Live monitor consent

Live monitoring is separately disabled at startup. After separate consent, it samples:

- Total CPU usage using a short one-second performance-counter sample.
- Total/free physical RAM and top memory-consuming processes (names, PIDs and working-set sizes).
- Drive letters and free/total capacity.
- Network adapter cumulative byte counters, converted into an approximate combined send+receive throughput between samples.

The dashboard polls every four seconds while enabled. A snapshot can take about a second because CPU is sampled. Process CPU values are cumulative CPU seconds, not instantaneous process percentages. GPU load/temperature is not measured by this universal collector. Stop the monitor to stop subsequent sampling.

### Repair consent and action restrictions

All repairs are off until the user scans, reviews a candidate and confirms one action. The browser submits only a server-generated candidate ID; it cannot submit an arbitrary path. The server rechecks the file's approved location, regular-file status, size and timestamp immediately before acting. The storage scan can list up to 30 top-level Temp files older than 14 days; age is only a review hint, not proof that the file is safe to remove.

| Action | What happens | Safeguards |
|---|---|---|
| Quarantine file | Moves one exact scanned file into the app's local quarantine folder; file is renamed to an extensionless ID | Separate confirmation; file must still match its scan metadata; can be restored if the original location is available |
| Permanent delete | Permanently unlinks one exact scanned file | Only files under the current user's Downloads or Temp folders; separate confirmation plus typing `DELETE PERMANENTLY`; cannot be restored by this tool |
| Disable startup | Removes one allowlisted current-user Run/RunOnce registry string value, or moves one current-user Startup-folder item into quarantine | Does not touch HKLM machine-wide Run keys, services, scheduled tasks, security products or drivers; can restore the saved value/item |
| Restore | Restores one app-quarantined file or startup entry | Separate confirmation; never overwrites an existing file or registry value; requires original parent folder to exist |

Quarantine files and its manifest/action log are stored under `%LOCALAPPDATA%\SystemHealthScanner\quarantine`. For a disabled Run-key entry, the full original registry value (which may contain arguments) is stored in the local manifest so it can be restored. This occurs only after the separate action is explicitly confirmed; it is never uploaded. The app does not automatically purge quarantine. This is a reversible holding area, **not a malware-proof vault**; do not open quarantined unknown files. Standard Windows user-account permissions apply.

The file actions are intentionally narrow. Permanent deletion is never offered for files outside Downloads/Temp. Older Temp files are optional review candidates only; in-use or unfamiliar files should be left alone. Startup disable is limited to the current user's Run/RunOnce keys and Startup folder. There is no “clean all”, no mass-delete, no terminate-process button, no service-disable action, no uninstall action and no changes to Defender, firewall, hosts, Windows system files or machine-wide startup keys.

The optional Defender Quick Scan checkbox is separate from read-only collection and has an additional confirmation. Defender itself controls any remediation according to its existing policy.

## Findings, score and false positives

Findings include severity, plain-language explanation, evidence, recommended action, classification and confidence. Suspicious process locations, extension permissions, hosts mappings, or executable filenames are **review indicators only**; no file is declared malware based on name or location. A Defender history record is historical evidence and does not prove the threat remains active.

The score is a transparent triage heuristic: `100 - up to 60 points for Critical findings (25 each) - up to 30 points for Warnings (8 each) - up to 10 points for Info (1 each)`, clamped to 0–100. It is not a malware probability, certification or guarantee of safety. Only selected, completed checks are represented. It is withheld for reduced mode, cancelled/incomplete scans or failed selected modules.

Slowness hypotheses are ranked using measured free disk space, available RAM at sample time, startup-entry count and a short CPU sample. One sample cannot prove a persistent issue or memory leak; repeat monitoring during actual slowdowns before changing settings or buying hardware.

## Cross-platform behavior

- **Windows 10/11:** full PowerShell scan modules, live monitor and bounded repair center.
- **macOS/Linux:** reduced basic snapshot only (OS details, root volume, RAM and process names where supported). Windows security, Defender, firewall, Windows startup registry, scheduled tasks, event logs, live PowerShell monitor and repair actions are not available. The UI labels these limitations rather than claiming a malware scan occurred.

## Validation and limitations

The package is validated for Python compilation, HTML/JavaScript syntax, local API consent gating and reduced-mode API smoke tests. The live Windows PowerShell scripts cannot be executed in this Linux build environment, so the full Windows runtime has not been verified on a real Windows PC. Please test on a non-critical Windows machine or with known disposable files before using repair actions on important data.

Other limitations:

- This is not an antivirus engine, EDR, forensic suite or malware removal tool. Run Microsoft Defender or another trusted antivirus independently.
- No file content scanning, duplicate hashing, VirusTotal/hash lookup or browser history collection.
- Folder metadata walks are bounded by time and file count; partial scans are labelled.
- SMART/reliability fields vary by device, controller and driver.
- Windows Update completeness is approximated; the latest listed hotfix and pending-restart markers do not prove full update compliance.
- Short CPU/RAM samples do not identify thermal throttling, GPU bottlenecks, driver faults or all intermittent issues.
- Quarantine movement can fail for files locked by an application, and restores can fail if the original path is no longer available.

## Troubleshooting

- **Browser cannot connect:** keep the Python console open and navigate to `http://127.0.0.1:8765/`.
- **PowerShell unavailable:** check that `powershell.exe` or `pwsh.exe` is installed and available on PATH.
- **Port already in use:** close another instance or change `PORT` in `server.py` and use the same port in the browser endpoint.
- **A scan/action is unavailable:** read the module note or the exact action error. No change should be assumed unless the dashboard reports success.
- **Quarantine manifest error:** repair actions stop rather than treating a corrupt manifest as empty. Back up the `quarantine` folder before manual recovery.

## Publishing your fork or repository

The repository owner can use the included Windows helper script to publish the project while preserving existing remote history and unrelated files:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\publish-to-github.ps1
```

The script requires Git for Windows and GitHub authentication configured locally (for example, Git Credential Manager). It clones the remote repository first, copies only the documented project files, displays the pending Git changes, and requires typing `PUSH` before committing and pushing. It does not ask for or store a GitHub token. Review the displayed file list before approving.