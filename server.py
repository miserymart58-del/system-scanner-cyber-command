#!/usr/bin/env python3
"""Local-only web server for the Windows System Health Scanner.

Uses only the Python standard library. It binds to loopback and starts PowerShell
collectors only after a user submits the dashboard consent form.
"""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import secrets
import uuid
import stat
import hashlib
from datetime import datetime
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
HTML_PATH = ROOT / "index.html"
COLLECTOR_PATH = ROOT / "collector.ps1"
LIVE_COLLECTOR_PATH = ROOT / "live.ps1"
HOST = "127.0.0.1"
PORT = 8765
VALID_MODULES = {
    "security", "processes", "startup", "storage", "performance", "integrity", "browser"
}
MODULE_LABELS = {
    "security": "Security baseline",
    "processes": "Processes and network",
    "startup": "Startup and background items",
    "storage": "Storage and file metadata",
    "performance": "RAM and CPU",
    "integrity": "System integrity and logs",
    "browser": "Browser extensions",
}


class ScanState:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.running = False
        self.cancel_requested = False
        self.current_process: subprocess.Popen[str] | None = None
        self.data: dict[str, Any] = {
            "running": False,
            "cancelled": False,
            "progress": 0,
            "phase": "Ready",
            "modules": [],
            "report": None,
            "error": None,
        }
        self.worker: threading.Thread | None = None

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return json.loads(json.dumps(self.data))

    def update(self, **changes: Any) -> None:
        with self.lock:
            self.data.update(changes)


STATE = ScanState()
APP_TOKEN = secrets.token_urlsafe(32)

# Repair controls are intentionally constrained to exact paths and per-user
# startup values returned by the most recent consented scan.
ACTION_LOCK = threading.RLock()
ACTION_CANDIDATES: dict[str, dict[str, Any]] = {}
LIVE_ENABLED = False
LIVE_FETCH_LOCK = threading.Lock()
LIVE_STATE: dict[str, Any] = {"lastNetworkBytes": None, "lastNetworkTime": None}


def app_data_dir() -> Path:
    root = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / ".local"))
    return root / "SystemHealthScanner"


def manifest_path() -> Path:
    return app_data_dir() / "quarantine" / "manifest.json"


def load_manifest() -> dict[str, Any]:
    path = manifest_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            data.setdefault("items", [])
            data.setdefault("history", [])
            return data
    except FileNotFoundError:
        pass
    except Exception:
        # A corrupt manifest is never treated as an empty quarantine. This
        # prevents overwriting or silently losing recovery information.
        raise RuntimeError("The local quarantine manifest cannot be read. Do not run repair actions until it is recovered.")
    return {"items": [], "history": []}


def save_manifest(data: dict[str, Any]) -> None:
    path = manifest_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(temp, path)


def log_action(manifest: dict[str, Any], action: str, title: str, detail: str, outcome: str = "Completed") -> None:
    manifest.setdefault("history", []).insert(0, {
        "id": uuid.uuid4().hex,
        "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "action": action,
        "title": title,
        "detail": detail,
        "outcome": outcome,
    })
    manifest["history"] = manifest["history"][:200]


def user_scan_roots() -> list[Path]:
    home = Path(os.environ.get("USERPROFILE") or Path.home())
    roots = [home / name for name in ("Desktop", "Downloads", "Documents", "Pictures", "Videos")]
    temp = Path(os.environ.get("TEMP") or os.environ.get("TMP") or (home / "AppData" / "Local" / "Temp"))
    roots.append(temp)
    appdata = Path(os.environ.get("APPDATA") or (home / "AppData" / "Roaming"))
    roots.append(appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
    return [r.resolve(strict=False) for r in roots]


def is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def canonical_candidate_file(raw_path: str) -> tuple[Path, os.stat_result] | None:
    if os.name != "nt" or not raw_path:
        return None
    try:
        candidate = Path(raw_path)
        if candidate.is_symlink() or not candidate.is_file():
            return None
        resolved = candidate.resolve(strict=True)
        if not any(is_within(resolved, root) for root in user_scan_roots()):
            return None
        info = resolved.stat()
        if not stat.S_ISREG(info.st_mode):
            return None
        # Reject Windows reparse-point files as well as symbolic links.
        if int(getattr(info, "st_file_attributes", 0)) & 0x400:
            return None
        return resolved, info
    except (OSError, RuntimeError, ValueError):
        return None


def build_repair_candidates(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Create server-owned candidate IDs; callers never submit arbitrary paths."""
    built: list[dict[str, Any]] = []
    lookup: dict[str, dict[str, Any]] = {}
    if os.name != "nt":
        return built

    with ACTION_LOCK:
        ACTION_CANDIDATES.clear()

        for module in report.get("modules", []):
            if module.get("status") != "ok":
                continue
            module_name = module.get("module")
            data = module.get("data") or {}

            file_rows: list[tuple[dict[str, Any], str, str]] = []
            if module_name == "storage":
                for row in data.get("largeFiles", []) or []:
                    file_rows.append((row, str(row.get("path") or ""), "Large file candidate"))
                for row in data.get("tempCleanupCandidates", []) or []:
                    file_rows.append((row, str(row.get("path") or ""), "Old temporary file candidate (age alone is not proof it is safe to remove)"))
            elif module_name == "processes":
                for row in data.get("riskyExtensionFiles", []) or []:
                    file_rows.append((row, str(row.get("fullPath") or ""), "Executable/script file in Downloads or Temp"))

            for row, raw_path, label in file_rows:
                checked = canonical_candidate_file(raw_path)
                if not checked:
                    continue
                path, info = checked
                scanned_size = row.get("sizeBytes")
                if scanned_size is not None and int(scanned_size) != int(info.st_size):
                    continue
                scanned_write = row.get("lastWrite")
                if scanned_write:
                    try:
                        scanned_epoch = datetime.fromisoformat(str(scanned_write).replace("Z", "+00:00")).timestamp()
                        if abs(scanned_epoch - info.st_mtime) > 2.0:
                            continue
                    except (ValueError, TypeError, OverflowError):
                        continue
                key = os.path.normcase(str(path))
                if key in lookup:
                    continue
                temp_download_roots = [
                    (Path(os.environ.get("USERPROFILE") or Path.home()) / "Downloads").resolve(strict=False),
                    Path(os.environ.get("TEMP") or os.environ.get("TMP") or (Path.home() / "AppData" / "Local" / "Temp")).resolve(strict=False),
                ]
                can_delete = any(is_within(path, r) for r in temp_download_roots)
                candidate_id = uuid.uuid4().hex
                public = {
                    "id": candidate_id,
                    "kind": "file",
                    "name": path.name,
                    "path": str(path),
                    "sizeBytes": int(info.st_size),
                    "modifiedAt": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(info.st_mtime)),
                    "source": label,
                    "canDelete": bool(can_delete),
                    "suggestedAction": "Review, then quarantine if unwanted. Filename or extension alone is not a malware verdict.",
                }
                internal = {
                    **public,
                    "expectedSize": int(info.st_size),
                    "expectedMtimeNs": int(info.st_mtime_ns),
                }
                ACTION_CANDIDATES[candidate_id] = internal
                lookup[key] = public
                built.append(public)

            if module_name == "startup":
                appdata = Path(os.environ.get("APPDATA") or "")
                current_startup = (appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup").resolve(strict=False)
                allowed_hkcu = {
                    r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run": r"Software\Microsoft\Windows\CurrentVersion\Run",
                    r"HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce": r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                }
                for row in data.get("startupItems", []) or []:
                    item_type = str(row.get("type") or "")
                    name = str(row.get("name") or "")
                    source = str(row.get("source") or "")
                    if not name:
                        continue
                    if item_type == "Registry Run" and source in allowed_hkcu and re.fullmatch(r"[0-9a-f]{64}", str(row.get("valueFingerprint") or "")):
                        candidate_id = uuid.uuid4().hex
                        public = {
                            "id": candidate_id,
                            "kind": "startup_registry",
                            "name": name,
                            "path": str(row.get("executable") or source),
                            "source": f"Current-user startup registry value ({source})",
                            "suggestedAction": "Disable this current-user auto-start entry. It can be restored from Quarantine & Activity.",
                        }
                        ACTION_CANDIDATES[candidate_id] = {
                            **public,
                            "registryKey": allowed_hkcu[source],
                            "valueName": name,
                            "valueFingerprint": str(row.get("valueFingerprint") or ""),
                        }
                        built.append(public)
                    elif item_type == "Startup folder":
                        checked = canonical_candidate_file(str(row.get("fullPath") or row.get("executable") or ""))
                        if not checked:
                            continue
                        path, info = checked
                        if not is_within(path, current_startup):
                            continue
                        candidate_id = uuid.uuid4().hex
                        public = {
                            "id": candidate_id,
                            "kind": "startup_file",
                            "name": name,
                            "path": str(path),
                            "sizeBytes": int(info.st_size),
                            "source": "Current-user Startup folder",
                            "suggestedAction": "Move this startup-folder item to quarantine to stop it launching at sign-in. It can be restored.",
                        }
                        ACTION_CANDIDATES[candidate_id] = {
                            **public,
                            "expectedSize": int(info.st_size),
                            "expectedMtimeNs": int(info.st_mtime_ns),
                        }
                        built.append(public)

    return built


def quarantine_file(candidate: dict[str, Any], reason: str) -> dict[str, Any]:
    checked = canonical_candidate_file(candidate.get("path", ""))
    if not checked:
        raise RuntimeError("The exact file is no longer present in an approved user folder, or it is a link/non-regular file.")
    path, info = checked
    if info.st_size != candidate.get("expectedSize") or info.st_mtime_ns != candidate.get("expectedMtimeNs"):
        raise RuntimeError("The file changed after the scan. Run a fresh scan before acting on it.")

    qroot = app_data_dir() / "quarantine" / "files"
    qroot.mkdir(parents=True, exist_ok=True)
    qid = uuid.uuid4().hex
    destination = qroot / f"{qid}.quarantined"
    entry = {
        "id": qid,
        "itemType": "file",
        "name": path.name,
        "originalPath": str(path),
        "quarantinePath": str(destination),
        "sizeBytes": int(info.st_size),
        "quarantinedAt": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "reason": reason,
        "status": "quarantined",
    }
    shutil.move(str(path), str(destination))
    return entry


def disable_registry_startup(candidate: dict[str, Any]) -> dict[str, Any]:
    if os.name != "nt":
        raise RuntimeError("Startup registry actions are available only on Windows.")
    try:
        import winreg
    except ImportError as exc:
        raise RuntimeError("Windows registry access is unavailable in this Python runtime.") from exc
    key_path = candidate.get("registryKey")
    value_name = candidate.get("valueName")
    if key_path not in (r"Software\Microsoft\Windows\CurrentVersion\Run", r"Software\Microsoft\Windows\CurrentVersion\RunOnce") or not value_name:
        raise RuntimeError("This startup registry target is outside the supported current-user allowlist.")
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
        value, value_type = winreg.QueryValueEx(key, value_name)
        if not isinstance(value, str) or value_type not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
            raise RuntimeError("This startup registry value is not a supported string value; it was left unchanged.")
        expected_fingerprint = str(candidate.get("valueFingerprint") or "")
        actual_fingerprint = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
        if not expected_fingerprint or not secrets.compare_digest(expected_fingerprint, actual_fingerprint):
            raise RuntimeError("The startup value changed after the scan. Run a fresh scan before disabling it.")
        winreg.DeleteValue(key, value_name)
    return {
        "id": uuid.uuid4().hex,
        "itemType": "startup_registry",
        "name": candidate.get("name", value_name),
        "originalPath": candidate.get("path"),
        "registryKey": key_path,
        "valueName": value_name,
        "registryData": value,
        "registryType": int(value_type),
        "quarantinedAt": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "reason": "Disabled by explicit user request",
        "status": "quarantined",
    }


def perform_repair(candidate_id: str, action: str, typed_confirmation: str = "") -> dict[str, Any]:
    with ACTION_LOCK:
        candidate = ACTION_CANDIDATES.get(candidate_id)
        if not candidate:
            raise RuntimeError("This item is not in the most recent scan's repair list. Run a fresh scan and review it again.")
        manifest = load_manifest()
        if action == "quarantine":
            if candidate.get("kind") != "file":
                raise RuntimeError("Quarantine is available for scanned files. Use Disable startup for startup entries.")
            entry = quarantine_file(candidate, "Moved to local quarantine by explicit user request")
            manifest["items"].append(entry)
            log_action(manifest, "Quarantine", entry["name"], entry["originalPath"])
            try:
                save_manifest(manifest)
            except Exception:
                try:
                    shutil.move(entry["quarantinePath"], entry["originalPath"])
                except Exception:
                    pass
                raise
            del ACTION_CANDIDATES[candidate_id]
            return {"success": True, "message": f"{entry['name']} was moved to local quarantine.", "item": entry}
        if action == "delete":
            if candidate.get("kind") != "file" or not candidate.get("canDelete"):
                raise RuntimeError("Permanent deletion is restricted to eligible files in Downloads or Temp. Use quarantine for this item.")
            if typed_confirmation != "DELETE PERMANENTLY":
                raise RuntimeError("Type DELETE PERMANENTLY in the confirmation prompt to authorize irreversible deletion.")
            checked = canonical_candidate_file(candidate.get("path", ""))
            if not checked:
                raise RuntimeError("The exact file is no longer present in an approved user folder.")
            path, info = checked
            if info.st_size != candidate.get("expectedSize") or info.st_mtime_ns != candidate.get("expectedMtimeNs"):
                raise RuntimeError("The file changed after the scan. Run a fresh scan before deleting it.")
            log_action(manifest, "Permanent delete", path.name, str(path), "Authorized by typed confirmation; filesystem operation pending")
            save_manifest(manifest)
            try:
                path.unlink()
            except Exception:
                log_action(manifest, "Permanent delete failed", path.name, str(path), "File was not deleted")
                save_manifest(manifest)
                raise
            manifest["history"][0]["outcome"] = "Deleted after typed confirmation"
            try:
                save_manifest(manifest)
            except Exception:
                # The pre-action log remains on disk if the final audit update fails.
                pass
            del ACTION_CANDIDATES[candidate_id]
            return {"success": True, "message": f"{path.name} was permanently deleted.", "item": None}
        if action == "disable_startup":
            registry_disabled = False
            if candidate.get("kind") == "startup_registry":
                entry = disable_registry_startup(candidate)
                registry_disabled = True
            elif candidate.get("kind") == "startup_file":
                entry = quarantine_file(candidate, "Current-user startup item disabled by moving it to quarantine")
                entry["itemType"] = "startup_file"
            else:
                raise RuntimeError("Only allowlisted current-user Run-key values and Startup-folder items can be disabled here.")
            manifest["items"].append(entry)
            log_action(manifest, "Disable startup", entry.get("name", "Startup item"), entry.get("originalPath", "Current-user startup"))
            try:
                save_manifest(manifest)
            except Exception:
                if registry_disabled:
                    try:
                        import winreg
                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, entry["registryKey"], 0, winreg.KEY_SET_VALUE) as key:
                            winreg.SetValueEx(key, entry["valueName"], 0, entry["registryType"], entry["registryData"])
                    except Exception:
                        pass
                else:
                    try:
                        shutil.move(entry["quarantinePath"], entry["originalPath"])
                    except Exception:
                        pass
                raise
            del ACTION_CANDIDATES[candidate_id]
            return {"success": True, "message": f"Startup item {entry.get('name')} was disabled. It can be restored from Quarantine & Activity.", "item": entry}
        raise RuntimeError("Unsupported repair action.")


def restore_quarantine_item(item_id: str) -> dict[str, Any]:
    with ACTION_LOCK:
        manifest = load_manifest()
        entry = next((x for x in manifest.get("items", []) if x.get("id") == item_id and x.get("status") == "quarantined"), None)
        if not entry:
            raise RuntimeError("That quarantine item is unavailable or has already been restored.")

        restored_registry = False
        restored_file = False
        original: Path | None = None
        stored: Path | None = None
        if entry.get("itemType") == "startup_registry":
            if os.name != "nt":
                raise RuntimeError("Windows registry restore is available only on Windows.")
            import winreg
            key_path = entry.get("registryKey")
            if key_path not in (r"Software\Microsoft\Windows\CurrentVersion\Run", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"):
                raise RuntimeError("The saved registry key is outside the supported allowlist.")
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE) as key:
                try:
                    winreg.QueryValueEx(key, entry["valueName"])
                    raise RuntimeError("A startup value with this name already exists. It was not overwritten.")
                except FileNotFoundError:
                    pass
                winreg.SetValueEx(key, entry["valueName"], 0, int(entry["registryType"]), str(entry["registryData"]))
            restored_registry = True
        else:
            original = Path(entry.get("originalPath", ""))
            stored = Path(entry.get("quarantinePath", ""))
            qroot = (app_data_dir() / "quarantine" / "files").resolve(strict=False)
            try:
                stored_resolved = stored.resolve(strict=True)
            except OSError:
                raise RuntimeError("The quarantined file is missing. The manifest was left unchanged.")
            if stored.is_symlink() or not is_within(stored_resolved, qroot) or not stored_resolved.is_file():
                raise RuntimeError("The quarantine file path is invalid or outside the app's quarantine folder.")
            roots = user_scan_roots()
            resolved_parent = original.parent.resolve(strict=False)
            if not any(is_within(resolved_parent, root) for root in roots):
                raise RuntimeError("The original destination is outside the approved user folders.")
            if original.exists():
                raise RuntimeError("A file already exists at the original location. It was not overwritten; move or rename that file first.")
            if not original.parent.exists():
                raise RuntimeError("The original folder no longer exists. It was not recreated automatically.")
            shutil.move(str(stored_resolved), str(original))
            restored_file = True

        entry["status"] = "restored"
        entry["restoredAt"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        log_action(manifest, "Restore", entry.get("name", "Quarantine item"), entry.get("originalPath", "Startup registry value"))
        try:
            save_manifest(manifest)
        except Exception:
            # Keep the persisted manifest and filesystem/registry state in sync
            # if the manifest write fails after a successful restore operation.
            if restored_registry:
                try:
                    import winreg
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, entry["registryKey"], 0, winreg.KEY_SET_VALUE) as key:
                        winreg.DeleteValue(key, entry["valueName"])
                except Exception:
                    pass
            elif restored_file and original and stored:
                try:
                    shutil.move(str(original), str(stored))
                except Exception:
                    pass
            raise
        return {"success": True, "message": f"{entry.get('name', 'Item')} was restored."}


def repair_status() -> dict[str, Any]:
    manifest = load_manifest()
    items = []
    for entry in manifest.get("items", []):
        items.append({k: v for k, v in entry.items() if k not in ("registryData", "registryType")})
    return {"items": items, "history": manifest.get("history", [])}


def get_live_snapshot() -> dict[str, Any]:
    if os.name != "nt":
        raise RuntimeError("Live hardware/process monitoring is currently implemented for Windows 10/11 only.")
    ps_exe = powershell_executable()
    if not ps_exe or not LIVE_COLLECTOR_PATH.exists():
        raise RuntimeError("The PowerShell live collector is unavailable.")
    args = [ps_exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(LIVE_COLLECTOR_PATH)]
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    result = subprocess.run(args, cwd=str(ROOT), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=12, creationflags=creationflags)
    if result.returncode != 0 and not result.stdout.strip():
        raise RuntimeError((result.stderr or "Live collector failed.")[-1000:])
    try:
        data = json.loads(result.stdout.strip())
        if not isinstance(data, dict):
            raise ValueError("Live collector output was not a JSON object.")
    except Exception as exc:
        raise RuntimeError(f"Could not parse live data: {exc}") from exc
    network_total = int(data.get("networkBytesTotal") or 0)
    now = time.time()
    previous_bytes = LIVE_STATE.get("lastNetworkBytes")
    previous_time = LIVE_STATE.get("lastNetworkTime")
    if previous_bytes is not None and previous_time is not None and network_total >= previous_bytes:
        elapsed = max(0.1, now - previous_time)
        data["networkMbps"] = round(((network_total - previous_bytes) * 8 / elapsed) / 1_000_000, 2)
    else:
        data["networkMbps"] = None
    LIVE_STATE["lastNetworkBytes"] = network_total
    LIVE_STATE["lastNetworkTime"] = now
    data["sampledAt"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    return data


def powershell_executable() -> str | None:
    # Windows PowerShell is present on supported Windows 10/11 installations.
    # Prefer PowerShell 7 if installed, otherwise use Windows PowerShell 5.1.
    import shutil
    return shutil.which("pwsh.exe") or shutil.which("powershell.exe") or shutil.which("pwsh") or shutil.which("powershell")


def terminate_current_process() -> None:
    proc: subprocess.Popen[str] | None
    with STATE.lock:
        proc = STATE.current_process
    if proc is not None and proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


def run_module(ps_exe: str, module: str, defender_quick_scan: bool) -> dict[str, Any]:
    args = [
        ps_exe,
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-File", str(COLLECTOR_PATH),
        "-Module", module,
    ]
    if module == "security" and defender_quick_scan:
        args.append("-DefenderQuickScan")

    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    proc = subprocess.Popen(
        args,
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=creationflags,
    )
    with STATE.lock:
        STATE.current_process = proc

    try:
        stdout, stderr = proc.communicate()
    finally:
        with STATE.lock:
            if STATE.current_process is proc:
                STATE.current_process = None

    if proc.returncode != 0 and not stdout.strip():
        detail = stderr.strip()[-1800:] if stderr else f"PowerShell exited with code {proc.returncode}."
        return {
            "module": module,
            "status": "error",
            "data": {},
            "findings": [],
            "notes": [detail],
        }

    # The collector emits one compressed JSON object. Stderr is retained as a
    # diagnostic note, but never shown as a command or executed by the UI.
    try:
        result = json.loads(stdout.strip())
        if not isinstance(result, dict):
            raise ValueError("Collector output was not a JSON object.")
        if stderr.strip():
            result.setdefault("notes", []).append("PowerShell diagnostic: " + stderr.strip()[-500:])
        return result
    except Exception as exc:
        return {
            "module": module,
            "status": "error",
            "data": {},
            "findings": [],
            "notes": [f"Could not read collector output: {exc}", (stdout or "")[-1200:], (stderr or "")[-800:]],
        }


def run_reduced_module(module: str) -> dict[str, Any]:
    """Very limited, read-only fallback for macOS/Linux; never claims Windows coverage."""
    note = "Windows-specific collection is not available on this operating system. This reduced module does not check for malware or replace the platform's security tools."
    data: dict[str, Any] = {}
    notes: list[str] = []
    if module == "integrity":
        data["os"] = {
            "caption": platform.platform(),
            "version": platform.release(),
            "build": platform.version(),
            "architecture": platform.machine(),
            "lastBoot": None,
        }
        notes.append("Only basic operating-system identification was collected; update, firewall, account, SMART and event-log checks were not performed.")
    elif module == "storage":
        root = Path.home().anchor or "/"
        try:
            usage = shutil.disk_usage(root)
            free_pct = round((usage.free / usage.total) * 100, 1) if usage.total else 0
            data["volumes"] = [{
                "drive": root,
                "label": "Root volume",
                "fileSystem": "",
                "totalGB": round(usage.total / (1024**3), 1),
                "usedGB": round(usage.used / (1024**3), 1),
                "freeGB": round(usage.free / (1024**3), 1),
                "freePercent": free_pct,
            }]
            data["physicalDisks"] = []
            data["folderMetadataScan"] = {"folders": [], "filesVisited": 0, "durationSeconds": 0, "partial": True, "scope": "Not performed in reduced mode."}
            data["largeFiles"] = []
            notes.append("Only root-volume capacity was checked. Per-folder sizes, large files, duplicate detection and disk health were not scanned.")
        except Exception as exc:
            notes.append(f"Root-volume capacity unavailable: {exc}")
    elif module == "performance":
        total_mb = available_mb = None
        if Path("/proc/meminfo").exists():
            try:
                values: dict[str, int] = {}
                for line in Path("/proc/meminfo").read_text(encoding="ascii", errors="ignore").splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        values[parts[0].rstrip(":")] = int(parts[1])
                total_mb = round(values.get("MemTotal", 0) / 1024)
                available_mb = round(values.get("MemAvailable", values.get("MemFree", 0)) / 1024)
            except Exception:
                pass
        elif platform.system() == "Darwin":
            try:
                total_bytes = int(subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True, timeout=2).strip())
                page_size = int(subprocess.check_output(["sysctl", "-n", "hw.pagesize"], text=True, timeout=2).strip())
                vm = subprocess.check_output(["vm_stat"], text=True, timeout=3)
                pages = {}
                for line in vm.splitlines():
                    match = re.match(r"([^:]+):\s+([0-9]+)", line)
                    if match:
                        pages[match.group(1).lower()] = int(match.group(2))
                avail_pages = sum(pages.get(k, 0) for k in ("pages free", "pages inactive", "pages speculative"))
                total_mb = round(total_bytes / (1024**2))
                available_mb = round((avail_pages * page_size) / (1024**2))
            except Exception:
                pass
        if total_mb is not None and available_mb is not None:
            used_mb = max(0, total_mb - available_mb)
            pct = round((available_mb / total_mb) * 100, 1) if total_mb else 0
            data["memory"] = {"totalMB": total_mb, "usedMB": used_mb, "availableMB": available_mb, "availablePercent": pct}
        else:
            data["memory"] = {}
            notes.append("RAM counters were unavailable using the standard local interfaces on this OS.")
        # Process names and PIDs only; no command-line arguments or environment.
        try:
            ps = subprocess.check_output(["ps", "-axo", "pid=,comm=,rss=,pcpu="], text=True, timeout=4, stderr=subprocess.DEVNULL)
            rows = []
            for line in ps.splitlines():
                parts = line.strip().split(None, 3)
                if len(parts) >= 4:
                    try:
                        rows.append({"processId": int(parts[0]), "name": Path(parts[1]).name, "workingSetMB": round(int(parts[2]) / 1024, 1), "cpuPercentSampled": float(parts[3])})
                    except Exception:
                        continue
            data["topMemoryProcesses"] = [{"name": x["name"], "processId": x["processId"], "workingSetMB": x["workingSetMB"]} for x in sorted(rows, key=lambda x: x["workingSetMB"], reverse=True)[:10]]
            data["topCpuProcesses"] = [{"name": x["name"], "processId": x["processId"], "cpuPercentSampled": x["cpuPercentSampled"]} for x in sorted(rows, key=lambda x: x["cpuPercentSampled"], reverse=True)[:10]]
        except Exception:
            data["topMemoryProcesses"] = []
            data["topCpuProcesses"] = []
            notes.append("Process-name inventory was unavailable; it does not include command-line arguments.")
        data["pagefile"] = []
        notes.append("Reduced mode provides a single snapshot only; no memory-leak trend or Windows pagefile analysis is performed.")
    elif module == "processes":
        try:
            ps = subprocess.check_output(["ps", "-axo", "pid=,comm="], text=True, timeout=4, stderr=subprocess.DEVNULL)
            processes = []
            for line in ps.splitlines()[:100]:
                parts = line.strip().split(None, 1)
                if len(parts) == 2:
                    try:
                        processes.append({"processId": int(parts[0]), "name": Path(parts[1]).name, "path": ""})
                    except Exception:
                        pass
            data["processCount"] = len(processes)
            data["processSample"] = processes
        except Exception:
            data["processCount"] = 0
            data["processSample"] = []
        data["establishedConnections"] = []
        data["suspiciousLocationProcesses"] = []
        data["riskyExtensionFiles"] = []
        notes.append("Only process names/PIDs may be listed. Network sockets and risky-file metadata were not inspected.")
    else:
        notes.append(note)
        return {"module": module, "status": "unsupported", "data": {}, "findings": [], "notes": notes, "completedAt": time.strftime("%Y-%m-%dT%H:%M:%S%z")}

    return {"module": module, "status": "ok", "data": data, "findings": [], "notes": notes, "completedAt": time.strftime("%Y-%m-%dT%H:%M:%S%z")}


def scan_worker(categories: list[str], defender_quick_scan: bool) -> None:
    ps_exe = powershell_executable() if os.name == "nt" else None
    results: list[dict[str, Any]] = []
    started = time.time()
    cancelled = False
    reduced_mode = os.name != "nt"
    try:
        if os.name == "nt" and not ps_exe:
            STATE.update(
                running=False,
                phase="PowerShell unavailable",
                error="PowerShell was not found. On Windows 10/11, install or enable Windows PowerShell, then restart this tool.",
                progress=0,
            )
            return

        for index, module in enumerate(categories):
            with STATE.lock:
                cancel_now = STATE.cancel_requested
            if cancel_now:
                cancelled = True
                break

            percent = int((index / max(1, len(categories))) * 90)
            STATE.update(progress=percent, phase=f"Scanning: {MODULE_LABELS[module]}")
            result = run_module(ps_exe, module, defender_quick_scan) if not reduced_mode else run_reduced_module(module)
            results.append(result)

            with STATE.lock:
                cancel_now = STATE.cancel_requested
            if cancel_now:
                cancelled = True
                break

        # A score is a transparent heuristic, not a malware probability.
        findings = [f for item in results for f in (item.get("findings") or [])]
        critical = sum(1 for f in findings if f.get("severity") == "Critical")
        warning = sum(1 for f in findings if f.get("severity") == "Warning")
        info = sum(1 for f in findings if f.get("severity") == "Info")
        score = max(0, 100 - min(60, critical * 25) - min(30, warning * 8) - min(10, info))
        score_applicable = bool(results) and not reduced_mode and not cancelled and all(item.get("status") == "ok" for item in results)
        report = {
            "schemaVersion": 2,
            "scannerVersion": "2.0",
            "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "platform": sys.platform,
            "elapsedSeconds": round(time.time() - started, 1),
            "cancelled": cancelled,
            "reducedMode": reduced_mode,
            "platformNote": ("Reduced cross-platform mode: only basic OS, process-name, root-volume and RAM information is collected where available. Windows security, startup, Defender, event-log, browser-extension and detailed SMART checks are not performed." if reduced_mode else "Windows 10/11 native collectors were used."),
            "healthScore": score if score_applicable else None,
            "scoreApplicable": score_applicable,
            "scoreMethod": ("Not calculated because this is reduced mode, a partial scan, or one or more selected modules did not complete." if not score_applicable else "100 minus up to 60 points for Critical findings (25 each), 30 for Warning findings (8 each), and 10 for Info findings (1 each). This is a triage heuristic, not a malware probability or certification."),
            "modules": results,
            "findings": findings,
            "counts": {"critical": critical, "warning": warning, "info": info},
            "consentedCategories": categories,
            "defenderQuickScanRequested": bool(defender_quick_scan),
        }
        report["repairCandidates"] = build_repair_candidates(report) if not reduced_mode and not cancelled else []
        STATE.update(
            running=False,
            cancelled=cancelled,
            progress=100 if not cancelled else min(99, int((len(results) / max(1, len(categories))) * 100)),
            phase="Scan cancelled; partial report ready" if cancelled else "Scan complete",
            report=report,
            error=None,
        )
    except Exception as exc:  # graceful failure; preserve any completed modules
        STATE.update(running=False, phase="Scan stopped with an error", error=str(exc))
    finally:
        with STATE.lock:
            STATE.running = False
            STATE.current_process = None


class Handler(BaseHTTPRequestHandler):
    server_version = "CyberCommandSystemScanner/2.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        # Avoid writing local system details or request content to a log file.
        return

    def _send(self, status: int, body: bytes, content_type: str = "application/json; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def _host_is_local(self) -> bool:
        host = self.headers.get("Host", "")
        return host in {f"127.0.0.1:{PORT}", f"localhost:{PORT}", f"[::1]:{PORT}"}

    def do_GET(self) -> None:
        if not self._host_is_local():
            self._send(403, b'{"error":"Local access only."}')
            return
        path = urlparse(self.path).path
        if path == "/" or path == "/index.html":
            global LIVE_ENABLED
            with ACTION_LOCK:
                LIVE_ENABLED = False
                LIVE_STATE["lastNetworkBytes"] = None
                LIVE_STATE["lastNetworkTime"] = None
            try:
                html = HTML_PATH.read_text(encoding="utf-8").replace("__APP_TOKEN__", APP_TOKEN).replace("__IS_WINDOWS__", "true" if os.name == "nt" else "false")
                self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
            except Exception as exc:
                self._send(500, json.dumps({"error": str(exc)}).encode("utf-8"))
        elif path in ("/api/status", "/api/repairs", "/api/live"):
            if self.headers.get("X-Session-Token") != APP_TOKEN:
                self._send(403, b'{"error":"Session token invalid. Reload the local dashboard."}')
                return
            if path == "/api/status":
                payload = STATE.snapshot()
            elif path == "/api/repairs":
                try:
                    payload = repair_status()
                except Exception as exc:
                    self._send(500, json.dumps({"error": str(exc)}).encode("utf-8"))
                    return
            else:
                with ACTION_LOCK:
                    enabled = LIVE_ENABLED
                if not enabled:
                    self._send(403, b'{"error":"Live monitoring is not enabled. Give separate consent first."}')
                    return
                try:
                    with LIVE_FETCH_LOCK:
                        payload = get_live_snapshot()
                except Exception as exc:
                    self._send(503, json.dumps({"error": str(exc)}).encode("utf-8"))
                    return
            self._send(200, json.dumps(payload).encode("utf-8"))
        else:
            self._send(404, b'{"error":"Not found."}')

    def do_POST(self) -> None:
        if not self._host_is_local():
            self._send(403, b'{"error":"Local access only."}')
            return
        origin = self.headers.get("Origin")
        if origin:
            parsed_origin = urlparse(origin)
            if not (parsed_origin.scheme == "http" and parsed_origin.hostname in {"127.0.0.1", "localhost"} and parsed_origin.port == PORT):
                self._send(403, b'{"error":"Cross-origin request rejected."}')
                return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 16_384:
                raise ValueError("Invalid request size.")
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if payload.get("token") != APP_TOKEN:
                self._send(403, b'{"error":"Session token invalid. Reload the local dashboard."}')
                return
        except Exception as exc:
            self._send(400, json.dumps({"error": str(exc)}).encode("utf-8"))
            return

        path = urlparse(self.path).path
        if path == "/api/live/start":
            global LIVE_ENABLED
            if payload.get("consent") is not True:
                self._send(400, b'{"error":"Separate live-monitor consent is required."}')
                return
            if os.name != "nt":
                self._send(400, b'{"error":"Live monitoring is currently available only on Windows 10/11."}')
                return
            if not LIVE_COLLECTOR_PATH.exists():
                self._send(500, b'{"error":"Live collector script is missing."}')
                return
            with ACTION_LOCK:
                LIVE_ENABLED = True
                LIVE_STATE["lastNetworkBytes"] = None
                LIVE_STATE["lastNetworkTime"] = None
            self._send(200, b'{"enabled":true}')
        elif path == "/api/live/stop":
            with ACTION_LOCK:
                LIVE_ENABLED = False
            self._send(200, b'{"enabled":false}')
        elif path == "/api/repair":
            if payload.get("consent") is not True or payload.get("confirmed") is not True:
                self._send(400, b'{"error":"A separate repair confirmation is required."}')
                return
            candidate_id = payload.get("candidateId")
            action = payload.get("action")
            if not isinstance(candidate_id, str) or not isinstance(action, str):
                self._send(400, b'{"error":"A valid candidate and action are required."}')
                return
            try:
                result = perform_repair(candidate_id, action, str(payload.get("typedConfirmation") or ""))
                self._send(200, json.dumps(result).encode("utf-8"))
            except Exception as exc:
                self._send(400, json.dumps({"error": str(exc)}).encode("utf-8"))
        elif path == "/api/restore":
            if payload.get("consent") is not True or payload.get("confirmed") is not True:
                self._send(400, b'{"error":"A separate restore confirmation is required."}')
                return
            item_id = payload.get("itemId")
            if not isinstance(item_id, str):
                self._send(400, b'{"error":"A valid quarantine item is required."}')
                return
            try:
                result = restore_quarantine_item(item_id)
                self._send(200, json.dumps(result).encode("utf-8"))
            except Exception as exc:
                self._send(400, json.dumps({"error": str(exc)}).encode("utf-8"))
        elif path == "/api/scan":
            if payload.get("consent") is not True:
                self._send(400, b'{"error":"Consent is required."}')
                return
            categories = payload.get("categories")
            if not isinstance(categories, list) or not categories:
                self._send(400, b'{"error":"Select at least one scan category."}')
                return
            categories = list(dict.fromkeys(x for x in categories if isinstance(x, str) and x in VALID_MODULES))
            if not categories:
                self._send(400, b'{"error":"No valid scan categories were selected."}')
                return
            defender_scan = payload.get("defenderQuickScan") is True
            if defender_scan and "security" not in categories:
                self._send(400, b'{"error":"The Defender quick scan requires the Security category."}')
                return
            with STATE.lock:
                if STATE.running:
                    self._send(409, b'{"error":"A scan is already running."}')
                    return
                STATE.running = True
                STATE.cancel_requested = False
                with ACTION_LOCK:
                    ACTION_CANDIDATES.clear()
                STATE.data = {
                    "running": True,
                    "cancelled": False,
                    "progress": 0,
                    "phase": "Preparing local scan",
                    "modules": [],
                    "report": None,
                    "error": None,
                }