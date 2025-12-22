import os
import subprocess
from typing import Dict, Any, List


def safe_read_file(path: str) -> str:
    """Safely read a file. Returns content or error string."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception as e:
        return f"[error reading: {e}]"


def run(state: Dict[str, Any]) -> None:
    """
    Cron Probe
    ----------
    Purpose:
        Safely enumerate cron configuration and job locations.
        Read-only. No modification. No exploitation.

    What this DOES:
        - Collects system + user cron locations
        - Reads accessible cron files
        - Captures raw contents
        - Stores structured results in state["cron"]

    What it DOES NOT do yet:
        - Deep risk analysis
        - Detect exploitation paths
        - Modify cron or create jobs

    That will be handled later in a dedicated cron abuse module.
    """

    cron: Dict[str, Any] = {}

    cron_paths: List[str] = [
        "/etc/crontab",
        "/etc/cron.d",
        "/var/spool/cron",
        "/var/spool/cron/crontabs",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ]

    cron["paths_checked"] = cron_paths
    cron["found_files"] = {}
    cron["user_crontab"] = ""
    cron["errors"] = []

    # Read paths
    for path in cron_paths:
        if os.path.isdir(path):
            try:
                files = []
                for item in os.listdir(path):
                    full_path = os.path.join(path, item)
                    if os.path.isfile(full_path):
                        files.append({
                            "path": full_path,
                            "content": safe_read_file(full_path)
                        })
                cron["found_files"][path] = files
            except Exception as e:
                cron["errors"].append(f"Failed reading dir {path}: {e}")

        elif os.path.isfile(path):
            cron["found_files"][path] = safe_read_file(path)

    # Attempt user crontab
    try:
        result = subprocess.run(
            ["crontab", "-l"],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            cron["user_crontab"] = result.stdout.strip()
        else:
            cron["user_crontab"] = "[no user crontab or not permitted]"

    except FileNotFoundError:
        cron["user_crontab"] = "[crontab command not found]"
    except subprocess.TimeoutExpired:
        cron["user_crontab"] = "[crontab -l timed out]"
    except Exception as e:
        cron["user_crontab"] = f"[error reading user crontab: {e}]"

    state["cron"] = cron
