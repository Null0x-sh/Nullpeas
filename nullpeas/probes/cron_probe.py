import os
import stat
import subprocess
from typing import Dict, Any, List


def safe_read_file(path: str) -> str:
    """Safely read a file. Returns content or error string."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception as e:
        return f"[error reading: {e}]"


def is_potentially_abusable(path: str, current_uid: int, current_gid: int) -> Dict[str, Any]:
    """
    Very lightweight heuristic:
    - file writable by current user
    - OR world-writable
    - OR directory writable where cron jobs live
    """
    info: Dict[str, Any] = {
        "path": path,
        "writable_by_user": False,
        "world_writable": False,
        "writable_by_group": False,
        "reason": [],
    }

    try:
        st = os.stat(path)
    except Exception as e:
        info["error"] = str(e)
        return info

    mode = st.st_mode

    # user/group/world bits
    user_w = bool(mode & stat.S_IWUSR)
    group_w = bool(mode & stat.S_IWGRP)
    other_w = bool(mode & stat.S_IWOTH)

    same_user = (st.st_uid == current_uid)
    same_group = (st.st_gid == current_gid)

    if same_user and user_w:
        info["writable_by_user"] = True
        info["reason"].append("writable_by_user")

    if same_group and group_w:
        info["writable_by_group"] = True
        info["reason"].append("writable_by_group")

    if other_w:
        info["world_writable"] = True
        info["reason"].append("world_writable")

    return info


def run(state: Dict[str, Any]) -> None:
    """
    Cron Probe
    ----------
    Purpose:
        Safely enumerate cron configuration and job locations,
        and perform a *basic* check for potentially abusable cron surfaces.

    What this DOES:
        - Collects system + user cron locations
        - Reads accessible cron files
        - Captures raw contents
        - Flags files/dirs that are writable by the current user/group/world
        - Sets cron["potential_risk"] = True if anything looks suspicious

    What it DOES NOT do yet:
        - Deep analysis of job commands
        - Confirmed exploitability
        - Any modification or exploitation

    Deeper logic will live in a future cron abuse / escalation module.
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
    cron["suspicious_entries"] = []
    cron["potential_risk"] = False

    current_uid = os.getuid()
    current_gid = os.getgid()

    # Read paths + check permissions
    for path in cron_paths:
        if os.path.isdir(path):
            try:
                files = []
                for item in os.listdir(path):
                    full_path = os.path.join(path, item)
                    if os.path.isfile(full_path):
                        # Store content
                        files.append({
                            "path": full_path,
                            "content": safe_read_file(full_path)
                        })

                        # Check permissions
                        perm_info = is_potentially_abusable(full_path, current_uid, current_gid)
                        if perm_info.get("reason"):
                            cron["suspicious_entries"].append(perm_info)

                cron["found_files"][path] = files
            except Exception as e:
                cron["errors"].append(f"Failed reading dir {path}: {e}")

        elif os.path.isfile(path):
            cron["found_files"][path] = safe_read_file(path)
            perm_info = is_potentially_abusable(path, current_uid, current_gid)
            if perm_info.get("reason"):
                cron["suspicious_entries"].append(perm_info)

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

    # Basic risk flag
    if cron["suspicious_entries"]:
        cron["potential_risk"] = True

    state["cron"] = cron
