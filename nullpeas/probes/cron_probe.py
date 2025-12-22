import os
from pathlib import Path
from typing import Dict, Any, List

import pwd
import grp

from nullpeas.core.exec import run_command


CRON_PATHS = [
    "/etc/crontab",
    "/etc/cron.d",
    "/var/spool/cron",
    "/var/spool/cron/crontabs",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
]


def _safe_read_file(path: Path) -> str:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception as e:
        return f"[error reading {path}: {e}]"


def _file_metadata(path: Path) -> Dict[str, Any]:
    """
    Collect permission / ownership metadata for cron-related files.
    This is where future modules will look to detect writable cron paths.
    """
    meta: Dict[str, Any] = {
        "path": str(path),
        "owner": None,
        "group": None,
        "mode": None,
        "size": None,
        "error": None,
    }

    try:
        st = path.stat()
        meta["size"] = st.st_size
        meta["mode"] = f"{st.st_mode & 0o777:04o}"

        try:
            meta["owner"] = pwd.getpwuid(st.st_uid).pw_name
        except Exception:
            meta["owner"] = st.st_uid

        try:
            meta["group"] = grp.getgrgid(st.st_gid).gr_name
        except Exception:
            meta["group"] = st.st_gid

    except Exception as e:
        meta["error"] = str(e)

    return meta


def run(state: dict):
    cron: Dict[str, Any] = {
        "paths_checked": CRON_PATHS,
        "found_files": {},      # Backwards-compatible summary of contents
        "files_metadata": [],   # New: structured metadata for each discovered file
        "user_crontab": {},
        "errors": [],
    }

    # Enumerate files/directories in CRON_PATHS
    for raw_path in CRON_PATHS:
        p = Path(raw_path)
        if not p.exists():
            continue

        if p.is_dir():
            try:
                entries: List[Dict[str, Any]] = []
                for entry_name in os.listdir(p):
                    entry_path = p / entry_name
                    if not entry_path.is_file():
                        continue
                    content = _safe_read_file(entry_path)
                    entries.append({
                        "path": str(entry_path),
                        "content": content,
                    })
                    cron["files_metadata"].append(_file_metadata(entry_path))

                if entries:
                    cron["found_files"][raw_path] = entries

            except Exception as e:
                cron["errors"].append(f"error reading directory {raw_path}: {e}")

        elif p.is_file():
            content = _safe_read_file(p)
            cron["found_files"][raw_path] = content
            cron["files_metadata"].append(_file_metadata(p))

    # Per-user crontab (via exec helper)
    user_crontab: Dict[str, Any] = {}
    res = run_command(["crontab", "-l"], timeout=5)

    if res["binary_missing"]:
        user_crontab["status"] = "crontab_binary_missing"
        user_crontab["detail"] = res["error"]
    elif res["timed_out"]:
        user_crontab["status"] = "timeout"
        user_crontab["detail"] = "crontab -l timed out after 5 seconds"
    elif res["ok"]:
        user_crontab["status"] = "ok"
        user_crontab["content"] = res["stdout"]
    else:
        # Non-zero return code: often "no crontab for user" or permission denied
        user_crontab["status"] = "non_zero_exit"
        user_crontab["return_code"] = res["return_code"]
        user_crontab["stdout"] = res["stdout"]
        user_crontab["stderr"] = res["stderr"]
        if res["error"]:
            user_crontab["error"] = res["error"]

    cron["user_crontab"] = user_crontab
    state["cron"] = cron
