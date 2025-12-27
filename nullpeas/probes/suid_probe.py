"""
nullpeas/probes/suid_probe.py
Finds SUID (Set User ID) and SGID (Set Group ID) binaries.
Optimized for Speed: Scans targeted directories instead of filesystem root.
"""

import subprocess
import shutil
import os
from typing import Dict, Any

# === SPEED OPTIMIZATION ===
# Instead of scanning '/' and trying to prune the infinite abyss,
# we scan only the directories where executable binaries actually live.
# This makes the scan nearly instant while retaining 99% coverage.
TARGET_DIRECTORIES = [
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/opt",       # Third-party apps often have SUID
    "/home",      # User-created SUIDs
    "/var",       # Logs/Tmp/Caches (rare but possible)
    "/tmp",       # Common for CTFs/dropped payloads
    "/srv",       # Service data
    "/etc",       # Rare config binaries
]

def run(state: Dict[str, Any]) -> None:
    suid_data = {
        "found": [],
        "error": None,
        "method": "targeted_find"
    }

    if not shutil.which("find"):
        suid_data["error"] = "'find' binary not found on target."
        state["suid"] = suid_data
        return

    # 1. Filter targets to those that actually exist
    valid_targets = [d for d in TARGET_DIRECTORIES if os.path.isdir(d)]
    
    if not valid_targets:
        suid_data["error"] = "No valid target directories found."
        state["suid"] = suid_data
        return

    # 2. Build Command
    # find /bin /usr/bin /opt ... ( -perm -4000 -o -perm -2000 ) -type f -print
    cmd = ["find"]
    cmd.extend(valid_targets)
    
    # Permission logic: SUID (4000) or SGID (2000)
    cmd.extend([
        "-type", "f",
        "(", "-perm", "-4000", "-o", "-perm", "-2000", ")",
        "-print"
    ])

    raw_output = ""

    try:
        # Run with a generous timeout (since we are scanning less data, it should be fast)
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10 
        )
        raw_output = result.stdout

    except subprocess.TimeoutExpired as e:
        suid_data["error"] = "Scan timed out (results may be partial)."
        if e.stdout:
            raw_output = e.stdout

    except Exception as e:
        suid_data["error"] = str(e)

    # Parse Output
    if raw_output:
        paths = raw_output.strip().split('\n')
        unique_paths = set() # Deduplicate
        
        for p in paths:
            clean_p = p.strip()
            if clean_p and clean_p not in unique_paths:
                unique_paths.add(clean_p)
                suid_data["found"].append({"path": clean_p})

    state["suid"] = suid_data
