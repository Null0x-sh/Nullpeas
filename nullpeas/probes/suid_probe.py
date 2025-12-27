"""
nullpeas/probes/suid_probe.py
Finds SUID (Set User ID) and SGID (Set Group ID) binaries on the filesystem.
"""

import subprocess
import shutil
from typing import Dict, Any

# Directories to ignore to prevent hanging, loops, or network drive scanning
PRUNE_PATHS = [
    "/proc", 
    "/sys", 
    "/dev", 
    "/run", 
    "/var/run", 
    "/snap", 
    "/var/lib/docker", 
    "/var/lib/kubelet",
    "/mnt",
    "/media"
]

def run(state: Dict[str, Any]) -> None:
    suid_data = {
        "found": [],
        "error": None,
        "method": "find_command"
    }

    # 1. Check if 'find' binary exists
    if not shutil.which("find"):
        suid_data["error"] = "'find' binary not found on target."
        state["suid"] = suid_data
        return

    # 2. Build the command
    # Logic: find / ( -path /proc -prune -o -path /sys -prune ... ) -o ( -type f -perm /6000 -print )
    cmd = ["find", "/"]

    # Add pruning arguments
    for path in PRUNE_PATHS:
        cmd.extend(["-path", path, "-prune", "-o"])

    # Add permission check
    # -perm -4000 = SUID
    # -perm -2000 = SGID
    # We use \( -perm -4000 -o -perm -2000 \) to catch either
    cmd.extend([
        "-type", "f",
        "(", "-perm", "-4000", "-o", "-perm", "-2000", ")",
        "-print"
    ])

    try:
        # Run with a timeout to ensure we don't hang indefinitely on massive filesystems
        # 15 seconds is usually enough for local disks; scanning network/slow disks is bad opsec anyway.
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=15
        )

        paths = result.stdout.strip().split('\n')
        
        # Parse output
        for p in paths:
            clean_p = p.strip()
            if clean_p:
                suid_data["found"].append({"path": clean_p})

    except subprocess.TimeoutExpired:
        suid_data["error"] = "Scan timed out (filesystem too large or slow)."
    except Exception as e:
        suid_data["error"] = str(e)

    state["suid"] = suid_data
