"""
nullpeas/probes/caps_probe.py
Enumerates binaries with Linux Capabilities (getcap).
Fix: Recovers partial results if the scan times out.
"""

import subprocess
import shutil
from typing import Dict, Any

# Directories to ignore to prevent hanging
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
    caps_data = {
        "found": [],
        "error": None,
        "method": "find_exec_getcap"
    }

    if not shutil.which("getcap"):
        caps_data["error"] = "'getcap' binary not found on target. Cannot enumerate capabilities."
        state["caps"] = caps_data
        return

    cmd = ["find", "/"]

    for path in PRUNE_PATHS:
        cmd.extend(["-path", path, "-prune", "-o"])

    cmd.extend([
        "-type", "f",
        "-exec", "getcap", "{}", "+",
    ])

    raw_output = ""

    try:
        # 20s timeout - capability scanning involves many syscalls
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=20
        )
        raw_output = result.stdout

    except subprocess.TimeoutExpired as e:
        # === FIX: Recover partial output from the exception ===
        caps_data["error"] = "Scan timed out (results may be partial)."
        if e.stdout:
            raw_output = e.stdout

    except Exception as e:
        caps_data["error"] = str(e)

    # Parse whatever output we got (Full or Partial)
    if raw_output:
        lines = raw_output.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Format: "/usr/bin/ping = cap_net_raw+ep"
            if " = " in line:
                try:
                    path, caps = line.split(" = ", 1)
                    caps_data["found"].append({
                        "path": path.strip(),
                        "capabilities": caps.strip()
                    })
                except ValueError:
                    continue

    state["caps"] = caps_data
