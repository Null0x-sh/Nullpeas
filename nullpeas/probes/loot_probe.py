"""
nullpeas/probes/loot_probe.py
Enumerates sensitive files (Loot) in targeted high-probability directories.
Optimized for speed: Does not scan the entire filesystem.
"""

import subprocess
import shutil
import os
from typing import Dict, Any

# Targeted directories for loot hunting
# We skip / to avoid hanging on massive mounts.
TARGET_DIRS = [
    "/home",
    "/root",        # We might have read access even if not root (misconfigured permissions)
    "/etc",         # Configs
    "/opt",         # Custom apps often drop secrets here
    "/var/www",     # Web roots (.env, config.php)
    "/var/backups", # Backup files
    "/tmp",         # Lazy admin drops
]

# Exact filename matches we care about
INTERESTING_FILES = {
    # SSH / Keys
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "authorized_keys", "known_hosts",
    "id_rsa.pub", "id_ed25519.pub", # Pub keys are useful for knowing WHO accesses this box
    
    # History
    ".bash_history", ".zsh_history", ".mysql_history", ".psql_history", ".dbshell",
    
    # Cloud / Configs
    "credentials",  # .aws/credentials
    "config",       # .kube/config
    ".env",         # Docker/Node secrets
    "wp-config.php",
    "LocalSettings.php",
    "config.php",
    
    # Generic
    "shadow",       # /etc/shadow backup copies?
    "passwd",       # Useful context
    "master.key",   # Rails
}

def run(state: Dict[str, Any]) -> None:
    loot_data = {
        "found": [],
        "error": None,
        "method": "targeted_find"
    }

    if not shutil.which("find"):
        loot_data["error"] = "'find' binary not found."
        state["loot"] = loot_data
        return

    # 1. Filter valid targets
    valid_targets = [d for d in TARGET_DIRS if os.path.isdir(d)]
    
    if not valid_targets:
        loot_data["error"] = "No valid target directories found to scan."
        state["loot"] = loot_data
        return

    # 2. Build Find Command
    # find /home /etc ... -maxdepth 4 ( -name id_rsa -o -name .bash_history ... ) -type f -print
    # We limit depth to 4 to prevent getting lost in deep node_modules or similar structures
    cmd = ["find"]
    cmd.extend(valid_targets)
    cmd.extend(["-maxdepth", "5"])
    
    # Build the OR clause for filenames
    # \( -name "id_rsa" -o -name ".env" ... \)
    cmd.append("(")
    first = True
    for fname in INTERESTING_FILES:
        if not first:
            cmd.append("-o")
        cmd.extend(["-name", fname])
        first = False
    cmd.append(")")
    
    cmd.extend(["-type", "f", "-print"])

    raw_output = ""
    try:
        # 15s timeout should be plenty for targeted depth scan
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=15
        )
        raw_output = result.stdout

    except subprocess.TimeoutExpired as e:
        loot_data["error"] = "Scan timed out (results may be partial)."
        if e.stdout:
            raw_output = e.stdout
    except Exception as e:
        loot_data["error"] = str(e)

    # 3. Process Results
    if raw_output:
        paths = raw_output.strip().split('\n')
        
        for p in paths:
            path = p.strip()
            if not path:
                continue
                
            # Filter out some noise? (e.g. inside "node_modules")
            if "node_modules" in path:
                continue
                
            # Basic Classification
            name = os.path.basename(path)
            category = "unknown"
            
            if "id_" in name or "key" in name:
                category = "ssh_key"
            elif "history" in name:
                category = "shell_history"
            elif ".env" in name or "config" in name:
                category = "config_secret"
            elif "credentials" in name:
                category = "cloud_creds"
                
            loot_data["found"].append({
                "path": path,
                "filename": name,
                "category": category
            })

    state["loot"] = loot_data
