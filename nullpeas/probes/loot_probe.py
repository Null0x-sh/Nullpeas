"""
nullpeas/probes/loot_probe.py
Enumerates sensitive files (Loot) in targeted high-probability directories.
Optimized for speed: Does not scan the entire filesystem.
v2.4 Improvements:
- Checks 'readable' status (os.access) for every file found.
- Differentiates between "file exists" and "file is loot".
"""

import subprocess
import shutil
import os
from typing import Dict, Any

# Targeted directories for loot hunting
TARGET_DIRS = [
    "/home",
    "/root",        
    "/etc",         
    "/opt",         
    "/var/www",     
    "/var/backups", 
    "/tmp",         
]

# Exact filename matches we care about
INTERESTING_FILES = {
    # SSH / Keys
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "id_rsa.pub", "id_ed25519.pub",
    "authorized_keys", "known_hosts",

    # History
    ".bash_history", ".zsh_history", ".mysql_history", ".psql_history", ".dbshell",

    # Cloud / Configs
    "credentials",           # .aws/credentials
    "config.json",           # Docker, cloud CLIs, etc.
    "settings.json",
    ".env", "wp-config.php", "LocalSettings.php", "config.php",

    # Generic / sensitive
    "shadow", "passwd",
    "master.key",            # Rails
    ".git-credentials",
    "docker-compose.yml",
}

MAX_RESULTS = 200  # Safety cap

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
    cmd = ["find"]
    cmd.extend(valid_targets)
    cmd.extend(["-maxdepth", "5"])
    
    # Build the OR clause for filenames
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
        # 15s timeout
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
        paths = sorted(set(raw_output.strip().split('\n')))
        
        for p in paths:
            path = p.strip()
            if not path:
                continue
            
            if len(loot_data["found"]) >= MAX_RESULTS:
                loot_data["error"] = f"Result cap reached ({MAX_RESULTS}). Listing truncated."
                break

            if "node_modules" in path:
                continue
                
            # Classification
            name = os.path.basename(path)
            category = "unknown"

            # 1. SSH & Keys
            if name == "master.key":
                category = "web_config" 
            elif "ssh" in path or name.startswith("id_") or name.endswith(".key"):
                category = "ssh_key"
            
            # 2. History
            elif "history" in name:
                category = "shell_history"
            
            # 3. Credentials & Configs
            elif ".git-credentials" in name:
                category = "scm_creds"
            elif ".env" in name or name.endswith(".php"):
                category = "web_config"
            elif "docker-compose" in name:
                category = "container_config"
            elif "credentials" in name:
                category = "cloud_creds"
            elif "shadow" in name:
                category = "password_hashes"
            elif name == "passwd":
                category = "account_db"
                
            # 4. Generic Configs
            elif name in ["config.json", "settings.json"]:
                category = "config_secret"
            
            # === NEW: Check Readability ===
            readable = os.access(path, os.R_OK)
            # ==============================

            loot_data["found"].append({
                "path": path,
                "filename": name,
                "category": category,
                "readable": readable, # <--- Stored here
            })

    state["loot"] = loot_data
