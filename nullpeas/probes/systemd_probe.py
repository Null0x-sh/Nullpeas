"""
nullpeas/probes/systemd_probe.py
Enumerates systemd service units to find writable configurations or binaries.
"""

from typing import Dict, Any, List, Optional
import os
import re

# Standard paths for systemd units
UNIT_PATHS = [
    "/etc/systemd/system",
    "/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/run/systemd/system",
]

# Binaries that systemd resolves internally or are standard tools.
# These frequently appear as "relative" in unit files but are not exploitable.
IGNORE_BINARIES = {
    "systemd-tmpfiles", "systemd-sysusers", "systemd-sysext", "systemd-confext",
    "systemd-tty-ask-password-agent", "systemctl", "journalctl", "udevadm",
    "rm", "mkdir", "touch", "install", "ln", "cp", "mv", "mount", "umount",
    "modprobe", "agetty", "fsck", "sulogin"
}

def _parse_exec_start(content: str) -> Optional[str]:
    """
    Robust regex to pull the binary path from ExecStart=...
    Handles:
    1. Prefixes: -, @, +, ! (e.g., ExecStart=-/bin/foo)
    2. Quotes: ExecStart="/bin/foo bar"
    3. Unquoted: ExecStart=/bin/foo -args
    """
    # Regex Logic:
    # ^ExecStart=       Start of line
    # [-@!+: ]* Optional systemd prefixes (including space)
    # (?:               Non-capturing group for alternation
    #   ["'](.*?)["']   Match 1: Quoted path (capture inside quotes)
    #   |               OR
    #   ([^ \t\n]+)     Match 2: Unquoted path (stop at whitespace)
    # )
    pattern = r'^ExecStart=[-@!+: ]*(?:["\'](.*?)["\']|([^ \t\n]+))'
    
    match = re.search(pattern, content, re.MULTILINE)
    if match:
        # Return whichever group matched (quoted or unquoted)
        return match.group(1) or match.group(2)
    return None

def run(state: Dict[str, Any]) -> None:
    systemd_data: Dict[str, Any] = {
        "units": [],
        "writable_units": [],
        "writable_binaries": [],
        "relative_paths": [],
        "error": None,
    }

    scanned_units = set()

    for base_dir in UNIT_PATHS:
        if not os.path.isdir(base_dir):
            continue

        try:
            for filename in os.listdir(base_dir):
                if not filename.endswith(".service"):
                    continue
                
                full_path = os.path.join(base_dir, filename)
                
                # Deduplicate (same unit name might exist in multiple folders)
                if filename in scanned_units:
                    continue
                scanned_units.add(filename)

                # 1. Check if Unit File is Writable (Write -> Persistence)
                can_write_unit = False
                try:
                    if os.access(full_path, os.W_OK):
                        can_write_unit = True
                except OSError:
                    pass

                # 2. Parse Content to find Binary
                exec_binary = None
                try:
                    with open(full_path, 'r', errors='ignore') as f:
                        content = f.read()
                    exec_binary = _parse_exec_start(content)
                except:
                    pass # Cannot read file, skip binary analysis

                # 3. Analyze Binary (Write -> Root; Relative -> Hijack)
                can_write_binary = False
                is_relative = False
                
                if exec_binary:
                    # Filter out systemd variables like ${...}
                    if exec_binary.startswith("$"):
                        pass
                        
                    # Check for Relative Path
                    elif not exec_binary.startswith("/"):
                        bin_name = os.path.basename(exec_binary)
                        # Only flag if it's NOT a known safe internal tool
                        if bin_name not in IGNORE_BINARIES and not bin_name.startswith("systemd-"):
                            is_relative = True
                    
                    # Check for Writable Binary (if absolute)
                    elif os.path.exists(exec_binary):
                        try:
                            if os.access(exec_binary, os.W_OK):
                                can_write_binary = True
                        except OSError:
                            pass

                unit_info = {
                    "name": filename,
                    "path": full_path,
                    "exec_start": exec_binary,
                    "writable_unit": can_write_unit,
                    "writable_binary": can_write_binary,
                    "is_relative_path": is_relative
                }

                systemd_data["units"].append(unit_info)

                if can_write_unit:
                    systemd_data["writable_units"].append(unit_info)
                if can_write_binary:
                    systemd_data["writable_binaries"].append(unit_info)
                if is_relative:
                    systemd_data["relative_paths"].append(unit_info)

        except Exception as e:
            systemd_data["error"] = str(e)

    state["systemd"] = systemd_data
