"""
nullpeas/probes/systemd_probe.py
Enumerates systemd service units to find writable configurations or binaries.
"""

from typing import Dict, Any, List
import os
import re

# Standard paths for systemd units
UNIT_PATHS = [
    "/etc/systemd/system",
    "/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/run/systemd/system",
]

def _parse_exec_start(content: str) -> str:
    """
    Simple regex to pull the binary path from ExecStart=...
    Ignores arguments, flags, etc.
    
    Updated to handle systemd prefixes: -, @, !, +
    """
    # Look for ExecStart followed by optional prefixes [-@!+], then the path.
    match = re.search(r'^ExecStart=[-@!+]*\s*([^\s]+)', content, re.MULTILINE)
    if match:
        return match.group(1)
    return ""

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

                # 1. Check if Unit File is Writable
                # We strictly check if WE can write to it.
                try:
                    can_write_unit = os.access(full_path, os.W_OK)
                except OSError:
                    can_write_unit = False
                
                # 2. Parse Content
                try:
                    with open(full_path, 'r', errors='ignore') as f:
                        content = f.read()
                except:
                    continue

                exec_binary = _parse_exec_start(content)
                
                # 3. Check Binary Permissions
                can_write_binary = False
                is_relative = False
                
                if exec_binary:
                    # Check for relative path (no leading /)
                    # Some paths might be valid systemd vars (e.g. ${...}), we skip those to avoid FPs
                    if not exec_binary.startswith("/") and not exec_binary.startswith("$"):
                        is_relative = True
                    
                    # Check if binary is writable (if absolute path)
                    elif exec_binary.startswith("/") and os.path.exists(exec_binary):
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

                # Fast access lists for the module
                if can_write_unit:
                    systemd_data["writable_units"].append(unit_info)
                if can_write_binary:
                    systemd_data["writable_binaries"].append(unit_info)
                if is_relative:
                    systemd_data["relative_paths"].append(unit_info)

        except Exception as e:
            systemd_data["error"] = str(e)

    state["systemd"] = systemd_data
