"""
nullpeas/probes/suid_probe.py
Finds SUID and SGID binaries on the filesystem.
"""

from typing import Dict, Any, List
import shutil

from nullpeas.core.exec import run_command


def run(state: Dict[str, Any]) -> None:
    suid_info: Dict[str, Any] = {
        "found": [],
        "error": None,
        "method": "unknown",
    }

    if shutil.which("find") is None:
        suid_info["error"] = "find binary not present"
        state["suid"] = suid_info
        return

    # === OPTIMIZATION ===
    # Exclude heavy directories typical in containers/dev environments.
    # /workspaces contains source code (git, node_modules) -> massive scan time.
    prune_paths = [
        "/proc", "/sys", "/dev", "/run", "/tmp",
        "/snap", "/var/lib/snapd", "/var/lib/flatpak",
        "/workspaces", "/home/codespace/.vscode-server"
    ]
    
    prune_args = []
    for p in prune_paths:
        prune_args.extend(["-path", p, "-prune", "-o"])

    # find / (prunes) -type f \( -perm -4000 -o -perm -2000 \) -print
    cmd = ["find", "/"] + prune_args + [
        "-type", "f",
        "(", "-perm", "-4000", "-o", "-perm", "-2000", ")",
        "-print"
    ]

    # Increased timeout from 20s to 60s to handle slow container I/O
    res = run_command(cmd, timeout=60, strip_output=True)

    if res["timed_out"]:
        suid_info["error"] = "find command timed out after 60s"
        state["suid"] = suid_info
        return

    if res["binary_missing"]:
        suid_info["error"] = "find binary missing"
        state["suid"] = suid_info
        return
    
    # Check if find failed critically (syntax error), not just perm denied
    # 'find' usually returns 0 even on perm denied, but >0 on syntax error.
    if not res["ok"] and not res["stdout"]:
        # If we got no hits AND an error code, record the stderr
        suid_info["error"] = f"find command failed: {res['stderr'][:200]}"
        state["suid"] = suid_info
        return

    entries = []
    if res["stdout"]:
        for line in res["stdout"].splitlines():
            path = line.strip()
            if not path:
                continue
            entries.append({"path": path})

    suid_info["found"] = entries
    suid_info["method"] = "find_command"
    state["suid"] = suid_info
