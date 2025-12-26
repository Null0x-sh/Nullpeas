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

    # We rely on 'find' because Python os.walk is too slow for the whole disk
    if shutil.which("find") is None:
        suid_info["error"] = "find binary not present"
        state["suid"] = suid_info
        return

    # Construct a fast find command
    # -perm -4000 = SUID
    # -perm -2000 = SGID
    # Exclude virtual filesystems to prevent hangs/loops
    prune_paths = [
        "/proc", "/sys", "/dev", "/run", 
        "/snap", "/var/lib/snapd", "/var/lib/flatpak"
    ]
    
    # Build prune arguments
    prune_args = []
    for p in prune_paths:
        prune_args.extend(["-path", p, "-prune", "-o"])

    # Full command: 
    # find / (prunes) -type f \( -perm -4000 -o -perm -2000 \) -print
    cmd = ["find", "/"] + prune_args + [
        "-type", "f",
        "(", "-perm", "-4000", "-o", "-perm", "-2000", ")",
        "-print"
    ]

    # Set a generous timeout as full disk scan can take time
    res = run_command(cmd, timeout=20, strip_output=True)

    if res["timed_out"]:
        suid_info["error"] = "find command timed out after 20s"
        state["suid"] = suid_info
        return

    if res["binary_missing"]:
        # Should be caught above, but safety first
        suid_info["error"] = "find binary missing"
        state["suid"] = suid_info
        return
        
    # We ignore standard errors (Permission Denied) because that's expected
    # when scanning as non-root. We only care about stdout.
    
    entries = []
    if res["stdout"]:
        for line in res["stdout"].splitlines():
            path = line.strip()
            if not path:
                continue
            
            # Basic classification (we could do stat() here but it slows it down)
            # We will let the Module confirm details if needed.
            entries.append({"path": path})

    suid_info["found"] = entries
    suid_info["method"] = "find_command"
    state["suid"] = suid_info
