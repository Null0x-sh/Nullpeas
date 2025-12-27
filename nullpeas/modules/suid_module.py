"""
nullpeas/modules/suid_module.py
Analyses SUID/SGID binaries for known privilege escalation vectors.
"""

from typing import Dict, Any, List, Set, Optional
import os
import stat

from nullpeas.core.report import Report
from nullpeas.modules import register_module
from nullpeas.core.offensive_schema import (
    Primitive,
    PrimitiveConfidence,
    OffensiveValue,
    new_primitive_id,
)

# Common SUID GTFOBins (High Priority)
KNOWN_SUID_BINS = {
    "bash", "sh", "ksh", "csh", "tcsh", "zsh",
    "env", "python", "python3", "perl", "ruby", "lua", "php",
    "vim", "vi", "nano", "find", "awk", "nmap", "gdb", "man", "less", "more",
    "cp", "mv", "chown", "chmod", "date", "base64", "tar", "zip",
    "systemctl", "docker", "snap", "git", "sed", "pip"
}

# Standard System Binaries (Ignore List)
# These are normally SUID but rarely exploitable in default configs.
# Filtering them removes noise.
IGNORE_LIST = {
    "sudo", "su", "passwd", "mount", "umount", "chfn", "chsh", "gpasswd",
    "newgrp", "pkexec", "polkit-agent-helper-1", "ssh-keysign", 
    "dbus-daemon-launch-helper", "fusermount", "fusermount3", "at", 
    "snap-confine", "chrome-sandbox"
}


def _get_binary_name(path: str) -> str:
    return os.path.basename(path)


def _analyze_suid_file(path: str) -> Dict[str, Any]:
    info = {
        "path": path,
        "is_suid": False,
        "is_sgid": False,
        "owner": None,
        "group": None,
        "known_gtfobin": False,
        "binary": _get_binary_name(path)
    }
    
    if info["binary"] in KNOWN_SUID_BINS:
        info["known_gtfobin"] = True

    try:
        st = os.stat(path)
        mode = st.st_mode
        info["is_suid"] = bool(mode & stat.S_ISUID)
        info["is_sgid"] = bool(mode & stat.S_ISGID)
        info["owner"] = st.st_uid
        info["group"] = st.st_gid
    except OSError:
        pass
        
    return info


def _build_suid_primitive(entry: Dict[str, Any], user_name: str) -> Optional[Primitive]:
    if not entry["is_suid"]:
        return None
        
    if entry["owner"] != 0:
        return None

    binary = entry["binary"]
    
    # FILTER: Skip standard system binaries to reduce noise
    if binary in IGNORE_LIST and not entry["known_gtfobin"]:
        return None

    path = entry["path"]
    is_known = entry["known_gtfobin"]

    if is_known:
        primitive_type = "root_shell_primitive"
        confidence_score = 9.5
        why = f"Known GTFOBin '{binary}' has SUID bit set. Trivial root escalation."
        classification = "catastrophic"
        exploitability = "trivial"
        stability = "safe"
    else:
        # Unknown custom SUID binary
        primitive_type = "suid_primitive" 
        confidence_score = 6.0
        why = f"Unknown SUID binary '{binary}'. May be vulnerable to buffer overflows or logic bugs."
        classification = "useful"
        exploitability = "advanced"
        stability = "unknown"

    confidence = PrimitiveConfidence(
        score=confidence_score,
        reason=f"Found SUID bit on {path} owned by root."
    )

    offensive_value = OffensiveValue(
        classification=classification,
        why=why
    )

    return Primitive(
        id=new_primitive_id("suid", primitive_type),
        surface="suid",
        type=primitive_type,
        run_as="root",
        origin_user=user_name,
        exploitability=exploitability,
        stability=stability,
        noise="low",
        confidence=confidence,
        offensive_value=offensive_value,
        context={
            "binary": binary,
            "binary_path": path,
            "is_known_gtfobin": is_known,
        },
        integration_flags={
            "root_goal_candidate": is_known,
        },
        affected_resource=path,
        module_source="suid_module",
        probe_source="suid_probe",
    )


@register_module(
    key="suid_module",
    description="Scan for SUID/SGID binaries that allow privilege escalation",
    required_triggers=["suid_files_present"],
)
def run(state: Dict[str, Any], report: Report):
    if state.get("triggers", {}).get("is_root"):
        return

    suid_data = state.get("suid", {})
    raw_found = suid_data.get("found", [])
    
    if not raw_found:
        return

    user = state.get("user", {}) or {}
    user_name = user.get("name") or "current_user"

    findings = []
    
    for raw in raw_found:
        info = _analyze_suid_file(raw["path"])
        if info["is_suid"] or info["is_sgid"]:
            findings.append(info)

    if not findings:
        return

    # Build Report
    lines = []
    lines.append("Analysis of Set-User-ID (SUID) and Set-Group-ID (SGID) files.")
    lines.append("These files execute with the permissions of their owner (usually root).")
    lines.append("")
    
    lines.append("### SUID Binaries")
    for f in findings:
        if f["is_suid"]:
            icon = "🚨" if f["known_gtfobin"] else "ℹ️"
            # Mark ignored binaries in the list for transparency
            note = "(Ignored Standard)" if f["binary"] in IGNORE_LIST else ""
            lines.append(f"- {icon} `{f['path']}` {note}")
    
    lines.append("")
    lines.append("### SGID Binaries")
    for f in findings:
        if f["is_sgid"]:
             lines.append(f"- `{f['path']}`")

    report.add_section("SUID/SGID Analysis", lines)

    # Generate Primitives
    primitives = state.setdefault("offensive_primitives", [])
    
    for f in findings:
        if f["is_suid"] and f["owner"] == 0:
            p = _build_suid_primitive(f, user_name)
            if p:
                primitives.append(p)
