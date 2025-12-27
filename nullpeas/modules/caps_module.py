"""
nullpeas/modules/caps_module.py
Analyzes Linux Capabilities for privilege escalation vectors.
"""

from typing import Dict, Any, List, Tuple
import os

from nullpeas.core.report import Report
from nullpeas.modules import register_module
from nullpeas.core.offensive_schema import (
    Primitive,
    PrimitiveConfidence,
    OffensiveValue,
    new_primitive_id,
)

# Capabilities that are functionally equivalent to high privileges
CRITICAL_CAPS = {
    "cap_setuid",      # Can become any user (including root)
    "cap_setgid",      # Can become any group
    "cap_dac_override" # Bypass file read/write checks (Read/Write anything)
}

# Known GTFOBins that work with capabilities (Same list as SUID usually)
KNOWN_CAP_BINS = {
    "python", "python3", "perl", "ruby", "lua", "php",
    "vim", "vi", "nano", "view", "emacs",
    "tar", "gdb", "node", "ruby", "openssl"
}

def _analyze_capability_impact(caps_str: str, binary_name: str) -> Tuple[str, str, str, str, str]:
    """
    Returns: (primitive_type, why, exploitability, stability, offensive_classification)
    """
    is_known = binary_name in KNOWN_CAP_BINS
    
    # Defaults for unknown custom binaries
    exploitability = "advanced"
    stability = "unknown"
    classification = "useful"
    
    if is_known:
        exploitability = "trivial"
        stability = "safe"
        classification = "catastrophic"

    # 1. CAP_SETUID (Root Shell)
    if "cap_setuid" in caps_str:
        return (
            "root_shell_primitive",
            f"Binary has 'cap_setuid'. Equivalent to SUID Root.",
            exploitability,
            stability,
            classification
        )

    # 2. CAP_DAC_OVERRIDE (Arbitrary File Write/Read)
    if "cap_dac_override" in caps_str:
        return (
            "arbitrary_file_access_primitive",
            f"Binary has 'cap_dac_override'. Can bypass file permissions to read/write sensitive files.",
            exploitability,
            stability,
            "severe" # High impact, but requires a second step (writing to /etc/passwd etc) to get shell
        )

    # 3. CAP_SETGID (Group Pivot)
    if "cap_setgid" in caps_str:
        return (
            "group_pivot_primitive",
            f"Binary has 'cap_setgid'. Can pivot to arbitrary groups (e.g. disk, shadow, root group).",
            exploitability,
            stability,
            "useful"
        )
        
    return ("unknown", "unknown", "theoretical", "unknown", "niche")


@register_module(
    key="caps_module",
    description="Analyze file capabilities for hidden privilege escalation paths",
    required_triggers=[], 
)
def run(state: Dict[str, Any], report: Report):
    if state.get("triggers", {}).get("is_root"):
        return

    caps_data = state.get("caps", {})
    found_items = caps_data.get("found", [])
    
    if not found_items:
        return

    user = state.get("user", {}) or {}
    origin_user = user.get("name") or "current_user"

    primitives = state.setdefault("offensive_primitives", [])
    
    # 1. First Pass: Stats & Report Generation
    lines = []
    lines.append("Analysis of Linux Capabilities (getcap).")
    lines.append("Capabilities split root privileges into distinct units. Some allow full escalation.")
    lines.append("")

    critical_count = 0
    total_count = len(found_items)
    report_items = []

    for item in found_items:
        path = item["path"]
        caps_str = item["capabilities"].lower()
        
        # We generally only care about "+ep" (Effective+Permitted) or "+eip"
        if "+ep" not in caps_str and "+eip" not in caps_str:
            continue

        is_critical = any(c in caps_str for c in CRITICAL_CAPS)
        if is_critical:
            critical_count += 1
            icon = "🚨"
        else:
            icon = "ℹ️"
            
        report_items.append(f"- {icon} `{path}` = `{caps_str}`")

    # 2. Add Summary Header
    lines.append(f"Found {total_count} binaries with Linux capabilities.")
    lines.append(f"{critical_count} contain critical escalation capabilities (cap_setuid / cap_setgid / cap_dac_override).")
    lines.append("")
    lines.extend(report_items)
    
    report.add_section("Capabilities Analysis", lines)

    # 3. Second Pass: Primitive Generation
    for item in found_items:
        path = item["path"]
        caps_str = item["capabilities"].lower()
        binary_name = os.path.basename(path)

        if "+ep" not in caps_str and "+eip" not in caps_str:
            continue
            
        is_critical = any(c in caps_str for c in CRITICAL_CAPS)
        
        if is_critical:
            p_type, why, exploitability, stability, classification = _analyze_capability_impact(caps_str, binary_name)
            
            primitive = Primitive(
                id=new_primitive_id("caps", p_type.replace("_primitive", "")),
                surface="capabilities",
                type=p_type,
                run_as="root" if "setuid" in caps_str else "privileged",
                origin_user=origin_user,
                exploitability=exploitability, # type: ignore
                stability=stability,           # type: ignore
                noise="low",
                confidence=PrimitiveConfidence(score=9.5, reason=f"Verified {caps_str}"),
                offensive_value=OffensiveValue(
                    classification=classification, # type: ignore
                    why=why
                ),
                context={
                    "binary": binary_name,
                    "binary_path": path,
                    "capabilities": caps_str
                },
                integration_flags={
                    "root_goal_candidate": "root" in p_type,
                    "file_write_candidate": "dac_override" in p_type,
                },
                module_source="caps_module",
                probe_source="caps_probe"
            )
            primitives.append(primitive)
