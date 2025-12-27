"""
nullpeas/modules/loot_module.py
Analyzes discovered files for sensitive information (credentials, history).
v2.5 Improvements:
- Honours 'readable' flag from probe.
- Downgrades unreadable /etc/shadow to 'theoretical' (reduces false positives).
- Refined primitive generation logic.
"""

from typing import Dict, Any, List, Optional
from nullpeas.core.report import Report
from nullpeas.modules import register_module
from nullpeas.core.offensive_schema import (
    Primitive,
    PrimitiveConfidence,
    OffensiveValue,
    new_primitive_id,
)

@register_module(
    key="loot_module",
    description="Analyze file system for sensitive loot (SSH keys, history, configs)",
    required_triggers=[], 
)
def run(state: Dict[str, Any], report: Report):
    loot_data = state.get("loot", {})
    found_items = loot_data.get("found", [])
    
    if not found_items:
        return

    user = state.get("user", {}) or {}
    origin_user = user.get("name") or "current_user"

    primitives = state.setdefault("offensive_primitives", [])
    
    # --- Reporting ---
    lines = []
    lines.append("Analysis of sensitive files (Loot).")
    lines.append("These files often contain hardcoded credentials, keys, or historic commands.")
    lines.append("")

    # Group by category safely
    # Note: We now store the full item dict, not just path
    by_cat: Dict[str, List[Dict[str, Any]]] = {}
    for item in found_items:
        cat = item.get("category", "unknown")
        by_cat.setdefault(cat, []).append(item)

    # 1. Critical Credentials (SSH, Shadow, SCM)
    if "password_hashes" in by_cat:
        lines.append("### 🚨 Password Hashes (Shadow)")
        for item in by_cat["password_hashes"]:
            p = item["path"]
            readable = item.get("readable", False)
            
            status_icon = "✅" if readable else "⛔"
            lines.append(f"- {status_icon} `{p}`")
            
            # Logic: Only Critical if Readable
            if readable:
                primitives.append(_make_primitive(
                    p, "critical", "password_hashes", "password_store", 
                    "Readable shadow file found.", origin_user, origin_user,
                    readable=readable,
                ))
            else:
                # Theoretical / Recon value only
                primitives.append(_make_primitive(
                    p, "useful", "password_hashes", "password_store",
                    "Shadow file exists but is not readable.", origin_user, origin_user,
                    exploitability_override="theoretical",
                    readable=readable,
                ))
        lines.append("")

    if "ssh_key" in by_cat:
        lines.append("### 🔑 SSH & Access Keys")
        for item in by_cat["ssh_key"]:
            p = item["path"]
            readable = item.get("readable", False)
            lines.append(f"- `{p}`")
            
            if "id_" in p and ".pub" not in p:
                if readable:
                    primitives.append(_make_primitive(
                        p, "critical", "ssh_key", "credential_file", 
                        "Private SSH key found.", origin_user, origin_user,
                        readable=readable,
                    ))
                else:
                    primitives.append(_make_primitive(
                        p, "useful", "ssh_key", "credential_file", 
                        "Private SSH key found (unreadable).", origin_user, origin_user,
                        exploitability_override="theoretical",
                        readable=readable,
                    ))

        lines.append("")

    if "scm_creds" in by_cat:
        lines.append("### 🐙 Source Control Credentials")
        for item in by_cat["scm_creds"]:
            p = item["path"]
            readable = item.get("readable", False)
            lines.append(f"- `{p}`")
            if readable:
                primitives.append(_make_primitive(
                    p, "severe", "scm_creds", "credential_file", 
                    "Git credentials file found.", origin_user, origin_user,
                    readable=readable,
                ))
        lines.append("")

    # 2. Cloud & Infrastructure
    if "cloud_creds" in by_cat:
        lines.append("### ☁️ Cloud Credentials")
        for item in by_cat["cloud_creds"]:
            p = item["path"]
            readable = item.get("readable", False)
            lines.append(f"- `{p}`")
            if readable:
                primitives.append(_make_primitive(
                    p, "severe", "cloud_creds", "credential_file", 
                    "Cloud credentials file found.", origin_user, origin_user,
                    readable=readable,
                ))
        lines.append("")
        
    if "container_config" in by_cat:
        lines.append("### 🐳 Container Configuration")
        for item in by_cat["container_config"]:
            p = item["path"]
            readable = item.get("readable", False)
            lines.append(f"- `{p}`")
            if readable:
                primitives.append(_make_primitive(
                    p, "useful", "container_config", "info_disclosure", 
                    "Container config (docker-compose) found.", origin_user, origin_user,
                    readable=readable,
                ))
        lines.append("")

    # 3. Application Configs
    if "web_config" in by_cat:
        lines.append("### 🌐 Web Configuration Secrets")
        for item in by_cat["web_config"]:
            p = item["path"]
            readable = item.get("readable", False)
            lines.append(f"- `{p}`")
            if readable:
                primitives.append(_make_primitive(
                    p, "useful", "web_config", "config_file", 
                    "Web config likely containing DB creds.", origin_user, origin_user,
                    readable=readable,
                ))
        lines.append("")
        
    if "config_secret" in by_cat:
        lines.append("### ⚙️ Other Configuration Secrets")
        for item in by_cat["config_secret"]:
            p = item["path"]
            lines.append(f"- `{p}`")
        lines.append("")

    # 4. User Enumeration / History
    if "account_db" in by_cat:
        lines.append("### 👥 Account Databases")
        for item in by_cat["account_db"]:
            p = item["path"]
            readable = item.get("readable", False)
            lines.append(f"- `{p}`")
            primitives.append(_make_primitive(
                p, "useful", "account_db", "info_disclosure", 
                "Account database (passwd) found.", origin_user, origin_user,
                readable=readable,
            ))
        lines.append("")

    if "shell_history" in by_cat:
        lines.append("### 📜 Shell History")
        for item in by_cat["shell_history"]:
            p = item["path"]
            readable = item.get("readable", False)
            lines.append(f"- `{p}`")
            if readable:
                primitives.append(_make_primitive(
                    p, "useful", "shell_history", "info_disclosure", 
                    "Shell history file found.", origin_user, origin_user,
                    readable=readable,
                ))
        lines.append("")

    # 5. Unknown / Unclassified
    if "unknown" in by_cat:
        lines.append("### 🧩 Other Potential Loot (Unclassified)")
        for item in by_cat["unknown"]:
            p = item["path"]
            lines.append(f"- `{p}`")
        lines.append("")

    if loot_data.get("error"):
        lines.append(f"> ⚠️ **Note:** {loot_data['error']}")

    report.add_section("Loot Analysis", lines)


def _make_primitive(
    path: str, 
    classification: str, 
    type_id: str, 
    ptype: str, 
    why: str, 
    user: str, 
    run_as: str,
    exploitability_override: Optional[str] = None,
    readable: Optional[bool] = None,
) -> Primitive:
    """
    Helper to keep the loop clean.
    v2.5: Accepts exploitability_override + readable.
    """
    score_map = {
        "critical": 10.0,
        "severe": 9.0,
        "high": 8.0,
        "useful": 7.0,
        "niche": 4.0
    }
    score = score_map.get(classification, 7.0)

    # Determine exploitability
    exploitability = "trivial"  # Default for reading text files
    
    if type_id == "password_hashes":
        exploitability = "moderate"
    elif classification == "useful":
        exploitability = "moderate"
        
    # Apply override if provided (e.g. "theoretical" for unreadable files)
    if exploitability_override:
        exploitability = exploitability_override

    ctx: Dict[str, Any] = {"path": path}
    if readable is not None:
        ctx["readable"] = readable

    return Primitive(
        id=new_primitive_id("loot", type_id),
        surface="file_system",
        type=ptype,
        run_as=run_as,
        origin_user=user,
        exploitability=exploitability,  # type: ignore
        stability="safe",
        noise="low",
        confidence=PrimitiveConfidence(score=score, reason=why),
        offensive_value=OffensiveValue(classification=classification, why=why),  # type: ignore
        context=ctx,
        affected_resource=path,
        module_source="loot_module",
        probe_source="loot_probe",
    )
