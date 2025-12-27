"""
nullpeas/modules/loot_module.py
Analyzes discovered files for sensitive information (credentials, history).
v2.4 Improvements:
- Added handler for 'account_db' (Fixes invisible /etc/passwd).
- Reports 'unknown' loot so nothing silently vanishes.
- Refined exploitability for password hashes.
- Added Python type hints.
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
    by_cat = {}
    for item in found_items:
        cat = item.get("category", "unknown")
        by_cat.setdefault(cat, []).append(item["path"])

    # 1. Critical Credentials (SSH, Shadow, SCM)
    if "password_hashes" in by_cat:
        lines.append("### 🚨 Password Hashes (Shadow)")
        for p in by_cat["password_hashes"]:
            lines.append(f"- `{p}`")
            primitives.append(_make_primitive(
                p, "critical", "password_hashes", "password_store", 
                "Readable shadow file found.", origin_user, origin_user
            ))
        lines.append("")

    if "ssh_key" in by_cat:
        lines.append("### 🔑 SSH & Access Keys")
        for p in by_cat["ssh_key"]:
            lines.append(f"- `{p}`")
            if "id_" in p and ".pub" not in p:
                primitives.append(_make_primitive(
                    p, "critical", "ssh_key", "credential_file", 
                    "Private SSH key found.", origin_user, origin_user
                ))
        lines.append("")

    if "scm_creds" in by_cat:
        lines.append("### 🐙 Source Control Credentials")
        for p in by_cat["scm_creds"]:
            lines.append(f"- `{p}`")
            primitives.append(_make_primitive(
                p, "severe", "scm_creds", "credential_file", 
                "Git credentials file found.", origin_user, origin_user
            ))
        lines.append("")

    # 2. Cloud & Infrastructure
    if "cloud_creds" in by_cat:
        lines.append("### ☁️ Cloud Credentials")
        for p in by_cat["cloud_creds"]:
            lines.append(f"- `{p}`")
            primitives.append(_make_primitive(
                p, "severe", "cloud_creds", "credential_file", 
                "Cloud credentials file found.", origin_user, origin_user
            ))
        lines.append("")
        
    if "container_config" in by_cat:
        lines.append("### 🐳 Container Configuration")
        for p in by_cat["container_config"]:
            lines.append(f"- `{p}`")
            primitives.append(_make_primitive(
                p, "useful", "container_config", "info_disclosure", 
                "Container config (docker-compose) found.", origin_user, origin_user
            ))
        lines.append("")

    # 3. Application Configs
    if "web_config" in by_cat:
        lines.append("### 🌐 Web Configuration Secrets")
        for p in by_cat["web_config"]:
            lines.append(f"- `{p}`")
            primitives.append(_make_primitive(
                p, "useful", "web_config", "config_file", 
                "Web config likely containing DB creds.", origin_user, origin_user
            ))
        lines.append("")
        
    if "config_secret" in by_cat:
        lines.append("### ⚙️ Other Configuration Secrets")
        for p in by_cat["config_secret"]:
            lines.append(f"- `{p}`")
        lines.append("")

    # 4. User Enumeration / History
    if "account_db" in by_cat:  # <--- NEW HANDLER
        lines.append("### 👥 Account Databases")
        for p in by_cat["account_db"]:
            lines.append(f"- `{p}`")
            # Useful for enumeration, but usually low impact on its own
            primitives.append(_make_primitive(
                p, "useful", "account_db", "info_disclosure", 
                "Account database (passwd) found.", origin_user, origin_user
            ))
        lines.append("")

    if "shell_history" in by_cat:
        lines.append("### 📜 Shell History")
        for p in by_cat["shell_history"]:
            lines.append(f"- `{p}`")
            primitives.append(_make_primitive(
                p, "useful", "shell_history", "info_disclosure", 
                "Shell history file found.", origin_user, origin_user
            ))
        lines.append("")

    # 5. Unknown / Unclassified (Safety Net)
    if "unknown" in by_cat:
        lines.append("### 🧩 Other Potential Loot (Unclassified)")
        for p in by_cat["unknown"]:
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
    run_as: str
) -> Primitive:
    """
    Helper to keep the loop clean.
    """
    score_map = {
        "critical": 10.0,
        "severe": 9.0,
        "useful": 7.0,
        "niche": 4.0
    }
    score = score_map.get(classification, 7.0)

    # Determine exploitability
    exploitability = "trivial" # Default for reading text files
    
    # Hashes require cracking -> Moderate
    if type_id == "password_hashes":
        exploitability = "moderate"
    # Useful info often needs parsing/inference -> Moderate
    elif classification == "useful":
        exploitability = "moderate"

    return Primitive(
        id=new_primitive_id("loot", type_id),
        surface="file_system",
        type=ptype,
        run_as=run_as,
        origin_user=user,
        exploitability=exploitability, # type: ignore
        stability="safe",
        noise="low",
        confidence=PrimitiveConfidence(score=score, reason=why),
        offensive_value=OffensiveValue(classification=classification, why=why), # type: ignore
        context={"path": path},
        affected_resource=path,
        module_source="loot_module",
        probe_source="loot_probe"
    )
