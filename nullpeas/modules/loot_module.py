"""
nullpeas/modules/loot_module.py
Analyzes discovered files for sensitive information (credentials, history).
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
    required_triggers=[], # Runs if probe has data
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

    # Group by category for cleaner report
    by_cat = {}
    for item in found_items:
        cat = item["category"]
        if cat not in by_cat: by_cat[cat] = []
        by_cat[cat].append(item["path"])

    # SSH Keys
    if "ssh_key" in by_cat:
        lines.append("### 🔑 SSH & Access Keys")
        for p in by_cat["ssh_key"]:
            lines.append(f"- `{p}`")
            
            # Create Primitive
            if "id_" in p and ".pub" not in p: # Private keys only
                primitives.append(Primitive(
                    id=new_primitive_id("loot", "ssh_key"),
                    surface="file_system",
                    type="credential_file",
                    run_as="current_user",
                    origin_user=origin_user,
                    exploitability="trivial",
                    stability="safe",
                    noise="low",
                    confidence=PrimitiveConfidence(score=10.0, reason="Private SSH key found"),
                    offensive_value=OffensiveValue(
                        classification="critical",
                        why="Private SSH keys allow immediate lateral movement or persistence."
                    ),
                    context={"path": p},
                    affected_resource=p,
                    module_source="loot_module",
                    probe_source="loot_probe"
                ))
        lines.append("")

    # Cloud Creds
    if "cloud_creds" in by_cat:
        lines.append("### ☁️ Cloud Credentials")
        for p in by_cat["cloud_creds"]:
            lines.append(f"- `{p}`")
            
            primitives.append(Primitive(
                id=new_primitive_id("loot", "cloud_creds"),
                surface="file_system",
                type="credential_file",
                run_as="current_user",
                origin_user=origin_user,
                exploitability="trivial",
                stability="safe",
                noise="low",
                confidence=PrimitiveConfidence(score=9.0, reason="Cloud credentials file found"),
                offensive_value=OffensiveValue(
                    classification="severe",
                    why="Cloud credentials often allow data exfiltration or infrastructure control."
                ),
                context={"path": p},
                affected_resource=p,
                module_source="loot_module",
                probe_source="loot_probe"
            ))
        lines.append("")

    # Configs
    if "config_secret" in by_cat:
        lines.append("### ⚙️ Configuration Secrets")
        for p in by_cat["config_secret"]:
            lines.append(f"- `{p}`")
            # Configs are context dependent, marked as useful/severe
            primitives.append(Primitive(
                id=new_primitive_id("loot", "config"),
                surface="file_system",
                type="sensitive_file",
                run_as="current_user",
                origin_user=origin_user,
                exploitability="moderate", # Requires reading/parsing
                stability="safe",
                noise="low",
                confidence=PrimitiveConfidence(score=7.0, reason="Potential secret in config file"),
                offensive_value=OffensiveValue(
                    classification="useful",
                    why="Configuration files often contain database passwords or API keys."
                ),
                context={"path": p},
                affected_resource=p,
                module_source="loot_module",
                probe_source="loot_probe"
            ))
        lines.append("")

    # History
    if "shell_history" in by_cat:
        lines.append("### 📜 Shell History")
        for p in by_cat["shell_history"]:
            lines.append(f"- `{p}`")
            # History is useful info disclosure
        lines.append("")

    report.add_section("Loot Analysis", lines)
