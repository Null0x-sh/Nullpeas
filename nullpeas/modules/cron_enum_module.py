from typing import Dict, Any, List, Set, Tuple, Optional

from nullpeas.core.report import Report
from nullpeas.modules import register_module
from nullpeas.core.offensive_schema import (
    Primitive,
    PrimitiveConfidence,
    OffensiveValue,
    new_primitive_id,
)


def _is_system_cron_path(path: str) -> bool:
    if not path:
        return False
    if path == "/etc/crontab":
        return True
    if path.startswith("/etc/cron."):
        return True
    if path.startswith("/etc/anacron"):
        return True
    return False


def _is_spool_cron_path(path: str) -> bool:
    if not path:
        return False
    if path.startswith("/var/spool/cron"):
        return True
    if path.startswith("/var/spool/cron/crontabs"):
        return True
    return False


def _split_cron_files(files_meta: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    system_files: List[Dict[str, Any]] = []
    spool_files: List[Dict[str, Any]] = []

    for fm in files_meta:
        path = fm.get("path") or ""
        if _is_system_cron_path(path):
            system_files.append(fm)
        elif _is_spool_cron_path(path):
            spool_files.append(fm)

    return system_files, spool_files


def _classify_cron_files(files_meta: List[Dict[str, Any]]) -> Dict[str, Any]:
    system_files, spool_files = _split_cron_files(files_meta)

    root_system = 0
    nonroot_system = 0
    root_spool = 0
    nonroot_spool = 0
    
    # === NEW: Track verified writable files ===
    writable_system_files: List[str] = []
    writable_spool_files: List[str] = []

    for fm in system_files:
        owner = fm.get("owner") or ""
        path = fm.get("path") or ""
        
        if owner == "root":
            root_system += 1
        else:
            nonroot_system += 1

        # High Fidelity Check
        if fm.get("can_i_write"):
            writable_system_files.append(path)

    for fm in spool_files:
        owner = fm.get("owner") or ""
        path = fm.get("path") or ""
        
        if owner == "root":
            root_spool += 1
        else:
            nonroot_spool += 1
            
        # High Fidelity Check
        if fm.get("can_i_write"):
            writable_spool_files.append(path)

    return {
        "system_files": system_files,
        "spool_files": spool_files,
        "root_system": root_system,
        "nonroot_system": nonroot_system,
        "root_spool": root_spool,
        "nonroot_spool": nonroot_spool,
        "writable_system_files": writable_system_files,
        "writable_spool_files": writable_spool_files,
        "any_writable": bool(writable_system_files or writable_spool_files),
    }


def _cron_severity_and_confidence(
    classification: Dict[str, Any],
    user_crontab_ok: bool,
) -> Tuple[Tuple[float, str], Tuple[float, str]]:
    
    any_writable = classification["any_writable"]
    writable_system = classification["writable_system_files"]
    
    # Baseline
    base_sev = 0.0
    
    # Presence of files increases score slightly
    if classification["root_system"] > 0: base_sev = max(base_sev, 0.4)
    if classification["root_spool"] > 0: base_sev = max(base_sev, 0.4)
    if user_crontab_ok: base_sev = max(base_sev, 0.3)

    # === SCORING LOGIC ===
    # If we can write to a system cron file, that is effectively root.
    if writable_system:
        base_sev = 1.0  # Critical
    elif any_writable:
        base_sev = 0.9  # High (Spool might be user-level, but still dangerous)
    
    severity_score = round(base_sev * 10.0, 1)

    if severity_score >= 8.5:
        severity_band = "Critical"
    elif severity_score >= 6.5:
        severity_band = "High"
    elif severity_score >= 3.5:
        severity_band = "Medium"
    else:
        severity_band = "Low"

    # Confidence
    conf_score = 5.0
    if any_writable:
        # We verified access with os.access, so confidence is max
        conf_score = 9.5
    elif classification["root_system"] > 0 or user_crontab_ok:
        conf_score = 7.0

    if conf_score >= 8.0:
        conf_band = "High"
    elif conf_score >= 5.5:
        conf_band = "Medium"
    else:
        conf_band = "Low"

    return (severity_score, severity_band), (conf_score, conf_band)


def _offensive_classification_from_band(severity_band: str) -> str:
    if severity_band == "Critical":
        return "catastrophic"
    if severity_band == "High":
        return "severe"
    if severity_band == "Medium":
        return "useful"
    return "niche"


def _primitive_type_for_cron_surface(
    classification: Dict[str, Any],
    severity_band: str,
    user_crontab_ok: bool,
) -> str:
    writable_system = classification["writable_system_files"]
    any_writable = classification["any_writable"]

    # 1. Root File Write (The Jackpot)
    if writable_system:
        return "cron_exec_primitive" # Maps to exploit template
    
    if any_writable:
        # Writable spool or other non-system cron
        return "cron_exec_primitive"

    if user_crontab_ok:
        return "cron_user_persistence_surface"

    return "cron_scheduled_execution_surface"


def _primitive_for_cron_surface(
    user_name: Optional[str],
    classification: Dict[str, Any],
    risk_categories: Set[str],
    capabilities: Set[str],
    severity_score: float,
    severity_band: str,
    conf_score: float,
    conf_band: str,
) -> Primitive:
    user_name = user_name or "current_user"

    primitive_type = _primitive_type_for_cron_surface(
        classification=classification,
        severity_band=severity_band,
        user_crontab_ok=("cron_user_crontab_present" in risk_categories),
    )

    # Determine Run As
    # If we are hijacking a system file, it runs as root.
    if classification["writable_system_files"]:
        run_as = "root"
    else:
        # Default assumption, might be refined later
        run_as = "root" if classification["root_system"] > 0 else user_name

    # Determine Exploitability
    if primitive_type == "cron_exec_primitive":
        exploitability = "high" # Verified write access
        stability = "safe"      # Appending to a file is generally safe
    else:
        exploitability = "theoretical"
        stability = "safe"

    noise = "low"

    classification_band = _offensive_classification_from_band(severity_band)

    confidence = PrimitiveConfidence(
        score=conf_score,
        reason=f"Cron surfaces observed with {conf_band} confidence (verified permissions).",
    )

    offensive_value = OffensiveValue(
        classification=classification_band,
        why=(
            f"Cron configuration grants {primitive_type} (run_as={run_as}). "
            "Writable cron files enable persistence and often direct privilege escalation."
        ),
    )
    
    # === CONTEXT FOR EXPLOIT GENERATOR ===
    # We pick the first writable file to be the target of our exploit suggestion
    target_file = None
    all_writables = classification["writable_system_files"] + classification["writable_spool_files"]
    if all_writables:
        target_file = all_writables[0]

    primitive = Primitive(
        id=new_primitive_id("cron", primitive_type),
        surface="cron",
        type=primitive_type,
        run_as=run_as,
        origin_user=user_name,
        exploitability=exploitability,  # type: ignore
        stability=stability,            # type: ignore
        noise=noise,                    # type: ignore
        confidence=confidence,
        offensive_value=offensive_value,
        context={
            "classification": classification,
            "risk_categories": sorted(risk_categories),
            "severity_band": severity_band,
            "target_file": target_file, # <--- Used by exploit_templates.py
        },
        conditions={
            "requires_writable_target": True if target_file else False,
        },
        integration_flags={
            "chaining_allowed": True,
        },
        cross_refs={
            "gtfobins": [],
            "cves": [],
            "documentation": [],
        },
        defensive_impact={
            "risk_to_system": "total_compromise" if run_as == "root" else "high",
        },
        # === Resource Linking ===
        affected_resource=target_file, 
        
        module_source="cron_enum",
        probe_source="cron_probe",
    )

    return primitive


@register_module(
    key="cron_enum",
    description="Analyse cron configuration and scheduled execution surfaces",
    required_triggers=["cron_privesc_surface"],
)
def run(state: dict, report: Report):
    cron = state.get("cron", {}) or {}
    user = state.get("user", {}) or {}

    files_meta = cron.get("files_metadata") or []
    user_cron = cron.get("user_crontab", {}) or {}
    user_cron_status = user_cron.get("status")
    user_crontab_ok = (user_cron_status == "ok")

    if not files_meta and not user_crontab_ok:
        report.add_section(
            "Cron Analysis",
            [
                "Cron metadata is present but no cron files or user crontab entries were identified.",
            ],
        )
        return

    classification = _classify_cron_files(files_meta)
    
    # Extract counts for report
    root_system = classification["root_system"]
    writable_system = classification["writable_system_files"]
    writable_spool = classification["writable_spool_files"]
    any_writable = classification["any_writable"]

    capabilities: Set[str] = set()
    if any_writable:
        capabilities.add("file_write")
        capabilities.add("scheduled_execution")
    if user_crontab_ok:
        capabilities.add("persistence")

    risk_categories: Set[str] = set()
    if writable_system:
        risk_categories.add("cron_root_writable")
    if user_crontab_ok:
        risk_categories.add("cron_user_crontab_present")

    (severity_score, severity_band), (conf_score, conf_band) = _cron_severity_and_confidence(
        classification=classification,
        user_crontab_ok=user_crontab_ok,
    )

    # --- Report section ---
    lines: List[str] = []
    lines.append("This section analyses cron configuration and scheduled execution surfaces.")
    lines.append("")

    lines.append("### Cron summary")
    lines.append(f"- Root-owned system cron files     : {root_system}")
    lines.append(f"- Writable system cron files       : {len(writable_system)}")
    lines.append(f"- Writable spool files             : {len(writable_spool)}")
    lines.append(f"- Per-user crontab for this user   : {user_crontab_ok}")
    lines.append("")
    
    if any_writable:
        lines.append("#### 🚨 Verified Writable Cron Files")
        for f in writable_system:
             lines.append(f"- SYSTEM (Root): `{f}`")
        for f in writable_spool:
             lines.append(f"- SPOOL: `{f}`")
        lines.append("")

    lines.append("### Assessed cron attack surface")
    lines.append(f"- Severity                        : {severity_band} ({severity_score}/10)")
    lines.append(f"- Confidence                      : {conf_band} ({conf_score}/10)")
    
    if risk_categories:
        lines.append(f"- Risk categories                 : {', '.join(sorted(risk_categories))}")
    lines.append("")

    report.add_section("Cron Analysis", lines)

    primitive = _primitive_for_cron_surface(
        user_name=user.get("name"),
        classification=classification,
        risk_categories=risk_categories,
        capabilities=capabilities,
        severity_score=severity_score,
        severity_band=severity_band,
        conf_score=conf_score,
        conf_band=conf_band,
    )

    state.setdefault("offensive_primitives", []).append(primitive)
