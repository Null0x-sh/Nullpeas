from typing import Dict, Any, List, Set, Tuple, Optional

from nullpeas.core.report import Report
from nullpeas.modules import register_module
from nullpeas.core.offensive_schema import (
    Primitive,
    PrimitiveConfidence,
    OffensiveValue,
    new_primitive_id,
)


def _mode_world_group_bits(mode_str: str) -> Tuple[bool, bool]:
    try:
        mode_int = int(mode_str, 8)
    except Exception:
        return False, False
    world_write = bool(mode_int & 0o002)
    group_write = bool(mode_int & 0o020)
    return world_write, group_write


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

    any_world_writable_system = False
    any_group_writable_system = False
    any_world_writable_spool = False
    any_group_writable_spool = False
    any_root_system_world_writable = False
    any_root_system_group_writable = False

    for fm in system_files:
        path = fm.get("path") or ""
        owner = fm.get("owner") or ""
        mode = fm.get("mode") or ""

        if owner == "root":
            root_system += 1
        else:
            nonroot_system += 1

        world_access, group_access = _mode_world_group_bits(mode)
        if world_access:
            any_world_writable_system = True
            if owner == "root":
                any_root_system_world_writable = True
        if group_access:
            any_group_writable_system = True
            if owner == "root":
                any_root_system_group_writable = True

    for fm in spool_files:
        owner = fm.get("owner") or ""
        mode = fm.get("mode") or ""

        if owner == "root":
            root_spool += 1
        else:
            nonroot_spool += 1

        world_access, group_access = _mode_world_group_bits(mode)
        if world_access:
            any_world_writable_spool = True
        if group_access:
            any_group_writable_spool = True

    return {
        "system_files": system_files,
        "spool_files": spool_files,
        "root_system": root_system,
        "nonroot_system": nonroot_system,
        "root_spool": root_spool,
        "nonroot_spool": nonroot_spool,
        "any_world_writable_system": any_world_writable_system,
        "any_group_writable_system": any_group_writable_system,
        "any_world_writable_spool": any_world_writable_spool,
        "any_group_writable_spool": any_group_writable_spool,
        "any_root_system_world_writable": any_root_system_world_writable,
        "any_root_system_group_writable": any_root_system_group_writable,
    }


def _cron_severity_and_confidence(
    classification: Dict[str, Any],
    user_crontab_ok: bool,
) -> Tuple[Tuple[float, str], Tuple[float, str]]:
    root_system = classification["root_system"]
    nonroot_system = classification["nonroot_system"]
    root_spool = classification["root_spool"]
    nonroot_spool = classification["nonroot_spool"]

    any_world_writable_system = classification["any_world_writable_system"]
    any_group_writable_system = classification["any_group_writable_system"]
    any_world_writable_spool = classification["any_world_writable_spool"]
    any_group_writable_spool = classification["any_group_writable_spool"]
    any_root_system_world_writable = classification["any_root_system_world_writable"]
    any_root_system_group_writable = classification["any_root_system_group_writable"]

    base_sev = 0.0

    if root_system > 0:
        base_sev = max(base_sev, 0.6)
    if nonroot_system > 0:
        base_sev = max(base_sev, 0.5)
    if root_spool > 0:
        base_sev = max(base_sev, 0.6)
    if nonroot_spool > 0:
        base_sev = max(base_sev, 0.4)

    if any_world_writable_system or any_group_writable_system:
        base_sev += 0.2

    if any_root_system_world_writable or any_root_system_group_writable:
        base_sev += 0.3

    if any_world_writable_spool or any_group_writable_spool:
        base_sev += 0.15

    if user_crontab_ok:
        base_sev = max(base_sev, 0.5)

    base_sev = max(0.0, min(1.0, base_sev))
    severity_score = round(base_sev * 10.0, 1)

    if severity_score >= 8.5:
        severity_band = "Critical"
    elif severity_score >= 6.5:
        severity_band = "High"
    elif severity_score >= 3.5:
        severity_band = "Medium"
    else:
        severity_band = "Low"

    if root_system > 0 or nonroot_system > 0 or root_spool > 0 or nonroot_spool > 0 or user_crontab_ok:
        conf_score = 7.5
    else:
        conf_score = 5.0

    if (
        any_world_writable_system
        or any_group_writable_system
        or any_world_writable_spool
        or any_group_writable_spool
    ):
        conf_score += 0.5

    conf_score = max(0.0, min(10.0, conf_score))

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
    root_system = classification["root_system"]
    any_root_system_world_writable = classification["any_root_system_world_writable"]
    any_root_system_group_writable = classification["any_root_system_group_writable"]
    root_spool = classification["root_spool"]
    nonroot_spool = classification["nonroot_spool"]

    if any_root_system_world_writable or any_root_system_group_writable:
        return "cron_root_file_write_primitive"

    if root_system > 0 or root_spool > 0:
        if severity_band in {"Critical", "High"}:
            return "cron_root_scheduled_execution_surface"
        return "cron_root_scheduled_surface"

    if user_crontab_ok or nonroot_spool > 0:
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

    if classification["root_system"] > 0 or classification["root_spool"] > 0:
        run_as = "root"
    else:
        run_as = user_name

    any_root_system_world_writable = classification["any_root_system_world_writable"]
    any_root_system_group_writable = classification["any_root_system_group_writable"]

    if primitive_type == "cron_root_file_write_primitive":
        exploitability = "moderate"
    elif primitive_type in {"cron_root_scheduled_execution_surface", "cron_root_scheduled_surface"}:
        exploitability = "advanced"
    elif primitive_type == "cron_user_persistence_surface":
        exploitability = "moderate"
    else:
        exploitability = "theoretical" if severity_band in {"Low"} else "advanced"

    if primitive_type in {"cron_root_file_write_primitive"} and (any_root_system_world_writable or any_root_system_group_writable):
        stability = "moderate"
    else:
        stability = "safe"

    noise = "low"

    classification_band = _offensive_classification_from_band(severity_band)

    confidence = PrimitiveConfidence(
        score=conf_score,
        reason=f"Cron surfaces observed with {conf_band} confidence based on discovered files and crontab status.",
    )

    offensive_value = OffensiveValue(
        classification=classification_band,
        why=(
            f"Cron configuration implies {primitive_type} for run_as={run_as} "
            f"with severity={severity_band} (score={severity_score}/10). "
            "If scripts or targets referenced by these jobs are writable, this becomes a reliable privesc/persistence path."
        ),
    )

    primitive = Primitive(
        id=new_primitive_id("cron", primitive_type),
        surface="cron",
        type=primitive_type,
        run_as=run_as,
        origin_user=user_name,
        exploitability=exploitability,  # type: ignore[arg-type]
        stability=stability,            # type: ignore[arg-type]
        noise=noise,                    # type: ignore[arg-type]
        confidence=confidence,
        offensive_value=offensive_value,
        context={
            "classification": classification,
            "risk_categories": sorted(risk_categories),
            "capabilities": sorted(capabilities),
            "severity_band": severity_band,
            "severity_score": severity_score,
        },
        conditions={
            "requires_writable_target": primitive_type
            in {"cron_root_scheduled_execution_surface", "cron_root_scheduled_surface"},
        },
        integration_flags={
            "chaining_allowed": True,
            "supports_persistence_extension": True,
            "supports_lateral_chain": False,
        },
        cross_refs={
            "gtfobins": [],
            "cves": [],
            "documentation": [],
        },
        defensive_impact={
            "risk_to_system": "total_compromise" if run_as == "root" else "high",
            "visibility_risk": "low",
        },
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
                "Either this system does not use cron heavily, or cron configuration lives outside typical paths.",
            ],
        )
        return

    classification = _classify_cron_files(files_meta)
    root_system = classification["root_system"]
    nonroot_system = classification["nonroot_system"]
    root_spool = classification["root_spool"]
    nonroot_spool = classification["nonroot_spool"]
    any_world_writable_system = classification["any_world_writable_system"]
    any_group_writable_system = classification["any_group_writable_system"]
    any_world_writable_spool = classification["any_world_writable_spool"]
    any_group_writable_spool = classification["any_group_writable_spool"]

    capabilities: Set[str] = set()
    if root_system or nonroot_system or root_spool or nonroot_spool or user_crontab_ok:
        capabilities.add("scheduled_execution")
    if (
        any_world_writable_system
        or any_group_writable_system
        or any_world_writable_spool
        or any_group_writable_spool
    ):
        capabilities.add("file_write")
    if user_crontab_ok or nonroot_spool > 0:
        capabilities.add("persistence")

    risk_categories: Set[str] = set()
    if root_system > 0:
        risk_categories.add("cron_root_system_files")
    if nonroot_system > 0:
        risk_categories.add("cron_nonroot_system_files")
    if root_spool > 0:
        risk_categories.add("cron_root_spool_files")
    if nonroot_spool > 0:
        risk_categories.add("cron_nonroot_spool_files")
    if any_world_writable_system:
        risk_categories.add("cron_system_file_world_writable")
    if any_group_writable_system:
        risk_categories.add("cron_system_file_group_writable")
    if any_world_writable_spool:
        risk_categories.add("cron_spool_file_world_writable")
    if any_group_writable_spool:
        risk_categories.add("cron_spool_file_group_writable")
    if user_crontab_ok:
        risk_categories.add("cron_user_crontab_present")
    if classification["any_root_system_world_writable"]:
        risk_categories.add("cron_root_system_world_writable")
    if classification["any_root_system_group_writable"]:
        risk_categories.add("cron_root_system_group_writable")

    (severity_score, severity_band), (conf_score, conf_band) = _cron_severity_and_confidence(
        classification=classification,
        user_crontab_ok=user_crontab_ok,
    )

    descriptor_parts: List[str] = []
    if root_system > 0:
        descriptor_parts.append(f"{root_system} root-owned system cron file(s) under /etc/cron.* or /etc/crontab")
    if nonroot_system > 0:
        descriptor_parts.append(f"{nonroot_system} non-root-owned system cron file(s) under /etc/cron.* or /etc/crontab")
    if root_spool > 0:
        descriptor_parts.append(f"{root_spool} root-owned cron spool file(s) under /var/spool/cron*")
    if nonroot_spool > 0:
        descriptor_parts.append(f"{nonroot_spool} non-root cron spool file(s) under /var/spool/cron*")
    if user_crontab_ok:
        descriptor_parts.append(f"Per-user crontab present for {user.get('name', 'this account')}")

    if not descriptor_parts:
        descriptor_parts.append("Cron configuration present but no clear escalation-prone patterns identified")

    descriptor = "; ".join(descriptor_parts)

    # --- Report section (facts + scoring) ---
    lines: List[str] = []
    lines.append("This section analyses cron configuration and scheduled execution surfaces observed by Nullpeas.")
    lines.append("It uses existing cron probe output (paths, ownership, permissions) and does not modify any jobs.")
    lines.append("Severity reflects potential impact if abused; confidence reflects how likely the described surface is actually usable on this host.")
    lines.append("")

    lines.append("### Cron summary")
    lines.append(f"- System cron files discovered     : {len(classification['system_files'])}")
    lines.append(f"- Root-owned system cron files     : {root_system}")
    lines.append(f"- Non-root system cron files       : {nonroot_system}")
    lines.append(f"- Root-owned spool cron files      : {root_spool}")
    lines.append(f"- Non-root spool cron files        : {nonroot_spool}")
    lines.append(f"- Any world-writable system files  : {any_world_writable_system}")
    lines.append(f"- Any group-writable system files  : {any_group_writable_system}")
    lines.append(f"- Any world-writable spool files   : {any_world_writable_spool}")
    lines.append(f"- Any group-writable spool files   : {any_group_writable_spool}")
    lines.append(f"- Per-user crontab for this user   : {user_crontab_ok}")
    lines.append("")
    lines.append("### Assessed cron attack surface")
    lines.append(f"- Descriptor                      : {descriptor}")
    lines.append(f"- Severity                        : {severity_band} ({severity_score}/10)")
    lines.append(f"- Confidence                      : {conf_band} ({conf_score}/10)")
    if capabilities:
        lines.append(f"- Capability tags                 : {', '.join(sorted(capabilities))}")
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