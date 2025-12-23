from typing import Dict, Any, List, Set, Tuple

from nullpeas.core.report import Report
from nullpeas.modules import register_module
from nullpeas.core.guidance import build_guidance, FindingContext


def _mode_world_group_bits(mode_str: str) -> Tuple[bool, bool]:
    """
    Given a string like '0644', return:
      (world_has_write_perm, group_has_write_perm)

    We only care about write, not read/execute, to avoid noisy findings.
    """
    try:
        mode_int = int(mode_str, 8)
    except Exception:
        return False, False

    # World write bit (…w)
    world_write = bool(mode_int & 0o002)
    # Group write bit (…w…)
    group_write = bool(mode_int & 0o020)

    return world_write, group_write


def _classify_cron_files(files_meta: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Very coarse classification of cron files by ownership and permissions.
    We don't try to fully parse the job content here – that stays manual.
    """
    root_system = 0
    nonroot_system = 0
    any_world_writable = False
    any_group_writable = False

    for fm in files_meta:
        path = fm.get("path") or ""
        owner = fm.get("owner") or ""
        mode = fm.get("mode") or ""

        # Treat /etc/cron.* and /etc/crontab as system-level cron.
        is_system = path.startswith("/etc/cron.") or path == "/etc/crontab"
        if not is_system:
            # /var/spool/cron or /var/spool/cron/crontabs can also be relevant,
            # but for now we focus our classification on /etc to keep semantics clear.
            continue

        if owner == "root":
            root_system += 1
        else:
            nonroot_system += 1

        world_access, group_access = _mode_world_group_bits(mode)
        if world_access:
            any_world_writable = True
        if group_access:
            any_group_writable = True

    return {
        "root_system": root_system,
        "nonroot_system": nonroot_system,
        "any_world_writable": any_world_writable,
        "any_group_writable": any_group_writable,
    }


def _cron_severity_and_confidence(
    root_system: int,
    nonroot_system: int,
    any_world_writable: bool,
    any_group_writable: bool,
    user_crontab_ok: bool,
) -> Tuple[Tuple[float, str], Tuple[float, str]]:
    """
    Coarse severity + confidence model for cron surfaces.
    """
    # ----- Severity -----
    base_sev = 0.0

    if root_system > 0:
        base_sev = 0.6
    if nonroot_system > 0:
        base_sev = max(base_sev, 0.5)

    if any_world_writable:
        base_sev += 0.2
    elif any_group_writable:
        base_sev += 0.1

    if user_crontab_ok:
        base_sev = max(base_sev, 0.4)

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

    # ----- Confidence -----
    # If we see any cron files, we are reasonably confident they exist.
    if root_system > 0 or nonroot_system > 0 or user_crontab_ok:
        conf_score = 7.5
    else:
        conf_score = 5.0

    if any_world_writable or any_group_writable:
        conf_score += 0.5

    conf_score = max(0.0, min(10.0, conf_score))

    if conf_score >= 8.0:
        conf_band = "High"
    elif conf_score >= 5.5:
        conf_band = "Medium"
    else:
        conf_band = "Low"

    return (severity_score, severity_band), (conf_score, conf_band)


@register_module(
    key="cron_enum",
    description="Analyse cron configuration and scheduled execution surfaces",
    required_triggers=["cron_privesc_surface"],
)
def run(state: dict, report: Report):
    """
    Cron analysis module.

    - Uses existing cron probe output (no extra crontab invocations).
    - Summarises system-level cron files and per-user crontab status.
    - Assigns high level risk categories and capabilities.
    - Computes severity and confidence scores.
    - Delegates narrative guidance to the central guidance engine.
    """
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
    any_world_writable = classification["any_world_writable"]
    any_group_writable = classification["any_group_writable"]

    # Capabilities from this surface.
    capabilities: Set[str] = set()
    if root_system or nonroot_system or user_crontab_ok:
        capabilities.add("scheduled_execution")
    if any_world_writable or any_group_writable:
        capabilities.add("file_write")

    # Risk categories.
    risk_categories: Set[str] = set()
    if root_system > 0:
        risk_categories.add("cron_root_system_files")
    if nonroot_system > 0:
        risk_categories.add("cron_nonroot_system_files")
    if any_world_writable:
        risk_categories.add("cron_system_file_world_writable")
    if any_group_writable:
        risk_categories.add("cron_system_file_group_writable")
    if user_crontab_ok:
        risk_categories.add("cron_user_crontab_present")

    (severity_score, severity_band), (conf_score, conf_band) = _cron_severity_and_confidence(
        root_system=root_system,
        nonroot_system=nonroot_system,
        any_world_writable=any_world_writable,
        any_group_writable=any_group_writable,
        user_crontab_ok=user_crontab_ok,
    )

    # Build a single high-level finding descriptor.
    descriptor_parts: List[str] = []
    if root_system > 0:
        descriptor_parts.append(f"{root_system} root-owned system cron file(s) under /etc/cron.* or /etc/crontab")
    if nonroot_system > 0:
        descriptor_parts.append(f"{nonroot_system} non-root-owned system cron file(s) under /etc/cron.* or /etc/crontab")
    if user_crontab_ok:
        descriptor_parts.append(f"Per-user crontab present for {user.get('name', 'this account')}")
    if not descriptor_parts:
        descriptor_parts.append("Cron configuration present but no clear escalation-prone patterns identified")

    descriptor = "; ".join(descriptor_parts)

    finding: FindingContext = {
        "surface": "cron",
        "rule": descriptor,
        "binary": None,
        "capabilities": capabilities,
        "risk_categories": risk_categories,
        "severity_band": severity_band,          # type: ignore[assignment]
        "severity_score": severity_score,
        "nopasswd": False,
        "gtfobins_url": None,
        "metadata": {
            "files_metadata": files_meta,
            "classification": classification,
            "user_crontab_status": user_cron_status,
            "user_name": user.get("name"),
        },
    }

    # ---- Analysis section (raw facts + scoring) ----
    lines: List[str] = []
    lines.append("This section analyses cron configuration and scheduled execution surfaces observed by Nullpeas.")
    lines.append("It uses existing cron probe output (paths, ownership, permissions) and does not modify any jobs.")
    lines.append("Severity reflects potential impact if abused; confidence reflects how likely the described surface is actually usable on this host.")
    lines.append("")
    lines.append("### Cron summary")
    lines.append(f"- System cron files discovered     : {len(files_meta)}")
    lines.append(f"- Root-owned system cron files     : {root_system}")
    lines.append(f"- Non-root system cron files       : {nonroot_system}")
    lines.append(f"- Any world-writable cron files    : {any_world_writable}")
    lines.append(f"- Any group-writable cron files    : {any_group_writable}")
    lines.append(f"- User crontab status              : {user_cron_status or 'unknown'}")
    lines.append("")
    lines.append("### Assessed cron attack surface")
    lines.append(f"- Rule description                 : {descriptor}")
    lines.append(f"- Severity                         : {severity_band} ({severity_score}/10)")
    lines.append(f"- Confidence                       : {conf_band} ({conf_score}/10)")
    if capabilities:
        lines.append(f"- Capability tags                  : {', '.join(sorted(capabilities))}")
    if risk_categories:
        lines.append(f"- Risk categories                  : {', '.join(sorted(risk_categories))}")
    lines.append("")

    report.add_section("Cron Analysis", lines)

    # ---- Attack chain section (guided reasoning via core.guidance) ----
    guidance = build_guidance(finding)

    chain_lines: List[str] = []
    chain_lines.append(
        "This section describes high level attack chains based on cron configuration and scheduled execution surfaces."
    )
    chain_lines.append(
        "Nullpeas does not alter cron jobs or their scripts. It describes how operators or attackers might reason about these surfaces, and how defenders can respond."
    )
    chain_lines.append("")
    chain_lines.append("### cron -> scheduled tasks -> elevated behaviour")
    chain_lines.append("")
    chain_lines.append("Descriptor:")
    chain_lines.append(f"- {descriptor}")
    chain_lines.append("")
    chain_lines.append("Severity:")
    chain_lines.append(f"- {severity_band} ({severity_score}/10)")
    chain_lines.append("")

    caps = finding["capabilities"]
    if caps:
        chain_lines.append("Capabilities:")
        chain_lines.append(f"- {', '.join(sorted(caps))}")
        chain_lines.append("")

    nav = guidance.get("navigation") or []
    if nav:
        chain_lines.append("Navigation guidance (for operators):")
        for line in nav:
            chain_lines.append(f"- {line}")
        chain_lines.append("")

    op_research = guidance.get("operator_research") or []
    if op_research:
        chain_lines.append("Operator research checklist:")
        for item in op_research:
            chain_lines.append(f"- {item}")
        chain_lines.append("")

    offensive = guidance.get("offensive_steps") or []
    if offensive:
        chain_lines.append("High level offensive path (for red teams and threat modelling):")
        chain_lines.append("")
        for idx, step in enumerate(offensive, start=1):
            chain_lines.append(f"{idx}. {step}")
        chain_lines.append("")
        chain_lines.append(
            "Note: Nullpeas does not execute any of the above. These steps describe possible operator behaviour."
        )
        chain_lines.append("")

    defensive = guidance.get("defensive_actions") or []
    if defensive:
        chain_lines.append("Defensive remediation path (for blue teams):")
        chain_lines.append("")
        for idx, action in enumerate(defensive, start=1):
            chain_lines.append(f"{idx}. {action}")
        chain_lines.append("")

    impact = guidance.get("impact") or []
    if impact:
        chain_lines.append("Potential impact if left unresolved:")
        for imp in impact:
            chain_lines.append(f"- {imp}")
        chain_lines.append("")

    refs = guidance.get("references") or []
    if refs:
        chain_lines.append("References:")
        for ref in refs:
            chain_lines.append(f"- {ref}")
        chain_lines.append("")

    report.add_section("Cron Attack Chains", chain_lines)
