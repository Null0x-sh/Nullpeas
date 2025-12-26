from typing import Dict, Any, List, Optional, Set, Tuple

from nullpeas.core.report import Report
from nullpeas.core.offensive_schema import (
    Primitive,
    PrimitiveConfidence,
    OffensiveValue,
    new_primitive_id,
)
from nullpeas.modules import register_module


def _attacker_group_ids(user: Dict[str, Any]) -> Set[int]:
    """
    Try to derive the current user's group IDs from state, with a
    best effort fallback to os.getgroups if needed.
    """
    group_ids: Set[int] = set()

    for g in user.get("groups", []) or []:
        gid = g.get("gid")
        if isinstance(gid, int):
            group_ids.add(gid)

    if group_ids:
        return group_ids

    # Fallback: direct OS query (cheap and safe)
    try:
        import os

        return set(os.getgroups())
    except Exception:
        return set()


def _entry_attacker_writable(
    entry: Dict[str, Any],
    user_uid: Optional[int],
    attacker_group_ids: Set[int],
) -> bool:
    if not entry.get("exists") or not entry.get("is_dir"):
        return False

    if entry.get("world_writable"):
        return True

    if user_uid is not None:
        if entry.get("owner_uid") == user_uid and entry.get("owner_writable"):
            return True

    owner_gid = entry.get("owner_gid")
    if owner_gid is not None and owner_gid in attacker_group_ids and entry.get("group_writable"):
        return True

    return False


def _severity_for_entry(
    attacker_writable: bool,
    world_w: bool,
    owner_name: Optional[str],
    in_home: bool,
    in_tmpfs_like: bool,
) -> Tuple[float, str]:
    """
    Severity is about how powerful this PATH directory is as a hijack surface,
    not about guaranteed root.

    High level rules:
      - World writable + on PATH is serious.
      - Writable root-owned PATH dir is serious.
      - User/home writable is medium.
      - Non attacker writable is low.
    """
    if not attacker_writable:
        return 1.0, "Low"

    # Default assumption: attacker writable PATH is at least Medium.
    score = 4.0

    if world_w:
        score += 2.0

    if owner_name == "root":
        score += 1.5

    if in_tmpfs_like:
        score += 0.5

    if in_home:
        score += 0.5

    if score >= 8.5:
        band = "Critical"
    elif score >= 6.5:
        band = "High"
    elif score >= 3.5:
        band = "Medium"
    else:
        band = "Low"

    # Clamp 0.0 to 10.0 just in case
    score = max(0.0, min(10.0, score))
    return score, band


def _confidence_for_entry(
    exists: bool,
    is_dir: bool,
) -> Tuple[float, str]:
    if exists and is_dir:
        return 8.0, "High"
    if exists:
        return 6.0, "Medium"
    return 3.0, "Low"


def _offensive_classification_from_band(severity_band: str) -> str:
    if severity_band == "Critical":
        return "severe"
    if severity_band == "High":
        return "severe"
    if severity_band == "Medium":
        return "useful"
    return "niche"


def _primitive_from_entry(
    state: Dict[str, Any],
    entry: Dict[str, Any],
    severity_score: float,
    severity_band: str,
    confidence_score: float,
    confidence_band: str,
) -> Primitive:
    user = state.get("user", {}) or {}
    origin_user = user.get("name") or "current_user"
    user_uid = user.get("uid")

    dir_path = entry.get("dir") or "unknown_path"
    owner_name = entry.get("owner_name")
    in_home = bool(entry.get("in_home"))
    in_tmpfs_like = bool(entry.get("in_tmpfs_like"))

    primitive_type = "path_hijack_primitive"
    classification = _offensive_classification_from_band(severity_band)

    # PATH hijack by itself is not a guaranteed root shell.
    # Treat exploitability as advanced until combined with other surfaces.
    exploitability = "advanced"
    stability = "safe"
    noise = "low"

    confidence = PrimitiveConfidence(
        score=confidence_score,
        reason=f"Attacker-writable PATH directory analysed at {dir_path} (band: {confidence_band})",
    )

    offensive_value = OffensiveValue(
        classification=classification,
        why=(
            f"Directory '{dir_path}' is on PATH and writable by the current user. "
            f"It supports execution hijack if a privileged process relies on PATH lookup."
        ),
    )

    context: Dict[str, Any] = {
        "dir": dir_path,
        "owner_name": owner_name,
        "owner_uid": entry.get("owner_uid"),
        "owner_gid": entry.get("owner_gid"),
        "in_home": in_home,
        "in_tmpfs_like": in_tmpfs_like,
        "mode": entry.get("mode"),
        "world_writable": entry.get("world_writable"),
        "group_writable": entry.get("group_writable"),
        "owner_writable": entry.get("owner_writable"),
        "severity_band": severity_band,
        "severity_score": severity_score,
        "confidence_band": confidence_band,
        "confidence_score": confidence_score,
    }

    # By itself this is not a root goal candidate, but the chaining engine
    # can combine it with sudo/cron/systemd surfaces.
    conditions: Dict[str, Any] = {
        "requires_privileged_consumer": True,
        "requires_path_lookup": True,
    }

    primitive = Primitive(
        id=new_primitive_id("path", primitive_type),
        surface="path",
        type=primitive_type,
        run_as="dependent",           # depends on the privileged consumer
        origin_user=origin_user,
        exploitability=exploitability,  # type: ignore[arg-type]
        stability=stability,            # type: ignore[arg-type]
        noise=noise,                    # type: ignore[arg-type]
        confidence=confidence,
        offensive_value=offensive_value,
        context=context,
        conditions=conditions,
        integration_flags={"root_goal_candidate": False},
        cross_refs={"gtfobins": [], "cves": [], "documentation": []},
        defensive_impact={
            "misconfiguration_summary": (
                "Writable directory on PATH can be used to hijack execution when privileged "
                "commands rely on PATH lookup."
            )
        },
        module_source="path_enum",
        probe_source="path",
    )

    return primitive


@register_module(
    key="path_enum",
    description="Analyse PATH directories for hijack and execution surfaces",
    required_triggers=["path_hijack_surface"],
)
def run(state: dict, report: Report):
    """
    PATH module.

    Responsibilities:
      - Consume path probe output.
      - Identify attacker-writable PATH directories.
      - Assess severity and confidence.
      - Emit offensive primitives for the chaining engine.
      - Add a human-readable PATH analysis section into state["analysis"].
    """
    path_state = state.get("path", {}) or {}
    entries: List[Dict[str, Any]] = path_state.get("entries") or []

    if not entries:
        # Nothing to analyse; avoid noisy reporting.
        return

    user = state.get("user", {}) or {}
    user_uid = user.get("uid")
    attacker_group_ids = _attacker_group_ids(user)

    analysis = state.setdefault("analysis", {})
    offensive_primitives: List[Primitive] = state.setdefault("offensive_primitives", [])

    interesting_lines: List[str] = []
    attacker_writable_dirs: List[Dict[str, Any]] = []

    for entry in entries:
        attacker_writable = _entry_attacker_writable(entry, user_uid, attacker_group_ids)
        if not attacker_writable:
            continue

        exists = bool(entry.get("exists"))
        is_dir = bool(entry.get("is_dir"))
        world_w = bool(entry.get("world_writable"))
        owner_name = entry.get("owner_name")
        in_home = bool(entry.get("in_home"))
        in_tmpfs_like = bool(entry.get("in_tmpfs_like"))

        severity_score, severity_band = _severity_for_entry(
            attacker_writable=attacker_writable,
            world_w=world_w,
            owner_name=owner_name,
            in_home=in_home,
            in_tmpfs_like=in_tmpfs_like,
        )

        confidence_score, confidence_band = _confidence_for_entry(
            exists=exists,
            is_dir=is_dir,
        )

        dir_path = entry.get("dir") or "unknown_path"

        attacker_writable_dirs.append(
            {
                "dir": dir_path,
                "severity_score": severity_score,
                "severity_band": severity_band,
                "confidence_score": confidence_score,
                "confidence_band": confidence_band,
                "world_writable": world_w,
                "owner_name": owner_name,
                "in_home": in_home,
                "in_tmpfs_like": in_tmpfs_like,
            }
        )

        primitive = _primitive_from_entry(
            state=state,
            entry=entry,
            severity_score=severity_score,
            severity_band=severity_band,
            confidence_score=confidence_score,
            confidence_band=confidence_band,
        )
        offensive_primitives.append(primitive)

    # Build PATH analysis narrative
    summary = path_state.get("summary") or {}
    total_entries = summary.get("total_entries")
    existing_entries = summary.get("existing_entries")
    world_writable_count = summary.get("world_writable_count")
    group_writable_count = summary.get("group_writable_count")
    user_writable_count = summary.get("user_writable_count")

    lines: List[str] = []
    lines.append("This section analyses PATH directories for writable locations that may support execution hijack surfaces.")
    lines.append("")
    lines.append("### PATH summary")
    lines.append(f"- Total PATH entries           : {total_entries}")
    lines.append(f"- Existing PATH directories    : {existing_entries}")
    lines.append(f"- Directly user-writable dirs  : {user_writable_count}")
    lines.append(f"- Group-writable dirs          : {group_writable_count}")
    lines.append(f"- World-writable dirs          : {world_writable_count}")
    lines.append("")

    if not attacker_writable_dirs:
        lines.append("### Assessed PATH attack surface")
        lines.append("- No attacker-writable PATH directories were identified based on current probe data.")
        lines.append("- PATH hijack is not a strong escalation surface on this host from the current user context.")
    else:
        lines.append("### Assessed PATH attack surface")
        lines.append("- One or more attacker-writable PATH directories were identified.")
        lines.append("- These locations are not guaranteed escalation paths by themselves, but can be chained with sudo, cron, or service misconfigurations that rely on PATH lookup.")
        lines.append("")
        lines.append("#### Attacker-writable PATH directories")
        for d in attacker_writable_dirs:
            dir_path = d["dir"]
            sev_score = d["severity_score"]
            sev_band = d["severity_band"]
            conf_score = d["confidence_score"]
            conf_band = d["confidence_band"]
            world_w = d["world_writable"]
            owner_name = d["owner_name"] or "unknown"

            flags = []
            if world_w:
                flags.append("world-writable")
            if d["in_home"]:
                flags.append("under home")
            if d["in_tmpfs_like"]:
                flags.append("tmpfs-like")

            flag_str = f" ({', '.join(flags)})" if flags else ""
            lines.append(
                f"- [{sev_band} {sev_score:.1f}/10] {dir_path} "
                f"(owner: {owner_name}, confidence {conf_score:.1f}/10 {conf_band}){flag_str}"
            )

    analysis["path"] = {
        "heading": "PATH Analysis",
        "summary_lines": lines,
    }