"""
nullpeas/modules/path_enum_module.py
Analyse PATH directories for hijack and execution surfaces.
"""

from typing import Dict, Any, List, Optional

from nullpeas.core.report import Report
from nullpeas.core.offensive_schema import (
    Primitive,
    PrimitiveConfidence,
    OffensiveValue,
    new_primitive_id,
)
from nullpeas.modules import register_module


def _summarise_path(path_state: Dict[str, Any]) -> Dict[str, Any]:
    entries: List[Dict[str, Any]] = path_state.get("entries") or []

    total_entries = len(entries)
    existing_entries = sum(1 for e in entries if e.get("exists"))
    
    user_writable = [e for e in entries if e.get("owner_writable")]
    group_writable = [e for e in entries if e.get("group_writable")]
    world_writable = [e for e in entries if e.get("world_writable")]
    
    # === NEW: Definitive Check ===
    confirmed_writable = [e for e in entries if e.get("can_i_write")]

    return {
        "total_entries": total_entries,
        "existing_entries": existing_entries,
        "user_writable_entries": user_writable,
        "group_writable_entries": group_writable,
        "world_writable_entries": world_writable,
        "confirmed_writable_entries": confirmed_writable,
    }


def _score_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Assign a simple severity and confidence score per PATH entry.
    """
    base_score = 4.0
    in_home = bool(entry.get("in_home"))
    world_w = bool(entry.get("world_writable"))
    
    can_write = bool(entry.get("can_i_write"))

    if can_write:
        base_score = 8.0  # High baseline if we can actually hijack it
    elif world_w:
        base_score = 5.0  # Medium if world writable but maybe we aren't the right user?
    
    if in_home:
        # Home hijacking is a valid vector but less critical than system hijacking
        pass

    if base_score > 10.0:
        base_score = 10.0

    severity_score = round(base_score, 1)
    if severity_score >= 8.5:
        band = "Critical"
    elif severity_score >= 6.5:
        band = "High"
    elif severity_score >= 3.5:
        band = "Medium"
    else:
        band = "Low"

    confidence_score = 9.0 if can_write else 6.0
    confidence_band = "High" if can_write else "Medium"

    return {
        "severity_score": severity_score,
        "severity_band": band,
        "confidence_score": confidence_score,
        "confidence_band": confidence_band,
    }


def _build_path_analysis_lines(path_state: Dict[str, Any]) -> List[str]:
    summary = _summarise_path(path_state)
    entries: List[Dict[str, Any]] = path_state.get("entries") or []

    lines: List[str] = []
    lines.append("This section analyses PATH directories for writable locations that may support execution hijack surfaces.")
    lines.append("")
    lines.append("### PATH summary")
    lines.append(f"- Total PATH entries           : {summary['total_entries']}")
    lines.append(f"- Existing PATH directories    : {summary['existing_entries']}")
    lines.append(f"- Confirmed user-writable dirs : {len(summary['confirmed_writable_entries'])}")
    lines.append(f"- Group-writable dirs (Raw)    : {len(summary['group_writable_entries'])}")
    lines.append(f"- World-writable dirs (Raw)    : {len(summary['world_writable_entries'])}")
    lines.append("")

    writable_candidates: List[Dict[str, Any]] = [
        e for e in entries
        if e.get("exists") and (e.get("can_i_write") or e.get("world_writable") or e.get("group_writable"))
    ]

    if not writable_candidates:
        lines.append("### Assessed PATH attack surface")
        lines.append("No attacker-writable PATH directories were identified.")
        lines.append("This does not rule out path hijack entirely, but no obvious surfaces were seen in PATH contents.")
        return lines

    lines.append("### Assessed PATH attack surface")
    lines.append(
        "One or more writable PATH directories were identified. "
        "These locations allow the current user to plant binaries that might be executed by privileged processes/users."
    )
    lines.append("")
    lines.append("#### Writable PATH directories")

    seen_dirs = set()
    for entry in writable_candidates:
        directory = entry.get("dir") or "unknown"
        if directory in seen_dirs:
            continue
        seen_dirs.add(directory)

        scoring = _score_entry(entry)
        owner_name = entry.get("owner_name") or str(entry.get("owner_uid", "unknown"))
        
        icon = "🚨" if entry.get("can_i_write") else "⚠️"

        note_parts: List[str] = []
        if entry.get("can_i_write"):
            note_parts.append("**Verified Writable**")
        if entry.get("in_home"):
            note_parts.append("home dir")
        if entry.get("in_tmpfs_like"):
            note_parts.append("tmpfs")
            
        note_suffix = ""
        if note_parts:
            note_suffix = " (" + ", ".join(note_parts) + ")"

        lines.append(
            f"- {icon} [{scoring['severity_band']} {scoring['severity_score']}/10] "
            f"`{directory}` (owner: {owner_name}){note_suffix}"
        )

    return lines


def _build_path_primitive(
    state: Dict[str, Any],
    path_state: Dict[str, Any],
) -> Optional[Primitive]:
    """
    Build a single PATH hijack surface primitive.
    """
    entries: List[Dict[str, Any]] = path_state.get("entries") or []
    if not entries:
        return None

    # We strictly care about what we can *actually* write to.
    confirmed_candidates: List[Dict[str, Any]] = [
        e for e in entries
        if e.get("exists") and e.get("can_i_write")
    ]
    
    if not confirmed_candidates:
        return None

    severity_score = 8.0 
    severity_band = "High"
    
    any_system_path = any(not e.get("in_home") for e in confirmed_candidates)
    if any_system_path:
        # Hijacking /usr/local/bin or similar is Critical
        severity_score = 9.0
        severity_band = "Critical"

    confidence_score = 9.5
    confidence_band = "High"

    user = state.get("user", {}) or {}
    origin_user = user.get("name") or "current_user"

    confidence = PrimitiveConfidence(
        score=confidence_score,
        reason=(
            "Probe confirmed write access (os.access) to one or more directories in the system PATH."
        ),
    )

    offensive_value = OffensiveValue(
        classification="severe" if severity_band == "Critical" else "useful",
        why=(
            "Writable PATH directories allow interception of commands executed by other users (including root). "
            "This is a high-probability lateral movement or escalation vector."
        ),
    )

    risky_dirs = sorted(
        {e.get("dir") for e in confirmed_candidates if e.get("dir")}
    )

    context: Dict[str, Any] = {
        "writable_entries": risky_dirs,
        "count": len(risky_dirs),
        "severity_band": severity_band,
        "severity_score": severity_score,
        "confidence_band": confidence_band,
        "confidence_score": confidence_score,
    }

    conditions: Dict[str, Any] = {
        "requires_victim_execution": True,
        "requires_relative_path": True,
    }

    affected_resource = risky_dirs[0] if risky_dirs else None

    primitive = Primitive(
        id=new_primitive_id("path", "path_hijack_surface"),
        surface="path",
        type="path_hijack_surface",
        run_as=origin_user,
        origin_user=origin_user,
        exploitability="high",
        stability="safe",
        noise="moderate",
        confidence=confidence,
        offensive_value=offensive_value,
        context=context,
        conditions=conditions,
        integration_flags={
            "path_hijack_candidate": True,
        },
        affected_resource=affected_resource,
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
    path_state = state.get("path", {}) or {}
    entries = path_state.get("entries") or []

    if not entries:
        analysis = state.setdefault("analysis", {})
        analysis["path"] = {
            "heading": "PATH Analysis",
            "summary_lines": [
                "PATH probe did not report any entries. Either PATH was empty or the probe failed to capture data."
            ],
        }
        return

    lines = _build_path_analysis_lines(path_state)

    analysis = state.setdefault("analysis", {})
    analysis["path"] = {
        "heading": "PATH Analysis",
        "summary_lines": lines,
    }

    primitive = _build_path_primitive(state, path_state)
    if primitive is not None:
        primitives: List[Primitive] = state.setdefault("offensive_primitives", [])
        primitives.append(primitive)
