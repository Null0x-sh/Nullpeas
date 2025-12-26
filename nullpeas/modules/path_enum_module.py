# nullpeas/modules/path_enum.py

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

    return {
        "total_entries": total_entries,
        "existing_entries": existing_entries,
        "user_writable_entries": user_writable,
        "group_writable_entries": group_writable,
        "world_writable_entries": world_writable,
    }


def _score_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Assign a simple severity and confidence score per PATH entry.

    This does not claim escalation on its own. It simply measures how strong
    the directory is as a candidate for PATH hijack style abuse.
    """
    base_score = 4.0
    in_home = bool(entry.get("in_home"))
    world_w = bool(entry.get("world_writable"))

    if in_home:
        base_score += 0.5

    if world_w:
        base_score += 0.5

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

    confidence_score = 8.0
    confidence_band = "High"

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
    lines.append(f"- Directly user-writable dirs  : {len(summary['user_writable_entries'])}")
    lines.append(f"- Group-writable dirs          : {len(summary['group_writable_entries'])}")
    lines.append(f"- World-writable dirs          : {len(summary['world_writable_entries'])}")
    lines.append("")

    writable_candidates: List[Dict[str, Any]] = [
        e for e in entries
        if e.get("exists") and (e.get("owner_writable") or e.get("group_writable") or e.get("world_writable"))
    ]

    if not writable_candidates:
        lines.append("### Assessed PATH attack surface")
        lines.append("No attacker-writable PATH directories were identified.")
        lines.append("This does not rule out path hijack entirely, but no obvious surfaces were seen in PATH contents.")
        return lines

    lines.append("### Assessed PATH attack surface")
    lines.append(
        "One or more attacker-writable PATH directories were identified. "
        "These locations are not guaranteed escalation paths by themselves, "
        "but can be chained with sudo, cron, or service misconfigurations that rely on PATH lookup."
    )
    lines.append("")
    lines.append("#### Attacker-writable PATH directories")

    seen_dirs = set()
    for entry in writable_candidates:
        directory = entry.get("dir") or "unknown"
        if directory in seen_dirs:
            continue
        seen_dirs.add(directory)

        scoring = _score_entry(entry)
        owner_name = entry.get("owner_name") or str(entry.get("owner_uid", "unknown"))

        note_parts: List[str] = []
        if entry.get("in_home"):
            note_parts.append("under home")
        if entry.get("in_tmpfs_like"):
            note_parts.append("under tmp style path")
        note_suffix = ""
        if note_parts:
            note_suffix = " (" + ", ".join(note_parts) + ")"

        lines.append(
            f"- [{scoring['severity_band']} {scoring['severity_score']}/10] "
            f"{directory} (owner: {owner_name}, confidence {scoring['confidence_score']}/10 {scoring['confidence_band']}){note_suffix}"
        )

    return lines


def _build_path_primitive(
    state: Dict[str, Any],
    path_state: Dict[str, Any],
) -> Optional[Primitive]:
    """
    Build a single PATH hijack surface primitive.

    This does not claim escalation by itself. It is intended to be combined later
    with sudo, service units, cron, or other surfaces in the chaining engine.
    """
    entries: List[Dict[str, Any]] = path_state.get("entries") or []
    if not entries:
        return None

    writable_candidates: List[Dict[str, Any]] = [
        e for e in entries
        if e.get("exists") and (e.get("owner_writable") or e.get("group_writable") or e.get("world_writable"))
    ]
    if not writable_candidates:
        return None

    any_world = any(e.get("world_writable") for e in writable_candidates)
    any_home = any(e.get("in_home") for e in writable_candidates)
    any_tmp_like = any(e.get("in_tmpfs_like") for e in writable_candidates)

    if any_world:
        severity_score = 5.5
    elif any_home or any_tmp_like:
        severity_score = 4.5
    else:
        severity_score = 4.0

    if severity_score >= 8.5:
        severity_band = "Critical"
    elif severity_score >= 6.5:
        severity_band = "High"
    elif severity_score >= 3.5:
        severity_band = "Medium"
    else:
        severity_band = "Low"

    confidence_score = 7.5
    confidence_band = "High"

    user = state.get("user", {}) or {}
    origin_user = user.get("name") or "current_user"

    confidence = PrimitiveConfidence(
        score=confidence_score,
        reason=(
            "Derived from attacker-writable PATH entries discovered by the path probe. "
            "Writable PATH segments are often combined with other misconfigurations to hijack execution."
        ),
    )

    offensive_value = OffensiveValue(
        classification="useful",
        why=(
            "Writable PATH directories provide an execution hijack candidate. "
            "On their own they do not guarantee escalation, "
            "but they become powerful when combined with sudo, service or cron misconfigurations."
        ),
    )

    risky_dirs = sorted(
        {e.get("dir") for e in writable_candidates if e.get("dir")}
    )

    context: Dict[str, Any] = {
        "writable_entries": risky_dirs,
        "any_world_writable": any_world,
        "any_home_path": any_home,
        "any_tmp_like": any_tmp_like,
        "severity_band": severity_band,
        "severity_score": severity_score,
        "confidence_band": confidence_band,
        "confidence_score": confidence_score,
    }

    conditions: Dict[str, Any] = {
        "requires_additional_surface": True,
        "example_chain_partners": ["sudo", "systemd", "cron"],
    }

    cross_refs: Dict[str, List[str]] = {
        "gtfobins": [],
        "cves": [],
        "documentation": [],
    }

    defensive_impact: Dict[str, Any] = {
        "misconfiguration_summary": (
            "Writable PATH directories give attackers control over which binaries are executed "
            "when privileged workloads rely on PATH lookups without fully qualified paths."
        )
    }

    primitive = Primitive(
        id=new_primitive_id("path", "path_hijack_surface"),
        surface="path",
        type="path_hijack_surface",
        run_as=origin_user,
        origin_user=origin_user,
        exploitability="moderate",  # type: ignore[arg-type]
        stability="safe",           # type: ignore[arg-type]
        noise="low",                # type: ignore[arg-type]
        confidence=confidence,
        offensive_value=offensive_value,
        context=context,
        conditions=conditions,
        integration_flags={
            "path_hijack_candidate": True,
        },
        cross_refs=cross_refs,
        defensive_impact=defensive_impact,
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