from typing import Dict, Any, List, Optional, Set

from nullpeas.core.report import Report
from nullpeas.core.offensive_schema import (
    Primitive,
    PrimitiveConfidence,
    OffensiveValue,
    new_primitive_id,
)
from nullpeas.modules import register_module


def _extract_version_info(docker_state: Dict[str, Any]) -> Dict[str, Any]:
    # ... [Same as before] ...
    return {"version_string": "unknown", "version_ok": False}


def _severity_and_confidence_for_surface(
    cli_present: bool,
    socket_exists: bool,
    socket_writable: bool,  # <--- NEW
    user_owns_socket: bool, # <--- NEW
    user_in_docker_group: bool,
    in_container: bool,
    version_ok: bool,
) -> Dict[str, Any]:
    
    # 1. Base Severity
    # Top Tier: Group member, Owner, or Writable Socket
    if socket_exists and (user_in_docker_group or user_owns_socket or socket_writable):
        severity_score = 10.0
        severity_band = "Critical"
    
    # Second Tier: Socket exists but we might not have permission
    elif socket_exists and cli_present:
        if socket_writable:
             severity_score = 7.5
             severity_band = "High"
        else:
             # If we can't write to it, it's useless
             severity_score = 1.0
             severity_band = "Low"
             
    elif socket_exists:
        severity_score = 5.0 if socket_writable else 1.0
        severity_band = "Medium" if socket_writable else "Low"
        
    elif cli_present:
        severity_score = 1.0
        severity_band = "Low"
    else:
        severity_score = 0.0
        severity_band = "Info"

    # 2. Confidence
    if cli_present and socket_exists:
        confidence_score = 8.5
        confidence_band = "High"
    else:
        confidence_score = 5.0
        confidence_band = "Medium"

    if in_container and socket_exists:
        severity_score = max(severity_score, 7.5)
        if severity_score >= 8.5: severity_band = "Critical"
        elif severity_score >= 6.5: severity_band = "High"

    return {
        "severity_score": round(severity_score, 1),
        "severity_band": severity_band,
        "confidence_score": round(confidence_score, 1),
        "confidence_band": confidence_band,
    }


def _build_docker_analysis_lines(
    docker_state: Dict[str, Any],
    container_state: Dict[str, Any],
    user_in_docker_group: bool,
    user_uid: int,
) -> List[str]:
    
    # Extract
    cli_present = bool(docker_state.get("binary_present"))
    socket_path = docker_state.get("socket_path") or "/var/run/docker.sock"
    socket_exists = bool(docker_state.get("socket_exists"))
    
    # New Flags (Need Probe to provide these!)
    # Default to False if probe hasn't been updated yet
    socket_writable = bool(docker_state.get("socket_writable", False))
    socket_uid = docker_state.get("socket_uid")
    
    user_owns_socket = (socket_uid is not None) and (socket_uid == user_uid)

    lines = [] # ... [Add your header lines] ...
    
    scoring = _severity_and_confidence_for_surface(
        cli_present=cli_present,
        socket_exists=socket_exists,
        socket_writable=socket_writable,
        user_owns_socket=user_owns_socket,
        user_in_docker_group=user_in_docker_group,
        in_container=bool(container_state.get("in_container")),
        version_ok=False,
    )
    
    # ... [Return rest] ...
    capability_tags = ["container_escape"] 
    risk_categories = []
    description = "Docker Analysis"
    
    return lines, scoring, capability_tags, risk_categories, description


@register_module(
    key="docker_enum",
    description="Analyse Docker daemon access and potential container escape surfaces",
    required_triggers=["docker_escape_surface"],
)
def run(state: dict, report: Report):
    runtime = state.get("runtime", {}) or {}
    docker_state = runtime.get("docker", {}) or {}
    container_state = runtime.get("container", {}) or {}
    user = state.get("user", {}) or {}
    
    user_uid = user.get("uid")

    # ... [Triggers] ...

    group_names = [g.get("name") for g in user.get("groups", []) if g.get("name")]
    user_in_docker_group = "docker" in (group_names or [])

    lines, scoring, capability_tags, risk_categories, description = _build_docker_analysis_lines(
        docker_state=docker_state,
        container_state=container_state,
        user_in_docker_group=user_in_docker_group,
        user_uid=user_uid,
    )
    
    # ... [Save Analysis & Primitive logic from original] ...
    pass
