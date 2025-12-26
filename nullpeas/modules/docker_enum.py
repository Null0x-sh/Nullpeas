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
    """
    Safely normalise version information from the docker runtime probe.
    """
    version_info = docker_state.get("version_info")

    result = {
        "version_ok": False,
        "version_string": "unknown",
    }

    if isinstance(version_info, dict):
        parsed = version_info.get("parsed")
        raw = version_info.get("raw")
        if parsed:
            result["version_ok"] = True
            result["version_string"] = str(parsed)
        elif raw:
            result["version_ok"] = True
            result["version_string"] = str(raw)
        else:
            result["version_string"] = "unknown"
        return result

    if isinstance(version_info, str):
        text = version_info.strip()
        if text and text.lower() not in {"unknown", "error"}:
            result["version_ok"] = True
            result["version_string"] = text
        else:
            result["version_string"] = "unknown"
        return result

    return result


def _severity_and_confidence_for_surface(
    cli_present: bool,
    socket_exists: bool,
    socket_writable: bool,
    user_owns_socket: bool,
    user_in_docker_group: bool,
    in_container: bool,
    version_ok: bool,
) -> Dict[str, Any]:
    """
    Scoring model for docker surfaces.
    """
    # === Logic Hardening ===
    # A socket is only useful if we can actually talk to it.
    # This happens if:
    # 1. We are in the 'docker' group (standard)
    # 2. We own the socket file (rootless docker)
    # 3. The socket is world-writable (misconfiguration)
    is_usable = user_in_docker_group or user_owns_socket or socket_writable

    # Base severity
    if socket_exists and is_usable:
        severity_score = 10.0
        severity_band = "Critical"
    
    elif socket_exists and cli_present:
        # Socket is there, CLI is there, but we don't have permission?
        # Use a low score unless we missed something.
        severity_score = 1.0
        severity_band = "Low"
        
    elif socket_exists:
        severity_score = 1.0
        severity_band = "Low"
        
    elif cli_present:
        severity_score = 1.0
        severity_band = "Low"
    else:
        severity_score = 0.0
        severity_band = "Info"

    # Confidence scoring
    if cli_present and socket_exists:
        confidence_score = 8.5
        confidence_band = "High"
    elif cli_present or socket_exists:
        confidence_score = 5.0
        confidence_band = "Medium"
    else:
        confidence_score = 3.0
        confidence_band = "Low"

    # Being inside a container with host docker socket implies critical access
    # regardless of CLI presence (we can use curl/API).
    if in_container and socket_exists:
        # Check write access inside container (usually true if mounted)
        # We assume mounted sockets in containers are meant to be used.
        severity_score = max(severity_score, 9.0)
        severity_band = "Critical"

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
    user_uid: Optional[int],
) -> tuple:
    lines: List[str] = []

    cli_present = bool(docker_state.get("binary_present"))
    socket_path = docker_state.get("socket_path") or "/var/run/docker.sock"
    socket_exists = bool(docker_state.get("socket_exists"))
    socket_mode = docker_state.get("socket_mode")
    socket_uid = docker_state.get("socket_uid")
    socket_gid = docker_state.get("socket_gid")
    
    # Defaults to False if probe doesn't support it yet
    socket_writable = bool(docker_state.get("socket_writable", False))

    version_meta = _extract_version_info(docker_state)
    version_ok = version_meta["version_ok"]
    version_string = version_meta["version_string"]

    in_container = bool(container_state.get("in_container"))
    
    # Rootless Docker detection
    user_owns_socket = False
    if socket_uid is not None and user_uid is not None:
        user_owns_socket = (socket_uid == user_uid)

    lines.append("This section analyses Docker related privilege surfaces observed by Nullpeas.")
    lines.append(
        "It uses existing runtime inspection (binary presence, version checks, and socket metadata) "
        "and does not start or modify any containers."
    )
    lines.append(
        "Severity reflects potential impact if abused; confidence reflects how likely the described "
        "surface is actually usable on this host based on current probes."
    )
    lines.append("")
    lines.append("### Docker daemon and socket summary")
    lines.append(f"- Docker CLI present          : {cli_present}")
    lines.append(f"- Version query OK            : {'True' if version_ok else 'False' if version_string != 'unknown' else 'unknown'}")
    lines.append(f"- Reported version            : {version_string}")
    lines.append(f"- Docker socket path          : {socket_path}")
    lines.append(f"- Docker socket exists        : {socket_exists}")
    lines.append(f"- Docker socket mode          : {socket_mode if socket_mode is not None else 'unknown'}")
    lines.append(f"- Docker socket writable      : {socket_writable}")
    lines.append(f"- Docker socket owner (uid)   : {socket_uid if socket_uid is not None else 'unknown'}")
    lines.append(f"- Docker socket group (gid)   : {socket_gid if socket_gid is not None else 'unknown'}")
    lines.append(f"- Running inside container    : {in_container}")
    lines.append(f"- User in docker group        : {user_in_docker_group}")
    lines.append(f"- User owns socket (rootless) : {user_owns_socket}")
    lines.append("")

    scoring = _severity_and_confidence_for_surface(
        cli_present=cli_present,
        socket_exists=socket_exists,
        socket_writable=socket_writable,
        user_owns_socket=user_owns_socket,
        user_in_docker_group=user_in_docker_group,
        in_container=in_container,
        version_ok=version_ok,
    )

    severity_score = scoring["severity_score"]
    severity_band = scoring["severity_band"]
    confidence_score = scoring["confidence_score"]
    confidence_band = scoring["confidence_band"]

    risk_categories: List[str] = []
    capability_tags: List[str] = ["container_escape", "file_read", "file_write", "platform_control"]

    if socket_exists and (user_in_docker_group or user_owns_socket or socket_writable):
        risk_categories.append("docker_user_daemon_access")
        risk_categories.append("docker_escape_surface")
    elif socket_exists:
        risk_categories.append("docker_socket_in_container" if in_container else "docker_socket_present")

    if in_container:
        risk_categories.append("container_escape_surface")

    description: str
    if socket_exists and (user_in_docker_group or user_owns_socket or socket_writable):
        description = f"Docker daemon reachable via socket {socket_path} (Group/Owner/Writable confirmed)"
    elif socket_exists:
        description = f"Docker socket {socket_path} exists but no write access confirmed"
    elif cli_present:
        description = "Docker CLI is present but no daemon socket was confirmed"
    else:
        description = "Docker appears installed minimally or not at all; no strong surfaces confirmed"

    lines.append("### Assessed Docker attack surface")
    lines.append(f"- Rule description            : {description}")
    lines.append(f"- Severity                    : {severity_band} ({severity_score}/10)")
    lines.append(f"- Confidence                  : {confidence_band} ({confidence_score}/10)")
    lines.append(f"- Capability tags             : {', '.join(capability_tags)}")
    lines.append(f"- Risk categories             : {', '.join(risk_categories) if risk_categories else 'none'}")
    lines.append("")

    if in_container and socket_exists:
        lines.append(
            "Running inside a container with access to the host Docker daemon is often treated as a host compromise surface in real practice."
        )

    return lines, scoring, capability_tags, risk_categories, description


def _build_docker_primitive(
    state: Dict[str, Any],
    scoring: Dict[str, Any],
    capability_tags: List[str],
    risk_categories: List[str],
    user_in_docker_group: bool,
    user_owns_socket: bool,
    socket_writable: bool,
    in_container: bool,
    description: str,
) -> Optional[Primitive]:
    """
    Convert the docker surface into a single offensive primitive.
    """
    cli_present = bool((state.get("runtime", {}) or {}).get("docker", {}).get("binary_present"))
    socket_exists = bool((state.get("runtime", {}) or {}).get("docker", {}).get("socket_exists"))

    # If nothing interesting, return None
    if not (cli_present or socket_exists):
        return None

    # Only generate primitives for actionable surfaces (Medium/High/Critical)
    if scoring["severity_score"] < 4.0:
        return None

    user = state.get("user", {}) or {}
    origin_user = user.get("name") or "current_user"

    severity_band = scoring["severity_band"]
    severity_score = scoring["severity_score"]
    confidence_band = scoring["confidence_band"]
    confidence_score = scoring["confidence_score"]

    is_usable = user_in_docker_group or user_owns_socket or socket_writable

    # Primitive type selection
    if is_usable and socket_exists:
        primitive_type = "docker_host_takeover"
        classification = "catastrophic"
        exploitability = "high"
    elif in_container and socket_exists:
        primitive_type = "container_escape_surface"
        classification = "severe"
        exploitability = "moderate"
    else:
        # Fallback for weird states
        primitive_type = "docker_exec_surface"
        classification = "useful"
        exploitability = "moderate"

    stability = "safe"
    noise = "low"

    confidence = PrimitiveConfidence(
        score=confidence_score,
        reason=(
            f"Derived from docker runtime surface: {description} "
            f"(severity {severity_score}/10 {severity_band}, confidence {confidence_score}/10 {confidence_band})."
        ),
    )

    offensive_value = OffensiveValue(
        classification=classification,  # type: ignore
        why=(
            f"Docker configuration exposes a surface classified as {classification}. "
            f"If combined with suitable primitive abuse it can materially weaken host boundaries."
        ),
    )

    context: Dict[str, Any] = {
        "description": description,
        "capability_tags": capability_tags,
        "risk_categories": risk_categories,
        "in_container": in_container,
        "user_in_docker_group": user_in_docker_group,
        "user_owns_socket": user_owns_socket,
        "socket_writable": socket_writable,
        "severity_band": severity_band,
        "severity_score": severity_score,
        "confidence_band": confidence_band,
        "confidence_score": confidence_score,
    }

    conditions: Dict[str, Any] = {
        "requires_docker_cli": cli_present,
        "requires_socket_access": socket_exists,
    }

    cross_refs: Dict[str, List[str]] = {
        "gtfobins": [],
        "cves": [],
        "documentation": [],
    }

    defensive_impact: Dict[str, Any] = {
        "misconfiguration_summary": (
            "Docker related surfaces were identified that may enable container escape or host control "
            "if abused by a capable attacker."
        )
    }

    # === NEW: Affected Resource (for chaining engine) ===
    # Docker gives control over the docker socket
    socket_path = (state.get("runtime", {}) or {}).get("docker", {}).get("socket_path") or "/var/run/docker.sock"
    
    primitive = Primitive(
        id=new_primitive_id("docker", primitive_type),
        surface="docker",
        type=primitive_type,
        run_as="root",  # Docker level control is generally treated as root level influence
        origin_user=origin_user,
        exploitability=exploitability,  # type: ignore[arg-type]
        stability=stability,            # type: ignore[arg-type]
        noise=noise,                    # type: ignore[arg-type]
        confidence=confidence,
        offensive_value=offensive_value,
        context=context,
        conditions=conditions,
        integration_flags={
            "root_goal_candidate": primitive_type == "docker_host_takeover",
            "docker_surface": True,
        },
        cross_refs=cross_refs,
        defensive_impact=defensive_impact,
        affected_resource=socket_path, # <--- Added this field
        module_source="docker_enum",
        probe_source="runtime",
    )

    return primitive


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

    cli_present = bool(docker_state.get("binary_present"))
    socket_exists = bool(docker_state.get("socket_exists"))

    # If both CLI and socket are absent there is nothing meaningful for this module to say.
    if not cli_present and not socket_exists:
        analysis = state.setdefault("analysis", {})
        analysis["docker"] = {
            "heading": "Docker Analysis",
            "summary_lines": [
                "Docker appears to be either absent or not meaningfully available to the current user.",
                "No strong Docker based privilege escalation surfaces were identified by the probes.",
            ],
        }
        return

    group_names = [g.get("name") for g in user.get("groups", []) if g.get("name")]
    user_in_docker_group = "docker" in (group_names or [])

    # Get socket_writable from state (ensure probe sets this)
    socket_writable = bool(docker_state.get("socket_writable", False))
    socket_uid = docker_state.get("socket_uid")
    user_owns_socket = (socket_uid is not None) and (user_uid is not None) and (socket_uid == user_uid)

    lines, scoring, capability_tags, risk_categories, description = _build_docker_analysis_lines(
        docker_state=docker_state,
        container_state=container_state,
        user_in_docker_group=user_in_docker_group,
        user_uid=user_uid,
    )

    analysis = state.setdefault("analysis", {})
    analysis["docker"] = {
        "heading": "Docker Analysis",
        "summary_lines": lines,
    }

    primitive = _build_docker_primitive(
        state=state,
        scoring=scoring,
        capability_tags=capability_tags,
        risk_categories=risk_categories,
        user_in_docker_group=user_in_docker_group,
        user_owns_socket=user_owns_socket,
        socket_writable=socket_writable,
        in_container=bool(container_state.get("in_container")),
        description=description,
    )

    if primitive is not None:
        primitives: List[Primitive] = state.setdefault("offensive_primitives", [])
        primitives.append(primitive)
