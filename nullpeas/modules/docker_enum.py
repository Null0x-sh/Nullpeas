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

    docker_state["version_info"] may be:
      - a dict with parsed / raw fields
      - a simple string like "unknown" or "error"
      - missing entirely
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
    user_in_docker_group: bool,
    in_container: bool,
    version_ok: bool,
) -> Dict[str, Any]:
    """
    Simple scoring model for docker surfaces.

    These scores are intentionally conservative and focus on realistic power,
    not on impressing the operator.
    """
    # Base severity
    if user_in_docker_group and socket_exists:
        severity_score = 10.0
        severity_band = "Critical"
    elif socket_exists and cli_present:
        # Likely strong surface, but we have not confirmed group membership
        severity_score = 7.5
        severity_band = "High"
    elif socket_exists:
        severity_score = 5.0
        severity_band = "Medium"
    elif cli_present:
        severity_score = 3.5
        severity_band = "Medium"
    else:
        severity_score = 1.0
        severity_band = "Low"

    # Confidence scoring
    if cli_present and socket_exists and version_ok:
        confidence_score = 8.5
        confidence_band = "High"
    elif cli_present and socket_exists:
        confidence_score = 7.0
        confidence_band = "High"
    elif cli_present or socket_exists:
        confidence_score = 5.0
        confidence_band = "Medium"
    else:
        confidence_score = 3.0
        confidence_band = "Low"

    # Being inside a container with host docker socket often implies real power,
    # but we still keep the numbers reasonable until we confirm access.
    if in_container and socket_exists:
        severity_score = max(severity_score, 7.5)
        if severity_score >= 8.5:
            severity_band = "Critical"
        elif severity_score >= 6.5:
            severity_band = "High"
        else:
            severity_band = "Medium"

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
) -> List[str]:
    lines: List[str] = []

    cli_present = bool(docker_state.get("binary_present"))
    socket_path = docker_state.get("socket_path") or "/var/run/docker.sock"
    socket_exists = bool(docker_state.get("socket_exists"))
    socket_mode = docker_state.get("socket_mode")
    socket_uid = docker_state.get("socket_uid")
    socket_gid = docker_state.get("socket_gid")

    version_meta = _extract_version_info(docker_state)
    version_ok = version_meta["version_ok"]
    version_string = version_meta["version_string"]

    in_container = bool(container_state.get("in_container"))

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
    lines.append(f"- Docker socket owner (uid)   : {socket_uid if socket_uid is not None else 'unknown'}")
    lines.append(f"- Docker socket group (gid)   : {socket_gid if socket_gid is not None else 'unknown'}")
    lines.append(f"- Running inside container    : {in_container}")
    lines.append(f"- User in docker group        : {user_in_docker_group}")
    lines.append("")

    scoring = _severity_and_confidence_for_surface(
        cli_present=cli_present,
        socket_exists=socket_exists,
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

    if socket_exists and user_in_docker_group:
        risk_categories.append("docker_user_daemon_access")
        risk_categories.append("docker_escape_surface")
    elif socket_exists:
        risk_categories.append("docker_socket_in_container" if in_container else "docker_socket_present")

    if in_container:
        risk_categories.append("container_escape_surface")

    description: str
    if socket_exists and user_in_docker_group:
        description = f"Docker daemon reachable via socket {socket_path} and current user is in docker group"
    elif socket_exists:
        description = f"Docker socket {socket_path} exists but group level access is not confirmed"
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
    in_container: bool,
    description: str,
) -> Optional[Primitive]:
    """
    Convert the docker surface into a single offensive primitive so the chaining engine
    can reason about it alongside sudo, cron, path, and other surfaces.
    """
    cli_present = bool((state.get("runtime", {}) or {}).get("docker", {}).get("binary_present"))
    socket_exists = bool((state.get("runtime", {}) or {}).get("docker", {}).get("socket_exists"))

    if not (cli_present or socket_exists):
        return None

    user = state.get("user", {}) or {}
    origin_user = user.get("name") or "current_user"

    severity_band = scoring["severity_band"]
    severity_score = scoring["severity_score"]
    confidence_band = scoring["confidence_band"]
    confidence_score = scoring["confidence_score"]

    # Primitive type selection
    if user_in_docker_group and socket_exists:
        primitive_type = "docker_host_takeover"
        classification = "catastrophic"
        exploitability = "high"
    elif in_container and socket_exists:
        primitive_type = "container_escape_surface"
        classification = "severe"
        exploitability = "moderate"
    else:
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
        classification=classification,
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

    lines, scoring, capability_tags, risk_categories, description = _build_docker_analysis_lines(
        docker_state=docker_state,
        container_state=container_state,
        user_in_docker_group=user_in_docker_group,
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
        in_container=bool(container_state.get("in_container")),
        description=description,
    )

    if primitive is not None:
        primitives: List[Primitive] = state.setdefault("offensive_primitives", [])
        primitives.append(primitive)