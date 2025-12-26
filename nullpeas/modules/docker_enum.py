from typing import Dict, Any, List, Optional, Set, Tuple

from nullpeas.core.report import Report
from nullpeas.core.offensive_schema import (
    Primitive,
    PrimitiveConfidence,
    OffensiveValue,
    new_primitive_id,
)
from nullpeas.modules import register_module


# ---------------------------------------------------------------------------
# Helpers: classification and scoring
# ---------------------------------------------------------------------------

def _offensive_classification_from_band(severity_band: str) -> str:
    if severity_band == "Critical":
        return "catastrophic"
    if severity_band == "High":
        return "severe"
    if severity_band == "Medium":
        return "useful"
    return "niche"


def _docker_capabilities(runtime: Dict[str, Any], user: Dict[str, Any]) -> Set[str]:
    """
    Derive capability tags from runtime Docker facts.

    Capabilities describe what this surface can realistically do for an operator.
    """
    caps: Set[str] = set()

    docker = runtime.get("docker", {}) or {}
    container = runtime.get("container", {}) or {}

    binary_present = bool(docker.get("binary_present"))
    socket_exists = bool(docker.get("socket_exists"))
    user_in_docker_group = bool(user.get("in_docker_group"))
    in_container = bool(container.get("in_container"))

    # Daemon-level control from a non-root user is effectively platform control.
    if binary_present and socket_exists and user_in_docker_group:
        caps.add("platform_control")
        caps.add("file_read")
        caps.add("file_write")
        caps.add("persistence")

    # Docker socket reachable from inside a container implies container escape surface.
    if socket_exists and in_container:
        caps.add("container_escape")

    return caps


def _docker_risk_categories(runtime: Dict[str, Any], user: Dict[str, Any]) -> Set[str]:
    """
    Risk categories describe why this surface matters offensively.
    """
    cats: Set[str] = set()

    docker = runtime.get("docker", {}) or {}
    container = runtime.get("container", {}) or {}

    binary_present = bool(docker.get("binary_present"))
    socket_exists = bool(docker.get("socket_exists"))
    socket_info = docker.get("socket") or {}
    socket_mode = socket_info.get("mode")
    socket_gid = socket_info.get("gid")
    user_in_docker_group = bool(user.get("in_docker_group"))
    in_container = bool(container.get("in_container"))

    if binary_present:
        cats.add("docker_cli_present")

    if socket_exists:
        cats.add("docker_socket_present")

    if socket_exists and user_in_docker_group:
        cats.add("docker_user_daemon_access")

    if socket_exists and in_container:
        cats.add("docker_socket_in_container")
        cats.add("container_escape_surface")

    # Mode flags on the socket.
    if socket_mode and isinstance(socket_mode, str):
        try:
            mode_int = int(socket_mode, 8)
            if mode_int & 0o020:
                cats.add("docker_socket_group_writable")
            if mode_int & 0o002:
                cats.add("docker_socket_world_writable")
        except Exception:
            # If we cannot parse the mode we simply do not add these tags.
            pass

    # Rough heuristic: if the socket group id matches the user's primary gid,
    # treat it as direct group-level daemon access.
    try:
        user_gid = int(user.get("gid"))
        if socket_gid is not None and int(socket_gid) == user_gid:
            cats.add("docker_socket_user_group")
    except Exception:
        pass

    return cats


def _docker_severity_and_confidence(
    capabilities: Set[str],
    risk_categories: Set[str],
) -> Tuple[Tuple[float, str], Tuple[float, str]]:
    """
    Severity and confidence model for Docker surfaces.

    Severity:
      - daemon control from a non-root user is treated as Critical
      - container escape surfaces are at least High

    Confidence:
      - based on how strong and direct the evidence is
    """
    base_sev = 0.0

    if "platform_control" in capabilities:
        # Daemon-level docker control is effectively "do almost anything on the host".
        base_sev = max(base_sev, 0.95)

    if "container_escape" in capabilities:
        base_sev = max(base_sev, 0.8)

    if "docker_socket_world_writable" in risk_categories:
        base_sev = max(base_sev, 1.0)

    if "docker_socket_group_writable" in risk_categories:
        base_sev = max(base_sev, 0.9)

    if "docker_user_daemon_access" in risk_categories:
        base_sev = max(base_sev, 0.95)

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

    # Confidence model: how sure we are that this surface is actually usable.
    conf = 5.0

    if "docker_user_daemon_access" in risk_categories:
        conf = max(conf, 9.0)
    elif "docker_socket_in_container" in risk_categories:
        conf = max(conf, 8.0)
    elif "docker_socket_present" in risk_categories:
        conf = max(conf, 7.0)

    if "docker_socket_world_writable" in risk_categories:
        conf = max(conf, 9.5)

    conf = max(0.0, min(10.0, conf))

    if conf >= 8.0:
        conf_band = "High"
    elif conf >= 5.5:
        conf_band = "Medium"
    else:
        conf_band = "Low"

    return (severity_score, severity_band), (conf, conf_band)


def _build_docker_descriptor(runtime: Dict[str, Any], user: Dict[str, Any]) -> str:
    """
    Human readable descriptor for the effective Docker surface.
    Offensive truth, not remediation.
    """
    docker = runtime.get("docker", {}) or {}
    container = runtime.get("container", {}) or {}

    socket_info = docker.get("socket") or {}
    socket_path = socket_info.get("path") or "/var/run/docker.sock"
    in_container = bool(container.get("in_container"))
    user_in_docker_group = bool(user.get("in_docker_group"))

    phrases: List[str] = []

    if docker.get("binary_present"):
        phrases.append("docker CLI present")
    if docker.get("socket_exists"):
        phrases.append(f"docker socket reachable at {socket_path}")
    if user_in_docker_group:
        phrases.append("current user is in docker group")
    if in_container:
        phrases.append("execution is occurring inside a container")

    if not phrases:
        return "Docker environment present but no clear daemon-level access identified"

    return "; ".join(phrases)


# ---------------------------------------------------------------------------
# Offensive Primitive
# ---------------------------------------------------------------------------

def _primitive_for_docker_surface(
    user: Dict[str, Any],
    capabilities: Set[str],
    risk_categories: Set[str],
    severity_score: float,
    severity_band: str,
    conf_score: float,
    conf_band: str,
) -> Primitive:
    """
    Build a single offensive Primitive representing the Docker surface.

    This primitive is what the chaining engine will stitch into multi-surface
    attack chains.
    """
    user_name = user.get("name") or "current_user"

    if "platform_control" in capabilities or "docker_user_daemon_access" in risk_categories:
        primitive_type = "docker_host_takeover"
        run_as = "root"
    elif "container_escape" in capabilities:
        primitive_type = "docker_container_escape_surface"
        run_as = "root"
    else:
        primitive_type = "docker_surface"
        run_as = "root"

    if primitive_type == "docker_host_takeover":
        exploitability = "trivial"
        stability = "safe"
        noise = "low"
    elif primitive_type == "docker_container_escape_surface":
        exploitability = "moderate"
        stability = "safe"
        noise = "low"
    else:
        exploitability = "advanced"
        stability = "moderate"
        noise = "low"

    classification_band = _offensive_classification_from_band(severity_band)

    confidence = PrimitiveConfidence(
        score=conf_score,
        reason=f"Docker surfaces observed with {conf_band} confidence based on daemon access indicators.",
    )

    offensive_value = OffensiveValue(
        classification=classification_band,
        why=(
            f"Docker configuration implies {primitive_type} for run_as={run_as} "
            f"with severity={severity_band} (score={severity_score}/10). "
            "Daemon level Docker access is commonly treated as equivalent to host level compromise."
        ),
    )

    primitive = Primitive(
        id=new_primitive_id("docker", primitive_type),
        surface="docker",
        type=primitive_type,
        run_as=run_as,
        origin_user=user_name,
        exploitability=exploitability,     # type: ignore[arg-type]
        stability=stability,               # type: ignore[arg-type]
        noise=noise,                       # type: ignore[arg-type]
        confidence=confidence,
        offensive_value=offensive_value,
        context={
            "capabilities": sorted(capabilities),
            "risk_categories": sorted(risk_categories),
            "severity_band": severity_band,
            "severity_score": severity_score,
            "confidence_band": conf_band,
            "confidence_score": conf_score,
        },
        conditions={
            "requires_docker_daemon": True,
        },
        integration_flags={
            "chaining_allowed": True,
            "root_goal_candidate": primitive_type == "docker_host_takeover",
        },
        cross_refs={
            "gtfobins": [],
            "cves": [],
            "documentation": [],
        },
        defensive_impact={
            "risk_to_system": "total_compromise",
            "visibility_risk": "low",
        },
        module_source="docker_enum",
        probe_source="runtime",
    )

    return primitive


# ---------------------------------------------------------------------------
# Module entrypoint
# ---------------------------------------------------------------------------

@register_module(
    key="docker_enum",
    description="Analyse Docker daemon access and potential container escape surfaces",
    required_triggers=["docker_escape_surface"],
)
def run(state: dict, report: Optional[Report] = None) -> None:
    """
    Docker analysis module.

    Responsibilities under the offensive pivot:
      - interpret Docker related probe data
      - extract structured offensive intelligence
      - classify capabilities and risk categories
      - score severity and confidence
      - emit offensive primitives for the chaining engine
      - provide a concise offensive summary for reports
    """
    runtime = state.get("runtime", {}) or {}
    user = state.get("user", {}) or {}

    docker = runtime.get("docker", {}) or {}
    container = runtime.get("container", {}) or {}

    # If nothing Docker related was probed, exit quietly.
    if not docker and not container:
        return

    capabilities = _docker_capabilities(runtime, user)
    risk_categories = _docker_risk_categories(runtime, user)
    (severity_score, severity_band), (conf_score, conf_band) = _docker_severity_and_confidence(
        capabilities=capabilities,
        risk_categories=risk_categories,
    )

    descriptor = _build_docker_descriptor(runtime, user)

    version_info = docker.get("version") or {}
    version_str = (
        version_info.get("parsed")
        or version_info.get("raw")
        or docker.get("version_string")
        or "unknown"
    )
    socket_info = docker.get("socket") or {}

    summary_lines: List[str] = []
    summary_lines.append("This section analyses Docker related privilege surfaces observed by Nullpeas.")
    summary_lines.append("It relies on existing runtime inspection (binary presence, version checks, socket metadata) and does not start or modify any containers.")
    summary_lines.append("Severity reflects potential impact if abused; confidence reflects how likely this surface is actually usable on this host.")
    summary_lines.append("")
    summary_lines.append("### Docker daemon and socket summary")
    summary_lines.append(f"- Docker CLI present          : {bool(docker.get('binary_present'))}")
    summary_lines.append(f"- Version query OK            : {bool(version_info.get('ok') or docker.get('version_ok'))}")
    summary_lines.append(f"- Reported version            : {version_str}")
    summary_lines.append(f"- Docker socket path          : {socket_info.get('path', '/var/run/docker.sock')}")
    summary_lines.append(f"- Docker socket exists        : {bool(docker.get('socket_exists'))}")
    summary_lines.append(f"- Docker socket mode          : {socket_info.get('mode', 'unknown')}")
    summary_lines.append(f"- Docker socket owner (uid)   : {socket_info.get('uid', 'unknown')}")
    summary_lines.append(f"- Docker socket group (gid)   : {socket_info.get('gid', 'unknown')}")
    summary_lines.append(f"- Running inside container    : {bool(container.get('in_container'))}")
    summary_lines.append(f"- User in docker group        : {bool(user.get('in_docker_group'))}")
    summary_lines.append("")
    summary_lines.append("### Assessed Docker attack surface")
    summary_lines.append(f"- Rule description            : {descriptor}")
    summary_lines.append(f"- Severity                    : {severity_band} ({severity_score}/10)")
    summary_lines.append(f"- Confidence                  : {conf_band} ({conf_score}/10)")
    summary_lines.append(f"- Capability tags             : {', '.join(sorted(capabilities)) if capabilities else 'none'}")
    summary_lines.append(f"- Risk categories             : {', '.join(sorted(risk_categories)) if risk_categories else 'none'}")
    summary_lines.append("")

    # Store structured analysis into state for the reporting engine.
    analysis_entry = {
        "heading": "Docker Analysis",
        "summary_lines": summary_lines,
        "capabilities": sorted(capabilities),
        "risk_categories": sorted(risk_categories),
        "severity_band": severity_band,
        "severity_score": severity_score,
        "confidence_band": conf_band,
        "confidence_score": conf_score,
        "descriptor": descriptor,
    }

    analysis = state.setdefault("analysis", {})
    analysis["docker"] = analysis_entry

    # Emit offensive primitive for the chaining engine.
    primitive = _primitive_for_docker_surface(
        user=user,
        capabilities=capabilities,
        risk_categories=risk_categories,
        severity_score=severity_score,
        severity_band=severity_band,
        conf_score=conf_score,
        conf_band=conf_band,
    )

    offensive_list: List[Primitive] = state.setdefault("offensive_primitives", [])
    offensive_list.append(primitive)

    # Optional direct report section for older flows.
    if report is not None:
        report.add_section("Docker Analysis", summary_lines)