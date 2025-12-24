from typing import Dict, Any, List, Set, Tuple

from nullpeas.core.report import Report
from nullpeas.modules import register_module
from nullpeas.core.offensive_schema import (
    Primitive,
    PrimitiveConfidence,
    OffensiveValue,
    new_primitive_id,
)


def _mode_to_int(mode_str: str) -> int:
    if not mode_str:
        return 0
    s = mode_str.strip()
    if s.startswith("0"):
        s = s[1:]
    try:
        return int(s, 8)
    except ValueError:
        return 0


def _docker_risk_categories(state: Dict[str, Any]) -> Set[str]:
    cats: Set[str] = set()

    runtime = state.get("runtime", {}) or {}
    docker = runtime.get("docker", {}) or {}
    container = runtime.get("container", {}) or {}
    user = state.get("user", {}) or {}
    triggers = state.get("triggers", {}) or {}

    docker_binary_present = docker.get("binary_present", False)
    docker_socket_exists = docker.get("socket_exists", False)
    socket_mode_str = docker.get("socket_mode", "") or ""
    socket_mode = _mode_to_int(socket_mode_str)

    in_docker_group = user.get("in_docker_group", False) or triggers.get(
        "in_docker_group", False
    )
    in_container = container.get("in_container", False)

    if docker_binary_present and docker_socket_exists and in_docker_group:
        cats.add("docker_user_daemon_access")

    if socket_mode & 0o002:
        cats.add("docker_socket_world_writable")
    if socket_mode & 0o020:
        cats.add("docker_socket_group_writable")

    if in_container and docker_socket_exists:
        cats.add("docker_socket_in_container")

    if triggers.get("docker_escape_surface"):
        cats.add("docker_escape_surface")
    if triggers.get("container_escape_surface"):
        cats.add("container_escape_surface")

    return cats


def _docker_capabilities_from_risk(risk_categories: Set[str]) -> Set[str]:
    caps: Set[str] = set()

    if (
        "docker_user_daemon_access" in risk_categories
        or "docker_socket_world_writable" in risk_categories
        or "docker_socket_group_writable" in risk_categories
    ):
        caps.add("platform_control")

    if (
        "docker_socket_in_container" in risk_categories
        or "docker_escape_surface" in risk_categories
        or "container_escape_surface" in risk_categories
    ):
        caps.add("container_escape")

    if "platform_control" in caps:
        caps.add("file_read")
        caps.add("file_write")

    return caps


def _docker_severity_and_confidence(
    risk_categories: Set[str],
    state: Dict[str, Any],
) -> Tuple[float, str, float, str]:
    runtime = state.get("runtime", {}) or {}
    docker = runtime.get("docker", {}) or {}

    docker_binary_present = docker.get("binary_present", False)
    docker_socket_exists = docker.get("socket_exists", False)
    version_query_ok = docker.get("version_query_ok", False)

    severity_raw = 0.0

    if "docker_user_daemon_access" in risk_categories:
        severity_raw += 0.6
    if "docker_socket_world_writable" in risk_categories:
        severity_raw += 0.7
    if "docker_socket_group_writable" in risk_categories:
        severity_raw += 0.4
    if "docker_socket_in_container" in risk_categories:
        severity_raw += 0.6
    if "docker_escape_surface" in risk_categories or "container_escape_surface" in risk_categories:
        severity_raw += 0.5

    if severity_raw == 0.0:
        severity_raw = 0.2

    severity_raw = min(severity_raw, 1.0)

    if "docker_user_daemon_access" in risk_categories and (
        "docker_socket_in_container" in risk_categories
        or "container_escape_surface" in risk_categories
    ):
        severity_raw = min(1.0, severity_raw + 0.2)

    severity_score = round(severity_raw * 10.0, 1)

    if severity_score >= 8.5:
        severity_band = "Critical"
    elif severity_score >= 6.5:
        severity_band = "High"
    elif severity_score >= 3.5:
        severity_band = "Medium"
    else:
        severity_band = "Low"

    conf_raw = 0.0
    if docker_binary_present:
        conf_raw += 0.4
    if docker_socket_exists:
        conf_raw += 0.4
    if version_query_ok:
        conf_raw += 0.2

    conf_raw = min(conf_raw, 1.0)
    confidence_score = round(conf_raw * 10.0, 1)

    if confidence_score >= 8.0:
        confidence_band = "High"
    elif confidence_score >= 5.0:
        confidence_band = "Medium"
    else:
        confidence_band = "Low"

    return severity_score, severity_band, confidence_score, confidence_band


def _offensive_classification_from_band(severity_band: str) -> str:
    if severity_band == "Critical":
        return "catastrophic"
    if severity_band == "High":
        return "severe"
    if severity_band == "Medium":
        return "useful"
    return "niche"


def _primitive_type_for_docker_surface(
    risk_categories: Set[str],
    capabilities: Set[str],
    severity_band: str,
) -> str:
    has_daemon_access = "docker_user_daemon_access" in risk_categories
    socket_world = "docker_socket_world_writable" in risk_categories
    socket_group = "docker_socket_group_writable" in risk_categories
    escape_hint = (
        "docker_socket_in_container" in risk_categories
        or "docker_escape_surface" in risk_categories
        or "container_escape_surface" in risk_categories
    )
    platform_control = "platform_control" in capabilities

    if socket_world or socket_group:
        return "docker_host_takeover"

    if has_daemon_access and platform_control:
        if severity_band in {"Critical", "High"}:
            return "docker_host_takeover"
        return "docker_platform_control_surface"

    if escape_hint and platform_control:
        return "docker_container_escape_surface"

    return "docker_daemon_present"


def _primitive_for_docker_surface(
    state: Dict[str, Any],
    risk_categories: Set[str],
    capabilities: Set[str],
    severity_score: float,
    severity_band: str,
    confidence_score: float,
    confidence_band: str,
    rule_desc: str,
) -> Primitive:
    user = state.get("user", {}) or {}
    runtime = state.get("runtime", {}) or {}
    docker = runtime.get("docker", {}) or {}

    user_name = user.get("name") or "current_user"
    in_docker_group = user.get("in_docker_group", False) or state.get("triggers", {}).get("in_docker_group", False)
    in_container = (runtime.get("container", {}) or {}).get("in_container", False)

    primitive_type = _primitive_type_for_docker_surface(
        risk_categories=risk_categories,
        capabilities=capabilities,
        severity_band=severity_band,
    )

    if primitive_type in {"docker_host_takeover", "docker_platform_control_surface", "docker_container_escape_surface"}:
        run_as = "root"
    else:
        run_as = user_name

    if primitive_type == "docker_host_takeover":
        exploitability = "trivial" if in_docker_group or "docker_socket_world_writable" in risk_categories else "moderate"
    elif primitive_type in {"docker_platform_control_surface", "docker_container_escape_surface"}:
        exploitability = "moderate"
    else:
        exploitability = "advanced" if severity_band in {"Medium", "High"} else "theoretical"

    if primitive_type in {"docker_host_takeover", "docker_platform_control_surface"}:
        stability = "safe"
    else:
        stability = "moderate"

    noise = "low"

    classification_band = _offensive_classification_from_band(severity_band)

    confidence = PrimitiveConfidence(
        score=confidence_score,
        reason=(
            f"Docker CLI/socket presence and metadata yield {confidence_band} confidence "
            f"in this daemon-related surface."
        ),
    )

    offensive_value = OffensiveValue(
        classification=classification_band,
        why=(
            f"Docker configuration implies {primitive_type} for run_as={run_as} "
            f"with severity={severity_band} (score={severity_score}/10). "
            "Daemon access can typically be turned into container-based host control with standard techniques."
        ),
    )

    socket_path = docker.get("socket_path") or "/var/run/docker.sock"

    primitive = Primitive(
        id=new_primitive_id("docker", primitive_type),
        surface="docker",
        type=primitive_type,
        run_as=run_as,
        origin_user=user_name,
        exploitability=exploitability,  # type: ignore[arg-type]
        stability=stability,            # type: ignore[arg-type]
        noise=noise,                    # type: ignore[arg-type]
        confidence=confidence,
        offensive_value=offensive_value,
        context={
            "rule": rule_desc,
            "risk_categories": sorted(risk_categories),
            "capabilities": sorted(capabilities),
            "severity_band": severity_band,
            "severity_score": severity_score,
            "socket_path": socket_path,
            "in_docker_group": in_docker_group,
            "in_container": in_container,
        },
        conditions={
            "requires_docker_cli": docker.get("binary_present", False),
            "requires_socket_access": docker.get("socket_exists", False),
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
        module_source="docker_enum",
        probe_source="runtime_probe",
    )

    return primitive


@register_module(
    key="docker_enum",
    description="Analyse Docker daemon access, socket exposure, and potential container escape surfaces",
    required_triggers=["docker_escape_surface"],
)
def run(state: dict, report: Report):
    runtime = state.get("runtime", {}) or {}
    docker = runtime.get("docker", {}) or {}

    if not docker.get("binary_present") and not docker.get("socket_exists"):
        report.add_section(
            "Docker Analysis",
            [
                "Docker CLI and Docker socket both appear to be absent on this host.",
                "No Docker-related privilege escalation surface was detected by the current probes.",
            ],
        )
        return

    risk_categories = _docker_risk_categories(state)
    capabilities = _docker_capabilities_from_risk(risk_categories)

    severity_score, severity_band, confidence_score, confidence_band = _docker_severity_and_confidence(
        risk_categories, state
    )

    socket_path = docker.get("socket_path") or "/var/run/docker.sock"
    socket_mode = docker.get("socket_mode")
    socket_owner = docker.get("socket_owner")
    socket_group = docker.get("socket_group")
    in_container = (runtime.get("container", {}) or {}).get("in_container", False)
    in_docker_group = state.get("user", {}).get("in_docker_group", False) or state.get(
        "triggers", {}
    ).get("in_docker_group", False)

    rule_desc = (
        f"Docker daemon reachable via socket {socket_path}"
        if docker.get("socket_exists")
        else "Docker CLI present without confirmed daemon/socket access"
    )

    # --- Docker Analysis (short factual section) ---
    lines: List[str] = []

    lines.append("This section analyses Docker-related privilege surfaces observed by Nullpeas.")
    lines.append(
        "It uses existing runtime inspection (binary presence, version checks, and socket metadata) "
        "and does not start or modify any containers."
    )
    lines.append("Severity reflects potential impact if abused; confidence reflects how likely")
    lines.append("the described surface is actually usable on this host based on current probes.")
    lines.append("")

    lines.append("### Docker daemon and socket summary")
    lines.append(f"- Docker CLI present          : {docker.get('binary_present')}")
    lines.append(f"- Version query OK            : {docker.get('version_query_ok')}")
    lines.append(f"- Reported version            : {docker.get('version')}")
    lines.append(f"- Docker socket path          : {socket_path}")
    lines.append(f"- Docker socket exists        : {docker.get('socket_exists')}")
    lines.append(f"- Docker socket mode          : {socket_mode}")
    lines.append(f"- Docker socket owner (uid)   : {socket_owner}")
    lines.append(f"- Docker socket group (gid)   : {socket_group}")
    lines.append(f"- Running inside container    : {in_container}")
    lines.append(f"- User in docker group        : {in_docker_group}")
    lines.append("")

    lines.append("### Assessed Docker attack surface")
    lines.append(f"- Rule description            : {rule_desc}")
    lines.append(f"- Severity                    : {severity_band} ({severity_score}/10)")
    lines.append(f"- Confidence                  : {confidence_band} ({confidence_score}/10)")
    if capabilities:
        lines.append(f"- Capability tags             : {', '.join(sorted(capabilities))}")
    if risk_categories:
        lines.append(f"- Risk categories             : {', '.join(sorted(risk_categories))}")
    lines.append("")

    report.add_section("Docker Analysis", lines)

    # --- Short Docker Attack Chain header (no guidance) ---
    chain_lines: List[str] = []
    chain_lines.append("This section describes high level attack chains based on Docker-related configuration and access.")
    chain_lines.append("Nullpeas does not start or modify containers, and does not execute any of the described actions.")
    chain_lines.append("It treats daemon-level Docker control as a potential host compromise surface.")
    chain_lines.append("")
    chain_lines.append("### docker -> daemon -> workload control")
    chain_lines.append("")
    chain_lines.append("Rule:")
    chain_lines.append(f"- {rule_desc}")
    chain_lines.append("")
    chain_lines.append("Severity:")
    chain_lines.append(f"- {severity_band} ({severity_score}/10)")
    chain_lines.append("")
    if capabilities:
        chain_lines.append("Capabilities:")
        chain_lines.append(f"- {', '.join(sorted(capabilities))}")
        chain_lines.append("")

    report.add_section("Docker Attack Chains", chain_lines)

    primitive = _primitive_for_docker_surface(
        state=state,
        risk_categories=risk_categories,
        capabilities=capabilities,
        severity_score=severity_score,
        severity_band=severity_band,
        confidence_score=confidence_score,
        confidence_band=confidence_band,
        rule_desc=rule_desc,
    )

    state.setdefault("offensive_primitives", []).append(primitive)