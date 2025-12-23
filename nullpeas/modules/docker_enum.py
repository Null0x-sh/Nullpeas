from typing import Dict, Any, List, Set, Tuple

from nullpeas.core.report import Report
from nullpeas.modules import register_module
from nullpeas.core.guidance import build_guidance, FindingContext


def _user_in_docker_group(user: Dict[str, Any]) -> bool:
    if user.get("in_docker_group"):
        return True
    for g in user.get("groups", []):
        if g.get("name") == "docker":
            return True
    return False


def _socket_world_group_bits(mode_str: str) -> Tuple[bool, bool]:
    """
    Given a string like '0660', return:
      (world_writable_or_readable, group_writable_or_readable)
    Very coarse – we just care about 'is this broadly accessible'.
    """
    try:
        mode_int = int(mode_str, 8)
    except Exception:
        return False, False

    world_bits = mode_int & 0o007
    group_bits = mode_int & 0o070

    world_access = bool(world_bits)
    group_access = bool(group_bits)

    return world_access, group_access


def _docker_severity_and_confidence(
    user_has_daemon_access: bool,
    in_container: bool,
    socket_world_access: bool,
    socket_group_access: bool,
) -> Tuple[Tuple[float, str], Tuple[float, str]]:
    """
    Coarse severity + confidence model for Docker daemon access.

    - user_has_daemon_access + not in_container => very high (host user == near-root)
    - user_has_daemon_access + in_container    => high (container escape path)
    - world-access or very loose permissions    => boosts severity
    """
    # ----- Severity -----
    if user_has_daemon_access and not in_container:
        base_sev = 0.9
    elif user_has_daemon_access and in_container:
        base_sev = 0.8
    elif socket_world_access:
        base_sev = 0.7
    else:
        base_sev = 0.4

    if socket_world_access:
        base_sev += 0.1
    elif socket_group_access:
        base_sev += 0.05

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
    if user_has_daemon_access:
        conf_score = 8.5
    elif socket_world_access or socket_group_access:
        conf_score = 7.5
    else:
        conf_score = 5.0

    if in_container and user_has_daemon_access:
        conf_score += 0.5  # docker-in-docker with socket mounted is usually obvious

    conf_score = max(0.0, min(10.0, conf_score))

    if conf_score >= 8.0:
        conf_band = "High"
    elif conf_score >= 5.5:
        conf_band = "Medium"
    else:
        conf_band = "Low"

    return (severity_score, severity_band), (conf_score, conf_band)


@register_module(
    key="docker_enum",
    description="Analyse Docker daemon access and potential container escape surfaces",
    required_triggers=["docker_escape_surface"],
)
def run(state: dict, report: Report):
    """
    Docker daemon / escape analysis module.

    - Uses existing runtime/docker probe output (no extra docker calls required).
    - Evaluates whether the current user can talk to the Docker daemon.
    - Assigns high level risk categories and capabilities.
    - Computes severity and confidence scores.
    - Delegates narrative guidance to the central guidance engine.
    """
    runtime = state.get("runtime", {}) or {}
    docker = runtime.get("docker", {}) or {}
    user = state.get("user", {}) or {}
    container = runtime.get("container", {}) or {}

    if not docker or not docker.get("binary_present"):
        report.add_section(
            "Docker Analysis",
            [
                "Docker CLI or daemon information not present in state.",
                "Either Docker is not installed, not in PATH, or the Docker probe did not run.",
            ],
        )
        return

    socket_path = docker.get("socket_path")
    socket_exists = docker.get("socket_exists", False)
    socket_mode = docker.get("socket_mode") or ""
    socket_owner = docker.get("socket_owner")
    socket_group = docker.get("socket_group")
    version = docker.get("version")
    version_query_ok = docker.get("version_query_ok", False)

    in_container = bool(container.get("in_container"))
    user_in_docker = _user_in_docker_group(user)

    world_access, group_access = _socket_world_group_bits(socket_mode) if socket_mode else (False, False)

    # Very coarse: if user is in docker group and socket exists, assume they can talk to daemon.
    user_has_daemon_access = bool(user_in_docker and socket_exists)

    # Capabilities from this context.
    capabilities: Set[str] = set()
    if user_has_daemon_access:
        capabilities.add("platform_control")
        capabilities.add("file_read")
        capabilities.add("file_write")
    if in_container and socket_exists:
        capabilities.add("container_escape")

    # Risk categories.
    risk_categories: Set[str] = set()
    if user_has_daemon_access:
        risk_categories.add("docker_user_daemon_access")
    if in_container and socket_exists:
        risk_categories.add("docker_socket_in_container")
    if world_access:
        risk_categories.add("docker_socket_world_writable")
    if group_access:
        risk_categories.add("docker_socket_group_writable")
    if docker.get("error") is None and docker.get("version"):
        # Very rough: treat anything that looks like rootless as a separate note.
        if "rootless" in str(docker.get("version")).lower():
            risk_categories.add("docker_rootless_daemon")

    (severity_score, severity_band), (conf_score, conf_band) = _docker_severity_and_confidence(
        user_has_daemon_access=user_has_daemon_access,
        in_container=in_container,
        socket_world_access=world_access,
        socket_group_access=group_access,
    )

    # Build a single high-level finding for this host/user.
    descriptor_parts: List[str] = []
    if user_has_daemon_access:
        if in_container:
            descriptor_parts.append("Container user has access to host Docker daemon")
        else:
            descriptor_parts.append("Host user has access to Docker daemon")
    elif socket_exists:
        descriptor_parts.append("Docker socket present but user access unclear")
    else:
        descriptor_parts.append("Docker CLI present; daemon/socket not detected")

    descriptor = "; ".join(descriptor_parts)

    finding = {
        "surface": "docker",
        "rule": descriptor,
        "binary": "docker",
        "capabilities": capabilities,
        "risk_categories": risk_categories,
        "severity_band": severity_band,
        "severity_score": severity_score,
        "nopasswd": False,  # sudo-specific; unused here but kept for uniformity
        "gtfobins_url": None,
        "metadata": {
            "socket_path": socket_path,
            "socket_exists": socket_exists,
            "socket_mode": socket_mode,
            "socket_owner": socket_owner,
            "socket_group": socket_group,
            "docker_version": version,
            "version_query_ok": version_query_ok,
            "in_container": in_container,
            "user_in_docker_group": user_in_docker,
        },
        "confidence_score": conf_score,
        "confidence_band": conf_band,
    }

    # ---- Analysis section (raw facts + scoring) ----
    analysis_lines: List[str] = []
    analysis_lines.append("This section analyses Docker daemon access and potential container escape surfaces.")
    analysis_lines.append("No containers are started or modified by Nullpeas; it reasons about risk only.")
    analysis_lines.append("Severity reflects potential impact if abused, confidence reflects how likely this access is usable on this host.")
    analysis_lines.append("")
    analysis_lines.append("### Docker environment snapshot")
    analysis_lines.append(f"- Docker CLI present          : {bool(docker.get('binary_present'))}")
    analysis_lines.append(f"- Docker version query OK     : {version_query_ok}")
    analysis_lines.append(f"- Reported Docker version     : {version or 'unknown'}")
    analysis_lines.append(f"- Socket path                 : {socket_path or 'unknown'}")
    analysis_lines.append(f"- Socket exists               : {socket_exists}")
    analysis_lines.append(f"- Socket mode                 : {socket_mode or 'unknown'}")
    analysis_lines.append(f"- Socket owner (uid)          : {socket_owner}")
    analysis_lines.append(f"- Socket group (gid)          : {socket_group}")
    analysis_lines.append(f"- User in 'docker' group      : {user_in_docker}")
    analysis_lines.append(f"- Running inside container    : {in_container}")
    analysis_lines.append("")
    analysis_lines.append("### Evaluated daemon access")
    analysis_lines.append(f"- Descriptor       : {descriptor}")
    analysis_lines.append(f"- Severity         : {severity_band} ({severity_score}/10)")
    analysis_lines.append(f"- Confidence       : {conf_band} ({conf_score}/10)")
    if capabilities:
        analysis_lines.append(f"- Capabilities     : {', '.join(sorted(capabilities))}")
    if risk_categories:
        analysis_lines.append(f"- Risk categories  : {', '.join(sorted(risk_categories))}")
    analysis_lines.append("")

    report.add_section("Docker Analysis", analysis_lines)

    # ---- Attack chain section (guided reasoning via core.guidance) ----
    guidance = build_guidance(finding)  # type: ignore[arg-type]

    chain_lines: List[str] = []
    chain_lines.append(
        "This section describes high level attack chains based on Docker daemon access."
    )
    chain_lines.append(
        "Nullpeas does not interact with the Docker daemon. It describes what an operator or attacker could do, and how defenders can respond."
    )
    chain_lines.append("")

    chain_lines.append("### docker -> platform control via daemon access")
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

    report.add_section("Docker Attack Chains", chain_lines)
