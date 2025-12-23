from typing import Dict, Any, List, Set, Tuple

from nullpeas.core.report import Report
from nullpeas.modules import register_module
from nullpeas.core.guidance import build_guidance, FindingContext, SeverityBand


def _mode_to_int(mode_str: str) -> int:
    """
    Convert a string like '0660' or '660' into an int (octal).
    Returns 0 on failure.
    """
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
    """
    Derive high-level risk categories from the collected runtime/docker info.
    """
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
    socket_group = docker.get("socket_group", None)

    in_docker_group = user.get("in_docker_group", False) or triggers.get(
        "in_docker_group", False
    )
    in_container = container.get("in_container", False)

    # User-level daemon access via group membership.
    if docker_binary_present and docker_socket_exists and in_docker_group:
        cats.add("docker_user_daemon_access")

    # Socket permissions.
    # Other write bit -> world-writable.
    if socket_mode & 0o002:
        cats.add("docker_socket_world_writable")
    # Group write bit (even if not "world") -> group-writable.
    if socket_mode & 0o020:
        cats.add("docker_socket_group_writable")

    # Socket accessible from inside a container.
    if in_container and docker_socket_exists:
        cats.add("docker_socket_in_container")

    # If the triggers think there is a docker/container escape surface,
    # echo that back as a risk category.
    if triggers.get("docker_escape_surface"):
        cats.add("docker_escape_surface")

    if triggers.get("container_escape_surface"):
        cats.add("container_escape_surface")

    return cats


def _docker_capabilities_from_risk(risk_categories: Set[str]) -> Set[str]:
    """
    Map docker-related risk categories to capability tags understood by guidance.
    """
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

    # If the daemon can control volumes, that can be modelled as file_read/write
    # even though it's indirect.
    if "platform_control" in caps:
        caps.add("file_read")
        caps.add("file_write")

    return caps


def _docker_severity_and_confidence(
    risk_categories: Set[str],
    state: Dict[str, Any],
) -> Tuple[float, SeverityBand, float, str]:
    """
    Basic scoring model for docker surfaces.

    Returns:
      (severity_score, severity_band, confidence_score, confidence_band)
    """
    runtime = state.get("runtime", {}) or {}
    docker = runtime.get("docker", {}) or {}

    docker_binary_present = docker.get("binary_present", False)
    docker_socket_exists = docker.get("socket_exists", False)
    version_query_ok = docker.get("version_query_ok", False)

    # ------------------------
    # Severity 0.0–1.0
    # ------------------------
    severity_raw = 0.0

    # Baseline per risk type.
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

    # Clamp base if nothing was set.
    if severity_raw == 0.0:
        severity_raw = 0.2  # mild: docker present but no obvious high-risk feature

    # Normalise (roughly) into 0–1 range.
    severity_raw = min(severity_raw, 1.0)

    # Strengthen if both daemon access and container-escape-ish signals exist.
    if "docker_user_daemon_access" in risk_categories and (
        "docker_socket_in_container" in risk_categories
        or "container_escape_surface" in risk_categories
    ):
        severity_raw = min(1.0, severity_raw + 0.2)

    severity_score = round(severity_raw * 10.0, 1)

    if severity_score >= 8.5:
        severity_band: SeverityBand = "Critical"
    elif severity_score >= 6.5:
        severity_band = "High"
    elif severity_score >= 3.5:
        severity_band = "Medium"
    else:
        severity_band = "Low"

    # ------------------------
    # Confidence 0.0–1.0
    # ------------------------
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


@register_module(
    key="docker_enum",
    description="Analyse Docker daemon access, socket exposure, and potential container escape surfaces",
    required_triggers=["docker_escape_surface"],
)
def run(state: dict, report: Report):
    """
    In depth Docker analysis module.

    - Uses existing runtime/docker probe output.
    - Identifies user access to the Docker daemon and socket exposure.
    - Assigns capability categories (platform_control, container_escape, file_read/write).
    - Scores severity and confidence.
    - Delegates narrative guidance to the shared guidance engine.
    """
    runtime = state.get("runtime", {}) or {}
    docker = runtime.get("docker", {}) or {}

    # If docker isn't even present, don't spam.
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

    # Build a single high-level finding representing docker daemon surface.
    rule_desc = f"Docker daemon reachable via socket {socket_path}" if docker.get(
        "socket_exists"
    ) else "Docker CLI present without confirmed daemon/socket access"

    # Build guidance context (surface="docker") – this is the only place
    # docker_enum needs to think about prose now.
    ctx: FindingContext = {
        "surface": "docker",
        "rule": rule_desc,
        "binary": "docker" if docker.get("binary_present") else None,
        "capabilities": capabilities,
        "risk_categories": risk_categories,
        "severity_band": severity_band,
        "severity_score": severity_score,
        "nopasswd": False,  # not relevant for docker, but field exists
        "gtfobins_url": None,
        "metadata": {
            "socket_path": socket_path,
            "socket_mode": socket_mode,
            "socket_owner": socket_owner,
            "socket_group": socket_group,
            "in_container": in_container,
            "in_docker_group": in_docker_group,
        },
    }

    guidance = build_guidance(ctx)

    # ------------------------------------------------------------------
    # Docker Analysis section (summary, facts, scoring)
    # ------------------------------------------------------------------
    lines: List[str] = []

    lines.append(
        "This section analyses Docker-related privilege surfaces observed by Nullpeas."
    )
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
        lines.append(
            f"- Capability tags             : {', '.join(sorted(capabilities))}"
        )
    if risk_categories:
        lines.append(
            f"- Risk categories             : {', '.join(sorted(risk_categories))}"
        )
    lines.append("")

    report.add_section("Docker Analysis", lines)

    # ------------------------------------------------------------------
    # Docker Attack Chains section (driven by guidance engine)
    # ------------------------------------------------------------------
    chain_lines: List[str] = []

    chain_lines.append(
        "This section describes high level attack chains based on Docker-related configuration and access."
    )
    chain_lines.append(
        "Nullpeas does not start or modify containers, and does not execute any of the described actions."
    )
    chain_lines.append("They illustrate how operators or attackers might reason about this surface,")
    chain_lines.append("and how defenders can respond.")
    chain_lines.append("")

    chain_lines.append(f"### docker -> daemon -> workload control")
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
