from typing import Dict, Any, List, Optional, Set

from nullpeas.core.offensive_schema import (
    Primitive,
    PrimitiveConfidence,
    OffensiveValue,
    new_primitive_id,
)
from nullpeas.modules import register_module


def _normalise_version_info(docker_state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handle multiple possible shapes for version info:

      - dict: {"raw": "...", "parsed": "...", "ok": True}
      - str:  "28.5.1-1"
      - older fields like version_str / version_ok

    Returns a small dict with:
      { "raw": Optional[str], "parsed": Optional[str], "ok": Optional[bool] }
    """
    version_info = docker_state.get("version_info")
    raw = None
    parsed = None
    ok: Optional[bool] = None

    # New style: dict
    if isinstance(version_info, dict):
        raw = version_info.get("raw")
        parsed = version_info.get("parsed") or raw
        if "ok" in version_info:
            ok = bool(version_info.get("ok"))

    # Simple string
    elif isinstance(version_info, str):
        raw = version_info
        parsed = version_info

    # Fallbacks from older probe schema
    if raw is None:
        raw = docker_state.get("version_raw") or docker_state.get("version_str")
    if parsed is None:
        parsed = docker_state.get("version_short") or raw
    if ok is None and "version_ok" in docker_state:
        ok = bool(docker_state.get("version_ok"))

    return {
        "raw": raw,
        "parsed": parsed,
        "ok": ok,
    }


def _severity_and_confidence(
    socket_exists: bool,
    user_has_daemon_access: bool,
    in_container: bool,
) -> Dict[str, Any]:
    """
    Very simple severity and confidence model for Docker daemon access.

    - If user can talk to the daemon socket, treat as potentially catastrophic.
    - Confidence is lowered if some conditions are missing.
    """
    if not socket_exists or not user_has_daemon_access:
        # No direct daemon control. Still a surface, but not confirmed.
        severity_score = 4.0
        severity_band = "Medium"
        confidence_score = 4.0
        confidence_band = "Medium"
        classification = "useful"
        exploitability = "theoretical"
    else:
        severity_score = 10.0
        severity_band = "Critical"
        confidence_score = 10.0
        confidence_band = "High"
        classification = "catastrophic"
        exploitability = "trivial"

    # Container context slightly tweaks the description, but not the score.
    context_note = (
        "Running inside a container with daemon access. In practice this is still usually equivalent "
        "to host-level compromise."
        if in_container
        else "Direct access to the Docker daemon socket from the host namespace."
    )

    return {
        "severity_score": severity_score,
        "severity_band": severity_band,
        "confidence_score": confidence_score,
        "confidence_band": confidence_band,
        "classification": classification,
        "exploitability": exploitability,
        "context_note": context_note,
    }


def _build_docker_primitive(
    state: Dict[str, Any],
    docker_state: Dict[str, Any],
    model: Dict[str, Any],
) -> Optional[Primitive]:
    """
    Create a docker_host_takeover primitive if the surface is strong enough.
    """
    socket_exists = bool(docker_state.get("socket_exists"))
    user_in_docker_group = bool(docker_state.get("user_in_group"))
    user_has_daemon_access = socket_exists and user_in_docker_group

    if not user_has_daemon_access:
        # Nothing strong enough yet for a docker_host_takeover primitive.
        return None

    user = state.get("user", {}) or {}
    origin_user = user.get("name") or "current_user"

    socket_path = docker_state.get("socket_path") or "/var/run/docker.sock"
    in_container = bool((state.get("runtime", {}) or {}).get("container", {}).get("in_container"))

    severity_score = model["severity_score"]
    severity_band = model["severity_band"]
    confidence_score = model["confidence_score"]
    confidence_band = model["confidence_band"]
    classification = model["classification"]
    exploitability = model["exploitability"]
    context_note = model["context_note"]

    confidence = PrimitiveConfidence(
        score=confidence_score,
        reason=f"Docker daemon socket {socket_path} reachable by user; band {confidence_band}.",
    )

    offensive_value = OffensiveValue(
        classification=classification,
        why=(
            f"User can communicate with the Docker daemon via {socket_path}. "
            "In realistic environments, daemon-level Docker control is usually equivalent to root-level "
            "host compromise. "
            f"Severity {severity_score}/10 ({severity_band}), confidence {confidence_score}/10 ({confidence_band})."
        ),
    )

    context = {
        "socket_path": socket_path,
        "socket_mode": docker_state.get("socket_mode"),
        "socket_uid": docker_state.get("socket_uid"),
        "socket_gid": docker_state.get("socket_gid"),
        "user_in_docker_group": user_in_docker_group,
        "in_container": in_container,
        "severity_band": severity_band,
        "severity_score": severity_score,
        "confidence_band": confidence_band,
        "confidence_score": confidence_score,
    }

    conditions = {
        "requires_docker_group": True,
        "requires_socket_access": True,
    }

    cross_refs = {
        "gtfobins": [],
        "cves": [],
        "documentation": [],
    }

    defensive_impact = {
        "misconfiguration_summary": (
            "Local user appears to have practical access to the Docker daemon. In many real-world cases "
            "this is effectively equivalent to granting root on the host through container escape primitives."
        )
    }

    primitive = Primitive(
        id=new_primitive_id("docker", "docker_host_takeover"),
        surface="docker",
        type="docker_host_takeover",
        run_as="root",
        origin_user=origin_user,
        exploitability=exploitability,  # type: ignore[arg-type]
        stability="safe",               # type: ignore[arg-type]
        noise="low",                    # type: ignore[arg-type]
        confidence=confidence,
        offensive_value=offensive_value,
        context=context,
        conditions=conditions,
        integration_flags={"root_goal_candidate": True},
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
def run(state: Dict[str, Any], report) -> None:
    """
    Docker analysis module.

    - Uses runtime["docker"] data from the probe
    - Assesses severity and confidence for daemon access
    - Emits a Docker Analysis section into state["analysis"]["docker"]
    - Emits a docker_host_takeover primitive when the surface is strong enough
    """
    runtime = state.get("runtime", {}) or {}
    docker_state = runtime.get("docker", {}) or {}

    cli_present = bool(docker_state.get("binary_present"))
    socket_path = docker_state.get("socket_path") or "/var/run/docker.sock"
    socket_exists = bool(docker_state.get("socket_exists"))

    socket_mode = docker_state.get("socket_mode")
    socket_uid = docker_state.get("socket_uid")
    socket_gid = docker_state.get("socket_gid")

    in_container = bool((runtime.get("container") or {}).get("in_container"))
    user_in_docker_group = bool(docker_state.get("user_in_group"))

    version_norm = _normalise_version_info(docker_state)
    version_ok = version_norm.get("ok")
    version_parsed = version_norm.get("parsed")

    if not docker_state:
        # Very conservative, but we still say something.
        state.setdefault("analysis", {})["docker"] = {
            "heading": "Docker Analysis",
            "summary_lines": [
                "Docker runtime information was not available from probes.",
                "Either Docker is not installed, not configured, or the runtime probe could not run.",
            ],
        }
        return

    # Compute severity model from the surface
    model = _severity_and_confidence(
        socket_exists=socket_exists,
        user_has_daemon_access=socket_exists and user_in_docker_group,
        in_container=in_container,
    )

    # Build human-facing analysis lines
    lines: List[str] = []
    lines.append("This section analyses Docker-related privilege surfaces observed by Nullpeas.")
    lines.append("It uses existing runtime inspection (binary presence, version checks, and socket metadata) "
                 "and does not start or modify any containers.")
    lines.append("Severity reflects potential impact if abused; confidence reflects how likely "
                 "the described surface is actually usable on this host based on current probes.")
    lines.append("")
    lines.append("### Docker daemon and socket summary")
    lines.append(f"- Docker CLI present          : {cli_present}")
    lines.append(f"- Version query OK            : {bool(version_ok) if version_ok is not None else 'unknown'}")
    lines.append(f"- Reported version            : {version_parsed or 'unknown'}")
    lines.append(f"- Docker socket path          : {socket_path}")
    lines.append(f"- Docker socket exists        : {socket_exists}")
    lines.append(f"- Docker socket mode          : {socket_mode or 'unknown'}")
    lines.append(f"- Docker socket owner (uid)   : {socket_uid if socket_uid is not None else 'unknown'}")
    lines.append(f"- Docker socket group (gid)   : {socket_gid if socket_gid is not None else 'unknown'}")
    lines.append(f"- Running inside container    : {in_container}")
    lines.append(f"- User in docker group        : {user_in_docker_group}")
    lines.append("")
    lines.append("### Assessed Docker attack surface")
    if socket_exists and user_in_docker_group:
        lines.append(f"- Rule description            : Docker daemon reachable via socket {socket_path}")
    elif socket_exists:
        lines.append(f"- Rule description            : Docker socket {socket_path} exists but group access is not confirmed")
    else:
        lines.append("- Rule description            : Docker daemon socket not confirmed as reachable from this user context")
    lines.append(f"- Severity                    : {model['severity_band']} ({model['severity_score']}/10)")
    lines.append(f"- Confidence                  : {model['confidence_band']} ({model['confidence_score']}/10)")
    lines.append("- Capability tags             : container_escape, file_read, file_write, platform_control")
    lines.append("- Risk categories             : container_escape_surface, docker_escape_surface, docker_socket_in_container")
    lines.append("")
    lines.append(model["context_note"])

    state.setdefault("analysis", {})["docker"] = {
        "heading": "Docker Analysis",
        "summary_lines": lines,
    }

    # Emit an offensive primitive if appropriate
    primitive = _build_docker_primitive(state, docker_state, model)
    if primitive:
        state.setdefault("offensive_primitives", []).append(primitive)
