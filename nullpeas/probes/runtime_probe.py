from pathlib import Path
from typing import Dict, Any, List

from nullpeas.core.exec import run_command


CONTAINER_TOKENS = {
    "docker": ["docker"],
    "containerd": ["containerd"],
    "kubernetes": ["kubepods", "kubepods.slice"],
    "lxc": ["lxc"],
    "podman": ["libpod"],
}


def _detect_container_from_cgroup(cgroup_lines: List[str]) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "in_container": False,
        "container_type": None,
        "raw_indicator": None,
    }

    lowered_lines = [line.lower() for line in cgroup_lines]

    for ctype, tokens in CONTAINER_TOKENS.items():
        for token in tokens:
            for line in lowered_lines:
                if token in line:
                    info["in_container"] = True
                    info["container_type"] = ctype
                    info["raw_indicator"] = line.strip()
                    return info

    return info


def _container_info() -> Dict[str, Any]:
    container: Dict[str, Any] = {
        "in_container": False,
        "container_type": None,
        "raw_indicator": None,
        "dockerenv_present": False,
        "proc_cgroup_error": None,
    }

    # Classic docker marker
    dockerenv = Path("/.dockerenv")
    if dockerenv.exists():
        container["in_container"] = True
        container["dockerenv_present"] = True
        container["container_type"] = container["container_type"] or "docker"

    # /proc/1/cgroup heuristics
    cgroup_path = Path("/proc/1/cgroup")
    if cgroup_path.exists():
        try:
            lines = cgroup_path.read_text(encoding="utf-8", errors="replace").splitlines()
            inferred = _detect_container_from_cgroup(lines)

            # Merge inference
            if inferred["in_container"]:
                container["in_container"] = True
                # Prefer explicit type from cgroup if we don't already have one
                if not container["container_type"]:
                    container["container_type"] = inferred["container_type"]
                container["raw_indicator"] = inferred["raw_indicator"]

        except Exception as e:
            container["proc_cgroup_error"] = str(e)

    return container


def _virtualization_info() -> Dict[str, Any]:
    virt: Dict[str, Any] = {
        "systemd_detect_virt_available": False,
        "type": None,          # e.g. "kvm", "microsoft", "none"
        "is_vm": None,
        "is_container": None,
        "error": None,
    }

    # systemd-detect-virt is the nicest single source if present
    res = run_command(["systemd-detect-virt"], timeout=3)

    if res["binary_missing"]:
        virt["error"] = "systemd-detect-virt not found"
        return virt

    virt["systemd_detect_virt_available"] = not res["binary_missing"]

    if res["timed_out"]:
        virt["error"] = "systemd-detect-virt timed out"
        return virt

    if res["error"] and not res["ok"]:
        virt["error"] = res["error"]
        return virt

    # systemd-detect-virt prints "none" for bare metal
    vtype = (res["stdout"] or "").strip().lower()
    virt["type"] = vtype or None

    if not vtype or vtype == "none":
        virt["is_vm"] = False
        virt["is_container"] = False
    else:
        # systemd-detect-virt uses some container-y types too (e.g. "docker", "lxc")
        if vtype in {"docker", "lxc", "systemd-nspawn"}:
            virt["is_vm"] = False
            virt["is_container"] = True
        else:
            virt["is_vm"] = True
            virt["is_container"] = False

    return virt


def _docker_info() -> Dict[str, Any]:
    """
    Host-level docker information (as much as we can safely infer):
      - is the docker binary present?
      - does /var/run/docker.sock exist and what are its basic perms?
    """
    info: Dict[str, Any] = {
        "binary_present": False,
        "version_query_ok": False,
        "version": None,
        "socket_path": "/var/run/docker.sock",
        "socket_exists": False,
        "socket_mode": None,
        "socket_owner": None,
        "socket_group": None,
        "socket_error": None,
        "error": None,
    }

    # Check docker binary & version (read-only, times out)
    res = run_command(["docker", "version", "--format", "{{.Client.Version}}"], timeout=3)

    if res["binary_missing"]:
        info["error"] = "docker binary not found"
    else:
        info["binary_present"] = True
        if res["ok"]:
            info["version_query_ok"] = True
            info["version"] = res["stdout"] or None
        elif res["timed_out"]:
            info["error"] = "docker version query timed out"
        elif res["error"]:
            info["error"] = res["error"]

    # Socket metadata (we don't try to connect to it here)
    sock = Path(info["socket_path"])
    if sock.exists():
        info["socket_exists"] = True
        try:
            st = sock.stat()
            info["socket_mode"] = f"{st.st_mode & 0o777:04o}"
            info["socket_owner"] = st.st_uid
            info["socket_group"] = st.st_gid
        except Exception as e:
            info["socket_error"] = str(e)

    return info


def run(state: dict):
    runtime: Dict[str, Any] = {
        "container": _container_info(),
        "virtualization": _virtualization_info(),
        "docker": _docker_info(),
    }

    state["runtime"] = runtime
