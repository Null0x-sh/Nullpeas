# nullpeas/probes/env_probe.py

import socket
import platform
from pathlib import Path
from typing import Dict, Any

from nullpeas.core.exec import run_command


def _parse_os_release(path: Path = Path("/etc/os-release")) -> Dict[str, Any]:
    """
    Parse /etc/os-release into a dict of lowercased keys.
    Falls back gracefully on errors.
    """
    data: Dict[str, Any] = {}

    if not path.exists():
        return data

    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key = key.strip().lower()
                val = val.strip().strip('"').strip("'")
                data[key] = val
    except Exception as e:
        # Don’t break the probe, just record the error
        data["_error"] = str(e)

    return data


def run(state: dict):
    env: Dict[str, Any] = {}

    # Basic host / platform info
    try:
        env["hostname"] = socket.gethostname()
    except Exception as e:
        env["hostname_error"] = str(e)

    try:
        env["platform_system"] = platform.system()
        env["platform_release"] = platform.release()
        env["platform_version"] = platform.version()
        env["architecture"] = platform.machine()
    except Exception as e:
        env["platform_error"] = str(e)

    # Raw uname (via central exec helper)
    uname_res = run_command(["uname", "-a"], timeout=3)
    if uname_res["ok"] or uname_res["stdout"]:
        env["raw_uname"] = uname_res["stdout"]
    else:
        env["raw_uname_error"] = uname_res["error"] or uname_res["stderr"]

    # Separate kernel info (even though it's also in uname/platform)
    uname_r_res = run_command(["uname", "-r"], timeout=3)
    if uname_r_res["ok"] or uname_r_res["stdout"]:
        env["kernel_release"] = uname_r_res["stdout"]

    # Parse /etc/os-release into structured fields
    os_release = _parse_os_release()
    if os_release:
        env["os_release"] = os_release

        # Convenience shortcuts for modules later
        env["os_id"] = os_release.get("id")
        env["os_version_id"] = os_release.get("version_id")
        env["os_pretty_name"] = os_release.get("pretty_name")

    # Simple flags that will be handy for triggers/modules
    system_lower = env.get("platform_system", "").lower()
    env["is_linux"] = (system_lower == "linux")
    env["is_bsd_like"] = system_lower in {"freebsd", "openbsd", "netbsd"}
    env["is_macos"] = system_lower == "darwin"

    state["env"] = env
