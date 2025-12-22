import os
import platform
import socket
import subprocess
from typing import Dict, Any


def run(state: Dict[str, Any]) -> None:
    """
    Collect basic environment information:
    - hostname
    - OS / distribution info (best-effort)
    - kernel version
    """

    env: Dict[str, Any] = {}

    # Hostname
    try:
        env["hostname"] = socket.gethostname()
    except Exception as e:
        env["hostname_error"] = str(e)

    # Platform / OS info
    try:
        env["platform_system"] = platform.system()
        env["platform_release"] = platform.release()
        env["platform_version"] = platform.version()
    except Exception as e:
        env["platform_error"] = str(e)

    # uname -a (raw)
    try:
        result = subprocess.run(
            ["uname", "-a"],
            capture_output=True,
            text=True,
            check=True,
        )
        env["raw_uname"] = result.stdout.strip()
    except Exception as e:
        env["raw_uname_error"] = str(e)

    # Optional: distro info (Linux only, best-effort)
    try:
        if env.get("platform_system") == "Linux":
            # This might not exist on all systems, so fail soft
            if os.path.exists("/etc/os-release"):
                with open("/etc/os-release", "r", encoding="utf-8") as f:
                    env["os_release"] = f.read()
    except Exception as e:
        env["os_release_error"] = str(e)

    # Write into state
    state["env"] = env
