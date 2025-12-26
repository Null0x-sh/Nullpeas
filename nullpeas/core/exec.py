# nullpeas/core/exec.py
import os
import shutil
import subprocess
from typing import List, Union, Dict, Any

DEFAULT_TIMEOUT = 5

def run_command(
    cmd: Union[List[str], str],
    timeout: int = DEFAULT_TIMEOUT,
    shell: bool = False,
    strip_output: bool = True,
) -> Dict[str, Any]:
    """
    Centralised wrapper around subprocess.run used by all probes.
    
    UPGRADES in v2:
    - Forces LC_ALL=C to ensure command output is always in English (critical for parsing).
    - Safely handles environment variables.
    """

    result: Dict[str, Any] = {
        "cmd": cmd,
        "shell": shell,
        "timeout": timeout,

        "ok": False,
        "stdout": "",
        "stderr": "",
        "return_code": None,

        "timed_out": False,
        "binary_missing": False,
        "error": None,
    }

    # Basic safety: for shell=False we expect a list like ["ls", "-la"]
    if not shell and isinstance(cmd, str):
        result["error"] = "run_command called with string cmd and shell=False"
        return result

    # Pre-check binary when not using shell to avoid ugly OSErrors
    if not shell and isinstance(cmd, list) and cmd:
        binary = cmd[0]
        if shutil.which(binary) is None:
            result["binary_missing"] = True
            result["error"] = f"binary '{binary}' not found"
            return result

    # === FIX: Force English Locale for consistent parsing ===
    # We copy the current environment to keep PATH, but override language.
    safe_env = os.environ.copy()
    safe_env["LC_ALL"] = "C"
    safe_env["LANG"] = "C"

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=shell,
            env=safe_env,  # <--- The Critical Fix
        )

        stdout = proc.stdout or ""
        stderr = proc.stderr or ""

        if strip_output:
            stdout = stdout.strip()
            stderr = stderr.strip()

        result["stdout"] = stdout
        result["stderr"] = stderr
        result["return_code"] = proc.returncode
        result["ok"] = (proc.returncode == 0)

    except subprocess.TimeoutExpired as e:
        result["timed_out"] = True
        result["error"] = "command timed out"
        # Sometimes TimeoutExpired carries partial output
        stdout = getattr(e, "stdout", "") or ""
        stderr = getattr(e, "stderr", "") or ""
        if strip_output:
            stdout = stdout.strip()
            stderr = stderr.strip()
        result["stdout"] = stdout
        result["stderr"] = stderr

    except Exception as e:
        # Any unexpected error gets captured here rather than killing the tool
        result["error"] = f"unexpected error: {e}"

    return result
