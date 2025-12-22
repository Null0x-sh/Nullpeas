# NullPEAS first helper

import shutil
import subprocess
from typing import List, Union, Optional, Dict, Any


DEFAULT_TIMEOUT = 5


def run_command(
    cmd: Union[List[str], str],
    timeout: int = DEFAULT_TIMEOUT,
    shell: bool = False,
    strip_output: bool = True,
) -> Dict[str, Any]:
    """
    Centralised wrapper around subprocess.run used by all probes.

    Returns a structured dict so callers don't need to worry about exceptions
    or low-level subprocess details.

    Keys in the returned dict:
        cmd: original command (list or string)
        shell: whether shell mode was used
        timeout: timeout passed in seconds

        ok: True if return_code == 0
        stdout: command stdout (string, possibly stripped)
        stderr: command stderr (string, possibly stripped)
        return_code: process return code (int or None)

        timed_out: True if the command hit the timeout
        binary_missing: True if the binary was not found (when shell=False)
        error: string description on unexpected error (else None)
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
    if not shell and isinstance(cmd, list):
        binary = cmd[0]
        if shutil.which(binary) is None:
            result["binary_missing"] = True
            result["error"] = f"binary '{binary}' not found"
            return result

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=shell,
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
