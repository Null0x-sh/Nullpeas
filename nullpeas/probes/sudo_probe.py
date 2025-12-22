import subprocess
from typing import Dict, Any


def run(state: Dict[str, Any]) -> None:
    """
    Sudo Probe
    ----------
    Purpose:
        Collect information about sudo privileges safely without blocking,
        and store raw + basic interpreted results in state["sudo"].

    What this DOES right now:
        - Runs `sudo -n -l` (non-interactive, so it won't hang for password input)
        - Captures return code, stdout, stderr
        - Identifies whether sudo EXISTS and responds
        - Identifies basic situations like "needs password" or "no sudo access"
        - Stores results in state for later analysis modules

    What it DOES NOT do yet (by design at this stage):
        - Deep parse sudo rules
        - Detect specific exploitable sudo configs
        - Perform GTFOBins matching
        - Handle multi-language sudo output robustly
        - Handle ALL weird sudo edge cases

    Those will be handled later in a dedicated sudo analysis module.
    """

    sudo: Dict[str, Any] = {}

    # -n = non-interactive mode
    # If sudo requires a password, it fails immediately instead of hanging.
    command = ["sudo", "-n", "-l"]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5  # safety timeout so nothing can block execution
        )

        sudo["return_code"] = result.returncode
        sudo["stdout"] = result.stdout.strip()
        sudo["stderr"] = result.stderr.strip()

        # Basic interpretation flags
        output_combined = (result.stdout + result.stderr).lower()

        # Did sudo respond at all?
        sudo["sudo_available"] = "usage:" not in output_combined

        # Did it immediately deny?
        sudo["permission_denied"] = "may not run sudo" in output_combined

        # Did it require a password?
        sudo["needs_password"] = "a password is required" in output_combined

        # VERY primitive indicator - I will replace this later with real parsing
        sudo["potential_rules_present"] = "command" in output_combined or "may run" in output_combined

        # High-level state flag for now
        sudo["has_sudo"] = (
            sudo["potential_rules_present"]
            and not sudo["permission_denied"]
        )

    except subprocess.TimeoutExpired:
        sudo["error"] = "sudo -l timed out after 5s"
    except FileNotFoundError:
        sudo["error"] = "sudo command not found on system"
    except Exception as e:
        sudo["error"] = str(e)

    # Attach to global runtime state
    state["sudo"] = sudo
