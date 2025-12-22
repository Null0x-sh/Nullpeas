from nullpeas.core.exec import run_command


def run(state: dict):
    sudo_info = {
        "binary_present": False,
        "return_code": None,
        "raw_stdout": "",
        "raw_stderr": "",

        # High-level interpretation
        "denied_completely": False,
        "rules_listed": False,
        "has_nopasswd_rule": False,

        # Final interpretation flags
        "has_sudo_rules": False,
        "passwordless_possible": False,

        # Errors
        "error": None,
    }

    # Use centralised runner
    res = run_command(["sudo", "-n", "-l"], timeout=5)

    # If the binary is missing entirely
    if res["binary_missing"]:
        sudo_info["error"] = res["error"] or "sudo binary not found on system"
        state["sudo"] = sudo_info
        return

    # Any unexpected error or timeout
    if res["timed_out"]:
        sudo_info["error"] = "sudo -l timed out after 5 seconds"
        state["sudo"] = sudo_info
        return

    if res["error"] and not res["ok"]:
        # Some non-timeout, non-binary-missing error
        sudo_info["error"] = res["error"]
        # Still store raw output in case it's useful
        sudo_info["raw_stdout"] = res["stdout"]
        sudo_info["raw_stderr"] = res["stderr"]
        sudo_info["return_code"] = res["return_code"]
        state["sudo"] = sudo_info
        return

    # At this point we know the binary exists
    sudo_info["binary_present"] = True
    sudo_info["return_code"] = res["return_code"]
    sudo_info["raw_stdout"] = res["stdout"]
    sudo_info["raw_stderr"] = res["stderr"]

    stdout = res["stdout"]
    stderr = res["stderr"]
    combined = (stdout + "\n" + stderr).lower()

    # --- Hard denials
    if "may not run sudo" in combined or "not allowed to run sudo" in combined:
        sudo_info["denied_completely"] = True

    # --- Detect any listed rules
    # Typical sudo lists rules like:
    #   (root) NOPASSWD: /usr/bin/vim
    #   (ALL : ALL) ALL
    for line in stdout.splitlines():
        line_strip = line.strip()
        if line_strip.startswith("(") and ")" in line_strip:
            sudo_info["rules_listed"] = True

            if "nopasswd" in line_strip.lower():
                sudo_info["has_nopasswd_rule"] = True

    # --- Final computed meaning
    sudo_info["has_sudo_rules"] = (
        sudo_info["binary_present"]
        and sudo_info["rules_listed"]
        and not sudo_info["denied_completely"]
    )

    sudo_info["passwordless_possible"] = sudo_info["has_nopasswd_rule"]

    state["sudo"] = sudo_info

